/**
 * Live on-chain test: submit a request transaction on Cardano preprod,
 * wait for the adapter to process it, and verify the response.
 *
 * Uses the deployer wallet (mnemonic from env) as the client.
 *
 * Run: source ~/projects/sharedenv/cardano-preprod.env
 *      cd adapters/cardano/adapter && npx tsx ../test-live.ts
 */

import { Bip32PrivateKey } from '@stricahq/bip32ed25519';
import { Transaction, address, types, crypto } from '@stricahq/typhonjs';
import BigNumber from 'bignumber.js';
import { Buffer } from 'buffer';
import * as bip39 from 'bip39';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes } from 'crypto';
import { readFileSync } from 'fs';

const KOIOS_URL = 'https://preprod.koios.rest/api/v1';
const REGISTRY_ADDRESS = 'addr_test1wz6scyhnjeythyt6gchn5r26qeyqe0p4v7dmvstl3gd5dlc3wwyvx';
const NFT_POLICY = '977981c01b9ea38cb3893999e631b804f7767b6c029ed07ffc46a8b7';

const DEPLOYER_MNEMONIC = process.env.DEPLOYER_MNEMONIC;
if (!DEPLOYER_MNEMONIC) {
    console.error('Missing DEPLOYER_MNEMONIC — source ~/projects/sharedenv/cardano-preprod.env');
    process.exit(1);
}

function log(msg: string) { console.error(`[live-test] ${msg}`); }

// ── Koios helpers ──────────────────────────────────────────────────

async function koiosPost(endpoint: string, body: any): Promise<any> {
    const resp = await fetch(`${KOIOS_URL}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    if (!resp.ok) throw new Error(`Koios ${endpoint} ${resp.status}: ${await resp.text()}`);
    return resp.json();
}

async function koiosGet(endpoint: string): Promise<any> {
    const resp = await fetch(`${KOIOS_URL}${endpoint}`);
    if (!resp.ok) throw new Error(`Koios ${endpoint} ${resp.status}: ${await resp.text()}`);
    return resp.json();
}

async function submitTx(cborHex: string): Promise<string> {
    const resp = await fetch(`${KOIOS_URL}/submittx`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/cbor' },
        body: Buffer.from(cborHex, 'hex'),
    });
    if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`submittx ${resp.status}: ${text}`);
    }
    return (await resp.text()).replace(/"/g, '').trim();
}

async function fetchProtocolParams(): Promise<types.ProtocolParams> {
    const tip = (await koiosGet('/tip'))[0];
    const pp = (await koiosGet(`/epoch_params?_epoch_no=${tip.epoch_no}`))[0];
    return {
        minFeeA: new BigNumber(pp.min_fee_a),
        minFeeB: new BigNumber(pp.min_fee_b),
        stakeKeyDeposit: new BigNumber(pp.key_deposit),
        lovelacePerUtxoWord: new BigNumber(0),
        utxoCostPerByte: new BigNumber(pp.coins_per_utxo_size),
        collateralPercent: new BigNumber(pp.collateral_percent),
        priceSteps: new BigNumber(pp.price_step),
        priceMem: new BigNumber(pp.price_mem),
        languageView: {
            PlutusScriptV1: pp.cost_models?.PlutusV1 ?? [],
            PlutusScriptV2: pp.cost_models?.PlutusV2 ?? [],
            PlutusScriptV3: pp.cost_models?.PlutusV3 ?? [],
        },
        maxTxSize: pp.max_tx_size,
        maxValueSize: pp.max_val_size,
        minFeeRefScriptCostPerByte: new BigNumber(pp.min_fee_ref_script_cost_per_byte ?? 15),
    };
}

// ── Main ───────────────────────────────────────────────────────────

async function main() {
    log('=== Cardano Live On-Chain Test ===');

    // 1. Derive deployer key
    const entropy = Buffer.from(bip39.mnemonicToEntropy(DEPLOYER_MNEMONIC!), 'hex');
    const rootKey = await Bip32PrivateKey.fromEntropy(entropy);
    const accountKey = rootKey
        .derive(2147483648 + 1852)
        .derive(2147483648 + 1815)
        .derive(2147483648 + 0);

    const paymentKey = accountKey.derive(0).derive(0);
    const stakeKey = accountKey.derive(2).derive(0);
    const signingKey = paymentKey.toPrivateKey();
    const clientPkh = signingKey.toPublicKey().hash();
    const stakePkh = stakeKey.toPrivateKey().toPublicKey().hash();

    const clientAddr = new address.BaseAddress(
        types.NetworkId.TESTNET,
        { hash: clientPkh, type: types.HashType.ADDRESS },
        { hash: stakePkh, type: types.HashType.ADDRESS },
    );

    log(`Client address: ${clientAddr.getBech32()}`);
    log(`Client PKH: ${clientPkh.toString('hex')}`);

    // 2. Query registry for broker ECIES pubkey
    const regUtxos: any[] = await koiosPost('/address_utxos', {
        _addresses: [REGISTRY_ADDRESS], _extended: true,
    });
    const regDatum = regUtxos.find((u: any) => u.inline_datum?.value);
    if (!regDatum) throw new Error('No registry datum');
    const regFields = regDatum.inline_datum.value.fields;
    const brokerEciesPubHex: string = regFields[1].bytes;
    const validatorHash: string = regFields[4].bytes;
    const beaconPolicyId: string = regFields[5].bytes;

    log(`Broker ECIES pub: ${brokerEciesPubHex.slice(0, 20)}...`);
    log(`Validator hash: ${validatorHash}`);
    log(`Beacon policy: ${beaconPolicyId}`);

    // Decompress broker pubkey
    const brokerPubCompressed = Buffer.from(brokerEciesPubHex, 'hex');
    const brokerPubUncompressed = Buffer.from(
        secp256k1.Point.fromHex(brokerPubCompressed.toString('hex')).toBytes(false),
    );

    // 3. Generate WG keypair + ECIES server keypair
    const wgPriv = randomBytes(32);
    const wgPub = randomBytes(32); // mock WG pubkey (adapter doesn't validate format)

    const serverPriv = secp256k1.utils.randomSecretKey();
    const serverPubCompressed = secp256k1.getPublicKey(serverPriv, true);
    const serverPubUncompressed = secp256k1.getPublicKey(serverPriv, false);

    // 4. Encrypt request payload: [32 wg_pubkey][33 server_pubkey_compressed]
    const payload = new Uint8Array(65);
    payload.set(wgPub, 0);
    payload.set(serverPubCompressed, 32);

    // ECIES encrypt
    const ephPriv = secp256k1.utils.randomSecretKey();
    const ephPub = secp256k1.getPublicKey(ephPriv, false);
    const shared = secp256k1.getSharedSecret(ephPriv, brokerPubUncompressed);
    const aesKey = hkdf(sha256, shared.slice(1), undefined, undefined, 32);
    const iv = randomBytes(16);
    const cipher = gcm(aesKey, iv);
    const encrypted = cipher.encrypt(payload);
    const ciphertext = encrypted.slice(0, encrypted.length - 16);
    const tag = encrypted.slice(encrypted.length - 16);

    const eciesBlob = new Uint8Array(65 + 16 + 16 + ciphertext.length);
    eciesBlob.set(ephPub, 0);
    eciesBlob.set(tag, 65);
    eciesBlob.set(iv, 65 + 16);
    eciesBlob.set(ciphertext, 65 + 16 + 16);

    log(`Encrypted payload: ${eciesBlob.length} bytes`);

    // 5. Load scripts and build request transaction
    const scripts = JSON.parse(readFileSync(
        new URL('./contracts/parameterized-scripts.json', import.meta.url), 'utf-8',
    ));

    const beaconScript: types.PlutusScript = {
        cborHex: scripts.beacon.cbor,
        type: types.PlutusScriptType.PlutusScriptV3,
    };
    const brokerScriptHash = Buffer.from(scripts.broker.hash, 'hex');
    const validatorAddr = new address.EnterpriseAddress(types.NetworkId.TESTNET, {
        hash: brokerScriptHash,
        type: types.HashType.SCRIPT,
    });

    const protocolParams = await fetchProtocolParams();
    const tip = (await koiosGet('/tip'))[0];

    const tx = new Transaction({ protocolParams });
    tx.setTTL(tip.abs_slot + 600);

    // Fetch client UTXOs
    const clientUtxos: any[] = await koiosPost('/address_utxos', {
        _addresses: [clientAddr.getBech32()], _extended: true,
    });

    // Find NFT UTXO
    const nftUtxo = clientUtxos.find((u: any) =>
        (u.asset_list ?? []).some((a: any) => a.policy_id === NFT_POLICY),
    );
    if (!nftUtxo) throw new Error('No NFT UTXO found');
    const nftAsset = nftUtxo.asset_list.find((a: any) => a.policy_id === NFT_POLICY);

    log(`Using NFT UTXO: ${nftUtxo.tx_hash.slice(0, 16)}...#${nftUtxo.tx_index}`);
    log(`NFT: ${NFT_POLICY} / ${nftAsset.asset_name}`);

    // Find ADA-only UTXO for fees + collateral
    const adaUtxo = clientUtxos.find((u: any) =>
        (!u.asset_list || u.asset_list.length === 0) && parseInt(u.value) >= 10_000_000,
    );
    if (!adaUtxo) throw new Error('No ADA UTXO >= 10 ADA for fees');

    log(`Fee UTXO: ${adaUtxo.tx_hash.slice(0, 16)}...#${adaUtxo.tx_index} (${parseInt(adaUtxo.value) / 1e6} ADA)`);

    const REQUEST_BEACON_NAME = Buffer.from('request').toString('hex');

    // ── Add NFT input
    const nftTokens: types.Token[] = (nftUtxo.asset_list ?? []).map((a: any) => ({
        policyId: a.policy_id,
        assetName: a.asset_name,
        amount: new BigNumber(a.quantity),
    }));

    tx.addInput({
        txId: nftUtxo.tx_hash,
        index: nftUtxo.tx_index,
        amount: new BigNumber(nftUtxo.value),
        tokens: nftTokens,
        address: clientAddr,
    });

    // ── Add ADA input (if different from NFT)
    if (adaUtxo.tx_hash !== nftUtxo.tx_hash || adaUtxo.tx_index !== nftUtxo.tx_index) {
        tx.addInput({
            txId: adaUtxo.tx_hash,
            index: adaUtxo.tx_index,
            amount: new BigNumber(adaUtxo.value),
            tokens: [],
            address: clientAddr,
        });
    }

    // ── Mint request beacon
    const mintRequestRedeemer: types.PlutusDataConstructor = {
        constructor: 0,
        fields: [],
    };

    tx.addMint({
        policyId: beaconPolicyId,
        assets: [{ assetName: REQUEST_BEACON_NAME, amount: new BigNumber(1) }],
        plutusScript: beaconScript,
        redeemer: { plutusData: mintRequestRedeemer, exUnits: { mem: 800_000, steps: 300_000_000 } },
    });

    // ── Output at validator: RequestDatum + beacon
    const requestDatum: types.PlutusDataConstructor = {
        constructor: 0,
        fields: [
            Buffer.from(NFT_POLICY, 'hex'),
            clientPkh,
            Buffer.from(eciesBlob),
        ],
    };

    const validatorOutput: types.Output = {
        amount: new BigNumber(2_000_000),
        address: validatorAddr,
        tokens: [{
            policyId: beaconPolicyId,
            assetName: REQUEST_BEACON_NAME,
            amount: new BigNumber(1),
        }],
        plutusData: requestDatum,
    };

    const minUtxo = tx.calculateMinUtxoAmountBabbage(validatorOutput);
    if (minUtxo.gt(validatorOutput.amount)) {
        validatorOutput.amount = minUtxo;
    }
    tx.addOutput(validatorOutput);

    log(`Validator output: ${validatorOutput.amount.toString()} lovelace (min utxo: ${minUtxo.toString()})`);

    // ── Return NFT to client
    tx.addOutput({
        amount: new BigNumber(1_200_000),
        address: clientAddr,
        tokens: nftTokens,
    });

    // ── Collateral
    tx.addCollateral({
        txId: adaUtxo.tx_hash,
        index: adaUtxo.tx_index,
        amount: new BigNumber(adaUtxo.value),
        address: clientAddr,
    });

    // ── Fee and change (iterative)
    // Sum outputs before change
    const preChangeOutputAda = tx.getOutputAmount().ada;
    const inputAda = tx.getInputAmount().ada;

    // Add change output with estimated amount
    const estChange = inputAda.minus(preChangeOutputAda).minus(500_000);
    const changeOutput: types.Output = {
        amount: estChange,
        address: clientAddr,
        tokens: [],
    };
    tx.addOutput(changeOutput);

    // Calculate fee with all outputs present.
    // TyphonJS underestimates tx size for Conway-era, so add 10% margin.
    const rawFee = tx.calculateFee();
    const fee = rawFee.times(1.1).integerValue(BigNumber.ROUND_CEIL);
    tx.setFee(fee);

    // Actual change
    const changeAda = inputAda.minus(preChangeOutputAda).minus(fee);

    log(`Fee: ${fee.toString()} lovelace (${fee.div(1e6).toFixed(4)} ADA)`);
    log(`Change: ${changeAda.toString()} lovelace`);

    if (changeAda.lt(1_000_000)) {
        throw new Error(`Change too small: ${changeAda.toString()}`);
    }

    changeOutput.amount = changeAda;

    // ── Sign with bip32ed25519
    const txHash = tx.getTransactionHash();
    const signature = signingKey.sign(txHash);
    const publicKey = signingKey.toPublicKey();

    tx.addWitness({
        publicKey: publicKey.toBytes(),
        signature,
    });

    const result = tx.buildTransaction();
    log(`Request tx built: ${result.hash}`);
    log(`CBOR: ${result.payload.length / 2} bytes`);

    // 6. Submit
    log('Submitting request transaction...');
    const txHashStr = await submitTx(result.payload);
    log(`Submitted! Tx hash: ${txHashStr}`);

    // 7. Watch for response
    log('Watching for response at validator address...');
    const RESPONSE_BEACON_NAME = 'response';
    const deadline = Date.now() + 10 * 60 * 1000; // 10 minutes

    while (Date.now() < deadline) {
        await new Promise(r => setTimeout(r, 15_000)); // 15s poll

        const utxos: any[] = await koiosPost('/address_utxos', {
            _addresses: [validatorAddr.getBech32()], _extended: true,
        });

        for (const u of utxos) {
            const assets = u.asset_list ?? [];
            const hasResponseBeacon = assets.some(
                (a: any) => a.policy_id === beaconPolicyId && a.asset_name_ascii === RESPONSE_BEACON_NAME,
            );
            if (!hasResponseBeacon) continue;

            const datum = u.inline_datum?.value;
            if (!datum) continue;
            const fields = datum.fields ?? [];
            if (fields.length < 2) continue;
            if (fields[0].bytes !== clientPkh.toString('hex')) continue;

            log(`Found response UTXO: ${u.tx_hash}#${u.tx_index}`);

            // Decrypt compact response
            const encryptedHex: string = fields[1].bytes;
            const encryptedBuf = Buffer.from(encryptedHex, 'hex');

            const clientShared = secp256k1.getSharedSecret(serverPriv, brokerPubUncompressed);
            const ikm = clientShared.slice(1);
            const decKey = hkdf(sha256, ikm, undefined, new TextEncoder().encode('blockhost-aes-key'), 32);
            const decIv = hkdf(sha256, ikm, undefined, new TextEncoder().encode('blockhost-aes-iv'), 12);
            const decipher = gcm(decKey, decIv);
            const plaintext = decipher.decrypt(encryptedBuf);

            log(`Decrypted response: ${plaintext.length} bytes`);

            // Parse response: prefix(18) + gateway(4) + broker_pubkey(32) + endpoint_ip(4) + endpoint_port(2) + padding(3) = 63 bytes
            const prefixBytes = plaintext.slice(0, 18);
            const gatewayBytes = plaintext.slice(18, 22);
            const brokerPubkeyBytes = plaintext.slice(22, 54);
            const endpointIpBytes = plaintext.slice(54, 58);
            const endpointPort = (plaintext[58] << 8) | plaintext[59];

            // Parse IPv6 prefix
            const prefixParts = [];
            for (let i = 0; i < 16; i += 2) {
                prefixParts.push(((prefixBytes[i] << 8) | prefixBytes[i + 1]).toString(16));
            }
            const prefix = prefixParts.join(':');
            const prefixLen = prefixBytes[16];

            // Parse gateway IPv4
            const gateway = `${gatewayBytes[0]}.${gatewayBytes[1]}.${gatewayBytes[2]}.${gatewayBytes[3]}`;

            // Parse endpoint
            const endpointIp = `${endpointIpBytes[0]}.${endpointIpBytes[1]}.${endpointIpBytes[2]}.${endpointIpBytes[3]}`;

            const brokerWgPub = Buffer.from(brokerPubkeyBytes).toString('base64');

            log('');
            log('=== ALLOCATION RECEIVED ===');
            log(`  Prefix:    ${prefix}/${prefixLen}`);
            log(`  Gateway:   ${gateway}`);
            log(`  WG Pubkey: ${brokerWgPub}`);
            log(`  Endpoint:  ${endpointIp}:${endpointPort}`);
            log('===========================');
            log('');
            log('Live test PASSED!');
            return;
        }

        const elapsed = Math.round((Date.now() - (deadline - 600000)) / 1000);
        log(`Polling... ${elapsed}s elapsed`);
    }

    throw new Error('Timed out waiting for response');
}

main().catch(err => {
    log(`FAILED: ${err}`);
    process.exit(1);
});
