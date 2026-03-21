/**
 * End-to-end simulation test for the Cardano adapter.
 *
 * Tests:
 *   1. Key derivation (bip32ed25519) — verify deployer mnemonic → known address
 *   2. Koios live queries — registry datum, protocol params, UTXOs
 *   3. Crypto round-trip — ECIES encrypt/decrypt, compact encrypt/decrypt
 *   4. Transaction building — build a mock response tx, verify CBOR is valid
 *   5. Client address derivation — raw Ed25519 key → PKH → bech32
 *
 * Run: cd adapters/cardano/adapter && npx tsx ../test-e2e.ts
 */

import { Bip32PrivateKey } from '@stricahq/bip32ed25519';
import { Transaction, address, types, crypto } from '@stricahq/typhonjs';
import BigNumber from 'bignumber.js';
import { Buffer } from 'buffer';
import * as bip39 from 'bip39';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes } from 'crypto';
import { readFileSync } from 'fs';

const KOIOS_URL = 'https://preprod.koios.rest/api/v1';
const REGISTRY_ADDRESS = 'addr_test1wz6scyhnjeythyt6gchn5r26qeyqe0p4v7dmvstl3gd5dlc3wwyvx';
const EXPECTED_DEPLOYER_ADDRESS = 'addr_test1qqkmm4qnqn54ujscgmqy2v5dw34lyfn6pfsea32ewmnmavv32enf02z4rss8f9fk5s55t4wrqh6kvdqcxx79zwtkkhtqvugrgs';
const EXPECTED_OPERATOR_PKH = '9a0bd0af05421768af08076244a25a39a3cdd57e48db4384ab95e27b';

const DEPLOYER_MNEMONIC = 'ten labor property dawn route inner tackle casino orient pretty kite hedgehog record shrimp license squirrel floor run spread crane remind install unfold embody';

let passed = 0;
let failed = 0;

function ok(label: string) { passed++; console.log(`  ✓ ${label}`); }
function fail(label: string, err: any) { failed++; console.error(`  ✗ ${label}: ${err}`); }
function assert(cond: boolean, label: string, detail?: string) {
    if (cond) ok(label);
    else fail(label, detail || 'assertion failed');
}

// ── 1. Key Derivation ──────────────────────────────────────────────

async function testKeyDerivation() {
    console.log('\n═══ 1. Key Derivation ═══');

    // Deployer mnemonic → address
    const entropy = Buffer.from(bip39.mnemonicToEntropy(DEPLOYER_MNEMONIC), 'hex');
    const rootKey = await Bip32PrivateKey.fromEntropy(entropy);

    const accountKey = rootKey
        .derive(2147483648 + 1852)
        .derive(2147483648 + 1815)
        .derive(2147483648 + 0);

    const paymentKey = accountKey.derive(0).derive(0);
    const stakeKey = accountKey.derive(2).derive(0);

    const paymentPkh = paymentKey.toPrivateKey().toPublicKey().hash();
    const stakePkh = stakeKey.toPrivateKey().toPublicKey().hash();

    // Build base address (with staking)
    const baseAddr = new address.BaseAddress(
        types.NetworkId.TESTNET,
        { hash: paymentPkh, type: types.HashType.ADDRESS },
        { hash: stakePkh, type: types.HashType.ADDRESS },
    );
    const bech32 = baseAddr.getBech32();

    assert(
        bech32 === EXPECTED_DEPLOYER_ADDRESS,
        'Deployer mnemonic → expected address',
        `got ${bech32}`,
    );

    // Enterprise address (no staking)
    const enterpriseAddr = new address.EnterpriseAddress(
        types.NetworkId.TESTNET,
        { hash: paymentPkh, type: types.HashType.ADDRESS },
    );
    ok(`Enterprise address: ${enterpriseAddr.getBech32()}`);

    // Client-style: raw Ed25519 key → PKH → address
    const testPrivKey = randomBytes(32);
    const testPubKey = ed25519.getPublicKey(testPrivKey);
    const testPkh = Buffer.from(blake2b(testPubKey, { dkLen: 28 }));
    const clientAddr = new address.EnterpriseAddress(
        types.NetworkId.TESTNET,
        { hash: testPkh, type: types.HashType.ADDRESS },
    );
    assert(clientAddr.getBech32().startsWith('addr_test1'), 'Client Ed25519 key → valid testnet address');

    return { paymentKey, paymentPkh, enterpriseAddr };
}

// ── 2. Koios Live Queries ──────────────────────────────────────────

async function testKoiosQueries() {
    console.log('\n═══ 2. Koios Live Queries ═══');

    // Tip
    const tipResp = await fetch(`${KOIOS_URL}/tip`);
    assert(tipResp.ok, 'Fetch chain tip');
    const tip = (await tipResp.json() as any[])[0];
    ok(`Tip: epoch ${tip.epoch_no}, slot ${tip.abs_slot}, block ${tip.block_no}`);

    // Protocol params
    const ppResp = await fetch(`${KOIOS_URL}/epoch_params?_epoch_no=${tip.epoch_no}`);
    assert(ppResp.ok, 'Fetch protocol params');
    const pp = (await ppResp.json() as any[])[0];
    assert(!!pp.cost_models?.PlutusV3, 'PlutusV3 cost model present');
    ok(`minFeeA=${pp.min_fee_a}, minFeeB=${pp.min_fee_b}, utxoCostPerByte=${pp.coins_per_utxo_size}`);

    // Registry datum
    const regResp = await fetch(`${KOIOS_URL}/address_utxos`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ _addresses: [REGISTRY_ADDRESS], _extended: true }),
    });
    assert(regResp.ok, 'Fetch registry UTXOs');
    const regUtxos: any[] = await regResp.json();
    assert(regUtxos.length > 0, 'Registry has UTXOs');

    const regUtxo = regUtxos.find((u: any) => u.inline_datum?.value);
    assert(!!regUtxo, 'Registry UTXO has inline datum');

    const fields = regUtxo.inline_datum.value.fields ?? [];
    assert(fields.length >= 6, `Registry datum has 6+ fields (got ${fields.length})`);

    const operatorPkh = fields[0].bytes;
    const eciesPubkey = fields[1].bytes;
    const capacityStatus = fields[2].int;
    const region = Buffer.from(fields[3].bytes, 'hex').toString('utf-8');
    const validatorHash = fields[4].bytes;
    const beaconPolicyId = fields[5].bytes;

    assert(operatorPkh === EXPECTED_OPERATOR_PKH, 'Registry operator PKH matches');
    ok(`ECIES pubkey: ${eciesPubkey.slice(0, 20)}...`);
    ok(`Region: ${region}, capacity: ${capacityStatus}`);
    ok(`Validator hash: ${validatorHash}`);
    ok(`Beacon policy: ${beaconPolicyId}`);

    // Operator UTXOs
    const operatorAddr = new address.EnterpriseAddress(
        types.NetworkId.TESTNET,
        { hash: Buffer.from(operatorPkh, 'hex'), type: types.HashType.ADDRESS },
    ).getBech32();

    // Query deployer UTXOs instead (operator is on server)
    const deplResp = await fetch(`${KOIOS_URL}/address_utxos`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ _addresses: [EXPECTED_DEPLOYER_ADDRESS], _extended: true }),
    });
    assert(deplResp.ok, 'Fetch deployer UTXOs');
    const deplUtxos: any[] = await deplResp.json();
    const totalAda = deplUtxos.reduce((sum: number, u: any) => sum + parseInt(u.value), 0);
    ok(`Deployer: ${deplUtxos.length} UTXOs, ${(totalAda / 1_000_000).toFixed(2)} ADA`);

    return {
        pp, tip, eciesPubkey, validatorHash, beaconPolicyId, operatorPkh,
    };
}

// ── 3. Crypto Round-Trip ───────────────────────────────────────────

function testCryptoRoundTrip() {
    console.log('\n═══ 3. Crypto Round-Trip ═══');

    // Generate broker ECIES keypair
    const brokerPriv = secp256k1.utils.randomSecretKey();
    const brokerPub = secp256k1.getPublicKey(brokerPriv, false); // uncompressed

    // Generate client server keypair
    const clientServerPriv = secp256k1.utils.randomSecretKey();
    const clientServerPubCompressed = secp256k1.getPublicKey(clientServerPriv, true);
    const clientServerPubUncompressed = secp256k1.getPublicKey(clientServerPriv, false);

    // Generate WG key (just random 32 bytes for test)
    const wgPubkey = randomBytes(32);

    // Serialize request payload: [32 WG pubkey][33 server pubkey compressed]
    const payload = new Uint8Array(65);
    payload.set(wgPubkey, 0);
    payload.set(clientServerPubCompressed, 32);
    assert(payload.length === 65, 'Request payload is 65 bytes');

    // ECIES encrypt (client → broker)
    const ephPriv = secp256k1.utils.randomSecretKey();
    const ephPub = secp256k1.getPublicKey(ephPriv, false);
    const shared = secp256k1.getSharedSecret(ephPriv, brokerPub);
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

    ok(`ECIES encrypted: ${eciesBlob.length} bytes`);

    // ECIES decrypt (broker side)
    const dEphPub = eciesBlob.slice(0, 65);
    const dTag = eciesBlob.slice(65, 65 + 16);
    const dIv = eciesBlob.slice(65 + 16, 65 + 16 + 16);
    const dCiphertext = eciesBlob.slice(65 + 16 + 16);

    const dShared = secp256k1.getSharedSecret(brokerPriv, dEphPub);
    const dAesKey = hkdf(sha256, dShared.slice(1), undefined, undefined, 32);
    const combined = new Uint8Array(dCiphertext.length + 16);
    combined.set(dCiphertext, 0);
    combined.set(dTag, dCiphertext.length);
    const decipher = gcm(dAesKey, dIv);
    const decrypted = decipher.decrypt(combined);

    assert(decrypted.length === 65, 'Decrypted payload is 65 bytes');
    assert(
        Buffer.from(decrypted.slice(0, 32)).equals(wgPubkey),
        'WG pubkey matches after decrypt',
    );
    assert(
        Buffer.from(decrypted.slice(32, 65)).equals(Buffer.from(clientServerPubCompressed)),
        'Server pubkey matches after decrypt',
    );

    // Compact encrypt (broker → client) for response
    const responseBuf = new Uint8Array(63);
    randomBytes(63).copy(responseBuf); // mock response

    const compactShared = secp256k1.getSharedSecret(brokerPriv, clientServerPubUncompressed);
    const compactIkm = compactShared.slice(1);
    const compactAesKey = hkdf(sha256, compactIkm, undefined, new TextEncoder().encode('blockhost-aes-key'), 32);
    const compactIv = hkdf(sha256, compactIkm, undefined, new TextEncoder().encode('blockhost-aes-iv'), 12);
    const compactCipher = gcm(compactAesKey, compactIv);
    const compactEncrypted = compactCipher.encrypt(responseBuf);

    ok(`Compact encrypted response: ${compactEncrypted.length} bytes (63 + 16 tag)`);

    // Compact decrypt (client side)
    const clientShared = secp256k1.getSharedSecret(clientServerPriv, brokerPub);
    const clientIkm = clientShared.slice(1);
    const clientAesKey = hkdf(sha256, clientIkm, undefined, new TextEncoder().encode('blockhost-aes-key'), 32);
    const clientIv = hkdf(sha256, clientIkm, undefined, new TextEncoder().encode('blockhost-aes-iv'), 12);
    const clientDecipher = gcm(clientAesKey, clientIv);
    const clientDecrypted = clientDecipher.decrypt(compactEncrypted);

    assert(clientDecrypted.length === 63, 'Compact decrypted response is 63 bytes');
    assert(
        Buffer.from(clientDecrypted).equals(Buffer.from(responseBuf)),
        'Response matches after compact round-trip',
    );
}

// ── 4. Transaction Building ────────────────────────────────────────

async function testTransactionBuilding(koiosData: any) {
    console.log('\n═══ 4. Transaction Building ═══');

    const { pp, tip, beaconPolicyId, validatorHash } = koiosData;

    // Load pre-parameterized scripts
    const scripts = JSON.parse(readFileSync(
        new URL('./contracts/parameterized-scripts.json', import.meta.url), 'utf-8',
    ));

    // Build protocol params for TyphonJS
    const protocolParams: types.ProtocolParams = {
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

    ok('Protocol params loaded');

    // ── 4a. Build a mock RESPONSE transaction ───────────────────────

    const tx = new Transaction({ protocolParams });
    tx.setTTL(tip.abs_slot + 600);

    const brokerScriptHash = Buffer.from(scripts.broker.hash, 'hex');
    const brokerScript: types.PlutusScript = {
        cborHex: scripts.broker.cbor,
        type: types.PlutusScriptType.PlutusScriptV3,
    };
    const beaconScript: types.PlutusScript = {
        cborHex: scripts.beacon.cbor,
        type: types.PlutusScriptType.PlutusScriptV3,
    };

    const REQUEST_BEACON_NAME = Buffer.from('request').toString('hex');
    const RESPONSE_BEACON_NAME = Buffer.from('response').toString('hex');

    // Mock operator
    const mockOperatorPriv = randomBytes(32);
    const mockOperatorPub = ed25519.getPublicKey(mockOperatorPriv);
    const mockOperatorPkh = Buffer.from(blake2b(mockOperatorPub, { dkLen: 28 }));
    const mockOperatorAddr = new address.EnterpriseAddress(
        types.NetworkId.TESTNET,
        { hash: mockOperatorPkh, type: types.HashType.ADDRESS },
    );

    // Mock request UTXO (script input)
    const mockClientPkh = randomBytes(28);
    const mockEncPayload = randomBytes(100);

    const requestDatum: types.PlutusDataConstructor = {
        constructor: 0,
        fields: [
            Buffer.from('aa'.repeat(28), 'hex'), // nft_policy_id
            Buffer.from(mockClientPkh),           // client_pkh
            Buffer.from(mockEncPayload),           // encrypted_payload
        ],
    };

    const consumeRequestRedeemer: types.PlutusDataConstructor = {
        constructor: 0,
        fields: [Buffer.from(beaconPolicyId, 'hex')],
    };

    tx.addInput({
        txId: 'a'.repeat(64),
        index: 0,
        amount: new BigNumber(3_000_000),
        tokens: [{
            policyId: beaconPolicyId,
            assetName: REQUEST_BEACON_NAME,
            amount: new BigNumber(1),
        }],
        address: new address.EnterpriseAddress(types.NetworkId.TESTNET, {
            hash: brokerScriptHash,
            type: types.HashType.SCRIPT,
            plutusScript: brokerScript,
        }),
        plutusData: requestDatum,
        redeemer: { plutusData: consumeRequestRedeemer, exUnits: { mem: 800_000, steps: 300_000_000 } },
    });

    // Operator input (for fees)
    tx.addInput({
        txId: 'b'.repeat(64),
        index: 0,
        amount: new BigNumber(10_000_000),
        tokens: [],
        address: mockOperatorAddr,
    });

    // Collateral
    tx.addCollateral({
        txId: 'b'.repeat(64),
        index: 0,
        amount: new BigNumber(10_000_000),
        address: mockOperatorAddr,
    });

    // Mint: burn request + mint response
    const mintResponseRedeemer: types.PlutusDataConstructor = {
        constructor: 2,
        fields: [],
    };

    tx.addMint({
        policyId: beaconPolicyId,
        assets: [
            { assetName: REQUEST_BEACON_NAME, amount: new BigNumber(-1) },
            { assetName: RESPONSE_BEACON_NAME, amount: new BigNumber(1) },
        ],
        plutusScript: beaconScript,
        redeemer: { plutusData: mintResponseRedeemer, exUnits: { mem: 800_000, steps: 300_000_000 } },
    });

    // Response output at validator
    const responseDatum: types.PlutusDataConstructor = {
        constructor: 1,
        fields: [
            Buffer.from(mockClientPkh),
            randomBytes(79), // encrypted response (63 + 16 tag)
        ],
    };

    const validatorAddr = new address.EnterpriseAddress(types.NetworkId.TESTNET, {
        hash: brokerScriptHash,
        type: types.HashType.SCRIPT,
    });

    const responseOutput: types.Output = {
        amount: new BigNumber(2_000_000),
        address: validatorAddr,
        tokens: [{
            policyId: beaconPolicyId,
            assetName: RESPONSE_BEACON_NAME,
            amount: new BigNumber(1),
        }],
        plutusData: responseDatum,
    };

    const minUtxo = tx.calculateMinUtxoAmountBabbage(responseOutput);
    if (minUtxo.gt(responseOutput.amount)) {
        responseOutput.amount = minUtxo;
    }
    tx.addOutput(responseOutput);

    // Required signer
    tx.addRequiredSigner({
        hash: mockOperatorPkh,
        type: types.HashType.ADDRESS,
    });

    // Fee
    const fee = tx.calculateFee();
    tx.setFee(fee);
    ok(`Fee calculated: ${fee.toString()} lovelace (${(fee.toNumber() / 1_000_000).toFixed(4)} ADA)`);

    // Change
    const totalIn = new BigNumber(3_000_000 + 10_000_000);
    const changeAda = totalIn.minus(fee).minus(responseOutput.amount);
    tx.addOutput({
        amount: changeAda,
        address: mockOperatorAddr,
        tokens: [],
    });

    // Sign
    const txHash = tx.getTransactionHash();
    assert(txHash.length === 32, `Tx hash is 32 bytes (got ${txHash.length})`);

    const signature = ed25519.sign(txHash, mockOperatorPriv);
    tx.addWitness({
        publicKey: Buffer.from(mockOperatorPub),
        signature: Buffer.from(signature),
    });

    // Build
    const result = tx.buildTransaction();
    assert(result.hash.length === 64, 'Tx hash is 64 hex chars');
    assert(result.payload.length > 0, 'Tx payload is non-empty');
    ok(`Response tx built: ${result.payload.length / 2} bytes CBOR`);
    ok(`Tx hash: ${result.hash}`);

    // ── 4b. Build a mock REQUEST transaction (client side) ──────────

    const txReq = new Transaction({ protocolParams });
    txReq.setTTL(tip.abs_slot + 600);

    const mockClientPriv = randomBytes(32);
    const mockClientPub = ed25519.getPublicKey(mockClientPriv);
    const mockClientPkhReq = Buffer.from(blake2b(mockClientPub, { dkLen: 28 }));
    const mockClientAddr = new address.EnterpriseAddress(
        types.NetworkId.TESTNET,
        { hash: mockClientPkhReq, type: types.HashType.ADDRESS },
    );

    // NFT input
    const mockNftPolicy = 'cc'.repeat(28);
    txReq.addInput({
        txId: 'c'.repeat(64),
        index: 0,
        amount: new BigNumber(5_000_000),
        tokens: [{ policyId: mockNftPolicy, assetName: Buffer.from('nft').toString('hex'), amount: new BigNumber(1) }],
        address: mockClientAddr,
    });

    // Fee input
    txReq.addInput({
        txId: 'd'.repeat(64),
        index: 0,
        amount: new BigNumber(10_000_000),
        tokens: [],
        address: mockClientAddr,
    });

    // Mint request beacon
    const mintRequestRedeemer: types.PlutusDataConstructor = {
        constructor: 0,
        fields: [],
    };

    txReq.addMint({
        policyId: beaconPolicyId,
        assets: [
            { assetName: REQUEST_BEACON_NAME, amount: new BigNumber(1) },
        ],
        plutusScript: beaconScript,
        redeemer: { plutusData: mintRequestRedeemer, exUnits: { mem: 800_000, steps: 300_000_000 } },
    });

    // Output at validator with RequestDatum
    const clientReqDatum: types.PlutusDataConstructor = {
        constructor: 0,
        fields: [
            Buffer.from(mockNftPolicy, 'hex'),
            mockClientPkhReq,
            randomBytes(162), // encrypted payload
        ],
    };

    const reqOutput: types.Output = {
        amount: new BigNumber(2_000_000),
        address: validatorAddr,
        tokens: [{
            policyId: beaconPolicyId,
            assetName: REQUEST_BEACON_NAME,
            amount: new BigNumber(1),
        }],
        plutusData: clientReqDatum,
    };

    const reqMinUtxo = txReq.calculateMinUtxoAmountBabbage(reqOutput);
    if (reqMinUtxo.gt(reqOutput.amount)) reqOutput.amount = reqMinUtxo;
    txReq.addOutput(reqOutput);

    // Return NFT to client
    txReq.addOutput({
        amount: new BigNumber(2_000_000),
        address: mockClientAddr,
        tokens: [{ policyId: mockNftPolicy, assetName: Buffer.from('nft').toString('hex'), amount: new BigNumber(1) }],
    });

    // Collateral
    txReq.addCollateral({
        txId: 'd'.repeat(64),
        index: 0,
        amount: new BigNumber(10_000_000),
        address: mockClientAddr,
    });

    const reqFee = txReq.calculateFee();
    txReq.setFee(reqFee);

    const reqChangeAda = new BigNumber(5_000_000 + 10_000_000)
        .minus(reqFee).minus(reqOutput.amount).minus(2_000_000);
    txReq.addOutput({
        amount: reqChangeAda,
        address: mockClientAddr,
        tokens: [],
    });

    const reqTxHash = txReq.getTransactionHash();
    const reqSig = ed25519.sign(reqTxHash, mockClientPriv);
    txReq.addWitness({
        publicKey: Buffer.from(mockClientPub),
        signature: Buffer.from(reqSig),
    });

    const reqResult = txReq.buildTransaction();
    assert(reqResult.hash.length === 64, 'Request tx hash is 64 hex chars');
    ok(`Request tx built: ${reqResult.payload.length / 2} bytes CBOR, fee ${reqFee} lovelace`);

    // ── 4c. Verify script hashes ────────────────────────────────────

    // Script hash = blake2b-224(0x03 || inner_CBOR) for Plutus V3
    // The compiledCode is double-CBOR: CBOR_bytes(CBOR_bytes(flat_UPLC))
    // The hash uses the inner layer (strip the outer CBOR bytestring wrapper)
    function stripOuterCbor(hex: string): Buffer {
        const buf = Buffer.from(hex, 'hex');
        // Outer CBOR is a bytestring: 59 XX XX (2-byte length) or 58 XX (1-byte)
        if (buf[0] === 0x59) return buf.slice(3, 3 + ((buf[1] << 8) | buf[2]));
        if (buf[0] === 0x58) return buf.slice(2, 2 + buf[1]);
        return buf; // short form: 4X where X is length
    }

    const brokerInner = stripOuterCbor(scripts.broker.cbor);
    const computedBrokerHash = crypto.hash28(Buffer.concat([Buffer.from([0x03]), brokerInner]));
    assert(
        computedBrokerHash.toString('hex') === scripts.broker.hash,
        'Broker script hash verified (blake2b-224)',
    );

    const beaconInner = stripOuterCbor(scripts.beacon.cbor);
    const computedBeaconHash = crypto.hash28(Buffer.concat([Buffer.from([0x03]), beaconInner]));
    assert(
        computedBeaconHash.toString('hex') === scripts.beacon.hash,
        'Beacon script hash verified (blake2b-224)',
    );

    // Verify validator address from script hash
    const computedValidatorAddr = new address.EnterpriseAddress(
        types.NetworkId.TESTNET,
        { hash: computedBrokerHash, type: types.HashType.SCRIPT },
    ).getBech32();
    assert(
        computedValidatorAddr === 'addr_test1wr30vlte5lujfpuvzakjfd86tl2ml6rdd9ppnths95cl3sceh35rv',
        'Validator address derived from computed hash matches deployed address',
    );
}

// ── Run ────────────────────────────────────────────────────────────

async function main() {
    console.log('BlockHost Cardano E2E Simulation Test');
    console.log('=====================================');

    await testKeyDerivation();
    const koiosData = await testKoiosQueries();
    testCryptoRoundTrip();
    await testTransactionBuilding(koiosData);

    console.log(`\n═══ Results: ${passed} passed, ${failed} failed ═══`);
    if (failed > 0) process.exit(1);
}

main().catch(err => {
    console.error('Fatal:', err);
    process.exit(1);
});
