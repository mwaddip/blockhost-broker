/**
 * Client-side transaction building for Cardano.
 *
 * Builds request transactions (send to validator with datum + mint beacon)
 * and cleanup transactions (consume response UTXO + burn beacon).
 *
 * Uses TyphonJS (pure JS, no WASM) for transaction building.
 */

import { Transaction, address, types, crypto } from '@stricahq/typhonjs';
import BigNumber from 'bignumber.js';
import { Buffer } from 'buffer';
import { ed25519 } from '@noble/curves/ed25519.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { readFileSync, existsSync } from 'node:fs';

const REQUEST_BEACON_NAME = Buffer.from('request').toString('hex');
const RESPONSE_BEACON_NAME = Buffer.from('response').toString('hex');

const SPEND_EX_UNITS: types.ExUnits = { mem: 800_000, steps: 300_000_000 };
const MINT_EX_UNITS: types.ExUnits = { mem: 800_000, steps: 300_000_000 };

interface ScriptInfo {
    cbor: string;
    hash: string;
}

interface ScriptsFile {
    broker: ScriptInfo;
    beacon: ScriptInfo;
}

/**
 * Load a signing key from hex string or file path.
 * Returns the raw 32-byte Ed25519 private key.
 */
export function loadSigningKey(keyOrPath: string): Uint8Array {
    let hex: string;
    if (existsSync(keyOrPath)) {
        hex = readFileSync(keyOrPath, 'utf-8').trim();
    } else {
        hex = keyOrPath;
    }
    if (hex.startsWith('0x')) hex = hex.slice(2);
    const bytes = Buffer.from(hex, 'hex');
    if (bytes.length !== 32) {
        throw new Error(`Signing key must be 32 bytes, got ${bytes.length}`);
    }
    return bytes;
}

/**
 * Derive payment key hash (Blake2b-224 of Ed25519 public key).
 */
export function deriveKeyHash(privateKey: Uint8Array): Buffer {
    const publicKey = ed25519.getPublicKey(privateKey);
    return Buffer.from(blake2b(publicKey, { dkLen: 28 }));
}

/**
 * Derive a Cardano enterprise address from a payment key hash.
 */
export function deriveAddress(
    pkh: Buffer,
    networkId: types.NetworkId,
): address.EnterpriseAddress {
    return new address.EnterpriseAddress(networkId, {
        hash: pkh,
        type: types.HashType.ADDRESS,
    });
}

/**
 * Sign transaction data with a raw Ed25519 key.
 */
function signTx(txHash: Buffer, privateKey: Uint8Array): types.VKeyWitness {
    const publicKey = ed25519.getPublicKey(privateKey);
    const signature = ed25519.sign(txHash, privateKey);
    return {
        publicKey: Buffer.from(publicKey),
        signature: Buffer.from(signature),
    };
}

export class ClientTxBuilder {
    private brokerScript: types.PlutusScript;
    private beaconScript: types.PlutusScript;
    private brokerScriptHash: Buffer;
    private beaconPolicyId: string;
    private validatorAddress: address.EnterpriseAddress;
    private signingKey: Uint8Array;
    private clientPkh: Buffer;
    private clientAddress: address.EnterpriseAddress;
    private koiosUrl: string;
    private protocolParams: types.ProtocolParams | null = null;

    constructor(
        scripts: ScriptsFile,
        signingKey: Uint8Array,
        networkId: types.NetworkId,
        koiosUrl: string,
    ) {
        this.brokerScript = {
            cborHex: scripts.broker.cbor,
            type: types.PlutusScriptType.PlutusScriptV3,
        };
        this.beaconScript = {
            cborHex: scripts.beacon.cbor,
            type: types.PlutusScriptType.PlutusScriptV3,
        };
        this.brokerScriptHash = Buffer.from(scripts.broker.hash, 'hex');
        this.beaconPolicyId = scripts.beacon.hash;
        this.validatorAddress = new address.EnterpriseAddress(networkId, {
            hash: this.brokerScriptHash,
            type: types.HashType.SCRIPT,
        });

        this.signingKey = signingKey;
        this.clientPkh = deriveKeyHash(signingKey);
        this.clientAddress = deriveAddress(this.clientPkh, networkId);
        this.koiosUrl = koiosUrl;
    }

    getClientPkh(): string {
        return this.clientPkh.toString('hex');
    }

    getClientAddress(): string {
        return this.clientAddress.getBech32();
    }

    /**
     * Build and submit a request transaction.
     *
     * - Include NFT UTXO as input (anti-spam — beacon policy checks tx.inputs)
     * - Mint a request beacon
     * - Send ADA + beacon to validator with RequestDatum (inline)
     * - Return NFT to client
     */
    async submitRequest(
        nftPolicyId: string,
        encryptedPayload: Uint8Array,
    ): Promise<string> {
        if (!this.protocolParams) {
            this.protocolParams = await this.fetchProtocolParams();
        }

        const tx = new Transaction({ protocolParams: this.protocolParams });
        const tipSlot = await this.fetchTipSlot();
        tx.setTTL(tipSlot + 600);

        // Fetch client UTXOs
        const utxos = await this.fetchUtxos(this.clientAddress.getBech32());
        if (utxos.length === 0) {
            throw new Error('No UTXOs at client address');
        }

        // Find NFT UTXO (anti-spam)
        const nftUtxo = utxos.find(u =>
            u.tokens.some(t => t.policyId === nftPolicyId),
        );
        if (!nftUtxo) {
            throw new Error(`No UTXO with NFT policy ${nftPolicyId}`);
        }

        // Find collateral (ADA-only, >= 5 ADA)
        const collateralUtxo = utxos.find(u =>
            u.tokens.length === 0 && u.amount.gte(5_000_000),
        );
        if (!collateralUtxo) {
            throw new Error('No ADA-only UTXO for collateral (need >= 5 ADA)');
        }

        // Find a fee input (ADA-only, different from collateral)
        const feeUtxo = utxos.find(u =>
            u.tokens.length === 0 &&
            !(u.txId === collateralUtxo.txId && u.index === collateralUtxo.index),
        ) || nftUtxo; // fallback to NFT UTXO if no other

        // ── 1. NFT UTXO as input (anti-spam proof) ─────────────────────

        tx.addInput({
            txId: nftUtxo.txId,
            index: nftUtxo.index,
            amount: nftUtxo.amount,
            tokens: nftUtxo.tokens,
            address: this.clientAddress,
        });

        // Add separate fee input if different from NFT UTXO
        if (feeUtxo.txId !== nftUtxo.txId || feeUtxo.index !== nftUtxo.index) {
            tx.addInput({
                txId: feeUtxo.txId,
                index: feeUtxo.index,
                amount: feeUtxo.amount,
                tokens: feeUtxo.tokens,
                address: this.clientAddress,
            });
        }

        // ── 2. Mint request beacon ──────────────────────────────────────

        // MintRequestBeacon — BeaconAction constructor 0
        const mintRequestRedeemer: types.PlutusDataConstructor = {
            constructor: 0,
            fields: [],
        };

        tx.addMint({
            policyId: this.beaconPolicyId,
            assets: [
                { assetName: REQUEST_BEACON_NAME, amount: new BigNumber(1) },
            ],
            plutusScript: this.beaconScript,
            redeemer: { plutusData: mintRequestRedeemer, exUnits: MINT_EX_UNITS },
        });

        // ── 3. Output to validator with RequestDatum + beacon ───────────

        // RequestDatum { nft_policy_id, client_pkh, encrypted_payload } — constructor 0
        const requestDatum: types.PlutusDataConstructor = {
            constructor: 0,
            fields: [
                Buffer.from(nftPolicyId, 'hex'),
                this.clientPkh,
                Buffer.from(encryptedPayload),
            ],
        };

        const validatorOutput: types.Output = {
            amount: new BigNumber(2_000_000),
            address: this.validatorAddress,
            tokens: [{
                policyId: this.beaconPolicyId,
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

        // ── 4. Return NFT to client ─────────────────────────────────────

        const nftTokens = nftUtxo.tokens.filter(t => t.policyId === nftPolicyId);
        if (nftTokens.length > 0) {
            tx.addOutput({
                amount: new BigNumber(2_000_000),
                address: this.clientAddress,
                tokens: nftTokens,
            });
        }

        // ── 5. Collateral ───────────────────────────────────────────────

        tx.addCollateral({
            txId: collateralUtxo.txId,
            index: collateralUtxo.index,
            amount: collateralUtxo.amount,
            address: this.clientAddress,
        });

        // ── 6. Fee and change ───────────────────────────────────────────

        const fee = tx.calculateFee();
        tx.setFee(fee);

        const inputAmount = tx.getInputAmount();
        const outputAmount = tx.getOutputAmount();
        const changeAda = inputAmount.ada.minus(outputAmount.ada).minus(fee);

        if (changeAda.gte(1_000_000)) {
            // Return remaining tokens from NFT UTXO that aren't the NFT
            const otherTokens = nftUtxo.tokens.filter(t => t.policyId !== nftPolicyId);
            tx.addOutput({
                amount: changeAda,
                address: this.clientAddress,
                tokens: otherTokens,
            });
        }

        // ── 7. Sign and submit ──────────────────────────────────────────

        const txHashBuf = tx.getTransactionHash();
        tx.addWitness(signTx(txHashBuf, this.signingKey));

        const result = tx.buildTransaction();
        console.error(`[tx] Request tx: ${result.hash}, ${result.payload.length / 2} bytes`);

        return this.submitTx(result.payload);
    }

    /**
     * Build and submit a cleanup transaction.
     *
     * - Consume response UTXO (ConsumeResponse redeemer)
     * - Burn response beacon
     * - Return ADA to client
     */
    async cleanupResponse(
        responseUtxoRef: { txHash: string; outputIndex: number },
        responseDatumClientPkh: string,
        responseDatumEncryptedPayload: string,
    ): Promise<string> {
        if (!this.protocolParams) {
            this.protocolParams = await this.fetchProtocolParams();
        }

        const tx = new Transaction({ protocolParams: this.protocolParams });
        const tipSlot = await this.fetchTipSlot();
        tx.setTTL(tipSlot + 600);

        // Fetch client UTXOs for fees/collateral
        const utxos = await this.fetchUtxos(this.clientAddress.getBech32());
        const collateralUtxo = utxos.find(u => u.tokens.length === 0 && u.amount.gte(5_000_000));
        if (!collateralUtxo) {
            throw new Error('No ADA-only UTXO for collateral');
        }

        // Fee input
        const feeUtxo = utxos.find(u =>
            u.tokens.length === 0 &&
            !(u.txId === collateralUtxo.txId && u.index === collateralUtxo.index),
        );
        if (feeUtxo) {
            tx.addInput({
                txId: feeUtxo.txId,
                index: feeUtxo.index,
                amount: feeUtxo.amount,
                tokens: [],
                address: this.clientAddress,
            });
        }

        // ── 1. Consume response UTXO ────────────────────────────────────

        // ResponseDatum { client_pkh, encrypted_response } — constructor 1
        const responseDatum: types.PlutusDataConstructor = {
            constructor: 1,
            fields: [
                Buffer.from(responseDatumClientPkh, 'hex'),
                Buffer.from(responseDatumEncryptedPayload, 'hex'),
            ],
        };

        // ConsumeResponse — BrokerAction constructor 1
        const consumeResponseRedeemer: types.PlutusDataConstructor = {
            constructor: 1,
            fields: [],
        };

        const scriptCredential: types.ScriptCredential = {
            hash: this.brokerScriptHash,
            type: types.HashType.SCRIPT,
            plutusScript: this.brokerScript,
        };

        // Fetch the response UTXO info from Koios
        const validatorUtxos = await this.fetchUtxos(this.validatorAddress.getBech32());
        const responseUtxo = validatorUtxos.find(u =>
            u.txId === responseUtxoRef.txHash && u.index === responseUtxoRef.outputIndex,
        );
        if (!responseUtxo) {
            throw new Error(`Response UTXO not found: ${responseUtxoRef.txHash}#${responseUtxoRef.outputIndex}`);
        }

        tx.addInput({
            txId: responseUtxo.txId,
            index: responseUtxo.index,
            amount: responseUtxo.amount,
            tokens: responseUtxo.tokens,
            address: new address.EnterpriseAddress(
                this.clientAddress.getNetworkId() as types.NetworkId,
                scriptCredential,
            ),
            plutusData: responseDatum,
            redeemer: { plutusData: consumeResponseRedeemer, exUnits: SPEND_EX_UNITS },
        });

        // ── 2. Burn response beacon ─────────────────────────────────────

        // BurnResponseBeacon — BeaconAction constructor 3
        const burnResponseRedeemer: types.PlutusDataConstructor = {
            constructor: 3,
            fields: [],
        };

        tx.addMint({
            policyId: this.beaconPolicyId,
            assets: [
                { assetName: RESPONSE_BEACON_NAME, amount: new BigNumber(-1) },
            ],
            plutusScript: this.beaconScript,
            redeemer: { plutusData: burnResponseRedeemer, exUnits: MINT_EX_UNITS },
        });

        // ── 3. Required signer (client_pkh for ConsumeResponse) ─────────

        tx.addRequiredSigner({
            hash: this.clientPkh,
            type: types.HashType.ADDRESS,
        });

        // ── 4. Collateral ───────────────────────────────────────────────

        tx.addCollateral({
            txId: collateralUtxo.txId,
            index: collateralUtxo.index,
            amount: collateralUtxo.amount,
            address: this.clientAddress,
        });

        // ── 5. Fee and change ───────────────────────────────────────────

        const fee = tx.calculateFee();
        tx.setFee(fee);

        const inputAmount = tx.getInputAmount();
        const outputAmount = tx.getOutputAmount();
        const changeAda = inputAmount.ada.minus(outputAmount.ada).minus(fee);

        if (changeAda.gte(1_000_000)) {
            tx.addOutput({
                amount: changeAda,
                address: this.clientAddress,
                tokens: [],
            });
        }

        // ── 6. Sign and submit ──────────────────────────────────────────

        const txHashBuf = tx.getTransactionHash();
        tx.addWitness(signTx(txHashBuf, this.signingKey));

        const result = tx.buildTransaction();
        console.error(`[tx] Cleanup tx: ${result.hash}, ${result.payload.length / 2} bytes`);

        return this.submitTx(result.payload);
    }

    // ── Koios helpers ──────────────────────────────────────────────────

    private async fetchProtocolParams(): Promise<types.ProtocolParams> {
        const resp = await fetch(`${this.koiosUrl}/tip`);
        if (!resp.ok) throw new Error(`Koios tip ${resp.status}`);
        const tip = (await resp.json() as any[])[0];

        const epochResp = await fetch(`${this.koiosUrl}/epoch_params?_epoch_no=${tip.epoch_no}`);
        if (!epochResp.ok) throw new Error(`Koios epoch_params ${epochResp.status}`);
        const params = (await epochResp.json() as any[])[0];

        return {
            minFeeA: new BigNumber(params.min_fee_a),
            minFeeB: new BigNumber(params.min_fee_b),
            stakeKeyDeposit: new BigNumber(params.key_deposit),
            lovelacePerUtxoWord: new BigNumber(0),
            utxoCostPerByte: new BigNumber(params.coins_per_utxo_size),
            collateralPercent: new BigNumber(params.collateral_percent),
            priceSteps: new BigNumber(params.price_step),
            priceMem: new BigNumber(params.price_mem),
            languageView: {
                PlutusScriptV1: params.cost_models?.PlutusV1 ?? [],
                PlutusScriptV2: params.cost_models?.PlutusV2 ?? [],
                PlutusScriptV3: params.cost_models?.PlutusV3 ?? [],
            },
            maxTxSize: params.max_tx_size,
            maxValueSize: params.max_val_size,
            minFeeRefScriptCostPerByte: new BigNumber(params.min_fee_ref_script_cost_per_byte ?? 15),
        };
    }

    private async fetchTipSlot(): Promise<number> {
        const resp = await fetch(`${this.koiosUrl}/tip`);
        if (!resp.ok) throw new Error(`Koios tip ${resp.status}`);
        const tip = (await resp.json() as any[])[0];
        return tip.abs_slot;
    }

    private async fetchUtxos(addr: string): Promise<Array<{
        txId: string;
        index: number;
        amount: BigNumber;
        tokens: types.Token[];
    }>> {
        const resp = await fetch(`${this.koiosUrl}/address_utxos`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ _addresses: [addr], _extended: true }),
        });
        if (!resp.ok) throw new Error(`Koios address_utxos ${resp.status}`);
        const utxos: any[] = await resp.json();

        return utxos.map(u => ({
            txId: u.tx_hash,
            index: u.tx_index,
            amount: new BigNumber(u.value),
            tokens: (u.asset_list ?? []).map((a: any) => ({
                policyId: a.policy_id,
                assetName: Buffer.from(a.asset_name ?? '', 'utf-8').toString('hex'),
                amount: new BigNumber(a.quantity),
            })),
        }));
    }

    private async submitTx(cborHex: string): Promise<string> {
        const txBytes = Buffer.from(cborHex, 'hex');
        const resp = await fetch(`${this.koiosUrl}/submittx`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/cbor' },
            body: txBytes,
        });
        if (!resp.ok) {
            const text = await resp.text();
            throw new Error(`Koios submittx ${resp.status}: ${text}`);
        }
        const hash = await resp.text();
        return hash.replace(/"/g, '').trim();
    }
}
