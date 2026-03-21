/**
 * Builds and submits response transactions on Cardano.
 *
 * Consumes a request UTXO, burns the request beacon,
 * mints a response beacon, and produces a response UTXO
 * at the validator address with an encrypted datum.
 *
 * Uses TyphonJS (pure JS, no WASM) for transaction building.
 */

import { Transaction, address, types, crypto } from '@stricahq/typhonjs';
import BigNumber from 'bignumber.js';
import { Buffer } from 'buffer';
import type { PrivateKey } from '@stricahq/bip32ed25519';
import type { RequestUtxo } from './poller.js';

const REQUEST_BEACON_NAME = Buffer.from('request').toString('hex');
const RESPONSE_BEACON_NAME = Buffer.from('response').toString('hex');

// Generous exUnit budgets for our simple validators.
// Actual costs are well below these — fee overhead is minimal.
const SPEND_EX_UNITS: types.ExUnits = { mem: 800_000, steps: 300_000_000 };
const MINT_EX_UNITS: types.ExUnits = { mem: 800_000, steps: 300_000_000 };

interface ScriptInfo {
    cbor: string;
    hash: string;
}

export class ResponseTxBuilder {
    private brokerScript: types.PlutusScript;
    private beaconScript: types.PlutusScript;
    private brokerScriptHash: Buffer;
    private beaconPolicyId: string;
    private validatorAddress: address.EnterpriseAddress;
    private operatorAddress: types.ShelleyAddress;
    private operatorPkh: Buffer;
    private signingKey: PrivateKey;
    private koiosUrl: string;
    private protocolParams: types.ProtocolParams | null = null;

    constructor(
        brokerInfo: ScriptInfo,
        beaconInfo: ScriptInfo,
        signingKey: PrivateKey,
        operatorPkh: Buffer,
        operatorAddress: types.ShelleyAddress,
        private networkId: types.NetworkId,
        koiosUrl: string,
    ) {
        this.brokerScript = {
            cborHex: brokerInfo.cbor,
            type: types.PlutusScriptType.PlutusScriptV3,
        };
        this.beaconScript = {
            cborHex: beaconInfo.cbor,
            type: types.PlutusScriptType.PlutusScriptV3,
        };
        this.brokerScriptHash = Buffer.from(brokerInfo.hash, 'hex');
        this.beaconPolicyId = beaconInfo.hash;
        this.validatorAddress = new address.EnterpriseAddress(
            networkId,
            { hash: this.brokerScriptHash, type: types.HashType.SCRIPT },
        );
        this.operatorAddress = operatorAddress;
        this.operatorPkh = operatorPkh;
        this.signingKey = signingKey;
        this.koiosUrl = koiosUrl;

        console.log(`[tx-builder] Broker script hash: ${brokerInfo.hash}`);
        console.log(`[tx-builder] Beacon policy: ${beaconInfo.hash}`);
        console.log(`[tx-builder] Validator: ${this.validatorAddress.getBech32()}`);
    }

    /**
     * Build and submit a response transaction.
     *
     * - Consumes the request UTXO (ConsumeRequest redeemer)
     * - Burns request beacon + mints response beacon (single policy, MintResponseBeacon redeemer)
     * - Produces a response UTXO at the validator with ResponseDatum
     *
     * Returns the transaction hash.
     */
    async submitResponse(
        requestUtxo: RequestUtxo,
        encryptedResponse: Uint8Array,
    ): Promise<string> {
        console.log(`[tx-builder] Building response tx for ${requestUtxo.ref.txHash}#${requestUtxo.ref.outputIndex}`);

        // Ensure protocol params are loaded
        if (!this.protocolParams) {
            this.protocolParams = await this.fetchProtocolParams();
        }

        const tx = new Transaction({ protocolParams: this.protocolParams });

        // Get current tip for TTL
        const tipSlot = await this.fetchTipSlot();
        tx.setTTL(tipSlot + 600); // ~10 minutes

        // ── 1. Consume request UTXO (script input) ─────────────────────

        // RequestDatum { nft_policy_id, client_pkh, encrypted_payload } — constructor 0
        const requestDatum: types.PlutusDataConstructor = {
            constructor: 0,
            fields: [
                Buffer.from(requestUtxo.nftPolicyId, 'hex'),
                Buffer.from(requestUtxo.clientPkh, 'hex'),
                Buffer.from(requestUtxo.encryptedPayload, 'hex'),
            ],
        };

        // ConsumeRequest { beacon_policy_id } — BrokerAction constructor 0
        const consumeRequestRedeemer: types.PlutusDataConstructor = {
            constructor: 0,
            fields: [Buffer.from(this.beaconPolicyId, 'hex')],
        };

        const scriptCredential: types.ScriptCredential = {
            hash: this.brokerScriptHash,
            type: types.HashType.SCRIPT,
            plutusScript: this.brokerScript,
        };

        // Note: plutusData is NOT included here because the request UTXO uses
        // an inline datum. The node provides the datum to the script automatically.
        // Including it would cause NotAllowedSupplementalDatums in Conway era.
        tx.addInput({
            txId: requestUtxo.ref.txHash,
            index: requestUtxo.ref.outputIndex,
            amount: new BigNumber(requestUtxo.lovelace),
            tokens: [{
                policyId: this.beaconPolicyId,
                assetName: REQUEST_BEACON_NAME,
                amount: new BigNumber(1),
            }],
            address: new address.EnterpriseAddress(this.networkId, scriptCredential),
            redeemer: { plutusData: consumeRequestRedeemer, exUnits: SPEND_EX_UNITS },
        });

        // ── 2. Operator inputs (for fees) ───────────────────────────────

        const operatorUtxos = await this.fetchUtxos(this.operatorAddress.getBech32());
        if (operatorUtxos.length === 0) {
            throw new Error('No UTXOs at operator address');
        }

        // Pick ADA-only UTXOs for inputs and collateral
        const adaOnlyUtxos = operatorUtxos
            .filter(u => u.tokens.length === 0)
            .sort((a, b) => b.amount.minus(a.amount).toNumber()); // largest first

        if (adaOnlyUtxos.length === 0) {
            throw new Error('No ADA-only UTXOs at operator address for fees/collateral');
        }

        // Add largest ADA UTXO as input
        const feeInput = adaOnlyUtxos[0];
        tx.addInput({
            txId: feeInput.txId,
            index: feeInput.index,
            amount: feeInput.amount,
            tokens: [],
            address: this.operatorAddress,
        });

        // Collateral
        const collateralUtxo = adaOnlyUtxos[0];
        tx.addCollateral({
            txId: collateralUtxo.txId,
            index: collateralUtxo.index,
            amount: collateralUtxo.amount,
            address: this.operatorAddress,
        });

        // ── 3. Mint: burn request beacon + mint response beacon ─────────
        //
        // Single policy, one redeemer: MintResponseBeacon (constructor 2).
        // Cardano allows only one redeemer per policy — MintResponseBeacon
        // validates operator signature and output placement, which covers
        // the security requirements for both operations.

        const mintResponseRedeemer: types.PlutusDataConstructor = {
            constructor: 2,
            fields: [],
        };

        tx.addMint({
            policyId: this.beaconPolicyId,
            assets: [
                { assetName: REQUEST_BEACON_NAME, amount: new BigNumber(-1) },
                { assetName: RESPONSE_BEACON_NAME, amount: new BigNumber(1) },
            ],
            plutusScript: this.beaconScript,
            redeemer: { plutusData: mintResponseRedeemer, exUnits: MINT_EX_UNITS },
        });

        // ── 4. Response UTXO at validator ───────────────────────────────

        // ResponseDatum { client_pkh, encrypted_response } — constructor 1
        const responseDatum: types.PlutusDataConstructor = {
            constructor: 1,
            fields: [
                Buffer.from(requestUtxo.clientPkh, 'hex'),
                Buffer.from(encryptedResponse),
            ],
        };

        const responseOutput: types.Output = {
            amount: new BigNumber(2_000_000),
            address: this.validatorAddress,
            tokens: [{
                policyId: this.beaconPolicyId,
                assetName: RESPONSE_BEACON_NAME,
                amount: new BigNumber(1),
            }],
            plutusData: responseDatum,
        };

        // Ensure min UTXO
        const minUtxo = tx.calculateMinUtxoAmountBabbage(responseOutput);
        if (minUtxo.gt(responseOutput.amount)) {
            responseOutput.amount = minUtxo;
        }

        tx.addOutput(responseOutput);

        // ── 5. Required signer (operator) ───────────────────────────────

        tx.addRequiredSigner({
            hash: this.operatorPkh,
            type: types.HashType.ADDRESS,
        });

        // ── 6. Fee calculation and change ───────────────────────────────

        const totalInputAda = feeInput.amount.plus(new BigNumber(requestUtxo.lovelace));
        const preChangeOutputAda = tx.getOutputAmount().ada;

        // Add change output with estimated amount (so fee calc includes it)
        const estChange = totalInputAda.minus(preChangeOutputAda).minus(500_000);
        const changeOutput: types.Output = {
            amount: estChange.gt(1_000_000) ? estChange : new BigNumber(2_000_000),
            address: this.operatorAddress,
            tokens: [],
        };
        tx.addOutput(changeOutput);

        // TyphonJS underestimates Conway-era tx size — add 10% margin
        const fee = tx.calculateFee().times(1.1).integerValue(BigNumber.ROUND_CEIL);
        tx.setFee(fee);

        const changeAda = totalInputAda.minus(preChangeOutputAda).minus(fee);

        if (changeAda.lt(1_000_000)) {
            // Need more inputs
            if (adaOnlyUtxos.length < 2) {
                throw new Error(`Insufficient ADA: need more inputs (change would be ${changeAda})`);
            }
            const extraInput = adaOnlyUtxos[1];
            tx.addInput({
                txId: extraInput.txId,
                index: extraInput.index,
                amount: extraInput.amount,
                tokens: [],
                address: this.operatorAddress,
            });

            const newFee = tx.calculateFee().times(1.1).integerValue(BigNumber.ROUND_CEIL);
            tx.setFee(newFee);
            const newChange = totalInputAda.plus(extraInput.amount).minus(preChangeOutputAda).minus(newFee);
            changeOutput.amount = newChange;
        } else {
            changeOutput.amount = changeAda;
        }

        // ── 7. Sign ─────────────────────────────────────────────────────

        const txHash = tx.getTransactionHash();
        const signature = this.signingKey.sign(txHash);
        const publicKey = this.signingKey.toPublicKey();

        tx.addWitness({
            publicKey: publicKey.toBytes(),
            signature,
        });

        // ── 8. Build and submit ─────────────────────────────────────────

        const result = tx.buildTransaction();
        console.log(`[tx-builder] Tx hash: ${result.hash}, size: ${result.payload.length / 2} bytes`);

        const submittedHash = await this.submitTx(result.payload);
        console.log(`[tx-builder] Response tx submitted: ${submittedHash}`);
        return submittedHash;
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
