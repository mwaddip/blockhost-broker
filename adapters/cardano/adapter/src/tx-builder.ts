/**
 * Builds and submits response transactions on Cardano.
 *
 * Consumes a request UTXO, burns the request beacon,
 * mints a response beacon, and produces a response UTXO
 * at the validator address with an encrypted datum.
 *
 * Uses cmttk (pure JS, no WASM) for transaction building.
 */

import { buildAndSubmitScriptTx, type ScriptInput, type MintEntry, type TxOutput } from 'cmttk/tx';
import { Constr, Data } from 'cmttk/data';
import { getProvider, type Provider } from 'cmttk/provider';
import { buildEnterpriseAddress } from 'cmttk/address';
import type { RequestUtxo } from './poller.js';

const REQUEST_BEACON_NAME = Buffer.from('request').toString('hex');
const RESPONSE_BEACON_NAME = Buffer.from('response').toString('hex');

interface ScriptInfo {
    cbor: string;
    hash: string;
}

export class ResponseTxBuilder {
    private brokerScriptCbor: string;
    private beaconScriptCbor: string;
    private brokerScriptHash: string;
    private beaconPolicyId: string;
    private validatorAddress: string;
    private operatorPkh: string;
    private signingKey: Uint8Array;
    private network: string;
    private provider: Provider;

    constructor(
        brokerInfo: ScriptInfo,
        beaconInfo: ScriptInfo,
        signingKey: Uint8Array,
        operatorPkh: Buffer,
        private operatorAddress: string,
        network: string,
        koiosUrl: string,
        blockfrostApiKey: string | null = null,
    ) {
        this.brokerScriptCbor = brokerInfo.cbor;
        this.beaconScriptCbor = beaconInfo.cbor;
        this.brokerScriptHash = brokerInfo.hash;
        this.beaconPolicyId = beaconInfo.hash;
        this.validatorAddress = buildEnterpriseAddress(brokerInfo.hash, network as any, true);
        this.operatorPkh = operatorPkh.toString('hex');
        this.signingKey = signingKey;
        this.network = network;
        // Use Koios provider for tx building — Blockfrost's cost model key ordering
        // doesn't match the canonical order the ledger expects for script_data_hash.
        // The poller uses Blockfrost separately for UTXO scanning.
        this.provider = getProvider(network as any, undefined, koiosUrl);

        console.log(`[tx-builder] Broker script hash: ${brokerInfo.hash}`);
        console.log(`[tx-builder] Beacon policy: ${beaconInfo.hash}`);
        console.log(`[tx-builder] Validator: ${this.validatorAddress}`);
    }

    /**
     * Build and submit a response transaction.
     *
     * - Consumes the request UTXO (ConsumeRequest redeemer)
     * - Burns request beacon + mints response beacon (MintResponseBeacon redeemer)
     * - Produces a response UTXO at the validator with ResponseDatum
     */
    async submitResponse(
        requestUtxo: RequestUtxo,
        encryptedResponse: Uint8Array,
    ): Promise<string> {
        console.log(`[tx-builder] Building response tx for ${requestUtxo.ref.txHash}#${requestUtxo.ref.outputIndex}`);

        // ConsumeRequest { beacon_policy_id } — BrokerAction constructor 0
        const consumeRequestRedeemer = Data.to(
            new Constr(0, [Buffer.from(this.beaconPolicyId, 'hex')]),
        );

        // Script input: consume the request UTXO
        const scriptInput: ScriptInput = {
            utxo: {
                txHash: requestUtxo.ref.txHash,
                index: requestUtxo.ref.outputIndex,
                lovelace: BigInt(String(requestUtxo.lovelace)),
                tokens: {
                    [this.beaconPolicyId + REQUEST_BEACON_NAME]: 1n,
                },
            },
            address: this.validatorAddress,
            redeemerCbor: consumeRequestRedeemer,
        };

        // MintResponseBeacon — BeaconAction constructor 2
        const mintResponseRedeemer = Data.to(new Constr(2, []));

        const mint: MintEntry = {
            policyId: this.beaconPolicyId,
            scriptCbor: this.beaconScriptCbor,
            redeemerCbor: mintResponseRedeemer,
            assets: {
                [REQUEST_BEACON_NAME]: -1n,
                [RESPONSE_BEACON_NAME]: 1n,
            },
        };

        // ResponseDatum { client_pkh, encrypted_response } — constructor 1
        const responseDatumCbor = Data.to(
            new Constr(1, [
                Buffer.from(requestUtxo.clientPkh, 'hex'),
                Buffer.from(encryptedResponse),
            ]),
        );

        const output: TxOutput = {
            address: this.validatorAddress,
            assets: {
                lovelace: 2_000_000n,
                [this.beaconPolicyId + RESPONSE_BEACON_NAME]: 1n,
            },
            datumCbor: responseDatumCbor,
        };

        const txHash = await buildAndSubmitScriptTx({
            provider: this.provider,
            walletAddress: this.operatorAddress,
            signingKey: this.signingKey,
            scriptInputs: [scriptInput],
            spendingScriptCbor: this.brokerScriptCbor,
            mints: [mint],
            outputs: [output],
            requiredSigners: [this.operatorPkh],
            network: this.network as any,
        });

        console.log(`[tx-builder] Response tx submitted: ${txHash}`);
        return txHash;
    }
}
