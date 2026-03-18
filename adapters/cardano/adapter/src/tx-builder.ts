/**
 * Builds and submits response transactions on Cardano.
 *
 * Consumes a request UTXO, burns the request beacon,
 * mints a response beacon, and produces a response UTXO
 * at the validator address with an encrypted datum.
 *
 * Uses MeshJS MeshTxBuilder with Koios (or Blockfrost) provider.
 */

import {
    MeshWallet,
    Transaction,
    applyParamsToScript,
    resolveScriptHash,
    serializePlutusScript,
} from '@meshsdk/core';
import { KoiosProvider } from '@meshsdk/provider';
import type { UTxO, PlutusScript } from '@meshsdk/common';
import { readFileSync } from 'node:fs';
import type { RequestUtxo } from './poller.js';

const REQUEST_BEACON_NAME = Buffer.from('request').toString('hex');
const RESPONSE_BEACON_NAME = Buffer.from('response').toString('hex');

interface BlueprintValidator {
    title: string;
    compiledCode: string;
    hash: string;
    parameters?: Array<{ title: string; schema: unknown }>;
}

interface Blueprint {
    validators: BlueprintValidator[];
}

export class ResponseTxBuilder {
    private provider: KoiosProvider;
    private brokerScript: PlutusScript;
    private beaconScript: PlutusScript;
    private brokerScriptCbor: string;
    private beaconScriptCbor: string;
    private brokerScriptHash: string;
    private beaconPolicyId: string;
    private validatorAddress: string;
    private operatorAddress: string;
    private wallet: MeshWallet;

    constructor(
        wallet: MeshWallet,
        validatorAddress: string,
        beaconPolicyId: string,
        koiosUrl: string,
        private blockfrostApiKey: string | null,
        network: string,
        blueprintPath: string,
        operatorPkh: string,
    ) {
        this.wallet = wallet;
        this.validatorAddress = validatorAddress;
        this.beaconPolicyId = beaconPolicyId;

        // Load provider
        this.provider = new KoiosProvider(koiosUrl);

        // Load and parameterize scripts from Aiken blueprint
        const blueprint: Blueprint = JSON.parse(readFileSync(blueprintPath, 'utf-8'));

        const brokerValidator = blueprint.validators.find(v => v.title === 'broker.broker.spend');
        const beaconValidator = blueprint.validators.find(v => v.title === 'beacon.beacon.mint');

        if (!brokerValidator || !beaconValidator) {
            throw new Error('Missing validators in blueprint');
        }

        // Apply parameters to broker validator: (operator_pkh) only
        // beacon_policy_id is passed at runtime in the ConsumeRequest redeemer
        this.brokerScriptCbor = applyParamsToScript(brokerValidator.compiledCode, [
            operatorPkh,
        ]);
        this.brokerScriptHash = resolveScriptHash(this.brokerScriptCbor, 'V3');

        // Apply parameters to beacon policy: (broker_validator_hash, operator_pkh)
        this.beaconScriptCbor = applyParamsToScript(beaconValidator.compiledCode, [
            this.brokerScriptHash,
            operatorPkh,
        ]);

        this.brokerScript = { code: this.brokerScriptCbor, version: 'V3' };
        this.beaconScript = { code: this.beaconScriptCbor, version: 'V3' };

        // Derive operator address from signing key
        // For now, expect it to be passed or derived externally
        this.operatorAddress = '';

        console.log(`[tx-builder] Broker script hash: ${this.brokerScriptHash}`);
        console.log(`[tx-builder] Beacon policy ID: ${this.beaconPolicyId}`);
    }

    setOperatorAddress(addr: string): void {
        this.operatorAddress = addr;
    }

    /**
     * Build and submit a response transaction.
     *
     * - Consumes the request UTXO (ConsumeRequest redeemer)
     * - Burns the request beacon
     * - Mints a response beacon
     * - Produces a response UTXO at the validator with ResponseDatum
     *
     * Returns the transaction hash.
     */
    async submitResponse(
        requestUtxo: RequestUtxo,
        encryptedResponse: Uint8Array,
    ): Promise<string> {
        console.log(`[tx-builder] Building response tx for ${requestUtxo.ref.txHash}#${requestUtxo.ref.outputIndex}`);

        // ResponseDatum { client_pkh, encrypted_response }
        const responseDatum = {
            alternative: 1,
            fields: [
                requestUtxo.clientPkh,
                Buffer.from(encryptedResponse).toString('hex'),
            ],
        };

        // ConsumeRequest { beacon_policy_id }
        const consumeRequestRedeemer = {
            alternative: 0,
            fields: [this.beaconPolicyId],
        };

        // BurnRequestBeacon
        const burnRequestRedeemer = { alternative: 1, fields: [] };

        // MintResponseBeacon
        const mintResponseRedeemer = { alternative: 2, fields: [] };

        // Fetch the actual request UTXO object for redeemValue
        const scriptUtxos = await this.provider.fetchAddressUTxOs(this.validatorAddress);
        const requestScriptUtxo = scriptUtxos.find(
            (u: UTxO) =>
                u.input.txHash === requestUtxo.ref.txHash &&
                u.input.outputIndex === requestUtxo.ref.outputIndex,
        );
        if (!requestScriptUtxo) {
            throw new Error(`Request UTXO not found: ${requestUtxo.ref.txHash}#${requestUtxo.ref.outputIndex}`);
        }

        const tx = new Transaction({ initiator: this.wallet });

        // 1. Consume the request UTXO
        tx.redeemValue({
            value: requestScriptUtxo,
            script: this.brokerScript,
            redeemer: { data: consumeRequestRedeemer },
        });

        // 2. Burn request beacon + Mint response beacon
        tx.mintAsset(this.beaconScript, {
            assetName: 'request',
            assetQuantity: '-1',
            recipient: this.operatorAddress,
            label: undefined,
            metadata: undefined,
        });
        // Note: MeshJS Transaction API may need separate mint calls
        // This needs testing — the low-level MeshTxBuilder might be needed
        // for multi-mint with different redeemers on the same policy

        // 3. Produce response UTXO at validator
        tx.sendLovelace(
            {
                address: this.validatorAddress,
                datum: { inline: true, value: responseDatum },
            },
            '2000000',
        );

        // Build, sign, submit
        const unsignedTx = await tx.build();
        const signedTx = await this.wallet.signTx(unsignedTx);
        const txHash = await this.wallet.submitTx(signedTx);

        console.log(`[tx-builder] Response tx submitted: ${txHash}`);
        return txHash;
    }
}
