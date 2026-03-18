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
    MeshTxBuilder,
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

    constructor(
        private operatorSigningKey: string,
        validatorAddress: string,
        beaconPolicyId: string,
        koiosUrl: string,
        private blockfrostApiKey: string | null,
        network: string,
        blueprintPath: string,
        operatorPkh: string,
    ) {
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

        // ResponseDatum: constructor 1 (second variant in the Datum union)
        // ResponseDatum { client_pkh, encrypted_response }
        const responseDatumJson = {
            constructor: 1, // ResponseDatum is the second type after RequestDatum
            fields: [
                { bytes: requestUtxo.clientPkh },
                { bytes: Buffer.from(encryptedResponse).toString('hex') },
            ],
        };

        // ConsumeRequest redeemer: constructor 0 in BrokerAction
        // ConsumeRequest { beacon_policy_id } — passed at runtime to avoid circular dep
        const consumeRequestRedeemer = {
            constructor: 0,
            fields: [{ bytes: this.beaconPolicyId }],
        };

        // BurnRequestBeacon redeemer: constructor 1 in BeaconAction
        const burnRequestRedeemer = {
            constructor: 1,
            fields: [],
        };

        // MintResponseBeacon redeemer: constructor 2 in BeaconAction
        const mintResponseRedeemer = {
            constructor: 2,
            fields: [],
        };

        // Find a collateral UTXO from the operator (needs pure ADA, no tokens)
        const operatorUtxos = await this.provider.fetchAddressUTxOs(this.operatorAddress);
        if (operatorUtxos.length === 0) {
            throw new Error('No UTXOs available at operator address');
        }

        const collateral = operatorUtxos.find(
            (u: UTxO) => u.output.amount.length === 1 && u.output.amount[0].unit === 'lovelace',
        );
        if (!collateral) {
            throw new Error('No pure ADA UTXO for collateral at operator address');
        }

        // Build the transaction
        const txBuilder = new MeshTxBuilder({
            fetcher: this.provider,
            submitter: this.provider,
        });

        // 1. Consume the request UTXO (spending from script)
        txBuilder
            .spendingPlutusScriptV3()
            .txIn(
                requestUtxo.ref.txHash,
                requestUtxo.ref.outputIndex,
            )
            .txInInlineDatumPresent()
            .txInRedeemerValue(consumeRequestRedeemer, 'JSON')
            .txInScript(this.brokerScriptCbor);

        // 2. Burn the request beacon
        txBuilder
            .mintPlutusScriptV3()
            .mint('-1', this.beaconPolicyId, REQUEST_BEACON_NAME)
            .mintingScript(this.beaconScriptCbor)
            .mintRedeemerValue(burnRequestRedeemer, 'JSON');

        // 3. Mint a response beacon
        txBuilder
            .mintPlutusScriptV3()
            .mint('1', this.beaconPolicyId, RESPONSE_BEACON_NAME)
            .mintingScript(this.beaconScriptCbor)
            .mintRedeemerValue(mintResponseRedeemer, 'JSON');

        // 4. Produce response UTXO at the validator with inline datum
        const minAda = '2000000'; // 2 ADA minimum
        txBuilder
            .txOut(this.validatorAddress, [
                { unit: 'lovelace', quantity: minAda },
                { unit: this.beaconPolicyId + RESPONSE_BEACON_NAME, quantity: '1' },
            ])
            .txOutInlineDatumValue(responseDatumJson, 'JSON');

        // 5. Collateral
        txBuilder.txInCollateral(
            collateral.input.txHash,
            collateral.input.outputIndex,
            collateral.output.amount,
            collateral.output.address,
        );

        // 6. Required signer (operator)
        txBuilder.signingKey(this.operatorSigningKey);

        // 7. Complete and submit
        const unsignedTx = await txBuilder.complete();
        const signedTx = txBuilder.completeSigning();
        const txHash = await this.provider.submitTx(signedTx);

        if (!txHash) {
            throw new Error('Transaction submission returned no hash');
        }

        console.log(`[tx-builder] Response tx submitted: ${txHash}`);
        return txHash;
    }
}
