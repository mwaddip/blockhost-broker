/**
 * Client-side transaction building for Cardano.
 *
 * Builds request transactions (send to validator with datum + mint beacon)
 * and cleanup transactions (consume response UTXO + burn beacon).
 *
 * Uses MeshJS MeshTxBuilder with Koios provider.
 */

import {
    MeshTxBuilder,
    applyParamsToScript,
    resolveScriptHash,
    resolvePaymentKeyHash,
} from '@meshsdk/core';
import { KoiosProvider } from '@meshsdk/provider';
import type { UTxO, PlutusScript } from '@meshsdk/common';
import { readFileSync } from 'node:fs';

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

export class ClientTxBuilder {
    private provider: KoiosProvider;
    private beaconScriptCbor: string;
    private brokerScriptCbor: string;
    private beaconPolicyId: string;
    private brokerScriptHash: string;

    constructor(
        private signingKey: string,
        private validatorAddress: string,
        beaconPolicyId: string,
        koiosUrl: string,
        private network: string,
        blueprintPath: string,
        operatorPkh: string,
    ) {
        this.beaconPolicyId = beaconPolicyId;
        this.provider = new KoiosProvider(koiosUrl);

        // Load blueprint and parameterize scripts
        const blueprint: Blueprint = JSON.parse(readFileSync(blueprintPath, 'utf-8'));

        const brokerValidator = blueprint.validators.find(v => v.title === 'broker.broker.spend');
        const beaconValidator = blueprint.validators.find(v => v.title === 'beacon.beacon.mint');

        if (!brokerValidator || !beaconValidator) {
            throw new Error('Missing validators in blueprint');
        }

        // Apply params: broker(operator_pkh) — beacon_policy_id in redeemer
        this.brokerScriptCbor = applyParamsToScript(brokerValidator.compiledCode, [
            operatorPkh,
        ]);
        this.brokerScriptHash = resolveScriptHash(this.brokerScriptCbor, 'V3');

        // Apply params: beacon(broker_validator_hash, operator_pkh)
        this.beaconScriptCbor = applyParamsToScript(beaconValidator.compiledCode, [
            this.brokerScriptHash,
            operatorPkh,
        ]);
    }

    /**
     * Get the client's pub key hash from the signing key.
     */
    getClientPkh(): string {
        return resolvePaymentKeyHash(this.signingKey);
    }

    /**
     * Get the client's address from the signing key.
     */
    async getClientAddress(): Promise<string> {
        // Derive from the provider or from the key directly
        // MeshJS resolvePaymentKeyHash gives the pkh, but we need the full bech32 address
        // For now, query UTXOs to find the address
        const pkh = this.getClientPkh();
        // The address can be derived from pkh + network
        // Use MeshJS utility if available, otherwise construct manually
        throw new Error('TODO: derive address from signing key and network');
    }

    /**
     * Build and submit a request transaction.
     *
     * - Send min ADA to validator address with RequestDatum (inline)
     * - Mint a request beacon
     * - Include NFT as a regular input (anti-spam — beacon policy checks tx.inputs)
     */
    async submitRequest(
        clientAddress: string,
        nftPolicyId: string,
        clientPkh: string,
        encryptedPayload: Uint8Array,
    ): Promise<string> {
        // RequestDatum: constructor 0
        // RequestDatum { nft_policy_id, client_pkh, encrypted_payload }
        const requestDatum = {
            alternative: 0,
            fields: [
                { bytes: nftPolicyId },
                { bytes: clientPkh },
                { bytes: Buffer.from(encryptedPayload).toString('hex') },
            ],
        };

        // MintRequestBeacon redeemer: constructor 0 in BeaconAction
        const mintRequestRedeemer = {
            alternative: 0,
            fields: [],
        };

        // Get client UTXOs
        const utxos = await this.provider.fetchAddressUTxOs(clientAddress);
        if (utxos.length === 0) {
            throw new Error('No UTXOs at client address');
        }

        // Find a UTXO with the NFT (anti-spam requirement)
        const nftUtxo = utxos.find((u: UTxO) =>
            u.output.amount.some(a => a.unit.startsWith(nftPolicyId)),
        );
        if (!nftUtxo) {
            throw new Error(`No UTXO found with NFT policy ${nftPolicyId}`);
        }

        // Find a collateral UTXO (pure ADA)
        const collateral = utxos.find(
            (u: UTxO) =>
                u.output.amount.length === 1 &&
                u.output.amount[0].unit === 'lovelace' &&
                parseInt(u.output.amount[0].quantity) >= 5_000_000,
        );
        if (!collateral) {
            throw new Error('No pure ADA UTXO for collateral (need >= 5 ADA)');
        }

        const txBuilder = new MeshTxBuilder({
            fetcher: this.provider,
            submitter: this.provider,
        });

        // 1. Include NFT UTXO as input (anti-spam proof)
        txBuilder.txIn(
            nftUtxo.input.txHash,
            nftUtxo.input.outputIndex,
        );

        // 2. Mint request beacon
        txBuilder
            .mintPlutusScriptV3()
            .mint('1', this.beaconPolicyId, REQUEST_BEACON_NAME)
            .mintingScript(this.beaconScriptCbor)
            .mintRedeemerValue(mintRequestRedeemer, 'JSON');

        // 3. Output to validator with RequestDatum + beacon token
        const minAda = '2000000'; // 2 ADA
        txBuilder
            .txOut(this.validatorAddress, [
                { unit: 'lovelace', quantity: minAda },
                { unit: this.beaconPolicyId + REQUEST_BEACON_NAME, quantity: '1' },
            ])
            .txOutInlineDatumValue(requestDatum, 'JSON');

        // 4. Return NFT to client (it was consumed as input, needs to go back)
        const nftAssets = nftUtxo.output.amount.filter(a => a.unit !== 'lovelace');
        if (nftAssets.length > 0) {
            txBuilder.txOut(clientAddress, [
                { unit: 'lovelace', quantity: '2000000' },
                ...nftAssets,
            ]);
        }

        // 5. Collateral
        txBuilder.txInCollateral(
            collateral.input.txHash,
            collateral.input.outputIndex,
            collateral.output.amount,
            collateral.output.address,
        );

        // 6. Sign
        txBuilder.signingKey(this.signingKey);

        // 7. Complete and submit
        const unsignedTx = await txBuilder.complete();
        const signedTx = txBuilder.completeSigning();
        const txHash = await this.provider.submitTx(signedTx);

        if (!txHash) {
            throw new Error('Transaction submission returned no hash');
        }

        return txHash;
    }

    /**
     * Build and submit a cleanup transaction.
     *
     * - Consume response UTXO (ConsumeResponse redeemer)
     * - Burn response beacon
     * - Return ADA to client
     */
    async cleanupResponse(
        clientAddress: string,
        responseUtxoRef: { txHash: string; outputIndex: number },
    ): Promise<string> {
        // ConsumeResponse redeemer: constructor 1 in BrokerAction
        const consumeResponseRedeemer = {
            alternative: 1,
            fields: [],
        };

        // BurnResponseBeacon redeemer: constructor 3 in BeaconAction
        const burnResponseRedeemer = {
            alternative: 3,
            fields: [],
        };

        const utxos = await this.provider.fetchAddressUTxOs(clientAddress);
        const collateral = utxos.find(
            (u: UTxO) =>
                u.output.amount.length === 1 &&
                u.output.amount[0].unit === 'lovelace',
        );
        if (!collateral) {
            throw new Error('No pure ADA UTXO for collateral');
        }

        const txBuilder = new MeshTxBuilder({
            fetcher: this.provider,
            submitter: this.provider,
        });

        // 1. Consume the response UTXO
        txBuilder
            .spendingPlutusScriptV3()
            .txIn(responseUtxoRef.txHash, responseUtxoRef.outputIndex)
            .txInInlineDatumPresent()
            .txInRedeemerValue(consumeResponseRedeemer, 'JSON')
            .txInScript(this.brokerScriptCbor);

        // 2. Burn response beacon
        txBuilder
            .mintPlutusScriptV3()
            .mint('-1', this.beaconPolicyId, RESPONSE_BEACON_NAME)
            .mintingScript(this.beaconScriptCbor)
            .mintRedeemerValue(burnResponseRedeemer, 'JSON');

        // 3. Collateral
        txBuilder.txInCollateral(
            collateral.input.txHash,
            collateral.input.outputIndex,
            collateral.output.amount,
            collateral.output.address,
        );

        // 4. Sign
        txBuilder.signingKey(this.signingKey);

        // 5. Complete and submit
        const unsignedTx = await txBuilder.complete();
        const signedTx = txBuilder.completeSigning();
        const txHash = await this.provider.submitTx(signedTx);

        if (!txHash) {
            throw new Error('Cleanup tx submission returned no hash');
        }

        return txHash;
    }
}
