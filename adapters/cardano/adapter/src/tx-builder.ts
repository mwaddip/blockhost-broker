/**
 * Builds and submits response transactions on Cardano.
 *
 * Consumes a request UTXO, burns the request beacon,
 * mints a response beacon, and produces a response UTXO
 * at the validator address with an encrypted datum.
 */

import type { RequestUtxo } from './poller.js';

export class ResponseTxBuilder {
    constructor(
        private operatorSigningKey: string,
        private validatorAddress: string,
        private beaconPolicyId: string,
        private koiosUrl: string,
        private blockfrostApiKey: string | null,
        private network: string,
    ) {}

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
        // MeshJS transaction building will be implemented here.
        // This is a placeholder that demonstrates the structure.
        //
        // The actual implementation needs:
        // 1. MeshJS Transaction builder
        // 2. Script references or inline scripts for the validator + beacon policy
        // 3. Proper datum encoding (CBOR) for ResponseDatum
        // 4. Collateral UTXO from the operator
        // 5. Redeemer construction for ConsumeRequest + BurnRequestBeacon + MintResponseBeacon

        const { MeshTxBuilder, deserializeAddress } = await import('@meshsdk/core');

        const requestBeaconName = Buffer.from('request').toString('hex');
        const responseBeaconName = Buffer.from('response').toString('hex');

        // Build ResponseDatum CBOR
        // Constructor 0: { client_pkh: ByteArray, encrypted_response: ByteArray }
        const responseDatum = {
            constructor: 0,
            fields: [
                { bytes: requestUtxo.clientPkh },
                { bytes: Buffer.from(encryptedResponse).toString('hex') },
            ],
        };

        // ConsumeRequest redeemer (constructor index 0 in BrokerAction)
        const consumeRequestRedeemer = { constructor: 0, fields: [] };

        // BurnRequestBeacon redeemer (constructor index 1 in BeaconAction)
        const burnRequestRedeemer = { constructor: 1, fields: [] };

        // MintResponseBeacon redeemer (constructor index 2 in BeaconAction)
        const mintResponseRedeemer = { constructor: 2, fields: [] };

        // Query operator UTXOs for fees + collateral
        const operatorUtxos = await this.queryOperatorUtxos();
        if (operatorUtxos.length === 0) {
            throw new Error('No UTXOs available for operator');
        }

        // Build transaction
        // Note: actual MeshJS API calls will be refined during testing
        console.log(`[tx-builder] Building response tx for ${requestUtxo.ref.txHash}#${requestUtxo.ref.outputIndex}`);
        console.log(`[tx-builder] ResponseDatum: ${JSON.stringify(responseDatum)}`);

        // TODO: Complete MeshJS transaction building
        // This requires the compiled validator scripts from plutus.json
        throw new Error('MeshJS transaction building not yet implemented — needs compiled scripts');
    }

    private async queryOperatorUtxos(): Promise<any[]> {
        // Derive operator address from signing key
        // Query UTXOs via Koios or Blockfrost
        const url = `${this.koiosUrl}/address_utxos?_address=${this.validatorAddress}`;
        const resp = await fetch(url);
        if (!resp.ok) {
            throw new Error(`Failed to query operator UTXOs: ${resp.status}`);
        }
        return resp.json();
    }
}
