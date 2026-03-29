/**
 * Client-side transaction building for Ergo.
 *
 * - Request tx: mint beacon token, send to guard address with client pubkey
 *   in R4 and encrypted payload in R5
 * - Cleanup tx: consume response box, burn beacon token
 *
 * Uses Fleet SDK for tx building, ergo-relay for signing + broadcast.
 */

import {
    TransactionBuilder,
    OutputBuilder,
    SAFE_MIN_BOX_VALUE,
} from '@fleet-sdk/core';
import { SColl, SByte } from '@fleet-sdk/serializer';
import {
    getUnspentBoxes,
    getHeight,
    signTx,
    submitTx,
    type ErgoBox,
} from './ergo-api.js';

export class ClientTxBuilder {
    constructor(
        private explorerUrl: string,
        private relayUrl: string,
        private clientAddress: string,
        private clientPrivateKey: string,
        private clientPubkeyHex: string,
        private guardAddress: string,
    ) {}

    /**
     * Build and submit a request transaction.
     *
     * Mints a beacon token (amount=1, ID = first input box ID),
     * sends it to the guard address with R4 (client pubkey) and R5 (encrypted payload).
     *
     * Returns the tx ID and beacon token ID.
     */
    async submitRequest(encryptedPayload: Uint8Array): Promise<{
        txId: string;
        beaconTokenId: string;
    }> {
        const height = await getHeight(this.explorerUrl);

        // Fetch client's UTXOs
        const clientBoxes = await getUnspentBoxes(this.explorerUrl, this.clientAddress);
        if (clientBoxes.length === 0) {
            throw new Error('No UTXOs available for client address');
        }

        const inputs = clientBoxes.map(toFleetBox);

        // Beacon token ID will be the first input's box ID
        const beaconTokenId = clientBoxes[0]!.boxId;

        // Build registers
        const r4 = SColl(SByte, Uint8Array.from(Buffer.from(this.clientPubkeyHex, 'hex'))).toHex();
        const r5 = SColl(SByte, encryptedPayload).toHex();

        // Build request output at guard address
        const requestOutput = new OutputBuilder(SAFE_MIN_BOX_VALUE, this.guardAddress)
            .mintToken({
                amount: 1n,
                name: 'blockhost-request',
            })
            .setAdditionalRegisters({ R4: r4, R5: r5 });

        const unsignedTx = new TransactionBuilder(height)
            .from(inputs)
            .to(requestOutput)
            .sendChangeTo(this.clientAddress)
            .payMinFee()
            .build();

        const signedTx = await signTx(
            this.relayUrl,
            unsignedTx,
            [this.clientPrivateKey],
            clientBoxes,
            height,
        );

        const txId = await submitTx(this.relayUrl, signedTx);
        console.error(`[tx] Request tx: ${txId}, beacon: ${beaconTokenId}`);
        return { txId, beaconTokenId };
    }

    /**
     * Build and submit a cleanup transaction.
     *
     * Consumes the response box (client signs) and burns the beacon token.
     * Returns ERG to client address.
     */
    async cleanupResponse(responseBox: ErgoBox, beaconTokenId: string): Promise<string> {
        const height = await getHeight(this.explorerUrl);

        // May need additional client boxes for fee
        const clientBoxes = await getUnspentBoxes(this.explorerUrl, this.clientAddress);
        const inputs = [toFleetBox(responseBox), ...clientBoxes.map(toFleetBox)];
        const allBoxes = [responseBox, ...clientBoxes];

        const unsignedTx = new TransactionBuilder(height)
            .from(inputs)
            .burnTokens({ tokenId: beaconTokenId, amount: 1n })
            .sendChangeTo(this.clientAddress)
            .payMinFee()
            .build();

        const signedTx = await signTx(
            this.relayUrl,
            unsignedTx,
            [this.clientPrivateKey],
            allBoxes,
            height,
        );

        const txId = await submitTx(this.relayUrl, signedTx);
        console.error(`[tx] Cleanup tx: ${txId}`);
        return txId;
    }
}

function toFleetBox(box: ErgoBox): any {
    return {
        boxId: box.boxId,
        transactionId: box.transactionId,
        index: box.index,
        value: box.value.toString(),
        ergoTree: box.ergoTree,
        creationHeight: box.creationHeight,
        assets: box.assets.map(a => ({
            tokenId: a.tokenId,
            amount: a.amount.toString(),
        })),
        additionalRegisters: box.additionalRegisters,
    };
}
