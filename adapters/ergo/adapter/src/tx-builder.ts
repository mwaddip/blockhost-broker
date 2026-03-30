/**
 * Builds and submits response transactions on Ergo.
 *
 * Consumes a request box, carries the beacon token to a new response
 * box at the same guard script address, with encrypted response in R5.
 *
 * Uses Fleet SDK for tx building, ergo-relay for signing + broadcast.
 */

import {
    TransactionBuilder,
    OutputBuilder,
    SAFE_MIN_BOX_VALUE,
} from '@fleet-sdk/core';
import { SColl, SByte } from '@fleet-sdk/serializer';
import { getUnspentBoxes, getHeight, signTx, submitTx, type ErgoBox } from './ergo-api.js';
import type { RequestBox } from './poller.js';

export class ResponseTxBuilder {
    constructor(
        private explorerUrl: string,
        private relayUrl: string,
        private operatorAddress: string,
        private operatorPrivateKey: string,
        private guardAddress: string,
    ) {}

    /**
     * Build, sign, and submit a response transaction.
     *
     * Transaction structure:
     *   Input 0: request box (at guard address, carries beacon)
     *   Input 1+: operator UTXOs (for fee)
     *   Output 0: response box (at guard address, same beacon, R5 = encrypted response)
     *   Output 1: change to operator
     *   Output 2: miner fee
     */
    async submitResponse(
        request: RequestBox,
        encryptedResponse: Uint8Array,
    ): Promise<string> {
        console.log(`[tx-builder] Building response for beacon ${request.beaconTokenId.slice(0, 16)}...`);

        const height = await getHeight(this.explorerUrl);

        // Fetch operator's UTXOs to fund the transaction fee
        const operatorBoxes = await getUnspentBoxes(this.explorerUrl, this.operatorAddress);
        if (operatorBoxes.length === 0) {
            throw new Error('No UTXOs available for operator address');
        }

        // Convert ErgoBox to Fleet SDK input format
        const requestInput = toFleetBox(request.box);
        const funderInputs = operatorBoxes.map(toFleetBox);

        // Build R4 (carry forward client pubkey) and R5 (encrypted response)
        const r4 = SColl(SByte, Uint8Array.from(Buffer.from(request.clientPubkeyHex, 'hex'))).toHex();
        const r5 = SColl(SByte, encryptedResponse).toHex();

        // Build the response output: same guard script, same beacon, new R5
        const responseOutput = new OutputBuilder(SAFE_MIN_BOX_VALUE, this.guardAddress)
            .addTokens({ tokenId: request.beaconTokenId, amount: 1n })
            .setAdditionalRegisters({ R4: r4, R5: r5 });

        // Build unsigned transaction
        const unsignedTx = new TransactionBuilder(height)
            .from([requestInput, ...funderInputs])
            .to(responseOutput)
            .sendChangeTo(this.operatorAddress)
            .payMinFee()
            .build();

        // Sign via ergo-relay
        const allInputBoxes = [request.box, ...operatorBoxes];
        const signedTx = await signTx(
            this.relayUrl,
            unsignedTx,
            [this.operatorPrivateKey],
            allInputBoxes,
            height,
        );

        // Broadcast via ergo-relay, fall back to Explorer
        const txId = await submitTx(this.relayUrl, signedTx, this.explorerUrl);
        console.log(`[tx-builder] Response tx submitted: ${txId}`);
        return txId;
    }
}

/** Convert our ErgoBox type to Fleet SDK's Box format. */
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
