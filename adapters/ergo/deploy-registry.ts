/**
 * Deploy the broker registry NFT on Ergo.
 *
 * Mints a singleton NFT (amount=1) with broker config in registers:
 *   R4: Coll[Byte] — operator compressed public key (33 bytes)
 *   R5: Coll[Byte] — ECIES compressed public key (33 bytes)
 *   R6: Coll[Byte] — guard script ErgoTree bytes
 *
 * Usage:
 *   DEPLOYER_KEY=<hex> OPERATOR_PK=<hex> ECIES_PK=<hex> \
 *     EXPLORER_URL=https://api-testnet.ergoplatform.com \
 *     npx tsx deploy-registry.ts
 */

import {
    TransactionBuilder,
    OutputBuilder,
    SAFE_MIN_BOX_VALUE,
    ErgoAddress,
    Network,
} from '@fleet-sdk/core';
import { SColl, SByte } from '@fleet-sdk/serializer';
import { secp256k1 } from '@noble/curves/secp256k1';
import { getUnspentBoxes, getHeight, signTx, submitTx } from './adapter/src/ergo-api.js';
import { getGuardErgoTree } from './contracts/contracts.js';

function requireEnv(name: string): string {
    const val = process.env[name];
    if (!val) { console.error(`Missing: ${name}`); process.exit(1); }
    return val;
}

async function main() {
    const deployerKeyHex = requireEnv('DEPLOYER_KEY');
    const operatorPkHex = requireEnv('OPERATOR_PK');
    const eciesPkHex = requireEnv('ECIES_PK');
    const explorerUrl = requireEnv('EXPLORER_URL');
    const relayUrl = process.env.RELAY_URL ?? 'http://127.0.0.1:9064';

    // Derive deployer address
    const deployerPub = Buffer.from(secp256k1.getPublicKey(deployerKeyHex, true)).toString('hex');
    const deployerAddr = ErgoAddress.fromPublicKey(deployerPub, Network.Testnet).encode(Network.Testnet);
    console.log(`Deployer: ${deployerAddr}`);

    // Derive guard ErgoTree from operator PK
    const guardErgoTree = getGuardErgoTree(operatorPkHex);
    console.log(`Guard ErgoTree: ${guardErgoTree.slice(0, 40)}... (${guardErgoTree.length / 2} bytes)`);

    // Fetch deployer UTXOs
    const boxes = await getUnspentBoxes(explorerUrl, deployerAddr);
    if (boxes.length === 0) throw new Error('No UTXOs for deployer');

    const height = await getHeight(explorerUrl);
    const inputs = boxes.map(b => ({
        boxId: b.boxId, transactionId: b.transactionId, index: b.index,
        value: b.value.toString(), ergoTree: b.ergoTree,
        creationHeight: b.creationHeight,
        assets: b.assets.map(a => ({ tokenId: a.tokenId, amount: a.amount.toString() })),
        additionalRegisters: b.additionalRegisters,
    }));

    // Registry NFT token ID = first input box ID
    const nftId = boxes[0]!.boxId;

    // Build registers
    const r4 = SColl(SByte, Uint8Array.from(Buffer.from(operatorPkHex, 'hex'))).toHex();
    const r5 = SColl(SByte, Uint8Array.from(Buffer.from(eciesPkHex, 'hex'))).toHex();
    const r6 = SColl(SByte, Uint8Array.from(Buffer.from(guardErgoTree, 'hex'))).toHex();

    const registryOutput = new OutputBuilder(SAFE_MIN_BOX_VALUE, deployerAddr)
        .mintToken({ amount: 1n, name: 'BlockHost Broker Registry', description: 'Broker config singleton' })
        .setAdditionalRegisters({ R4: r4, R5: r5, R6: r6 });

    const unsignedTx = new TransactionBuilder(height)
        .from(inputs)
        .to(registryOutput)
        .sendChangeTo(deployerAddr)
        .payMinFee()
        .build();

    const signedTx = await signTx(relayUrl, unsignedTx, [deployerKeyHex], boxes, height);
    const txId = await submitTx(relayUrl, signedTx);

    console.log(`Registry NFT minted!`);
    console.log(`  TX: ${txId}`);
    console.log(`  NFT ID: ${nftId}`);
    console.log(`\nAdd to registry-ergo-testnet.json:`);
    console.log(JSON.stringify({
        registry_nft_id: nftId,
        explorer_url: explorerUrl,
        network: 'ergo-testnet',
    }, null, 2));
}

main().catch(err => { console.error(err); process.exit(1); });
