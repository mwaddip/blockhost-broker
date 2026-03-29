/**
 * One-time compilation script for the broker guard ErgoScript.
 *
 * Compiles via an Ergo node's /script/p2sAddress endpoint, extracts
 * the ErgoTree hex, and writes it as a template constant.
 *
 * Usage:
 *   ERGO_NODE=http://213.239.193.208:9052 npx tsx compile-guard.ts
 *
 * The template uses the secp256k1 generator point as the operator PK
 * placeholder (same convention as blockhost-engine-ergo).
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { ErgoAddress, Network } from '@fleet-sdk/core';

const TEMPLATE_PK_HEX = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const TEMPLATE_PK_BASE64 = Buffer.from(TEMPLATE_PK_HEX, 'hex').toString('base64');

async function main() {
    const nodeUrl = process.env.ERGO_NODE;
    if (!nodeUrl) {
        console.error('Set ERGO_NODE to an Ergo node URL (e.g. http://213.239.193.208:9052)');
        process.exit(1);
    }

    // Read and parameterize the ErgoScript source
    const source = readFileSync('guard.es', 'utf-8')
        .replace('$$OPERATOR_PK_BASE64$$', TEMPLATE_PK_BASE64);

    console.log('Compiling guard script...');
    const resp = await fetch(`${nodeUrl}/script/p2sAddress`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source, treeVersion: 0 }),
    });

    if (!resp.ok) {
        const text = await resp.text();
        console.error(`Compilation failed (${resp.status}): ${text}`);
        process.exit(1);
    }

    const { address } = (await resp.json()) as { address: string };
    console.log(`P2S address: ${address}`);

    // Extract ErgoTree hex from the address
    const ergoTree = ErgoAddress.fromBase58(address).ergoTree;
    console.log(`ErgoTree (${ergoTree.length / 2} bytes): ${ergoTree}`);

    // Write the template
    const output = {
        ergoTreeTemplate: ergoTree,
        templatePkHex: TEMPLATE_PK_HEX,
        compiledWith: nodeUrl,
        compiledAt: new Date().toISOString(),
    };

    writeFileSync('guard-template.json', JSON.stringify(output, null, 2) + '\n');
    console.log('Written to guard-template.json');
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
