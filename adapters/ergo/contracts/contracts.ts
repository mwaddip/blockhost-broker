/**
 * Compiled guard script ErgoTree template + byte surgery.
 *
 * Same pattern as blockhost-engine-ergo/src/ergo/contracts.ts:
 * pre-compiled ErgoTree with a template public key, substituted
 * at deploy time via byte surgery. No compiler or JRE needed.
 */

import { ErgoAddress, Network } from '@fleet-sdk/core';

/**
 * Template public key (secp256k1 generator point).
 * Searched for in the ErgoTree constants and replaced with the actual operator PK.
 */
const TEMPLATE_PK_HEX = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

/**
 * Pre-compiled guard script ErgoTree (hex).
 *
 * Compiled from guard.es using an Ergo node. Contains the template PK
 * as a Coll[Byte] constant. Two spending paths:
 *   1. Respond: operator signs + beacon preserved in successor
 *   2. Client:  client signs (cancel or cleanup)
 *
 * PLACEHOLDER — replaced after running compile-guard.ts
 */
export const GUARD_ERGO_TREE_TEMPLATE = '10070400040004000400040005020e210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798d803d601b2a5730000d602db63087201d603e4c6a7040eeb02ea02d1edededed91b172027301938cb27202730200018cb2db6308a773030001938cb2720273040002730593c27201c2a793e4c67201040e7203cdee7306cdee7203';

// ── VLQ parsing ─────────────────────────────────────────────────────

function readVLQ(bytes: Uint8Array, offset: number): [number, number] {
    let result = 0;
    let shift = 0;
    let pos = offset;
    while (pos < bytes.length) {
        const byte = bytes[pos]!;
        result |= (byte & 0x7f) << shift;
        pos++;
        if ((byte & 0x80) === 0) break;
        shift += 7;
    }
    return [result, pos];
}

// ── Byte surgery ────────────────────────────────────────────────────

function findPkConstant(
    ergoTreeBytes: Uint8Array,
    templatePkBytes: Uint8Array,
): { offset: number; length: number } | null {
    const header = ergoTreeBytes[0]!;
    if ((header & 0x10) === 0) {
        throw new Error('ErgoTree does not have segregated constants');
    }

    let pos = 1;
    let numConstants: number;
    [numConstants, pos] = readVLQ(ergoTreeBytes, pos);

    for (let i = 0; i < numConstants; i++) {
        const typeByte = ergoTreeBytes[pos]!;
        pos++;

        if (typeByte === 0x01) {
            pos++; // SBoolean
        } else if (typeByte === 0x04) {
            [, pos] = readVLQ(ergoTreeBytes, pos); // SInt
        } else if (typeByte === 0x05) {
            [, pos] = readVLQ(ergoTreeBytes, pos); // SLong
        } else if (typeByte === 0x0e) {
            let length: number;
            [length, pos] = readVLQ(ergoTreeBytes, pos);
            if (length === 33) {
                const candidate = ergoTreeBytes.slice(pos, pos + 33);
                let match = true;
                for (let j = 0; j < 33; j++) {
                    if (candidate[j] !== templatePkBytes[j]) { match = false; break; }
                }
                if (match) return { offset: pos, length: 33 };
            }
            pos += length;
        } else if (typeByte === 0x08) {
            pos += 33; // SGroupElement — 33 bytes compressed point
        } else {
            throw new Error(`Unknown constant type 0x${typeByte.toString(16)} at position ${pos - 1}`);
        }
    }

    return null;
}

/**
 * Substitute the operator PK into the pre-compiled guard ErgoTree template.
 */
export function getGuardErgoTree(operatorPkHex: string): string {
    if (operatorPkHex.length !== 66) {
        throw new Error(`Expected 66 hex char compressed public key, got ${operatorPkHex.length}`);
    }

    const treeBytes = hexToBytes(GUARD_ERGO_TREE_TEMPLATE);
    const templatePkBytes = hexToBytes(TEMPLATE_PK_HEX);
    const operatorPkBytes = hexToBytes(operatorPkHex);

    const loc = findPkConstant(treeBytes, templatePkBytes);
    if (!loc) {
        throw new Error('Template PK not found in ErgoTree constants section');
    }

    const result = new Uint8Array(treeBytes);
    for (let i = 0; i < 33; i++) {
        result[loc.offset + i] = operatorPkBytes[i]!;
    }

    return bytesToHex(result);
}

/**
 * Compute the P2S address from an ErgoTree hex string.
 */
export function guardAddress(ergoTreeHex: string, mainnet = false): string {
    const network = mainnet ? Network.Mainnet : Network.Testnet;
    return ErgoAddress.fromErgoTree(ergoTreeHex, network).encode(network);
}

/**
 * Derive the P2PK address from a compressed public key.
 */
export function p2pkAddress(pubKeyHex: string, mainnet = false): string {
    const network = mainnet ? Network.Mainnet : Network.Testnet;
    return ErgoAddress.fromPublicKey(pubKeyHex, network).encode(network);
}

// ── Hex helpers ─────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
