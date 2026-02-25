/**
 * Crypto for the OPNet client.
 *
 * Request encryption: full ECIES (eciespy-compatible) with broker's pubkey.
 * Response decryption: compact ECDH-derived AES-GCM (matches adapter's delivery.ts).
 * WireGuard key generation: x25519.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes } from 'crypto';

// ── ECIES encryption (eciespy-compatible, for request payloads) ─────
//
// Format: [65 bytes ephemeral uncompressed pubkey]
//         [16 bytes AES-GCM tag]
//         [16 bytes AES-GCM nonce/iv]
//         [... ciphertext ...]

const UNCOMPRESSED_KEY_LEN = 65;
const ECIES_TAG_LEN = 16;
const ECIES_IV_LEN = 16;

export function eciesEncrypt(
    plaintext: Uint8Array,
    recipientPubkey: Uint8Array,
): Uint8Array {
    const ephPriv = secp256k1.utils.randomSecretKey();
    const ephPub = secp256k1.getPublicKey(ephPriv, false);

    const shared = secp256k1.getSharedSecret(ephPriv, recipientPubkey);
    const aesKey = hkdf(sha256, shared.slice(1), undefined, undefined, 32);

    const iv = randomBytes(ECIES_IV_LEN);
    const cipher = gcm(aesKey, iv);
    const encrypted = cipher.encrypt(plaintext);
    const ciphertext = encrypted.slice(0, encrypted.length - ECIES_TAG_LEN);
    const tag = encrypted.slice(encrypted.length - ECIES_TAG_LEN);

    const result = new Uint8Array(
        UNCOMPRESSED_KEY_LEN + ECIES_TAG_LEN + ECIES_IV_LEN + ciphertext.length,
    );
    result.set(ephPub, 0);
    result.set(tag, UNCOMPRESSED_KEY_LEN);
    result.set(iv, UNCOMPRESSED_KEY_LEN + ECIES_TAG_LEN);
    result.set(ciphertext, UNCOMPRESSED_KEY_LEN + ECIES_TAG_LEN + ECIES_IV_LEN);
    return result;
}

// ── Compact decryption (ECDH-derived AES-GCM, for OP_RETURN responses) ──
//
// The broker encrypts with ECDH(broker_priv, client_serverPubkey).
// The client decrypts with ECDH(client_serverPriv, broker_eciesPubkey).
// IV is derived deterministically — not in the payload.

const COMPACT_AES_IV_LEN = 12;

export function deriveKeyAndIv(
    myPrivkey: Uint8Array,
    theirPubkey: Uint8Array,
): { aesKey: Uint8Array; iv: Uint8Array } {
    const shared = secp256k1.getSharedSecret(myPrivkey, theirPubkey);
    const ikm = shared.slice(1);

    const aesKey = hkdf(sha256, ikm, undefined, new TextEncoder().encode('blockhost-aes-key'), 32);
    const iv = hkdf(
        sha256,
        ikm,
        undefined,
        new TextEncoder().encode('blockhost-aes-iv'),
        COMPACT_AES_IV_LEN,
    );

    return { aesKey, iv };
}

export function decryptCompact(
    ciphertext: Uint8Array,
    myPrivkey: Uint8Array,
    theirPubkey: Uint8Array,
): Uint8Array {
    const { aesKey, iv } = deriveKeyAndIv(myPrivkey, theirPubkey);
    const decipher = gcm(aesKey, iv);
    return decipher.decrypt(ciphertext);
}

// ── Response deserialization ────────────────────────────────────────
//
// Binary layout (55 bytes):
//   [32 bytes broker WG pubkey]
//   [4  bytes broker endpoint IPv4]
//   [2  bytes broker endpoint port BE]
//   [1  byte  prefix mask length]
//   [16 bytes prefix network (IPv6)]

export interface TunnelConfig {
    brokerPubkey: string; // base64
    brokerEndpoint: string; // ip:port
    prefix: string; // CIDR
    gateway: string; // prefix::1
}

export function deserializeResponse(data: Uint8Array): TunnelConfig {
    if (data.length !== 55) {
        throw new Error(`Invalid response length: ${data.length} (expected 55)`);
    }

    let offset = 0;

    const wgKey = Buffer.from(data.slice(offset, offset + 32)).toString('base64');
    offset += 32;

    const ip = `${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}`;
    offset += 4;

    const port = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    const mask = data[offset++];

    // Reconstruct IPv6
    const parts: string[] = [];
    for (let i = 0; i < 8; i++) {
        const val = (data[offset + i * 2] << 8) | data[offset + i * 2 + 1];
        parts.push(val.toString(16));
    }
    // Compress IPv6 (collapse longest run of :0: to ::)
    const prefix = compressIPv6(parts.join(':'));
    const gateway = deriveGateway(prefix);

    return {
        brokerPubkey: wgKey,
        brokerEndpoint: `${ip}:${port}`,
        prefix: `${prefix}/${mask}`,
        gateway,
    };
}

function deriveGateway(prefixAddr: string): string {
    // Gateway is always prefix::1
    // Take the prefix, zero out the host part, add ::1
    const expanded = expandIPv6(prefixAddr);
    const parts = expanded.split(':');
    // Set the last group to 1, rest of host to 0
    // For a /120 within a /64, groups 4-7 are host.
    // But we just need prefix::1 which means last group = 1
    parts[7] = '1';
    return compressIPv6(parts.join(':'));
}

function expandIPv6(addr: string): string {
    if (addr.includes('::')) {
        const [left, right] = addr.split('::');
        const leftParts = left ? left.split(':') : [];
        const rightParts = right ? right.split(':') : [];
        const missing = 8 - leftParts.length - rightParts.length;
        const middle = Array(missing).fill('0000');
        const all = [...leftParts, ...middle, ...rightParts];
        return all.map((p) => p.padStart(4, '0')).join(':');
    }
    return addr
        .split(':')
        .map((p) => p.padStart(4, '0'))
        .join(':');
}

function compressIPv6(addr: string): string {
    const parts = addr.split(':').map((p) => p.replace(/^0+/, '') || '0');
    // Find longest run of consecutive '0' groups
    let bestStart = -1;
    let bestLen = 0;
    let curStart = -1;
    let curLen = 0;
    for (let i = 0; i < parts.length; i++) {
        if (parts[i] === '0') {
            if (curStart === -1) curStart = i;
            curLen++;
            if (curLen > bestLen) {
                bestStart = curStart;
                bestLen = curLen;
            }
        } else {
            curStart = -1;
            curLen = 0;
        }
    }
    if (bestLen >= 2) {
        const left = parts.slice(0, bestStart).join(':');
        const right = parts.slice(bestStart + bestLen).join(':');
        return `${left}::${right}`;
    }
    return parts.join(':');
}

// ── WireGuard key generation (x25519) ───────────────────────────────

export interface WgKeypair {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
    publicKeyBase64: string;
    privateKeyBase64: string;
}

export function generateWgKeypair(): WgKeypair {
    const privateKey = x25519.utils.randomPrivateKey();
    const publicKey = x25519.getPublicKey(privateKey);
    return {
        privateKey,
        publicKey,
        publicKeyBase64: Buffer.from(publicKey).toString('base64'),
        privateKeyBase64: Buffer.from(privateKey).toString('base64'),
    };
}

// ── Ephemeral secp256k1 keypair ─────────────────────────────────────

export interface ServerKeypair {
    privateKey: Uint8Array;
    publicKeyCompressed: Uint8Array; // 33 bytes
    publicKeyUncompressed: Uint8Array; // 65 bytes (for ECDH with broker)
}

export function generateServerKeypair(): ServerKeypair {
    const privateKey = secp256k1.utils.randomSecretKey();
    return {
        privateKey,
        publicKeyCompressed: secp256k1.getPublicKey(privateKey, true),
        publicKeyUncompressed: secp256k1.getPublicKey(privateKey, false),
    };
}

// ── Binary request payload ──────────────────────────────────────────
//
// Layout (65 bytes):
//   [32 bytes WireGuard pubkey (raw)]
//   [33 bytes compressed secp256k1 server pubkey]

export function serializeRequestPayload(
    wgPubkey: Uint8Array,
    serverPubkeyCompressed: Uint8Array,
): Uint8Array {
    if (wgPubkey.length !== 32) throw new Error(`WG pubkey must be 32 bytes, got ${wgPubkey.length}`);
    if (serverPubkeyCompressed.length !== 33)
        throw new Error(`Server pubkey must be 33 bytes compressed, got ${serverPubkeyCompressed.length}`);

    const buf = new Uint8Array(65);
    buf.set(wgPubkey, 0);
    buf.set(serverPubkeyCompressed, 32);
    return buf;
}
