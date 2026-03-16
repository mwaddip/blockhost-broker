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
    gateway: string; // broker WireGuard address (upstream::2)
}

export function deserializeResponse(data: Uint8Array): TunnelConfig {
    if (data.length !== 63) {
        throw new Error(`Invalid response length: ${data.length} (expected 63)`);
    }

    let offset = 0;

    const wgKey = Buffer.from(data.slice(offset, offset + 32)).toString('base64');
    offset += 32;

    const ip = `${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}`;
    offset += 4;

    const port = (data[offset] << 8) | data[offset + 1];
    offset += 2;

    const mask = data[offset++];

    // Reconstruct prefix IPv6 (16 bytes)
    const prefixParts: string[] = [];
    for (let i = 0; i < 8; i++) {
        const val = (data[offset + i * 2] << 8) | data[offset + i * 2 + 1];
        prefixParts.push(val.toString(16));
    }
    const prefix = compressIPv6(prefixParts.join(':'));
    offset += 16;

    // Reconstruct gateway: upper 64 bits from prefix, lower 64 bits from payload
    const gwParts = prefixParts.slice(0, 4);
    for (let i = 0; i < 4; i++) {
        const val = (data[offset + i * 2] << 8) | data[offset + i * 2 + 1];
        gwParts.push(val.toString(16));
    }
    const gateway = compressIPv6(gwParts.join(':'));

    return {
        brokerPubkey: wgKey,
        brokerEndpoint: `${ip}:${port}`,
        prefix: `${prefix}/${mask}`,
        gateway,
    };
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

export function serverKeypairFromHex(hex: string): ServerKeypair {
    const h = hex.startsWith('0x') ? hex.slice(2) : hex;
    const privateKey = Uint8Array.from(Buffer.from(h, 'hex'));
    if (privateKey.length !== 32) throw new Error(`Server key must be 32 bytes, got ${privateKey.length}`);
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
