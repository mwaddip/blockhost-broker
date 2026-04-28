/**
 * Shared adapter-side crypto + response serialization.
 *
 * Used by Cardano, Ergo, and OPNet adapters. Each adapter imports from here
 * but bundles independently via esbuild — no shared runtime dependency.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { gcm } from '@noble/ciphers/aes.js';

// ── Payload types ────────────────────────────────────────────────────

export interface RequestPayload {
    /** WireGuard public key (base64) */
    wgPubkey: string;
    /** Ephemeral secp256k1 pubkey for response encryption (hex, compressed) */
    serverPubkey: string;
}

export interface ResponsePayload {
    prefix: string;
    gateway: string;
    brokerPubkey: string;
    brokerEndpoint: string;
    dnsZone?: string;
}

// ── ECIES (eciespy-compatible decrypt) ──────────────────────────────
//
// Format: [65 bytes ephemeral uncompressed pubkey] [16 bytes tag] [16 bytes iv] [ciphertext]
// Shared secret: ECDH(ephemeral, recipient) → HKDF-SHA256

const UNCOMPRESSED_KEY_LEN = 65;
const TAG_LEN = 16;
const IV_LEN = 16;

function eciesDecrypt(data: Uint8Array, privateKey: Uint8Array): Uint8Array {
    if (data.length < UNCOMPRESSED_KEY_LEN + TAG_LEN + IV_LEN + 1) {
        throw new Error('ECIES ciphertext too short');
    }

    const ephPub = data.slice(0, UNCOMPRESSED_KEY_LEN);
    const tag = data.slice(UNCOMPRESSED_KEY_LEN, UNCOMPRESSED_KEY_LEN + TAG_LEN);
    const iv = data.slice(UNCOMPRESSED_KEY_LEN + TAG_LEN, UNCOMPRESSED_KEY_LEN + TAG_LEN + IV_LEN);
    const ciphertext = data.slice(UNCOMPRESSED_KEY_LEN + TAG_LEN + IV_LEN);

    const shared = secp256k1.getSharedSecret(privateKey, ephPub);
    const aesKey = hkdf(sha256, shared.slice(1), undefined, undefined, 32);

    const combined = new Uint8Array(ciphertext.length + TAG_LEN);
    combined.set(ciphertext, 0);
    combined.set(tag, ciphertext.length);

    const decipher = gcm(aesKey, iv);
    return decipher.decrypt(combined);
}

// ── Compact encryption (ECDH-derived key + deterministic IV) ────────
//
// ECDH(broker_priv, client_serverPubkey) → HKDF → AES-GCM
// IV is derived deterministically — not in the payload.

const COMPACT_AES_IV_LEN = 12;

export function deriveKeyAndIv(
    senderPrivkey: Uint8Array,
    recipientPubkey: Uint8Array,
): { aesKey: Uint8Array; iv: Uint8Array } {
    const shared = secp256k1.getSharedSecret(senderPrivkey, recipientPubkey);
    const ikm = shared.slice(1);

    const aesKey = hkdf(sha256, ikm, undefined, new TextEncoder().encode('blockhost-aes-key'), 32);
    const iv = hkdf(sha256, ikm, undefined, new TextEncoder().encode('blockhost-aes-iv'), COMPACT_AES_IV_LEN);

    return { aesKey, iv };
}

export function encryptCompact(
    plaintext: Uint8Array,
    senderPrivkey: Uint8Array,
    recipientPubkey: Uint8Array,
): Uint8Array {
    const { aesKey, iv } = deriveKeyAndIv(senderPrivkey, recipientPubkey);
    const cipher = gcm(aesKey, iv);
    return cipher.encrypt(plaintext);
}

// ── High-level adapter API ──────────────────────────────────────────

export class EciesEncryption {
    private privateKey: Uint8Array;
    private publicKey: Uint8Array;

    constructor(privateKeyHex: string) {
        const hex = privateKeyHex.startsWith('0x') ? privateKeyHex.slice(2) : privateKeyHex;
        this.privateKey = Buffer.from(hex, 'hex');
        this.publicKey = secp256k1.getPublicKey(this.privateKey, false);
    }

    publicKeyHex(): string {
        return Buffer.from(this.publicKey).toString('hex');
    }

    decrypt(ciphertext: Uint8Array): Uint8Array {
        return eciesDecrypt(ciphertext, this.privateKey);
    }

    /**
     * Decrypt a binary request payload.
     *
     * Binary layout (65 bytes):
     *   [32 bytes WireGuard pubkey]
     *   [33 bytes compressed secp256k1 server pubkey]
     */
    decryptRequestPayload(encoded: string): RequestPayload {
        const isHex = /^[0-9a-fA-F]+$/.test(encoded);
        const ciphertext = Buffer.from(encoded, isHex ? 'hex' : 'base64');
        const plaintext = this.decrypt(ciphertext);

        if (plaintext.length !== 65) {
            throw new Error(`Invalid request payload length: ${plaintext.length} (expected 65)`);
        }

        const wgPubkey = Buffer.from(plaintext.slice(0, 32)).toString('base64');
        const serverPubkey = Buffer.from(plaintext.slice(32, 65)).toString('hex');

        return { wgPubkey, serverPubkey };
    }

    /**
     * Encrypt a response for the client's server pubkey using compact ECDH-AES-GCM.
     * Returns the encrypted blob (ciphertext || tag).
     */
    encryptResponse(plaintext: Uint8Array, recipientServerPubkeyHex: string): Uint8Array {
        const recipientPub = Buffer.from(recipientServerPubkeyHex, 'hex');
        const recipientPubUncompressed = recipientPub.length === 33
            ? Buffer.from(secp256k1.Point.fromHex(recipientPub.toString('hex')).toBytes(false))
            : recipientPub;
        return encryptCompact(plaintext, this.privateKey, recipientPubUncompressed);
    }
}

// ── Response serialization (63-byte binary) ─────────────────────────
//
// Layout — same across all adapters and OPNet's OP_RETURN format:
//   [32 bytes broker WireGuard pubkey]
//   [4  bytes broker endpoint IPv4]
//   [2  bytes broker endpoint port BE]
//   [1  byte  prefix mask length]
//   [16 bytes prefix network (IPv6)]
//   [8  bytes gateway host part (lower 64 bits)]

export function serializeResponse(resp: ResponsePayload): Uint8Array {
    const buf = new Uint8Array(63);
    let offset = 0;

    const wgKey = Buffer.from(resp.brokerPubkey, 'base64');
    if (wgKey.length !== 32) {
        throw new Error(`Invalid WG pubkey length: ${wgKey.length}`);
    }
    buf.set(wgKey, offset);
    offset += 32;

    const [epHost, epPortStr] = resp.brokerEndpoint.split(':');
    const ipParts = epHost.split('.');
    if (ipParts.length !== 4) {
        throw new Error(`Invalid IPv4 endpoint: ${epHost}`);
    }
    for (let i = 0; i < 4; i++) {
        buf[offset++] = parseInt(ipParts[i], 10);
    }

    const port = parseInt(epPortStr, 10);
    buf[offset++] = (port >> 8) & 0xff;
    buf[offset++] = port & 0xff;

    const slashIdx = resp.prefix.indexOf('/');
    if (slashIdx === -1) {
        throw new Error(`Invalid prefix (no mask): ${resp.prefix}`);
    }
    buf[offset++] = parseInt(resp.prefix.slice(slashIdx + 1), 10);

    const prefixAddr = resp.prefix.slice(0, slashIdx);
    const ipv6Bytes = ipv6ToBytes(prefixAddr);
    buf.set(ipv6Bytes, offset);
    offset += 16;

    const gwBytes = ipv6ToBytes(resp.gateway);
    buf.set(gwBytes.slice(8, 16), offset);

    return buf;
}

// ── IPv6 helpers ────────────────────────────────────────────────────

export function expandIPv6(addr: string): string {
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

export function ipv6ToBytes(addr: string): Uint8Array {
    const expanded = expandIPv6(addr);
    const parts = expanded.split(':');
    const buf = new Uint8Array(16);
    for (let i = 0; i < 8; i++) {
        const val = parseInt(parts[i], 16);
        buf[i * 2] = (val >> 8) & 0xff;
        buf[i * 2 + 1] = val & 0xff;
    }
    return buf;
}
