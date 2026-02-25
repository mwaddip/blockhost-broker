/**
 * ECIES encryption/decryption for request/response payloads.
 *
 * Uses secp256k1 curve, compatible with the Rust broker's eciespy format.
 * The `ecies` npm package from @noble/curves provides the primitives.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes } from 'crypto';

// ── Payload types (match Rust broker's ecies.rs) ────────────────────

export interface RequestPayload {
    /** WireGuard public key (base64) */
    wgPubkey: string;
    /** Ephemeral secp256k1 pubkey for response encryption (hex, uncompressed) */
    serverPubkey: string;
}

export interface ResponsePayload {
    prefix: string;
    gateway: string;
    brokerPubkey: string;
    brokerEndpoint: string;
    dnsZone?: string;
}

// ── ECIES (eciespy-compatible) ──────────────────────────────────────
//
// eciespy format:
//   [65 bytes ephemeral uncompressed pubkey]
//   [16 bytes AES-GCM tag]
//   [16 bytes AES-GCM nonce/iv]
//   [... ciphertext ...]
//
// Shared secret: ECDH(ephemeral, recipient) → HKDF-SHA256

const UNCOMPRESSED_KEY_LEN = 65;
const TAG_LEN = 16;
const IV_LEN = 16;

function eciesEncrypt(plaintext: Uint8Array, recipientPubkey: Uint8Array): Uint8Array {
    // Generate ephemeral keypair
    const ephPriv = secp256k1.utils.randomSecretKey();
    const ephPub = secp256k1.getPublicKey(ephPriv, false); // uncompressed

    // ECDH shared secret
    const shared = secp256k1.getSharedSecret(ephPriv, recipientPubkey);
    // eciespy uses HKDF with SHA-256, no info, no salt
    const aesKey = hkdf(sha256, shared.slice(1), undefined, undefined, 32); // skip 0x04 prefix

    // AES-256-GCM
    const iv = randomBytes(IV_LEN);
    const cipher = gcm(aesKey, iv);
    const encrypted = cipher.encrypt(plaintext);
    // @noble/ciphers gcm.encrypt returns ciphertext || tag
    const ciphertext = encrypted.slice(0, encrypted.length - TAG_LEN);
    const tag = encrypted.slice(encrypted.length - TAG_LEN);

    // eciespy format: ephPub || tag || iv || ciphertext
    const result = new Uint8Array(UNCOMPRESSED_KEY_LEN + TAG_LEN + IV_LEN + ciphertext.length);
    result.set(ephPub, 0);
    result.set(tag, UNCOMPRESSED_KEY_LEN);
    result.set(iv, UNCOMPRESSED_KEY_LEN + TAG_LEN);
    result.set(ciphertext, UNCOMPRESSED_KEY_LEN + TAG_LEN + IV_LEN);
    return result;
}

function eciesDecrypt(data: Uint8Array, privateKey: Uint8Array): Uint8Array {
    if (data.length < UNCOMPRESSED_KEY_LEN + TAG_LEN + IV_LEN + 1) {
        throw new Error('ECIES ciphertext too short');
    }

    const ephPub = data.slice(0, UNCOMPRESSED_KEY_LEN);
    const tag = data.slice(UNCOMPRESSED_KEY_LEN, UNCOMPRESSED_KEY_LEN + TAG_LEN);
    const iv = data.slice(UNCOMPRESSED_KEY_LEN + TAG_LEN, UNCOMPRESSED_KEY_LEN + TAG_LEN + IV_LEN);
    const ciphertext = data.slice(UNCOMPRESSED_KEY_LEN + TAG_LEN + IV_LEN);

    // ECDH shared secret
    const shared = secp256k1.getSharedSecret(privateKey, ephPub);
    const aesKey = hkdf(sha256, shared.slice(1), undefined, undefined, 32);

    // AES-256-GCM: reassemble ciphertext || tag for @noble/ciphers
    const combined = new Uint8Array(ciphertext.length + TAG_LEN);
    combined.set(ciphertext, 0);
    combined.set(tag, ciphertext.length);

    const decipher = gcm(aesKey, iv);
    return decipher.decrypt(combined);
}

// ── High-level API ──────────────────────────────────────────────────

export class EciesEncryption {
    private privateKey: Uint8Array;
    private publicKey: Uint8Array;

    constructor(privateKeyHex: string) {
        const hex = privateKeyHex.startsWith('0x') ? privateKeyHex.slice(2) : privateKeyHex;
        this.privateKey = Buffer.from(hex, 'hex');
        this.publicKey = secp256k1.getPublicKey(this.privateKey, false); // uncompressed
    }

    /** Uncompressed public key (65 bytes) as hex. */
    publicKeyHex(): string {
        return Buffer.from(this.publicKey).toString('hex');
    }

    /** Decrypt an ECIES ciphertext encrypted for this key. */
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
        // Accept both hex and base64 (base64 is shorter, fits OPNet event limits)
        const isHex = /^[0-9a-fA-F]+$/.test(encoded);
        console.log(`[crypto] Payload: ${encoded.length} chars, isHex=${isHex}, preview=${encoded.slice(0, 40)}...`);
        const ciphertext = Buffer.from(encoded, isHex ? 'hex' : 'base64');
        console.log(`[crypto] Decoded: ${ciphertext.length} bytes`);
        const plaintext = this.decrypt(ciphertext);

        if (plaintext.length !== 65) {
            throw new Error(`Invalid request payload length: ${plaintext.length} (expected 65)`);
        }

        const wgPubkey = Buffer.from(plaintext.slice(0, 32)).toString('base64');
        // Compressed 33-byte pubkey — getSharedSecret/getPublicKey accept both formats,
        // but store as hex for the delivery module to use.
        const serverPubkey = Buffer.from(plaintext.slice(32, 65)).toString('hex');

        return { wgPubkey, serverPubkey };
    }

    /** Encrypt a response payload for a recipient's pubkey. */
    encryptResponsePayload(response: ResponsePayload, recipientPubkeyHex: string): Uint8Array {
        const recipientPubkey = Buffer.from(recipientPubkeyHex, 'hex');
        const plaintext = Buffer.from(JSON.stringify(response), 'utf-8');
        return eciesEncrypt(plaintext, recipientPubkey);
    }
}
