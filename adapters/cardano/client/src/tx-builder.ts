/**
 * Client-side transaction building for Cardano.
 *
 * Builds request transactions (mint beacon + send to validator with datum)
 * and cleanup transactions (consume response UTXO + burn beacon).
 *
 * Uses cmttk (pure JS, no WASM) for transaction building.
 */

import { buildAndSubmitScriptTx, type MintEntry, type TxOutput, type ScriptInput } from 'cmttk/tx';
import { Constr, Data } from 'cmttk/data';
import { getProvider, type Provider } from 'cmttk/provider';
import { buildBaseAddress, buildEnterpriseAddress } from 'cmttk/address';
import { Bip32PrivateKey } from 'noble-bip32ed25519';
import { mnemonicToEntropy } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { readFileSync, existsSync } from 'node:fs';
import { Buffer } from 'buffer';

const REQUEST_BEACON_NAME = Buffer.from('request').toString('hex');
const RESPONSE_BEACON_NAME = Buffer.from('response').toString('hex');

interface ScriptInfo {
    cbor: string;
    hash: string;
}

interface ScriptsFile {
    broker: ScriptInfo;
    beacon: ScriptInfo;
}

/** Abstraction over signing — works with both raw keys and mnemonic-derived keys. */
export interface CardanoSigner {
    pkh: string;
    addr: string;
    /** 64-byte extended signing key (kL + kR) for cmttk */
    signingKeyBytes: Uint8Array;
}

/**
 * Load wallet key material from string (inline value or file path).
 * Detects format: BIP39 mnemonic (words) or raw 32-byte hex key.
 */
export function loadSigner(
    keyOrPath: string,
    network: string,
): CardanoSigner {
    let content: string;
    if (existsSync(keyOrPath)) {
        content = readFileSync(keyOrPath, 'utf-8').trim();
    } else {
        content = keyOrPath;
    }

    // Mnemonic: contains spaces (12/15/24 words)
    if (content.includes(' ')) {
        return deriveFromMnemonic(content, network);
    }

    // Raw hex key
    if (content.startsWith('0x')) content = content.slice(2);
    const bytes = Buffer.from(content, 'hex');
    if (bytes.length !== 32) {
        throw new Error(`Signing key must be 32 bytes, got ${bytes.length}`);
    }
    return rawKeySigner(bytes, network);
}

function deriveFromMnemonic(mnemonic: string, network: string): CardanoSigner {
    const entropy = mnemonicToEntropy(mnemonic, wordlist);
    const rootKey = Bip32PrivateKey.fromEntropy(entropy);
    const accountKey = rootKey
        .derive(2147483648 + 1852)
        .derive(2147483648 + 1815)
        .derive(2147483648 + 0);

    const paymentKey = accountKey.derive(0).derive(0);
    const stakeKey = accountKey.derive(2).derive(0);
    const signingKey = paymentKey.toPrivateKey();
    const pkh = Buffer.from(signingKey.toPublicKey().hash()).toString('hex');
    const stakePkh = Buffer.from(stakeKey.toPrivateKey().toPublicKey().hash()).toString('hex');

    const addr = buildBaseAddress(pkh, stakePkh, network as any);

    return { pkh, addr, signingKeyBytes: signingKey.toBytes() };
}

function rawKeySigner(privateKey: Uint8Array, network: string): CardanoSigner {
    const { ed25519 } = require('@noble/curves/ed25519.js');
    const { blake2b } = require('@noble/hashes/blake2.js');

    const publicKey = ed25519.getPublicKey(privateKey);
    const pkh = Buffer.from(blake2b(publicKey, { dkLen: 28 })).toString('hex');
    const addr = buildEnterpriseAddress(pkh, network as any, false);

    // cmttk expects 64-byte kL+kR for Ed25519-BIP32 signing.
    // For raw Ed25519 keys, pad with zeros for kR (only kL is used for signing).
    const extendedKey = new Uint8Array(64);
    extendedKey.set(privateKey, 0);

    return { pkh, addr, signingKeyBytes: extendedKey };
}

export class ClientTxBuilder {
    private brokerScriptCbor: string;
    private beaconScriptCbor: string;
    private beaconPolicyId: string;
    private validatorAddress: string;
    private signer: CardanoSigner;
    private network: string;
    private provider: Provider;

    constructor(
        scripts: ScriptsFile,
        signer: CardanoSigner,
        network: string,
        koiosUrl: string,
    ) {
        this.brokerScriptCbor = scripts.broker.cbor;
        this.beaconScriptCbor = scripts.beacon.cbor;
        this.beaconPolicyId = scripts.beacon.hash;
        this.validatorAddress = buildEnterpriseAddress(scripts.broker.hash, network as any, true);
        this.signer = signer;
        this.network = network;
        this.provider = getProvider(network as any, undefined, koiosUrl);
    }

    getClientPkh(): string {
        return this.signer.pkh;
    }

    getClientAddress(): string {
        return this.signer.addr;
    }

    /**
     * Build and submit a request transaction.
     *
     * - Mint a request beacon (validator checks client_pkh signed the tx)
     * - Send ADA + beacon to validator with RequestDatum (inline)
     */
    async submitRequest(
        nftPolicyId: string,
        encryptedPayload: Uint8Array,
    ): Promise<string> {
        // MintRequestBeacon — BeaconAction constructor 0
        const mintRedeemer = Data.to(new Constr(0, []));

        const mint: MintEntry = {
            policyId: this.beaconPolicyId,
            scriptCbor: this.beaconScriptCbor,
            redeemerCbor: mintRedeemer,
            assets: {
                [REQUEST_BEACON_NAME]: 1n,
            },
        };

        // RequestDatum { nft_policy_id, client_pkh, encrypted_payload } — constructor 0
        const datumCbor = Data.to(
            new Constr(0, [
                Buffer.from(nftPolicyId, 'hex'),
                Buffer.from(this.signer.pkh, 'hex'),
                Buffer.from(encryptedPayload),
            ]),
        );

        const output: TxOutput = {
            address: this.validatorAddress,
            assets: {
                lovelace: 2_000_000n,
                [this.beaconPolicyId + REQUEST_BEACON_NAME]: 1n,
            },
            datumCbor,
        };

        const txHash = await buildAndSubmitScriptTx({
            provider: this.provider,
            walletAddress: this.signer.addr,
            signingKey: this.signer.signingKeyBytes,
            mints: [mint],
            outputs: [output],
            requiredSigners: [this.signer.pkh],
            network: this.network as any,
        });

        console.error(`[tx] Request tx: ${txHash}`);
        return txHash;
    }

    /**
     * Build and submit a cleanup transaction.
     *
     * - Consume response UTXO (ConsumeResponse redeemer)
     * - Burn response beacon
     * - Return ADA to client
     */
    async cleanupResponse(
        responseUtxoRef: { txHash: string; outputIndex: number },
        responseLovelace: bigint,
    ): Promise<string> {
        // ConsumeResponse — BrokerAction constructor 1
        const consumeRedeemer = Data.to(new Constr(1, []));

        const scriptInput: ScriptInput = {
            utxo: {
                txHash: responseUtxoRef.txHash,
                index: responseUtxoRef.outputIndex,
                lovelace: responseLovelace,
                tokens: {
                    [this.beaconPolicyId + RESPONSE_BEACON_NAME]: 1n,
                },
            },
            address: this.validatorAddress,
            redeemerCbor: consumeRedeemer,
        };

        // BurnResponseBeacon — BeaconAction constructor 3
        const burnRedeemer = Data.to(new Constr(3, []));

        const mint: MintEntry = {
            policyId: this.beaconPolicyId,
            scriptCbor: this.beaconScriptCbor,
            redeemerCbor: burnRedeemer,
            assets: {
                [RESPONSE_BEACON_NAME]: -1n,
            },
        };

        const txHash = await buildAndSubmitScriptTx({
            provider: this.provider,
            walletAddress: this.signer.addr,
            signingKey: this.signer.signingKeyBytes,
            scriptInputs: [scriptInput],
            spendingScriptCbor: this.brokerScriptCbor,
            mints: [mint],
            requiredSigners: [this.signer.pkh],
            network: this.network as any,
        });

        console.error(`[tx] Cleanup tx: ${txHash}`);
        return txHash;
    }
}
