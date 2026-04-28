/**
 * BlockHost Ergo client — subprocess mode.
 *
 * Submits a request box to the guard address, watches for the
 * broker's response box, and outputs tunnel configuration
 * as a single JSON line to stdout.
 *
 * Usage:
 *   node dist/main.js request \
 *     --explorer-url https://api-testnet.ergoplatform.com \
 *     --signing-key /path/to/key.hex \
 *     --registry-nft-id abc123...
 */

import { existsSync, readFileSync, writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ErgoAddress, Network } from '@fleet-sdk/core';
import {
    eciesEncrypt,
    decryptCompact,
    deserializeResponse,
    generateWgKeypair,
    generateServerKeypair,
    serializeRequestPayload,
} from '../../../_shared/src/client-crypto.js';
import { ClientTxBuilder } from './tx-builder.js';
import {
    getBoxesByTokenId,
    decodeCollByte,
    type ErgoBox,
} from './ergo-api.js';

// ── Logging ─────────────────────────────────────────────────────────

function log(msg: string): void {
    process.stderr.write(`[ergo-client] ${msg}\n`);
}

function fatal(msg: string): never {
    process.stderr.write(`[ergo-client] FATAL: ${msg}\n`);
    process.exit(1);
}

// ── Arg parsing ─────────────────────────────────────────────────────

interface Args {
    command: string;
    explorerUrl: string;
    relayUrl: string;
    signingKey: string;
    registryNftId: string;
    nftContract: string;
    timeoutMs: number;
    network: 'testnet' | 'mainnet';
}

function parseArgs(): Args {
    const argv = process.argv.slice(2);
    const command = argv[0];

    if (!command || command === '--help') {
        process.stderr.write(
            `Usage: node dist/main.js request [options]\n\n` +
            `  --explorer-url URL    Explorer API URL\n` +
            `  --relay-url URL       ergo-relay URL (default: http://127.0.0.1:9064)\n` +
            `  --signing-key PATH    Hex private key file\n` +
            `  --registry-nft-id ID  Registry NFT token ID (64 hex chars)\n` +
            `  --nft-contract ADDR   Subscription P2S address (nft_contract identifier)\n` +
            `  --timeout N           Response timeout in seconds (default: 600)\n` +
            `  --network NAME        testnet or mainnet (default: testnet)\n`,
        );
        process.exit(command ? 0 : 1);
    }

    function getFlag(names: string[], fallback?: string): string {
        for (const name of names) {
            const idx = argv.indexOf(name);
            if (idx !== -1 && idx + 1 < argv.length) return argv[idx + 1]!;
        }
        if (fallback !== undefined) return fallback;
        fatal(`Missing required argument: ${names.join(' | ')}`);
    }

    return {
        command,
        explorerUrl: getFlag(['--explorer-url', '--rpc-url'], 'https://api-testnet.ergoplatform.com'),
        relayUrl: getFlag(['--relay-url'], 'http://127.0.0.1:9064'),
        signingKey: getFlag(['--signing-key', '--mnemonic']),
        registryNftId: getFlag(['--registry-nft-id', '--registry-pubkey']),
        nftContract: getFlag(['--nft-contract', '--nft-pubkey']),
        timeoutMs: Number(getFlag(['--timeout'], '600')) * 1000,
        network: getFlag(['--network'], 'testnet') as 'testnet' | 'mainnet',
    };
}

// ── Address helpers ─────────────────────────────────────────────────

function p2pkAddr(pubKeyHex: string, mainnet: boolean): string {
    const network = mainnet ? Network.Mainnet : Network.Testnet;
    return ErgoAddress.fromPublicKey(pubKeyHex, network).encode(network);
}

function ergoTreeToAddress(ergoTreeHex: string, mainnet: boolean): string {
    const network = mainnet ? Network.Mainnet : Network.Testnet;
    return ErgoAddress.fromErgoTree(ergoTreeHex, network).encode(network);
}

// ── Key loading ─────────────────────────────────────────────────────

function loadSigningKey(keyOrPath: string, mainnet: boolean): {
    privKeyHex: string;
    pubKeyHex: string;
    address: string;
} {
    let content: string;
    if (existsSync(keyOrPath)) {
        content = readFileSync(keyOrPath, 'utf-8').trim();
    } else {
        content = keyOrPath;
    }
    if (content.startsWith('0x')) content = content.slice(2);
    if (content.length !== 64) {
        fatal(`Signing key must be 32 bytes hex (64 chars), got ${content.length}`);
    }

    const privBytes = Uint8Array.from(Buffer.from(content, 'hex'));
    const pubKey = Buffer.from(secp256k1.getPublicKey(privBytes, true)).toString('hex');
    const addr = p2pkAddr(pubKey, mainnet);
    return { privKeyHex: content, pubKeyHex: pubKey, address: addr };
}

// ── Registry ────────────────────────────────────────────────────────

interface RegistryInfo {
    operatorPubkeyHex: string;
    eciesPubkeyHex: string;
    guardErgoTreeHex: string;
    guardAddress: string;
}

async function fetchRegistry(explorerUrl: string, nftId: string, mainnet: boolean): Promise<RegistryInfo> {
    const boxes = await getBoxesByTokenId(explorerUrl, nftId);
    if (boxes.length === 0) throw new Error('Registry NFT not found');

    const registryBox = boxes.find(b => b.assets.some(a => a.tokenId === nftId && a.amount === 1n));
    if (!registryBox) throw new Error('Registry NFT box not found');

    const r4 = registryBox.additionalRegisters['R4'];
    const r5 = registryBox.additionalRegisters['R5'];
    const r6 = registryBox.additionalRegisters['R6'];
    if (!r4 || !r5 || !r6) throw new Error('Registry box missing registers');

    const operatorPubkey = decodeCollByte(r4);
    const eciesPubkey = decodeCollByte(r5);
    const guardErgoTree = decodeCollByte(r6);

    if (operatorPubkey.length !== 33) throw new Error(`Invalid operator pubkey length: ${operatorPubkey.length}`);
    if (eciesPubkey.length !== 33) throw new Error(`Invalid ECIES pubkey length: ${eciesPubkey.length}`);

    const guardErgoTreeHex = Buffer.from(guardErgoTree).toString('hex');
    const guardAddress = ergoTreeToAddress(guardErgoTreeHex, mainnet);

    return {
        operatorPubkeyHex: Buffer.from(operatorPubkey).toString('hex'),
        eciesPubkeyHex: Buffer.from(eciesPubkey).toString('hex'),
        guardErgoTreeHex,
        guardAddress,
    };
}

// ── Recovery ────────────────────────────────────────────────────────

const RECOVERY_FILE = '/var/lib/blockhost/ergo-recovery.json';

interface RecoveryState {
    beaconTokenId: string;
    serverPrivkeyHex: string;
    brokerPubkeyHex: string;
    guardAddress: string;
    operatorPubkeyHex: string;
    wgPrivateKeyBase64: string;
    wgPublicKeyBase64: string;
    explorerUrl: string;
    network: string;
    savedAt: string;
}

function saveRecoveryState(state: RecoveryState): void {
    mkdirSync(dirname(RECOVERY_FILE), { recursive: true });
    writeFileSync(RECOVERY_FILE, JSON.stringify(state, null, 2));
    log(`Recovery state saved`);
}

function loadRecoveryState(): RecoveryState | null {
    if (!existsSync(RECOVERY_FILE)) return null;
    try { return JSON.parse(readFileSync(RECOVERY_FILE, 'utf-8')); } catch { return null; }
}

function clearRecoveryState(): void {
    try { if (existsSync(RECOVERY_FILE)) unlinkSync(RECOVERY_FILE); } catch {}
}

// ── Response watcher ────────────────────────────────────────────────

const RESPONSE_POLL_MS = 10_000;

async function watchForResponse(
    explorerUrl: string,
    beaconTokenId: string,
    serverPrivkey: Uint8Array,
    brokerPub: Uint8Array,
    timeoutMs: number,
): Promise<{ config: ReturnType<typeof deserializeResponse>; responseBox: ErgoBox }> {
    log(`Watching for response (beacon=${beaconTokenId.slice(0, 16)}..., timeout=${timeoutMs / 1000}s)`);
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
        try {
            const boxes = await getBoxesByTokenId(explorerUrl, beaconTokenId);

            for (const box of boxes) {
                const r5Hex = box.additionalRegisters['R5'];
                if (!r5Hex) continue;

                const encrypted = decodeCollByte(r5Hex);
                try {
                    const plaintext = decryptCompact(encrypted, serverPrivkey, brokerPub);
                    log(`Response found in box ${box.boxId.slice(0, 16)}...`);
                    return { config: deserializeResponse(plaintext), responseBox: box };
                } catch {
                    // Decryption failed — might be the request box (our own encrypted payload).
                    // Skip and try next.
                }
            }
        } catch (e) {
            log(`Query failed, will retry: ${e}`);
        }

        await new Promise(r => setTimeout(r, RESPONSE_POLL_MS));
    }

    throw new Error('Timed out waiting for broker response');
}

// ── Request command ─────────────────────────────────────────────────

async function cmdRequest(args: Args): Promise<void> {
    const isMainnet = args.network === 'mainnet';

    // Check for recovery
    const recovery = loadRecoveryState();
    if (recovery) {
        log('Found recovery state, attempting re-scan...');
        const serverPriv = Uint8Array.from(Buffer.from(recovery.serverPrivkeyHex, 'hex'));
        const brokerPub = Uint8Array.from(Buffer.from(recovery.brokerPubkeyHex, 'hex'));
        try {
            const { config } = await watchForResponse(
                recovery.explorerUrl,
                recovery.beaconTokenId,
                serverPriv,
                brokerPub,
                60_000,
            );
            clearRecoveryState();
            process.stdout.write(JSON.stringify({
                prefix: config.prefix,
                gateway: config.gateway,
                broker_pubkey: config.brokerPubkey,
                broker_endpoint: config.brokerEndpoint,
                wg_private_key: recovery.wgPrivateKeyBase64,
                wg_public_key: recovery.wgPublicKeyBase64,
                broker_wallet: p2pkAddr(recovery.operatorPubkeyHex, recovery.network === 'mainnet'),
            }) + '\n');
            return;
        } catch {
            log('Recovery scan found no response, proceeding fresh');
            clearRecoveryState();
        }
    }

    // 1. Load signing key
    const key = loadSigningKey(args.signingKey, isMainnet);
    log(`Client: ${key.address}`);

    // 2. Fetch registry
    log('Fetching registry...');
    const registry = await fetchRegistry(args.explorerUrl, args.registryNftId, isMainnet);
    log(`Guard: ${registry.guardAddress}`);

    // 3. Generate keypairs
    const wgKeys = generateWgKeypair();
    const serverKeys = generateServerKeypair();
    log(`WG pubkey: ${wgKeys.publicKeyBase64}`);

    // 4. Encrypt request payload
    const payload = serializeRequestPayload(wgKeys.publicKey, serverKeys.publicKeyCompressed);
    const eciesPub = Buffer.from(registry.eciesPubkeyHex, 'hex');
    const eciesPubUncompressed = eciesPub.length === 33
        ? Buffer.from(secp256k1.Point.fromHex(Buffer.from(eciesPub).toString('hex')).toBytes(false))
        : eciesPub;
    const encrypted = eciesEncrypt(payload, eciesPubUncompressed);
    log(`Encrypted payload: ${encrypted.length} bytes`);

    // 5. Submit request tx
    const txBuilder = new ClientTxBuilder(
        args.explorerUrl,
        args.relayUrl,
        key.address,
        key.privKeyHex,
        key.pubKeyHex,
        registry.guardAddress,
    );

    log('Submitting request transaction...');
    const { beaconTokenId } = await txBuilder.submitRequest(encrypted, args.nftContract);

    // 6. Save recovery state
    saveRecoveryState({
        beaconTokenId,
        serverPrivkeyHex: Buffer.from(serverKeys.privateKey).toString('hex'),
        brokerPubkeyHex: Buffer.from(eciesPubUncompressed).toString('hex'),
        guardAddress: registry.guardAddress,
        operatorPubkeyHex: registry.operatorPubkeyHex,
        wgPrivateKeyBase64: wgKeys.privateKeyBase64,
        wgPublicKeyBase64: wgKeys.publicKeyBase64,
        explorerUrl: args.explorerUrl,
        network: args.network,
        savedAt: new Date().toISOString(),
    });

    // 7. Watch for response
    try {
        const { config, responseBox } = await watchForResponse(
            args.explorerUrl,
            beaconTokenId,
            serverKeys.privateKey,
            eciesPubUncompressed,
            args.timeoutMs,
        );

        clearRecoveryState();

        process.stdout.write(JSON.stringify({
            prefix: config.prefix,
            gateway: config.gateway,
            broker_pubkey: config.brokerPubkey,
            broker_endpoint: config.brokerEndpoint,
            wg_private_key: wgKeys.privateKeyBase64,
            wg_public_key: wgKeys.publicKeyBase64,
            broker_wallet: p2pkAddr(registry.operatorPubkeyHex, isMainnet),
        }) + '\n');

        // 8. Cleanup response box (best effort)
        try {
            await txBuilder.cleanupResponse(responseBox, beaconTokenId);
        } catch (e) {
            log(`Cleanup failed (non-fatal): ${e}`);
        }
    } catch (e) {
        log(`Watch failed: ${e} — recovery state preserved`);
        throw e;
    }
}

// ── Entry ───────────────────────────────────────────────────────────

const args = parseArgs();
if (args.command === 'request') {
    cmdRequest(args).catch(err => fatal(String(err)));
} else {
    fatal(`Unknown command: ${args.command}`);
}
