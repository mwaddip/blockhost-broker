/**
 * BlockHost Cardano client — subprocess mode.
 *
 * Submits a request UTXO to the broker validator, watches for the
 * broker's response UTXO, and outputs the tunnel configuration
 * as a single JSON line to stdout.
 *
 * All progress/status logging goes to stderr.
 *
 * Usage:
 *   node dist/main.js request \
 *     --koios-url https://preprod.koios.rest/api/v1 \
 *     --signing-key /path/to/key \
 *     --nft-policy-id abc123... \
 *     --registry-address addr_test1... \
 *     --beacon-policy abc123... \
 *     --scripts-path /path/to/parameterized-scripts.json
 */

import {
    eciesEncrypt,
    decryptCompact,
    deserializeResponse,
    generateWgKeypair,
    generateServerKeypair,
    serverKeypairFromHex,
    serializeRequestPayload,
    type TunnelConfig,
} from '../../../_shared/src/client-crypto.js';
import {
    ClientTxBuilder,
    loadSigner,
} from './tx-builder.js';
import { existsSync, readFileSync, writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { buildEnterpriseAddress } from 'cmttk/address';

// ── Logging (all to stderr) ─────────────────────────────────────────

function log(msg: string): void {
    process.stderr.write(`[cardano-client] ${msg}\n`);
}

function fatal(msg: string): never {
    process.stderr.write(`[cardano-client] FATAL: ${msg}\n`);
    process.exit(1);
}

// ── Arg parsing ─────────────────────────────────────────────────────

interface Args {
    command: string;
    koiosUrl: string;
    signingKey: string;
    nftPolicyId: string;
    registryAddress: string;
    beaconPolicyId: string;
    scriptsPath: string;
    timeoutMs: number;
    serverKey: string | null;
}

function parseArgs(): Args {
    const argv = process.argv.slice(2);
    const command = argv[0];

    if (!command || command === '--help' || command === '-h') {
        process.stderr.write(
            `Usage: node dist/main.js request [options]\n\n` +
            `Options:\n` +
            `  --koios-url URL            Koios REST API URL (default: https://preprod.koios.rest/api/v1)\n` +
            `  --signing-key KEY          Client signing key (hex or file path)\n` +
            `  --nft-policy-id HEX        NFT policy ID (56 hex chars)\n` +
            `  --registry-address ADDR    Registry validator bech32 address\n` +
            `  --beacon-policy HEX        Beacon minting policy ID\n` +
            `  --scripts-path PATH        Path to parameterized-scripts.json\n` +
            `  --timeout N                Response timeout in seconds (default: 600)\n` +
            `  --server-key HEX           Persistent ECIES private key (optional)\n`,
        );
        process.exit(command ? 0 : 1);
    }

    function getFlag(names: string | string[], fallback?: string): string {
        const nameList = Array.isArray(names) ? names : [names];
        for (const name of nameList) {
            const idx = argv.indexOf(name);
            if (idx !== -1 && idx + 1 < argv.length) return argv[idx + 1];
        }
        if (fallback !== undefined) return fallback;
        fatal(`Missing required argument: ${nameList.join(' | ')}`);
    }

    function getFlagOptional(names: string | string[]): string | null {
        const nameList = Array.isArray(names) ? names : [names];
        for (const name of nameList) {
            const idx = argv.indexOf(name);
            if (idx !== -1 && idx + 1 < argv.length) return argv[idx + 1];
        }
        return null;
    }

    return {
        command,
        koiosUrl: getFlag(['--rpc-url', '--koios-url'], 'https://preprod.koios.rest/api/v1'),
        signingKey: getFlag(['--mnemonic', '--signing-key']),
        nftPolicyId: getFlag(['--nft-pubkey', '--nft-policy-id']),
        registryAddress: getFlag(['--registry-pubkey', '--registry-address']),
        beaconPolicyId: getFlag('--beacon-policy', ''),
        scriptsPath: getFlag('--scripts-path', '/opt/blockhost/adapters/cardano/contracts/parameterized-scripts.json'),
        timeoutMs: Number(getFlag('--timeout', '600')) * 1000,
        serverKey: getFlagOptional('--server-key'),
    };
}

// ── Constants ───────────────────────────────────────────────────────

const RESPONSE_POLL_MS = 10_000; // 10s — Cardano blocks are ~20s
const RPC_CALL_TIMEOUT_MS = 30_000;
const RECOVERY_FILE = '/var/lib/blockhost/cardano-recovery.json';

interface RecoveryState {
    serverPrivkeyHex: string;
    brokerPubkeyHex: string;
    requestTxHash: string;
    validatorAddress: string;
    beaconPolicyId: string;
    clientPkh: string;
    operatorPkh: string;
    wgPrivateKeyBase64: string;
    wgPublicKeyBase64: string;
    koiosUrl: string;
    savedAt: string;
}

// ── Recovery ────────────────────────────────────────────────────────

function saveRecoveryState(state: RecoveryState): void {
    mkdirSync(dirname(RECOVERY_FILE), { recursive: true });
    writeFileSync(RECOVERY_FILE, JSON.stringify(state, null, 2));
    log(`Recovery state saved to ${RECOVERY_FILE}`);
}

function loadRecoveryState(): RecoveryState | null {
    if (!existsSync(RECOVERY_FILE)) return null;
    try {
        return JSON.parse(readFileSync(RECOVERY_FILE, 'utf-8'));
    } catch {
        return null;
    }
}

function clearRecoveryState(): void {
    try {
        if (existsSync(RECOVERY_FILE)) {
            unlinkSync(RECOVERY_FILE);
            log('Recovery state cleared');
        }
    } catch { /* ignore */ }
}

// ── Timeout wrapper ─────────────────────────────────────────────────

function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
    return new Promise<T>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
        promise.then(
            (v) => { clearTimeout(timer); resolve(v); },
            (e) => { clearTimeout(timer); reject(e); },
        );
    });
}

// ── Koios helpers ───────────────────────────────────────────────────

async function queryUtxos(koiosUrl: string, address: string): Promise<any[]> {
    const url = `${koiosUrl}/address_utxos`;
    const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ _addresses: [address], _extended: true }),
    });
    if (!resp.ok) throw new Error(`Koios ${resp.status}: ${await resp.text()}`);
    return resp.json();
}

async function queryRegistryDatum(
    koiosUrl: string,
    registryAddress: string,
): Promise<{
    operatorPkh: string;
    eciesPubkey: string;
    capacityStatus: number;
    region: string;
    validatorHash: string;
    beaconPolicyId: string;
}> {
    const utxos = await queryUtxos(koiosUrl, registryAddress);
    if (utxos.length === 0) {
        throw new Error('No UTXOs at registry address');
    }

    // Find the UTXO with an inline datum
    // Pick the most recent registry UTXO (highest block) in case of multiple
    const registryUtxos = utxos
        .filter((u: any) => u.inline_datum?.value)
        .sort((a: any, b: any) => (b.block_height ?? 0) - (a.block_height ?? 0));
    const registryUtxo = registryUtxos[0];
    if (!registryUtxo) {
        throw new Error('No registry UTXO with inline datum found');
    }

    const fields = registryUtxo.inline_datum.value.fields ?? [];
    if (fields.length < 6) {
        throw new Error(`Invalid registry datum: expected 6 fields, got ${fields.length}`);
    }

    return {
        operatorPkh: fields[0].bytes,
        eciesPubkey: fields[1].bytes,
        capacityStatus: fields[2].int,
        region: Buffer.from(fields[3].bytes, 'hex').toString('utf-8'),
        validatorHash: fields[4].bytes,
        beaconPolicyId: fields[5].bytes,
    };
}

// ── Response watcher ────────────────────────────────────────────────

async function watchForResponse(
    koiosUrl: string,
    validatorAddress: string,
    beaconPolicyId: string,
    clientPkh: string,
    serverPrivkey: Uint8Array,
    brokerPubkey: Uint8Array,
    timeoutMs: number,
): Promise<TunnelConfig> {
    log(`watchForResponse: timeout=${timeoutMs}ms (${timeoutMs / 1000}s)`);
    const deadline = Date.now() + timeoutMs;
    const responseBeaconHex = Buffer.from('response').toString('hex'); // 726573706f6e7365

    while (Date.now() < deadline) {
        let utxos: any[];
        try {
            utxos = await withTimeout(
                queryUtxos(koiosUrl, validatorAddress),
                RPC_CALL_TIMEOUT_MS,
                'queryUtxos',
            );
        } catch (e) {
            log(`Query failed, will retry: ${e}`);
            await new Promise(r => setTimeout(r, RESPONSE_POLL_MS));
            continue;
        }

        for (const utxo of utxos) {
            // Check for response beacon
            const assets = utxo.asset_list ?? [];
            const hasBeacon = assets.some(
                (a: any) => a.policy_id === beaconPolicyId && a.asset_name === responseBeaconHex,
            );
            if (!hasBeacon) continue;

            // Check datum matches our client_pkh
            const datum = utxo.inline_datum?.value;
            if (!datum) continue;
            const fields = datum.fields ?? [];
            if (fields.length < 2) continue;
            if (fields[0].bytes !== clientPkh) continue;

            // Decrypt the response
            const encryptedHex = fields[1].bytes;
            const encrypted = Buffer.from(encryptedHex, 'hex');
            try {
                const plaintext = decryptCompact(encrypted, serverPrivkey, brokerPubkey);
                log(`Response found in UTXO ${utxo.tx_hash}#${utxo.tx_index}`);
                return deserializeResponse(plaintext);
            } catch (e) {
                log(`  Response decrypt failed: ${e}`);
            }
        }

        await new Promise(r => setTimeout(r, RESPONSE_POLL_MS));
    }

    throw new Error('Timed out waiting for broker response');
}

// ── Recovery attempt ────────────────────────────────────────────────

async function attemptRecovery(
    state: RecoveryState,
): Promise<{
    brokerPubkey: string;
    brokerEndpoint: string;
    prefix: string;
    gateway: string;
    wgPrivateKeyBase64: string;
    wgPublicKeyBase64: string;
    brokerWallet: string;
} | null> {
    log(`Attempting recovery (saved ${state.savedAt})`);

    const serverPrivkey = Uint8Array.from(Buffer.from(state.serverPrivkeyHex, 'hex'));
    const brokerPub = Uint8Array.from(Buffer.from(state.brokerPubkeyHex, 'hex'));

    try {
        const config = await watchForResponse(
            state.koiosUrl,
            state.validatorAddress,
            state.beaconPolicyId,
            state.clientPkh,
            serverPrivkey,
            brokerPub,
            60_000, // 60s recovery timeout
        );
        clearRecoveryState();
        return {
            ...config,
            wgPrivateKeyBase64: state.wgPrivateKeyBase64,
            wgPublicKeyBase64: state.wgPublicKeyBase64,
            brokerWallet: buildEnterpriseAddress(state.operatorPkh, 'preprod', false),
        };
    } catch {
        log('Recovery scan found no response');
        return null;
    }
}

// ── Request command ─────────────────────────────────────────────────

async function cmdRequest(args: Args): Promise<void> {
    // Check for recovery state
    const recovery = loadRecoveryState();
    if (recovery) {
        log('Found recovery state from previous attempt');
        const recovered = await attemptRecovery(recovery);
        if (recovered) {
            log('Recovered allocation from previous attempt!');
            process.stdout.write(JSON.stringify({
                prefix: recovered.prefix,
                gateway: recovered.gateway,
                broker_pubkey: recovered.brokerPubkey,
                broker_endpoint: recovered.brokerEndpoint,
                wg_private_key: recovered.wgPrivateKeyBase64,
                wg_public_key: recovered.wgPublicKeyBase64,
                broker_wallet: recovered.brokerWallet,
            }) + '\n');
            return;
        }
        clearRecoveryState();
        log('Proceeding with fresh request');
    }

    // 1. Query registry
    log('Querying registry...');
    const registry = await withTimeout(
        queryRegistryDatum(args.koiosUrl, args.registryAddress),
        RPC_CALL_TIMEOUT_MS,
        'queryRegistry',
    );

    log(`Broker region: ${registry.region}`);

    // 2. Check capacity
    if (registry.capacityStatus === 2) {
        throw new Error('Broker capacity is closed');
    }
    if (registry.capacityStatus === 1) {
        log('Warning: broker capacity is limited');
    }

    // 3. Generate keypairs
    const wgKeys = generateWgKeypair();
    const serverKeys = args.serverKey
        ? serverKeypairFromHex(args.serverKey)
        : generateServerKeypair();

    log(`WG pubkey: ${wgKeys.publicKeyBase64}`);

    // 4. Encrypt request payload
    const payload = serializeRequestPayload(wgKeys.publicKey, serverKeys.publicKeyCompressed);

    const brokerPubBytes = Buffer.from(registry.eciesPubkey, 'hex');
    const brokerPubUncompressed =
        brokerPubBytes.length === 33
            ? secp256k1.Point.fromHex(Buffer.from(brokerPubBytes).toString('hex')).toBytes(false)
            : brokerPubBytes;

    const encrypted = eciesEncrypt(payload, brokerPubUncompressed);

    log(`Encrypted payload: ${encrypted.length} bytes`);

    // 5. Load signing key and derive address
    const network = args.koiosUrl.includes('mainnet') ? 'mainnet' : 'preprod';
    const signer = loadSigner(args.signingKey, network);
    const clientPkh = signer.pkh;

    log(`Client address: ${signer.addr}`);
    log(`Client PKH: ${clientPkh}`);

    // 6. Build and submit request transaction
    const scripts = JSON.parse(readFileSync(args.scriptsPath, 'utf-8'));
    const txBuilder = new ClientTxBuilder(scripts, signer, network, args.koiosUrl);

    log('Submitting request transaction...');
    const requestTxHash = await txBuilder.submitRequest(args.nftPolicyId, encrypted);
    log(`Request tx submitted: ${requestTxHash}`);

    // Derive validator address from registry
    const validatorAddress = buildEnterpriseAddress(registry.validatorHash, network as any, true);

    // 7. Save recovery state
    saveRecoveryState({
        serverPrivkeyHex: Buffer.from(serverKeys.privateKey).toString('hex'),
        brokerPubkeyHex: Buffer.from(brokerPubUncompressed).toString('hex'),
        requestTxHash,
        validatorAddress,
        beaconPolicyId: registry.beaconPolicyId,
        clientPkh: clientPkh,
        operatorPkh: registry.operatorPkh,
        wgPrivateKeyBase64: wgKeys.privateKeyBase64,
        wgPublicKeyBase64: wgKeys.publicKeyBase64,
        koiosUrl: args.koiosUrl,
        savedAt: new Date().toISOString(),
    });

    // 8. Watch for response
    try {
        const config = await watchForResponse(
            args.koiosUrl,
            validatorAddress,
            registry.beaconPolicyId,
            clientPkh.toString('hex'),
            serverKeys.privateKey,
            brokerPubUncompressed,
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
            broker_wallet: buildEnterpriseAddress(registry.operatorPkh, network as any, false),
        }) + '\n');
    } catch (e) {
        log(`Watch failed: ${e} — recovery state preserved at ${RECOVERY_FILE}`);
        throw e;
    }
}

// ── Entry ───────────────────────────────────────────────────────────

const args = parseArgs();

switch (args.command) {
    case 'request':
        cmdRequest(args).catch((err) => {
            fatal(String(err));
        });
        break;
    default:
        fatal(`Unknown command: ${args.command}`);
}
