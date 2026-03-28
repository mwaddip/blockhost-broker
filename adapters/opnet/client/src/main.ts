/**
 * BlockHost OPNet client — subprocess mode.
 *
 * Submits a request to the BrokerRequests contract, watches for the
 * broker's OP_RETURN response, and outputs the tunnel configuration
 * as a single JSON line to stdout.
 *
 * All progress/status logging goes to stderr.
 *
 * Usage:
 *   npx tsx src/main.ts request \
 *     --rpc-url https://regtest.opnet.org \
 *     --mnemonic "word1 word2 ..." \
 *     --nft-pubkey 0x... \
 *     --registry-pubkey 0x... \
 *     --broker-id 1
 */

import {
    AddressTypes,
    Address,
    MLDSASecurityLevel,
    Mnemonic,
} from '@btc-vision/transaction';
import {
    getContract,
    JSONRpcProvider,
    ABIDataTypes,
    BitcoinAbiTypes,
    OP_NET_ABI,
    type CallResult,
    type OPNetEvent,
    type IOP_NETContract,
} from 'opnet';
import { networks, opcodes, type Network } from '@btc-vision/bitcoin';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import {
    eciesEncrypt,
    decryptCompact,
    deserializeResponse,
    generateWgKeypair,
    generateServerKeypair,
    serverKeypairFromHex,
    serializeRequestPayload,
} from './crypto.js';
import { existsSync, readFileSync, writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

// ── Logging (all to stderr) ─────────────────────────────────────────

function log(msg: string): void {
    process.stderr.write(`[opnet-client] ${msg}\n`);
}

function fatal(msg: string): never {
    process.stderr.write(`[opnet-client] FATAL: ${msg}\n`);
    process.exit(1);
}

// ── Arg parsing ─────────────────────────────────────────────────────

interface Args {
    command: string;
    rpcUrl: string;
    mnemonic: string;
    nftPubkey: string;
    registryPubkey: string;
    brokerId: bigint;
    maxSat: bigint;
    timeoutMs: number;
    serverKey: string | null;
}

function parseArgs(): Args {
    const argv = process.argv.slice(2);
    const command = argv[0];

    if (!command || command === '--help' || command === '-h') {
        process.stderr.write(
            `Usage: npx tsx src/main.ts request [options]\n\n` +
            `Options:\n` +
            `  --rpc-url URL          OPNet RPC URL (default: https://regtest.opnet.org)\n` +
            `  --mnemonic "WORDS"     Client wallet mnemonic\n` +
            `  --nft-pubkey 0x...     NFT contract pubkey\n` +
            `  --registry-pubkey 0x.. BrokerRegistry pubkey\n` +
            `  --broker-id N          Broker ID (default: 1)\n` +
            `  --max-sat N            Max satoshi to spend (default: 100000)\n` +
            `  --timeout N            Response timeout in seconds (default: 1200)\n` +
            `  --server-key 0x...     Persistent ECIES private key hex (optional, generates ephemeral if omitted)\n`,
        );
        process.exit(command ? 0 : 1);
    }

    function getFlag(name: string, fallback?: string): string {
        const idx = argv.indexOf(name);
        if (idx === -1 || idx + 1 >= argv.length) {
            if (fallback !== undefined) return fallback;
            fatal(`Missing required argument: ${name}`);
        }
        return argv[idx + 1];
    }

    function getFlagOptional(name: string): string | null {
        const idx = argv.indexOf(name);
        if (idx === -1 || idx + 1 >= argv.length) return null;
        return argv[idx + 1];
    }

    return {
        command,
        rpcUrl: getFlag('--rpc-url', 'https://regtest.opnet.org'),
        mnemonic: getFlag('--mnemonic'),
        nftPubkey: getFlag('--nft-pubkey'),
        registryPubkey: getFlag('--registry-pubkey'),
        brokerId: BigInt(getFlag('--broker-id', '1')),
        maxSat: BigInt(getFlag('--max-sat', '100000')),
        timeoutMs: Number(getFlag('--timeout', '1200')) * 1000,
        serverKey: getFlagOptional('--server-key'),
    };
}

// ── ABIs ────────────────────────────────────────────────────────────

const BrokerRegistryAbi = [
    {
        name: 'getBroker',
        inputs: [{ name: 'brokerId', type: ABIDataTypes.UINT256 }],
        outputs: [
            { name: 'operator', type: ABIDataTypes.ADDRESS },
            { name: 'requestsContract', type: ABIDataTypes.ADDRESS },
            { name: 'encryptionPubkey', type: ABIDataTypes.STRING },
            { name: 'region', type: ABIDataTypes.STRING },
            { name: 'active', type: ABIDataTypes.BOOL },
            { name: 'registeredAt', type: ABIDataTypes.UINT256 },
        ],
        type: BitcoinAbiTypes.Function as BitcoinAbiTypes.Function,
    },
    ...OP_NET_ABI,
];

interface IBrokerRegistry extends IOP_NETContract {
    getBroker(brokerId: bigint): Promise<
        CallResult<
            {
                operator: Address;
                requestsContract: Address;
                encryptionPubkey: string;
                region: string;
                active: boolean;
                registeredAt: bigint;
            },
            OPNetEvent<never>[]
        >
    >;
}

const BrokerRequestsAbi = [
    {
        name: 'submitRequest',
        inputs: [
            { name: 'nftContract', type: ABIDataTypes.ADDRESS },
            { name: 'encryptedPayload', type: ABIDataTypes.STRING },
        ],
        outputs: [{ name: 'requestId', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function as BitcoinAbiTypes.Function,
    },
    {
        name: 'getCapacityStatus',
        inputs: [],
        outputs: [{ name: 'status', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function as BitcoinAbiTypes.Function,
    },
    ...OP_NET_ABI,
];

interface IBrokerRequests extends IOP_NETContract {
    submitRequest(
        nftContract: Address,
        encryptedPayload: string,
    ): Promise<CallResult<{ requestId: bigint }, OPNetEvent<never>[]>>;
    getCapacityStatus(): Promise<CallResult<{ status: bigint }, OPNetEvent<never>[]>>;
}

// ── Constants ───────────────────────────────────────────────────────

const OP_RETURN_VERSION = 0x01;
const RESPONSE_POLL_MS = 15_000;
const RECOVERY_FILE = '/var/lib/blockhost/opnet-recovery.json';

interface RecoveryState {
    serverPrivkeyHex: string;
    brokerPubkeyHex: string;      // uncompressed, hex
    startBlock: string;           // bigint as string
    wgPrivateKeyBase64: string;
    wgPublicKeyBase64: string;
    brokerWallet: string;
    savedAt: string;
}

// ── Recovery ────────────────────────────────────────────────────────

function saveRecoveryState(
    serverKeys: { privateKey: Uint8Array },
    brokerPubUncompressed: Uint8Array,
    startBlock: bigint,
    wgKeys: { privateKeyBase64: string; publicKeyBase64: string },
    brokerWallet: string,
): void {
    const state: RecoveryState = {
        serverPrivkeyHex: Buffer.from(serverKeys.privateKey).toString('hex'),
        brokerPubkeyHex: Buffer.from(brokerPubUncompressed).toString('hex'),
        startBlock: startBlock.toString(),
        wgPrivateKeyBase64: wgKeys.privateKeyBase64,
        wgPublicKeyBase64: wgKeys.publicKeyBase64,
        brokerWallet,
        savedAt: new Date().toISOString(),
    };
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

async function attemptRecovery(
    provider: JSONRpcProvider,
    state: RecoveryState,
    timeoutMs: number,
): Promise<{ brokerPubkey: string; brokerEndpoint: string; prefix: string; gateway: string; wgPrivateKeyBase64: string; wgPublicKeyBase64: string } | null> {
    log(`Attempting recovery from block ${state.startBlock} (saved ${state.savedAt})`);

    const serverPrivkey = Uint8Array.from(Buffer.from(state.serverPrivkeyHex, 'hex'));
    const brokerPub = Uint8Array.from(Buffer.from(state.brokerPubkeyHex, 'hex'));
    const startBlock = BigInt(state.startBlock);

    try {
        const config = await watchForResponse(
            provider,
            serverPrivkey,
            brokerPub,
            startBlock,
            timeoutMs,
        );
        clearRecoveryState();
        return {
            ...config,
            wgPrivateKeyBase64: state.wgPrivateKeyBase64,
            wgPublicKeyBase64: state.wgPublicKeyBase64,
        };
    } catch {
        log('Recovery scan found no response');
        return null;
    }
}

// ── Request command ─────────────────────────────────────────────────

async function cmdRequest(args: Args): Promise<void> {
    const network: Network = args.rpcUrl.includes('mainnet')
        ? networks.bitcoin
        : args.rpcUrl.includes('testnet')
          ? networks.opnetTestnet
          : networks.regtest;

    const provider = new JSONRpcProvider({ url: args.rpcUrl, network });

    // Check for recovery state from a previous timed-out attempt
    const recovery = loadRecoveryState();
    if (recovery) {
        log('Found recovery state from previous attempt');
        // Quick scan: use a short timeout to check all blocks since the last attempt
        const RECOVERY_TIMEOUT_MS = 60_000;
        const recovered = await attemptRecovery(provider, recovery, RECOVERY_TIMEOUT_MS);
        if (recovered) {
            log('Recovered allocation from previous attempt!');
            const result = {
                prefix: recovered.prefix,
                gateway: recovered.gateway,
                broker_pubkey: recovered.brokerPubkey,
                broker_endpoint: recovered.brokerEndpoint,
                wg_private_key: recovered.wgPrivateKeyBase64,
                wg_public_key: recovered.wgPublicKeyBase64,
                broker_wallet: recovery.brokerWallet,
            };
            process.stdout.write(JSON.stringify(result) + '\n');
            await provider.close();
            return;
        }
        // No response found — clear stale state and proceed with a fresh request
        clearRecoveryState();
        log('Proceeding with fresh request');
    }

    // Derive client wallet
    const mnemonic = new Mnemonic(args.mnemonic, '', network, MLDSASecurityLevel.LEVEL2);
    const wallet = mnemonic.deriveOPWallet(AddressTypes.P2TR, 0);
    log(`Address: ${wallet.p2tr}`);

    // 1. Look up broker
    log(`Looking up broker #${args.brokerId}...`);
    const registry = getContract<IBrokerRegistry>(
        args.registryPubkey,
        BrokerRegistryAbi,
        provider,
        network,
    );

    const brokerResult = await registry.getBroker(args.brokerId);
    if ('error' in brokerResult) {
        throw new Error(`getBroker failed: ${brokerResult.error}`);
    }

    const broker = brokerResult.properties;
    if (!broker.active) {
        throw new Error('Broker is not active');
    }

    const encryptionPubkey = broker.encryptionPubkey;
    const requestsContractPubkey = broker.requestsContract.toHex();

    log(`Broker region: ${broker.region}`);
    log(`Requests contract: ${requestsContractPubkey.slice(0, 20)}...`);

    // 2. Check capacity
    const requests = getContract<IBrokerRequests>(
        requestsContractPubkey,
        BrokerRequestsAbi,
        provider,
        network,
        wallet.address,
    );

    const capResult = await requests.getCapacityStatus();
    if ('error' in capResult) {
        throw new Error(`getCapacityStatus failed: ${capResult.error}`);
    }
    const capacity = capResult.properties.status;
    if (capacity === 2n) {
        throw new Error('Broker capacity is closed');
    }
    if (capacity === 1n) {
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

    const brokerPubBytes = Buffer.from(encryptionPubkey, 'hex');
    const brokerPubUncompressed =
        brokerPubBytes.length === 33
            ? secp256k1Point(brokerPubBytes)
            : brokerPubBytes;

    const encrypted = eciesEncrypt(payload, brokerPubUncompressed);
    const encryptedB64 = Buffer.from(encrypted).toString('base64');

    log(`Encrypted payload: ${encrypted.length} bytes (${encryptedB64.length} chars base64)`);

    // 5. Submit request
    const nftAddr = Address.fromString(args.nftPubkey);

    log('Simulating submitRequest...');
    const sim = await requests.submitRequest(nftAddr, encryptedB64);
    if ('error' in sim) {
        throw new Error(`submitRequest simulation failed: ${sim.error}`);
    }

    log(`Simulation OK, requestId: ${sim.properties.requestId}`);

    log('Sending transaction...');
    const txResult = await sim.sendTransaction({
        signer: wallet.keypair,
        mldsaSigner: wallet.mldsaKeypair,
        refundTo: wallet.p2tr,
        maximumAllowedSatToSpend: args.maxSat,
        network,
    });

    log(`Request submitted: txid=${txResult.transactionId}`);

    // 6. Watch for OP_RETURN response
    const startBlock = await provider.getBlockNumber();
    log(`Watching for response from block ${startBlock}...`);

    // Save recovery state so a retry can find the response if we time out
    saveRecoveryState(serverKeys, brokerPubUncompressed, startBlock, wgKeys, broker.operator.toHex());

    try {
        const config = await watchForResponse(
            provider,
            serverKeys.privateKey,
            brokerPubUncompressed,
            startBlock,
            args.timeoutMs,
        );

        clearRecoveryState();

        // 7. Output result as JSON to stdout
        const result = {
            prefix: config.prefix,
            gateway: config.gateway,
            broker_pubkey: config.brokerPubkey,
            broker_endpoint: config.brokerEndpoint,
            wg_private_key: wgKeys.privateKeyBase64,
            wg_public_key: wgKeys.publicKeyBase64,
            broker_wallet: broker.operator.toHex(),
        };

        process.stdout.write(JSON.stringify(result) + '\n');
    } catch (e) {
        // On timeout, leave recovery file in place for next attempt
        log(`Watch failed: ${e} — recovery state preserved at ${RECOVERY_FILE}`);
        throw e;
    }

    await provider.close();
}

// ── OP_RETURN watcher ───────────────────────────────────────────────

/** Wrap a promise with a hard timeout to guard against SDK connection stalls. */
function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
    return new Promise<T>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
        promise.then(
            (v) => { clearTimeout(timer); resolve(v); },
            (e) => { clearTimeout(timer); reject(e); },
        );
    });
}

const RPC_CALL_TIMEOUT_MS = 30_000;

async function watchForResponse(
    provider: JSONRpcProvider,
    serverPrivkey: Uint8Array,
    brokerPubkey: Uint8Array,
    startBlock: bigint,
    timeoutMs: number,
): Promise<{ brokerPubkey: string; brokerEndpoint: string; prefix: string; gateway: string }> {
    log(`watchForResponse: timeout=${timeoutMs}ms (${timeoutMs/1000}s), startBlock=${startBlock}`);
    const deadline = Date.now() + timeoutMs;
    let lastCheckedBlock = startBlock - 1n;

    while (Date.now() < deadline) {
        let currentHeight: bigint;
        try {
            currentHeight = await withTimeout(
                provider.getBlockNumber(),
                RPC_CALL_TIMEOUT_MS,
                'getBlockNumber',
            );
        } catch (e) {
            log(`getBlockNumber failed, will retry: ${e}`);
            await new Promise((resolve) => setTimeout(resolve, RESPONSE_POLL_MS));
            continue;
        }

        for (let h = lastCheckedBlock + 1n; h <= currentHeight; h++) {
            let block;
            try {
                block = await withTimeout(
                    provider.getBlock(h, true),
                    RPC_CALL_TIMEOUT_MS,
                    `getBlock(${h})`,
                );
            } catch (e) {
                log(`Block ${h} not yet available, will retry: ${e}`);
                break; // stop advancing lastCheckedBlock; retry this height next cycle
            }
            const txs = block.transactions;
            log(`Scanning block ${h}: ${txs.length} txs`);

            for (const tx of txs) {
                for (const output of tx.outputs) {
                    if (output.value !== 0n) continue;
                    if (!output.script || output.script.length < 2) continue;
                    if (output.script[0] !== opcodes.OP_RETURN) continue;

                    const data = output.script[1];
                    if (!(data instanceof Uint8Array)) continue;
                    if (data.length < 2) continue;
                    if (data[0] !== OP_RETURN_VERSION) continue;

                    const encrypted = data.slice(1);
                    try {
                        const plaintext = decryptCompact(
                            encrypted,
                            serverPrivkey,
                            brokerPubkey,
                        );
                        log(`Response found in block ${h}, tx ${tx.id ?? 'unknown'}`);
                        return deserializeResponse(plaintext);
                    } catch (e) {
                        log(`  OP_RETURN v1 decrypt failed (len=${data.length}): ${e}`);
                    }
                }
            }

            lastCheckedBlock = h;
        }

        await new Promise((resolve) => setTimeout(resolve, RESPONSE_POLL_MS));
    }

    throw new Error('Timed out waiting for broker response');
}

// ── Helpers ─────────────────────────────────────────────────────────

function secp256k1Point(compressed: Uint8Array): Uint8Array {
    const point = secp256k1.ProjectivePoint.fromHex(compressed);
    return point.toRawBytes(false);
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
