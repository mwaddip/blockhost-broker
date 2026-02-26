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

// ── Request command ─────────────────────────────────────────────────

async function cmdRequest(args: Args): Promise<void> {
    const network: Network = args.rpcUrl.includes('mainnet')
        ? networks.bitcoin
        : args.rpcUrl.includes('testnet')
          ? networks.opnetTestnet
          : networks.regtest;

    const provider = new JSONRpcProvider({ url: args.rpcUrl, network });

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

    const config = await watchForResponse(
        provider,
        serverKeys.privateKey,
        brokerPubUncompressed,
        startBlock,
        args.timeoutMs,
    );

    // 7. Output result as JSON to stdout
    const result = {
        prefix: config.prefix,
        gateway: config.gateway,
        broker_pubkey: config.brokerPubkey,
        broker_endpoint: config.brokerEndpoint,
        wg_private_key: wgKeys.privateKeyBase64,
        wg_public_key: wgKeys.publicKeyBase64,
    };

    process.stdout.write(JSON.stringify(result) + '\n');

    await provider.close();
}

// ── OP_RETURN watcher ───────────────────────────────────────────────

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
        const currentHeight = await provider.getBlockNumber();

        for (let h = lastCheckedBlock + 1n; h <= currentHeight; h++) {
            let block;
            try {
                block = await provider.getBlock(h, true);
            } catch (e) {
                log(`Block ${h} not yet available, will retry: ${e}`);
                break; // stop advancing lastCheckedBlock; retry this height next cycle
            }
            const txs = block.transactions;
            log(`Scanning block ${h}: ${txs.length} txs`);

            for (const tx of txs) {
                for (const output of tx.outputs) {
                    log(`  output: value=${output.value} script=${output.script ? JSON.stringify(output.script.map(x => x instanceof Uint8Array ? '[bytes:'+x.length+']' : x)) : null}`);
                    if (output.value !== 0n) continue;
                    if (!output.script || output.script.length < 2) continue;
                    if (output.script[0] !== opcodes.OP_RETURN) continue;

                    const data = output.script[1];
                    log(`  OP_RETURN found: data type=${data?.constructor?.name} len=${data?.length} data[0]=${data?.[0]}`);
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
                        log(`  Decrypt failed: ${e}`);
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
