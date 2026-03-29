/**
 * Adapter configuration — loaded from environment variables.
 * Same pattern as the Cardano adapter config.
 */

export interface AdapterConfig {
    explorerUrl: string;
    relayUrl: string;
    operatorPrivateKey: string;
    eciesPrivateKey: string;
    guardAddress: string;
    registryNftId: string;
    brokerApiUrl: string;
    source: string;
    leaseDuration: number;
    pollIntervalMs: number;
    stateFile: string;
    network: 'testnet' | 'mainnet';
}

function requireEnv(name: string, fallback?: string): string {
    const val = process.env[name] ?? fallback;
    if (!val) {
        console.error(`Missing required environment variable: ${name}`);
        process.exit(1);
    }
    return val;
}

export function loadConfig(): AdapterConfig {
    const network = requireEnv('ERGO_NETWORK', 'testnet') as 'testnet' | 'mainnet';
    const explorerBase = network === 'mainnet'
        ? 'https://api.ergoplatform.com'
        : 'https://api-testnet.ergoplatform.com';

    return {
        explorerUrl: requireEnv('EXPLORER_URL', explorerBase),
        relayUrl: requireEnv('RELAY_URL', 'http://127.0.0.1:9064'),
        operatorPrivateKey: requireEnv('OPERATOR_PRIVATE_KEY'),
        eciesPrivateKey: requireEnv('ECIES_PRIVATE_KEY'),
        guardAddress: requireEnv('GUARD_ADDRESS'),
        registryNftId: requireEnv('REGISTRY_NFT_ID'),
        brokerApiUrl: requireEnv('BROKER_API_URL', 'http://127.0.0.1:8080'),
        source: requireEnv('ADAPTER_SOURCE', `ergo-${network}`),
        leaseDuration: parseInt(requireEnv('LEASE_DURATION', '0'), 10),
        pollIntervalMs: parseInt(requireEnv('POLL_INTERVAL_MS', '15000'), 10),
        stateFile: requireEnv(
            'STATE_FILE',
            `/var/lib/blockhost-broker/adapter-ergo-${network}.state`,
        ),
        network,
    };
}
