/**
 * Adapter configuration, loaded from environment variables.
 * Same pattern as the OPNet adapter.
 */

export interface AdapterConfig {
    koiosUrl: string;
    blockfrostApiKey: string | null;
    operatorMnemonic: string;
    eciesPrivateKey: string;
    validatorAddress: string;
    beaconPolicyId: string;
    registryAddress: string;
    brokerApiUrl: string;
    source: string;
    leaseDuration: number;
    pollIntervalMs: number;
    scriptsPath: string;
    stateFile: string;
    network: string;
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
    const network = requireEnv('CARDANO_NETWORK', 'preprod');

    return {
        koiosUrl: requireEnv('KOIOS_URL', `https://${network}.koios.rest/api/v1`),
        blockfrostApiKey: process.env['BLOCKFROST_API_KEY'] || null,
        operatorMnemonic: requireEnv('OPERATOR_MNEMONIC'),
        eciesPrivateKey: requireEnv('ECIES_PRIVATE_KEY'),
        validatorAddress: requireEnv('VALIDATOR_ADDRESS'),
        beaconPolicyId: requireEnv('BEACON_POLICY_ID'),
        registryAddress: requireEnv('REGISTRY_ADDRESS'),
        brokerApiUrl: requireEnv('BROKER_API_URL', 'http://127.0.0.1:8080'),
        source: requireEnv('ADAPTER_SOURCE', `cardano-${network}`),
        leaseDuration: parseInt(requireEnv('LEASE_DURATION', '0'), 10),
        pollIntervalMs: parseInt(requireEnv('POLL_INTERVAL_MS', '20000'), 10),
        scriptsPath: requireEnv(
            'SCRIPTS_PATH',
            '/opt/blockhost/adapters/cardano/contracts/parameterized-scripts.json',
        ),
        stateFile: requireEnv(
            'STATE_FILE',
            `/var/lib/blockhost-broker/adapter-cardano-${network}.state`,
        ),
        network,
    };
}
