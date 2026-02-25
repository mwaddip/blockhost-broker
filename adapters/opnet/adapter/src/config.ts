import { networks, type Network } from '@btc-vision/bitcoin';

export interface AdapterConfig {
    /** OPNet JSON-RPC URL */
    rpcUrl: string;
    /** Bitcoin network */
    network: Network;
    /** BrokerRequests contract tweaked pubkey (0x-prefixed) */
    requestsContractPubkey: string;
    /** Operator mnemonic (deploys BrokerRequests, signs responses) */
    operatorMnemonic: string;
    /** Broker ECIES private key (hex, for decrypting request payloads) */
    eciesPrivateKey: string;
    /** Broker HTTP API base URL */
    brokerApiUrl: string;
    /** Adapter source identifier (e.g. "opnet-regtest") */
    source: string;
}

export function loadConfig(): AdapterConfig {
    const rpcUrl = requireEnv('OPNET_RPC_URL', 'https://regtest.opnet.org');
    const networkName = rpcUrl.includes('mainnet')
        ? 'mainnet'
        : rpcUrl.includes('testnet')
          ? 'testnet'
          : 'regtest';
    const network = networkName === 'mainnet'
        ? networks.bitcoin
        : networkName === 'testnet'
          ? networks.opnetTestnet
          : networks.regtest;

    return {
        rpcUrl,
        network,
        requestsContractPubkey: requireEnv('OPNET_BROKER_REQUESTS_PUBKEY'),
        operatorMnemonic: requireEnv('OPNET_OPERATOR_MNEMONIC'),
        eciesPrivateKey: requireEnv('BROKER_ECIES_PRIVATE_KEY'),
        brokerApiUrl: requireEnv('BROKER_API_URL', 'http://127.0.0.1:8080'),
        source: requireEnv('ADAPTER_SOURCE', `opnet-${networkName}`),
    };
}

function requireEnv(name: string, fallback?: string): string {
    const val = process.env[name] ?? fallback;
    if (!val) {
        console.error(`Missing required environment variable: ${name}`);
        process.exit(1);
    }
    return val;
}
