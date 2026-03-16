import {
    AddressTypes,
    Mnemonic,
    MLDSASecurityLevel,
    Address,
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
import { networks } from '@btc-vision/bitcoin';

const BrokerRegistryAbi = [
    {
        name: 'registerBroker',
        inputs: [
            { name: 'operator', type: ABIDataTypes.ADDRESS },
            { name: 'requestsContract', type: ABIDataTypes.ADDRESS },
            { name: 'encryptionPubkey', type: ABIDataTypes.STRING },
            { name: 'region', type: ABIDataTypes.STRING },
        ],
        outputs: [{ name: 'brokerId', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function,
    },
    ...OP_NET_ABI,
];

interface IBrokerRegistry extends IOP_NETContract {
    registerBroker(
        operator: Address,
        requestsContract: Address,
        encryptionPubkey: string,
        region: string,
    ): Promise<CallResult<{ brokerId: bigint }, OPNetEvent<never>[]>>;
}

const RPC_URL = process.env.OPNET_RPC_URL ?? 'https://regtest.opnet.org';
const network = RPC_URL.includes('mainnet')
    ? networks.bitcoin
    : RPC_URL.includes('testnet')
      ? networks.opnetTestnet
      : networks.regtest;

const DEPLOYER_MNEMONIC = process.env.OPNET_DEPLOYER_MNEMONIC;
if (!DEPLOYER_MNEMONIC) {
    console.error('Set OPNET_DEPLOYER_MNEMONIC environment variable');
    process.exit(1);
}

const REGISTRY_PUBKEY = process.env.OPNET_BROKER_REGISTRY_PUBKEY;
if (!REGISTRY_PUBKEY) {
    console.error('Set OPNET_BROKER_REGISTRY_PUBKEY environment variable');
    process.exit(1);
}

const OPERATOR_ADDRESS = process.env.OPNET_OPERATOR_ADDRESS;
if (!OPERATOR_ADDRESS) {
    console.error('Set OPNET_OPERATOR_ADDRESS environment variable');
    process.exit(1);
}

const REQUESTS_PUBKEY = process.env.OPNET_BROKER_REQUESTS_PUBKEY;
if (!REQUESTS_PUBKEY) {
    console.error('Set OPNET_BROKER_REQUESTS_PUBKEY environment variable');
    process.exit(1);
}

// Broker's ECIES secp256k1 public key (compressed, hex)
const ENCRYPTION_PUBKEY = '02eac77a552ada6c01a25f0a995f8c5d813ff95a27d141de4f30c611f8202e7ead';

const REGION = 'eu-west';

const MAX_SAT_TO_SPEND = 100_000n;

async function main(): Promise<void> {
    const provider = new JSONRpcProvider({ url: RPC_URL, network });

    // Deployer owns the registry
    const mnemonic = new Mnemonic(
        DEPLOYER_MNEMONIC,
        '',
        network,
        MLDSASecurityLevel.LEVEL2,
    );
    const wallet = mnemonic.deriveOPWallet(AddressTypes.P2TR, 0);

    console.log('Deployer:', wallet.p2tr);
    console.log('Deployer OPNet addr:', wallet.address.toHex());

    // Resolve operator address — need tweaked pubkey from the operator wallet
    const operatorMnemonic = process.env.OPNET_OPERATOR_MNEMONIC;
    if (!operatorMnemonic) {
        console.error('Set OPNET_OPERATOR_MNEMONIC environment variable');
        await provider.close();
        process.exit(1);
    }
    const opMnemonic = new Mnemonic(operatorMnemonic, '', network, MLDSASecurityLevel.LEVEL2);
    const opWallet = opMnemonic.deriveOPWallet(AddressTypes.P2TR, 0);

    const operatorAddr = Address.fromString(
        OPERATOR_ADDRESS,
        opWallet.address.tweakedToHex(),
    );
    console.log('Operator addr:', operatorAddr.toHex());

    // Resolve requests contract address (contracts don't have tweaked pubkeys — use pubkey directly)
    const requestsAddr = Address.fromString(REQUESTS_PUBKEY);
    console.log('Requests contract addr:', requestsAddr.toHex());

    // Get registry contract
    const registry = getContract<IBrokerRegistry>(
        REGISTRY_PUBKEY,
        BrokerRegistryAbi,
        provider,
        network,
        wallet.address,
    );

    console.log('Simulating registerBroker...');
    const sim = await registry.registerBroker(
        operatorAddr,
        requestsAddr,
        ENCRYPTION_PUBKEY,
        REGION,
    );

    if ('error' in sim) {
        console.error('Simulation failed:', sim.error);
        await provider.close();
        process.exit(1);
    }

    console.log('Simulation OK, brokerId:', sim.properties.brokerId.toString());

    console.log('Sending transaction...');
    const result = await sim.sendTransaction({
        signer: wallet.keypair,
        mldsaSigner: wallet.mldsaKeypair,
        refundTo: wallet.p2tr,
        maximumAllowedSatToSpend: MAX_SAT_TO_SPEND,
        network,
    });

    console.log('Transaction result:', JSON.stringify(result));
    console.log('\nBroker registered!');

    await provider.close();
}

main().catch((err) => {
    console.error('Registration failed:', err);
    process.exit(1);
});
