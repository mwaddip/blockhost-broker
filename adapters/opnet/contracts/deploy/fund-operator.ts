import {
    AddressTypes,
    Mnemonic,
    MLDSASecurityLevel,
    FundingTransaction,
} from '@btc-vision/transaction';
import { JSONRpcProvider } from 'opnet';
import { networks } from '@btc-vision/bitcoin';

// Send this many sats from deployer → operator
const AMOUNT_SATS = 500_000n;

const RPC_URL = process.env.OPNET_RPC_URL ?? 'https://testnet.opnet.org';
const network = RPC_URL.includes('mainnet')
    ? networks.bitcoin
    : RPC_URL.includes('testnet')
      ? networks.opnetTestnet
      : networks.regtest;

const DEPLOYER_MNEMONIC = process.env.OPNET_DEPLOYER_MNEMONIC;
const OPERATOR_MNEMONIC = process.env.OPNET_OPERATOR_MNEMONIC;

if (!DEPLOYER_MNEMONIC || !OPERATOR_MNEMONIC) {
    console.error('Set OPNET_DEPLOYER_MNEMONIC and OPNET_OPERATOR_MNEMONIC');
    process.exit(1);
}

async function main(): Promise<void> {
    const provider = new JSONRpcProvider({ url: RPC_URL, network });

    const deployerMnemonic = new Mnemonic(DEPLOYER_MNEMONIC, '', network, MLDSASecurityLevel.LEVEL2);
    const deployer = deployerMnemonic.deriveOPWallet(AddressTypes.P2TR, 0);

    const operatorMnemonic = new Mnemonic(OPERATOR_MNEMONIC, '', network, MLDSASecurityLevel.LEVEL2);
    const operator = operatorMnemonic.deriveOPWallet(AddressTypes.P2TR, 0);

    console.log('From (deployer):', deployer.p2tr);
    console.log('To   (operator):', operator.p2tr);

    const balance = await provider.getBalance(deployer.p2tr, true);
    console.log('Deployer balance:', balance.toString(), 'sats');

    if (balance < AMOUNT_SATS) {
        console.error(`Insufficient balance: have ${balance}, need ${AMOUNT_SATS}`);
        await provider.close();
        process.exit(1);
    }

    const utxos = await provider.utxoManager.getUTXOs({ address: deployer.p2tr });
    console.log('UTXOs:', utxos.length);

    const tx = new FundingTransaction({
        from: deployer.p2tr,
        to: operator.p2tr,
        utxos,
        signer: deployer.keypair,
        mldsaSigner: deployer.mldsaKeypair,
        network,
        feeRate: 15,
        priorityFee: 0n,
        gasSatFee: 0n,
        amount: AMOUNT_SATS,
        autoAdjustAmount: false,
        linkMLDSAPublicKeyToAddress: true,
        revealMLDSAPublicKey: true,
    });

    const signed = await tx.signTransaction();
    const hex = signed.toHex();

    console.log('Broadcasting...');
    const result = await provider.sendRawTransaction(hex, false);
    console.log('Result:', JSON.stringify(result));
    console.log(`Sent ${AMOUNT_SATS} sats to operator. Deployer retains ~${balance - AMOUNT_SATS} sats (minus fees).`);

    await provider.close();
}

main().catch((err) => {
    console.error('Transfer failed:', err);
    process.exit(1);
});
