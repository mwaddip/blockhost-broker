import {
    AddressTypes,
    Mnemonic,
    MLDSASecurityLevel,
    FundingTransaction,
} from '@btc-vision/transaction';
import { JSONRpcProvider } from 'opnet';
import { networks } from '@btc-vision/bitcoin';

const RPC_URL = process.env.OPNET_RPC_URL ?? 'https://regtest.opnet.org';
const network = RPC_URL.includes('mainnet')
    ? networks.bitcoin
    : RPC_URL.includes('testnet')
      ? networks.opnetTestnet
      : networks.regtest;

const MNEMONIC = process.env.OPNET_OPERATOR_MNEMONIC;
if (!MNEMONIC) {
    console.error('Set OPNET_OPERATOR_MNEMONIC environment variable');
    process.exit(1);
}

async function main(): Promise<void> {
    const provider = new JSONRpcProvider({ url: RPC_URL, network });

    const mnemonic = new Mnemonic(MNEMONIC, '', network, MLDSASecurityLevel.LEVEL2);

    // Source: wrong derivation path where funds landed
    const srcWallet = mnemonic.derive(0, 0, false);
    // Destination: correct deriveOPWallet path
    const dstWallet = mnemonic.deriveOPWallet(AddressTypes.P2TR, 0);

    console.log('Source:', srcWallet.p2tr);
    console.log('Destination:', dstWallet.p2tr);

    const balance = await provider.getBalance(srcWallet.p2tr, true);
    console.log('Source balance:', balance.toString(), 'sats');

    if (balance === 0n) {
        console.error('No funds to sweep');
        await provider.close();
        process.exit(1);
    }

    const utxos = await provider.utxoManager.getUTXOs({
        address: srcWallet.p2tr,
    });
    console.log('UTXOs:', utxos.length);

    const tx = new FundingTransaction({
        from: srcWallet.p2tr,
        to: dstWallet.p2tr,
        utxos: utxos,
        signer: srcWallet.keypair,
        mldsaSigner: srcWallet.mldsaKeypair,
        network: network,
        feeRate: 15,
        priorityFee: 0n,
        gasSatFee: 0n,
        amount: balance,
        autoAdjustAmount: true,
        linkMLDSAPublicKeyToAddress: true,
        revealMLDSAPublicKey: true,
    });

    const signed = await tx.signTransaction();
    const hex = signed.toHex();

    console.log('Broadcasting...');
    const result = await provider.sendRawTransaction(hex);
    console.log('Result:', JSON.stringify(result));

    console.log('Sweep complete!');
    await provider.close();
}

main().catch((err) => {
    console.error('Sweep failed:', err);
    process.exit(1);
});
