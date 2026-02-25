/**
 * OPNet key utility — derive deployer address from mnemonic,
 * generate new operator mnemonic + address.
 *
 * Usage:
 *   node keygen.mjs derive <mnemonic>     — show address for existing mnemonic
 *   node keygen.mjs generate              — generate new mnemonic + address
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);

const { Mnemonic, MnemonicStrength, AddressTypes } = require('./broker-requests/node_modules/@btc-vision/transaction');
const { networks } = require('./broker-requests/node_modules/@btc-vision/bitcoin');

const network = networks.regtest;

function showWallet(label, mnemonic) {
    const wallet = mnemonic.deriveOPWallet(AddressTypes.P2TR, 0);
    console.log(`\n=== ${label} ===`);
    console.log(`Mnemonic:    ${mnemonic.phrase}`);
    console.log(`OPNet addr:  ${wallet.address.toHex()}`);
    console.log(`P2TR:        ${wallet.p2tr}`);
    console.log(`P2WPKH:      ${wallet.p2wpkh}`);
    console.log(`Tweaked pub: ${wallet.address.tweakedToHex()}`);
}

const cmd = process.argv[2];

if (cmd === 'derive') {
    const phrase = process.argv.slice(3).join(' ');
    if (!phrase) {
        console.error('Usage: node keygen.mjs derive <mnemonic words>');
        process.exit(1);
    }
    const mnemonic = new Mnemonic(phrase, '', network);
    showWallet('Derived Wallet', mnemonic);
} else if (cmd === 'generate') {
    const mnemonic = Mnemonic.generate(MnemonicStrength.MAXIMUM, '', network);
    showWallet('Generated Wallet', mnemonic);
} else {
    console.log('Usage:');
    console.log('  node keygen.mjs derive <mnemonic words>');
    console.log('  node keygen.mjs generate');
}
