// Shim for bip39 — maps to @scure/bip39 (English-only, ~350KB smaller).
// The OPNet SDK's Mnemonic class uses validateMnemonic, mnemonicToSeedSync, generateMnemonic.
import { validateMnemonic as _validate, mnemonicToSeedSync as _seedSync, generateMnemonic as _generate } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

export function validateMnemonic(mnemonic: string): boolean {
    return _validate(mnemonic, wordlist);
}

export function mnemonicToSeedSync(mnemonic: string, passphrase?: string): Uint8Array {
    return _seedSync(mnemonic, passphrase);
}

export function generateMnemonic(strength?: number): string {
    return _generate(wordlist, strength);
}
