/**
 * Deploy broker validators to Cardano preprod.
 *
 * Parameterizes the Aiken-compiled scripts and outputs addresses/policy IDs.
 * Also creates the registry reference UTXO with broker info.
 *
 * Environment:
 *   OPERATOR_MNEMONIC  - Operator wallet mnemonic (24 words)
 *   ECIES_PRIVATE_KEY  - Broker ECIES private key (hex)
 */

import { readFileSync } from 'node:fs';
import {
    MeshWallet,
    Transaction,
    applyParamsToScript,
    resolveScriptHash,
    resolvePaymentKeyHash,
    serializePlutusScript,
} from '@meshsdk/core';
import { KoiosProvider } from '@meshsdk/provider';

const OPERATOR_MNEMONIC = process.env.OPERATOR_MNEMONIC;
const ECIES_PRIVATE_KEY = process.env.ECIES_PRIVATE_KEY;

if (!OPERATOR_MNEMONIC) { console.error('Missing OPERATOR_MNEMONIC'); process.exit(1); }
if (!ECIES_PRIVATE_KEY) { console.error('Missing ECIES_PRIVATE_KEY'); process.exit(1); }

// Load blueprint
const blueprint = JSON.parse(
    readFileSync(new URL('../contracts/plutus.json', import.meta.url), 'utf-8'),
);

const registryRaw = blueprint.validators.find((v: any) => v.title === 'registry.registry.spend');
const brokerRaw = blueprint.validators.find((v: any) => v.title === 'broker.broker.spend');
const beaconRaw = blueprint.validators.find((v: any) => v.title === 'beacon.beacon.mint');

if (!registryRaw || !brokerRaw || !beaconRaw) {
    throw new Error('Missing validators in blueprint');
}

// Provider + wallet
const provider = new KoiosProvider('preprod');
const wallet = new MeshWallet({
    networkId: 0,
    fetcher: provider,
    submitter: provider,
    key: { type: 'mnemonic', words: OPERATOR_MNEMONIC.split(' ') },
});

const operatorAddress = wallet.getChangeAddress();
const operatorPkh = resolvePaymentKeyHash(operatorAddress);

console.log('Operator address:', operatorAddress);
console.log('Operator PKH:', operatorPkh);

// Derive ECIES public key
import { secp256k1 } from '@noble/curves/secp256k1.js';
const eciesPriv = Buffer.from(ECIES_PRIVATE_KEY.startsWith('0x') ? ECIES_PRIVATE_KEY.slice(2) : ECIES_PRIVATE_KEY, 'hex');
const eciesPubkey = Buffer.from(secp256k1.getPublicKey(eciesPriv, true)).toString('hex'); // compressed
console.log('ECIES pubkey (compressed):', eciesPubkey);

// === 1. Registry validator (no params) ===
const registryScript = { code: registryRaw.compiledCode, version: 'V3' as const };
const registryInfo = serializePlutusScript(registryScript, undefined, 0);
console.log('\nRegistry:');
console.log('  Hash:', registryRaw.hash);
console.log('  Address:', registryInfo.address);

// === 2. Broker validator (param: operator_pkh) ===
const brokerCbor = applyParamsToScript(brokerRaw.compiledCode, [operatorPkh]);
const brokerHash = resolveScriptHash(brokerCbor, 'V3');
const brokerScript = { code: brokerCbor, version: 'V3' as const };
const brokerInfo = serializePlutusScript(brokerScript, undefined, 0);
console.log('\nBroker:');
console.log('  Hash:', brokerHash);
console.log('  Address:', brokerInfo.address);

// === 3. Beacon minting policy (params: broker_hash, operator_pkh) ===
const beaconCbor = applyParamsToScript(beaconRaw.compiledCode, [brokerHash, operatorPkh]);
const beaconPolicyId = resolveScriptHash(beaconCbor, 'V3');
console.log('\nBeacon:');
console.log('  Policy ID:', beaconPolicyId);

// === Summary ===
const config = {
    registry_address: registryInfo.address,
    broker_address: brokerInfo.address,
    beacon_policy_id: beaconPolicyId,
    operator_pkh: operatorPkh,
    network: 'cardano-preprod',
};
console.log('\n--- registry-cardano-preprod.json ---');
console.log(JSON.stringify(config, null, 2));

// === 4. Create registry reference UTXO ===
const MODE = process.argv[2];
if (MODE !== '--deploy') {
    console.log('\nDry run. Pass --deploy to create the registry UTXO on-chain.');
    process.exit(0);
}

console.log('\n=== Deploying registry UTXO ===');

// Build RegistryDatum
const registryDatum = {
    alternative: 0,
    fields: [
        operatorPkh,
        eciesPubkey,
        0,                                              // capacity_status: available
        Buffer.from('eu-west').toString('hex'),
        brokerHash,                                     // requests_validator_hash
        beaconPolicyId,
    ],
};

const tx = new Transaction({ initiator: wallet });
tx.sendLovelace(
    {
        address: registryInfo.address,
        datum: { inline: true, value: registryDatum },
    },
    '5000000', // 5 ADA for the registry UTXO
);

const unsignedTx = await tx.build();
const signedTx = await wallet.signTx(unsignedTx);
const txHash = await wallet.submitTx(signedTx);
console.log('Registry UTXO created:', txHash);
console.log('\nDone! Update registry-cardano-preprod.json with the values above.');
