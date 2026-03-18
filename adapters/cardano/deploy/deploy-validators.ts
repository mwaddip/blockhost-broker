/**
 * Deploy broker validators to Cardano preprod.
 *
 * Reads compiled scripts from ../contracts/plutus.json,
 * parameterizes them with the operator's pubkey hash,
 * and outputs the derived addresses and policy IDs.
 *
 * Environment:
 *   SIGNING_KEY       - Operator ed25519 signing key (hex)
 *
 * Usage:
 *   SIGNING_KEY=... npx tsx deploy-validators.ts
 */

import { readFileSync } from 'node:fs';
import {
    applyParamsToScript,
    resolveScriptHash,
    resolvePaymentKeyHash,
    serializePlutusScript,
} from '@meshsdk/core';

const SIGNING_KEY = process.env['SIGNING_KEY'];

if (!SIGNING_KEY) {
    console.error('Missing SIGNING_KEY env var');
    process.exit(1);
}

// Load blueprint
const blueprint = JSON.parse(
    readFileSync(new URL('../contracts/plutus.json', import.meta.url), 'utf-8'),
);

const registryValidator = blueprint.validators.find(
    (v: any) => v.title === 'registry.registry.spend',
);
const brokerValidator = blueprint.validators.find(
    (v: any) => v.title === 'broker.broker.spend',
);
const beaconValidator = blueprint.validators.find(
    (v: any) => v.title === 'beacon.beacon.mint',
);

if (!registryValidator || !brokerValidator || !beaconValidator) {
    throw new Error('Missing validators in blueprint');
}

const operatorPkh = resolvePaymentKeyHash(SIGNING_KEY);
console.log(`Operator PKH: ${operatorPkh}`);

// 1. Registry — no params
const registryInfo = serializePlutusScript(
    { code: registryValidator.compiledCode, version: 'V3' },
    undefined,
    0, // preprod = 0
);
console.log(`\nRegistry validator:`);
console.log(`  Hash:    ${registryValidator.hash}`);
console.log(`  Address: ${registryInfo.address}`);

// 2. Broker — param: operator_pkh only (no circular dep)
const brokerCbor = applyParamsToScript(brokerValidator.compiledCode, [operatorPkh]);
const brokerHash = resolveScriptHash(brokerCbor, 'V3');
const brokerInfo = serializePlutusScript(
    { code: brokerCbor, version: 'V3' },
    undefined,
    0,
);
console.log(`\nBroker validator:`);
console.log(`  Hash:    ${brokerHash}`);
console.log(`  Address: ${brokerInfo.address}`);

// 3. Beacon — params: (broker_hash, operator_pkh)
const beaconCbor = applyParamsToScript(beaconValidator.compiledCode, [
    brokerHash,
    operatorPkh,
]);
const beaconPolicyId = resolveScriptHash(beaconCbor, 'V3');
console.log(`\nBeacon minting policy:`);
console.log(`  Policy ID: ${beaconPolicyId}`);

// Output summary for registry config
console.log(`\n--- Registry config (registry-cardano-preprod.json) ---`);
console.log(JSON.stringify({
    registry_address: registryInfo.address,
    broker_address: brokerInfo.address,
    beacon_policy_id: beaconPolicyId,
    operator_pkh: operatorPkh,
    network: 'cardano-preprod',
}, null, 2));
