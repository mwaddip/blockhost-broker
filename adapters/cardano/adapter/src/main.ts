/**
 * Blockhost Cardano adapter — server-side.
 *
 * Polls for request UTXOs at the broker validator address,
 * decrypts the payload, requests an allocation from the broker
 * REST API, encrypts the response, and submits a response
 * transaction on Cardano.
 *
 * Same architecture as the OPNet adapter.
 */

import * as fs from 'node:fs';
import { loadConfig } from './config.js';
import { EciesEncryption, serializeResponse, type ResponsePayload } from '../../../_shared/src/adapter-crypto.js';
import { requestAllocation, type AllocationResponse } from '../../../_shared/src/broker-api.js';
import { RequestPoller, type RequestUtxo } from './poller.js';
import { ResponseTxBuilder } from './tx-builder.js';
import { Bip32PrivateKey } from 'noble-bip32ed25519';
import { buildBaseAddress } from 'cmttk/address';
import { mnemonicToEntropy } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { Buffer } from 'buffer';

const config = loadConfig();

// ── Persistent state ─────────────────────────────────────────────────

interface AdapterState {
    processedRefs: string[];
}

function loadState(): Set<string> {
    try {
        const data = JSON.parse(fs.readFileSync(config.stateFile, 'utf-8')) as AdapterState;
        const refs = new Set(data.processedRefs);
        console.log(`[state] Loaded ${refs.size} processed refs from ${config.stateFile}`);
        return refs;
    } catch {
        console.log(`[state] No state file found, starting fresh`);
        return new Set();
    }
}

function saveState(processedRefs: Set<string>): void {
    const data: AdapterState = { processedRefs: [...processedRefs] };
    fs.writeFileSync(config.stateFile, JSON.stringify(data) + '\n');
}

// ── Key derivation ──────────────────────────────────────────────────

function deriveOperatorKey(mnemonic: string, network: string): {
    signingKey: ReturnType<ReturnType<typeof Bip32PrivateKey.prototype.derive>['toPrivateKey']>;
    pkh: Buffer;
    addr: string;
} {
    const entropy = mnemonicToEntropy(mnemonic, wordlist);
    const rootKey = Bip32PrivateKey.fromEntropy(entropy);

    // Cardano BIP44: m/1852'/1815'/0'/0/0
    const accountKey = rootKey
        .derive(2147483648 + 1852)
        .derive(2147483648 + 1815)
        .derive(2147483648 + 0);

    const paymentKey = accountKey.derive(0).derive(0);
    const stakeKey = accountKey.derive(2).derive(0);
    const signingKey = paymentKey.toPrivateKey();
    const pkh = Buffer.from(signingKey.toPublicKey().hash());
    const stakePkh = Buffer.from(stakeKey.toPrivateKey().toPublicKey().hash());

    const addr = buildBaseAddress(pkh.toString('hex'), stakePkh.toString('hex'), network as any);

    return { signingKey, pkh, addr };
}

// ── Request handler ─────────────────────────────────────────────────

let txBuilder: ResponseTxBuilder;
const encryption = new EciesEncryption(config.eciesPrivateKey);

async function handleNewRequests(requests: RequestUtxo[]): Promise<void> {
    for (const req of requests) {
        console.log(`[adapter] New request from ${req.clientPkh.slice(0, 16)}... (nft: ${req.nftPolicyId.slice(0, 16)}...)`);

        // Decrypt the payload
        let payload;
        try {
            payload = encryption.decryptRequestPayload(req.encryptedPayload);
        } catch (err) {
            console.error(`[adapter] Failed to decrypt request:`, err);
            continue;
        }

        console.log(`[adapter] Request: wgPubkey=${payload.wgPubkey.slice(0, 20)}...`);

        // Request allocation from broker
        let allocation: AllocationResponse;
        try {
            allocation = await requestAllocation(payload.wgPubkey, req.nftPolicyId, {
                brokerApiUrl: config.brokerApiUrl,
                source: config.source,
                leaseDuration: config.leaseDuration,
            });
        } catch (err) {
            console.error(`[adapter] Allocation failed:`, err);
            continue;
        }

        console.log(`[adapter] Allocated ${allocation.prefix}`);

        // Build and encrypt response
        const response: ResponsePayload = {
            prefix: allocation.prefix,
            gateway: allocation.gateway,
            brokerPubkey: allocation.broker_pubkey,
            brokerEndpoint: allocation.broker_endpoint,
        };

        const binary = serializeResponse(response);
        const encryptedResponse = encryption.encryptResponse(binary, payload.serverPubkey);

        // Submit response transaction
        try {
            const txHash = await txBuilder.submitResponse(req, encryptedResponse);
            console.log(`[adapter] Response delivered: ${txHash}`);
        } catch (err) {
            console.error(`[adapter] Delivery failed:`, err);
        }
    }
}

// ── Main ────────────────────────────────────────────────────────────

async function main(): Promise<void> {
    console.log(`[adapter] Cardano adapter starting`);

    // Derive operator key
    const network = config.network === 'mainnet' ? 'mainnet' : 'preprod';
    const operator = deriveOperatorKey(config.operatorMnemonic, network);
    console.log(`[adapter] Operator: ${operator.addr}`);
    console.log(`[adapter] Operator PKH: ${operator.pkh.toString('hex')}`);

    // Load pre-parameterized scripts
    const scripts = JSON.parse(fs.readFileSync(config.scriptsPath, 'utf-8'));

    // Init tx builder
    txBuilder = new ResponseTxBuilder(
        scripts.broker,
        scripts.beacon,
        operator.signingKey.toBytes(),
        operator.pkh,
        operator.addr,
        network,
        config.koiosUrl,
        config.blockfrostApiKey,
    );

    console.log(`[adapter] Validator: ${config.validatorAddress}`);
    console.log(`[adapter] Beacon policy: ${config.beaconPolicyId}`);
    console.log(`[adapter] ECIES pubkey: ${encryption.publicKeyHex().slice(0, 20)}...`);
    console.log(`[adapter] Broker API: ${config.brokerApiUrl}`);
    console.log(`[adapter] Source: ${config.source}`);
    console.log(`[adapter] Network: ${config.network}`);

    // Restore state from previous run
    const refs = loadState();
    if (refs.size > 0) {
        poller.setProcessedRefs(refs);
    }

    poller.start(config.pollIntervalMs);

    // Graceful shutdown
    const shutdown = () => {
        console.log('[adapter] Shutting down...');
        poller.stop();
        process.exit(0);
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
}

// ── Poller ───────────────────────────────────────────────────────────

const poller = new RequestPoller(
    config.koiosUrl,
    config.blockfrostApiKey,
    config.validatorAddress,
    config.beaconPolicyId,
    handleNewRequests,
    (processedRefs) => {
        saveState(processedRefs);
        console.log(`[state] Saved ${processedRefs.size} processed refs`);
    },
);

main().catch((err) => {
    console.error('[adapter] Fatal error:', err);
    process.exit(1);
});
