/**
 * Blockhost Ergo adapter — server-side.
 *
 * Polls for request boxes at the guard script address,
 * decrypts the payload, requests an allocation from the broker
 * REST API, encrypts the response, and submits a response
 * transaction on Ergo.
 */

import * as fs from 'node:fs';
import { loadConfig } from './config.js';
import { EciesEncryption, serializeResponse, type ResponsePayload } from '../../../_shared/src/adapter-crypto.js';
import { requestAllocation, type AllocationResponse } from '../../../_shared/src/broker-api.js';
import { RequestPoller, type RequestBox } from './poller.js';
import { ResponseTxBuilder } from './tx-builder.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { p2pkAddress } from '../../contracts/contracts.js';

const config = loadConfig();

// ── Persistent state ─────────────────────────────────────────────────

interface AdapterState {
    processedBeacons: string[];
}

function loadState(): Set<string> {
    try {
        const data = JSON.parse(fs.readFileSync(config.stateFile, 'utf-8')) as AdapterState;
        const beacons = new Set(data.processedBeacons);
        console.log(`[state] Loaded ${beacons.size} processed beacons from ${config.stateFile}`);
        return beacons;
    } catch {
        console.log(`[state] No state file found, starting fresh`);
        return new Set();
    }
}

function saveState(processedBeacons: Set<string>): void {
    const dir = config.stateFile.substring(0, config.stateFile.lastIndexOf('/'));
    fs.mkdirSync(dir, { recursive: true });
    const data: AdapterState = { processedBeacons: [...processedBeacons] };
    fs.writeFileSync(config.stateFile, JSON.stringify(data) + '\n');
}

// ── Request handler ─────────────────────────────────────────────────

const encryption = new EciesEncryption(config.eciesPrivateKey);

async function handleNewRequests(requests: RequestBox[]): Promise<void> {
    for (const req of requests) {
        console.log(`[adapter] New request, beacon=${req.beaconTokenId.slice(0, 16)}...`);

        // Decrypt the payload
        let payload;
        try {
            payload = encryption.decryptRequestPayload(req.encryptedPayloadHex);
        } catch (err) {
            console.error(`[adapter] Failed to decrypt request:`, err);
            continue;
        }

        console.log(`[adapter] Request: wgPubkey=${payload.wgPubkey.slice(0, 20)}...`);

        // Request allocation from broker
        let allocation: AllocationResponse;
        try {
            allocation = await requestAllocation(payload.wgPubkey, req.nftContract, {
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
            const txId = await txBuilder.submitResponse(req, encryptedResponse);
            console.log(`[adapter] Response delivered: ${txId}`);
        } catch (err) {
            console.error(`[adapter] Delivery failed:`, err);
        }
    }
}

// ── Main ────────────────────────────────────────────────────────────

const isMainnet = config.network === 'mainnet';
const operatorPrivKeyBytes = Uint8Array.from(Buffer.from(config.operatorPrivateKey, 'hex'));
const operatorPubkeyHex = Buffer.from(
    secp256k1.getPublicKey(operatorPrivKeyBytes, true),
).toString('hex');
const operatorAddress = p2pkAddress(operatorPubkeyHex, isMainnet);

const txBuilder = new ResponseTxBuilder(
    config.explorerUrl,
    config.relayUrl,
    operatorAddress,
    config.operatorPrivateKey,
    config.guardAddress,
);

const poller = new RequestPoller(
    config.explorerUrl,
    config.guardAddress,
    handleNewRequests,
    (processedBeacons) => {
        saveState(processedBeacons);
        console.log(`[state] Saved ${processedBeacons.size} processed beacons`);
    },
);

async function main(): Promise<void> {
    console.log(`[adapter] Ergo adapter starting`);
    console.log(`[adapter] Operator: ${operatorAddress}`);
    console.log(`[adapter] Guard: ${config.guardAddress}`);
    console.log(`[adapter] ECIES pubkey: ${encryption.publicKeyHex().slice(0, 20)}...`);
    console.log(`[adapter] Broker API: ${config.brokerApiUrl}`);
    console.log(`[adapter] Source: ${config.source}`);
    console.log(`[adapter] Network: ${config.network}`);

    const beacons = loadState();
    if (beacons.size > 0) {
        poller.setProcessedBeacons(beacons);
    }

    poller.start(config.pollIntervalMs);

    const shutdown = () => {
        console.log('[adapter] Shutting down...');
        poller.stop();
        process.exit(0);
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
}

main().catch((err) => {
    console.error('[adapter] Fatal error:', err);
    process.exit(1);
});
