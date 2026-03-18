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
import { EciesEncryption, serializeResponse, type ResponsePayload } from './crypto.js';
import { RequestPoller, type RequestUtxo } from './poller.js';
import { ResponseTxBuilder } from './tx-builder.js';

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

// ── Services ────────────────────────────────────────────────────────

const encryption = new EciesEncryption(config.eciesPrivateKey);
const txBuilder = new ResponseTxBuilder(
    config.operatorSigningKey,
    config.validatorAddress,
    config.beaconPolicyId,
    config.koiosUrl,
    config.blockfrostApiKey,
    config.network,
);

// ── Broker API client ──────────────────────────────────────────────

interface AllocationResponse {
    prefix: string;
    gateway: string;
    broker_pubkey: string;
    broker_endpoint: string;
}

async function requestAllocation(
    wgPubkey: string,
    nftContract: string,
): Promise<AllocationResponse> {
    const url = `${config.brokerApiUrl}/v1/allocations`;
    const body = JSON.stringify({
        wg_pubkey: wgPubkey,
        nft_contract: nftContract,
        source: config.source,
        ...(config.leaseDuration > 0 && { lease_duration: config.leaseDuration }),
    });

    const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
    });

    if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`Broker API ${resp.status}: ${text}`);
    }

    return (await resp.json()) as AllocationResponse;
}

// ── Request handler ─────────────────────────────────────────────────

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
            allocation = await requestAllocation(payload.wgPubkey, req.nftPolicyId);
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

// ── Main ────────────────────────────────────────────────────────────

async function main(): Promise<void> {
    console.log(`[adapter] Cardano adapter starting`);
    console.log(`[adapter] Validator: ${config.validatorAddress}`);
    console.log(`[adapter] Beacon policy: ${config.beaconPolicyId}`);
    console.log(`[adapter] ECIES pubkey: ${encryption.publicKeyHex().slice(0, 20)}...`);
    console.log(`[adapter] Broker API: ${config.brokerApiUrl}`);
    console.log(`[adapter] Source: ${config.source}`);
    console.log(`[adapter] Network: ${config.network}`);
    console.log(`[adapter] Provider: ${config.blockfrostApiKey ? 'Blockfrost' : 'Koios'}`);

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

main().catch((err) => {
    console.error('[adapter] Fatal error:', err);
    process.exit(1);
});
