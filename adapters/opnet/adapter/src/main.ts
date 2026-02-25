import { JSONRpcProvider } from 'opnet';
import { loadConfig } from './config.js';
import { RequestsContract, type OnChainRequest } from './contract.js';
import { EciesEncryption, type RequestPayload, type ResponsePayload } from './crypto.js';
import { ResponseDelivery } from './delivery.js';
import { RequestPoller } from './poller.js';

const config = loadConfig();

// ── Services ────────────────────────────────────────────────────────

const provider = new JSONRpcProvider({ url: config.rpcUrl, network: config.network });
const contract = new RequestsContract(config.requestsContractPubkey, provider, config.network);
const encryption = new EciesEncryption(config.eciesPrivateKey);
const delivery = new ResponseDelivery(
    provider,
    config.network,
    config.eciesPrivateKey,
    config.operatorMnemonic,
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

async function handleNewRequests(requests: OnChainRequest[]): Promise<void> {
    for (const req of requests) {
        console.log(`[adapter] New request #${req.id} from ${req.requester} (nft: ${req.nftContract})`);

        // Decrypt the payload
        let payload: RequestPayload;
        try {
            payload = encryption.decryptRequestPayload(req.encryptedPayload);
        } catch (err) {
            console.error(`[adapter] Failed to decrypt request #${req.id}:`, err);
            continue;
        }

        console.log(`[adapter] Request #${req.id}: wgPubkey=${payload.wgPubkey.slice(0, 20)}...`);

        // Request allocation from broker
        let allocation: AllocationResponse;
        try {
            allocation = await requestAllocation(payload.wgPubkey, req.nftContract);
        } catch (err) {
            console.error(`[adapter] Allocation failed for request #${req.id}:`, err);
            continue;
        }

        console.log(`[adapter] Allocated ${allocation.prefix} for request #${req.id}`);

        // Build response and deliver via OP_RETURN
        const response: ResponsePayload = {
            prefix: allocation.prefix,
            gateway: allocation.gateway,
            brokerPubkey: allocation.broker_pubkey,
            brokerEndpoint: allocation.broker_endpoint,
        };

        try {
            const txid = await delivery.deliver(response, payload.serverPubkey);
            console.log(`[adapter] Response delivered for request #${req.id}: ${txid}`);
        } catch (err) {
            console.error(`[adapter] Delivery failed for request #${req.id}:`, err);
        }
    }
}

// ── Poller ───────────────────────────────────────────────────────────

const poller = new RequestPoller(provider, contract, handleNewRequests);

// ── Main ────────────────────────────────────────────────────────────

async function main(): Promise<void> {
    console.log(`[adapter] OPNet adapter starting`);
    console.log(`[adapter] Contract: ${config.requestsContractPubkey}`);
    console.log(`[adapter] ECIES pubkey: ${encryption.publicKeyHex().slice(0, 20)}...`);
    console.log(`[adapter] Broker API: ${config.brokerApiUrl}`);
    console.log(`[adapter] Source: ${config.source}`);

    poller.start();

    // Graceful shutdown
    const shutdown = async () => {
        console.log('[adapter] Shutting down...');
        poller.stop();
        await provider.close();
        process.exit(0);
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
}

main().catch((err) => {
    console.error('[adapter] Fatal error:', err);
    process.exit(1);
});
