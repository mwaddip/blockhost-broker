/**
 * End-to-end test: mock adapter that picks up requests and delivers
 * a fake allocation response via OP_RETURN.
 *
 * Bypasses the broker core socket — generates a mock response directly.
 *
 * Usage:
 *   source ~/projects/sharedenv/opnet-regtest.env
 *   npx tsx src/test-e2e.ts [--start-from-id N]
 */

import { JSONRpcProvider } from 'opnet';
import { networks } from '@btc-vision/bitcoin';
import { RequestsContract } from './contract.js';
import { EciesEncryption } from './crypto.js';
import { ResponseDelivery } from './delivery.js';
import type { ResponsePayload } from './crypto.js';

// ── Config from env ─────────────────────────────────────────────────

const RPC_URL = process.env.OPNET_RPC_URL ?? 'https://regtest.opnet.org';
const network = networks.regtest;
const REQUESTS_PUBKEY = process.env.OPNET_BROKER_REQUESTS_PUBKEY!;
const OPERATOR_MNEMONIC = process.env.OPNET_OPERATOR_MNEMONIC!;
const ECIES_KEY = process.env.BROKER_ECIES_PRIVATE_KEY!;

if (!REQUESTS_PUBKEY || !OPERATOR_MNEMONIC || !ECIES_KEY) {
    console.error('Missing env vars. Source opnet-regtest.env first.');
    process.exit(1);
}

// ── Mock allocation response ────────────────────────────────────────
// Uses real broker server values so the response is realistic.

const MOCK_RESPONSE: ResponsePayload = {
    prefix: '2a11:6c7:f04:276::100/120',
    gateway: '2a11:6c7:f04:276::1',
    brokerPubkey: 'dGVzdC13Zy1wdWJrZXktMzItYnl0ZXMtcGFkWFhYWFg=', // 32 bytes base64 (test key)
    brokerEndpoint: '95.179.128.177:51820',
};

// ── Main ────────────────────────────────────────────────────────────

async function main(): Promise<void> {
    // Parse optional --start-from-id
    const startIdx = process.argv.indexOf('--start-from-id');
    const startFromId = startIdx !== -1 ? BigInt(process.argv[startIdx + 1]) : 0n;

    const provider = new JSONRpcProvider({ url: RPC_URL, network });
    const contract = new RequestsContract(REQUESTS_PUBKEY, provider, network);
    const encryption = new EciesEncryption(ECIES_KEY);
    const delivery = new ResponseDelivery(provider, network, ECIES_KEY, OPERATOR_MNEMONIC);

    console.log(`[e2e] Mock adapter starting`);
    console.log(`[e2e] ECIES pubkey: ${encryption.publicKeyHex().slice(0, 20)}...`);
    console.log(`[e2e] Operator: ${delivery.operatorAddress}`);
    console.log(`[e2e] Starting from request ID: ${startFromId || 'latest'}`);

    // Determine where to start polling
    let lastProcessedId = startFromId;
    if (lastProcessedId === 0n) {
        lastProcessedId = await contract.getRequestCount();
        console.log(`[e2e] Current request count: ${lastProcessedId}, will watch for new ones`);
    } else {
        lastProcessedId = startFromId - 1n;
    }

    console.log(`[e2e] Waiting for new requests...`);
    console.log(`[e2e] (Submit a client request now)\n`);

    const POLL_MS = 15_000;
    const TIMEOUT_MS = 30 * 60_000; // 30 minutes
    const deadline = Date.now() + TIMEOUT_MS;

    while (Date.now() < deadline) {
        const count = await contract.getRequestCount();

        if (count > lastProcessedId) {
            for (let id = lastProcessedId + 1n; id <= count; id++) {
                console.log(`[e2e] Found request #${id}`);

                const req = await contract.getRequest(id);

                // Decrypt
                let payload;
                try {
                    payload = encryption.decryptRequestPayload(req.encryptedPayload);
                } catch (err) {
                    console.log(`[e2e] Failed to decrypt request #${id}: ${err}`);
                    continue;
                }

                console.log(`[e2e] Decrypted request #${id}:`);
                console.log(`[e2e]   WG pubkey: ${payload.wgPubkey.slice(0, 20)}...`);
                console.log(`[e2e]   Server pubkey: ${payload.serverPubkey.slice(0, 20)}...`);

                // Deliver mock response via OP_RETURN
                console.log(`[e2e] Delivering mock response...`);
                try {
                    const txid = await delivery.deliver(MOCK_RESPONSE, payload.serverPubkey);
                    console.log(`[e2e] Response delivered! txid: ${txid}`);
                    console.log(`[e2e] Client should pick this up in the next block.\n`);
                } catch (err) {
                    console.error(`[e2e] Delivery failed:`, err);
                }
            }

            lastProcessedId = count;
        }

        await new Promise((resolve) => setTimeout(resolve, POLL_MS));
    }

    console.log('[e2e] Timed out');
    await provider.close();
}

main().catch((err) => {
    console.error('[e2e] Fatal:', err);
    process.exit(1);
});
