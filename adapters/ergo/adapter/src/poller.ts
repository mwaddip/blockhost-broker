/**
 * Polls for request boxes at the guard script address.
 *
 * Scans for unspent boxes at the guard address that carry a beacon
 * token in tokens(0) and have R4 (client pubkey) + R5 (encrypted payload).
 *
 * Same exponential backoff pattern as the Cardano/OPNet adapters.
 */

import { getUnspentBoxes, decodeCollByte, type ErgoBox } from './ergo-api.js';

export interface RequestBox {
    box: ErgoBox;
    beaconTokenId: string;
    clientPubkeyHex: string;
    encryptedPayloadHex: string;
}

type RequestHandler = (requests: RequestBox[]) => Promise<void>;
type StateChangeHandler = (processedBeacons: Set<string>) => void;

export class RequestPoller {
    private processedBeacons = new Set<string>();
    private timer: ReturnType<typeof setTimeout> | null = null;
    private consecutiveErrors = 0;
    private pollIntervalMs = 15_000;
    private static readonly MAX_BACKOFF_MS = 5 * 60_000;

    constructor(
        private explorerUrl: string,
        private guardAddress: string,
        private onNewRequests: RequestHandler,
        private onStateChange?: StateChangeHandler,
    ) {}

    setProcessedBeacons(beacons: Set<string>): void {
        this.processedBeacons = beacons;
    }

    start(intervalMs: number): void {
        this.pollIntervalMs = intervalMs;
        console.log(`[poller] Starting with ${intervalMs}ms interval`);
        this.scheduleNext(0);
    }

    stop(): void {
        if (this.timer) {
            clearTimeout(this.timer);
            this.timer = null;
        }
    }

    private scheduleNext(delayMs: number): void {
        this.timer = setTimeout(async () => {
            this.timer = null;

            try {
                const requests = await this.fetchRequestBoxes();
                const newRequests = requests.filter(r => !this.processedBeacons.has(r.beaconTokenId));

                if (newRequests.length > 0) {
                    console.log(`[poller] Found ${newRequests.length} new request(s)`);
                    await this.onNewRequests(newRequests);

                    for (const req of newRequests) {
                        this.processedBeacons.add(req.beaconTokenId);
                    }
                    this.onStateChange?.(this.processedBeacons);
                }

                this.consecutiveErrors = 0;
                this.scheduleNext(this.pollIntervalMs);
            } catch (err) {
                this.consecutiveErrors++;
                const msg = err instanceof Error ? err.message : String(err);
                if (this.consecutiveErrors === 1 || this.consecutiveErrors % 30 === 0) {
                    console.error(`[poller] Explorer error (${this.consecutiveErrors}x): ${msg}`);
                }
                const backoff = Math.min(
                    this.pollIntervalMs * Math.pow(2, this.consecutiveErrors - 1),
                    RequestPoller.MAX_BACKOFF_MS,
                );
                this.scheduleNext(backoff);
            }
        }, delayMs);
    }

    private async fetchRequestBoxes(): Promise<RequestBox[]> {
        const boxes = await getUnspentBoxes(this.explorerUrl, this.guardAddress);
        const results: RequestBox[] = [];

        for (const box of boxes) {
            // Must have at least one token (beacon)
            if (box.assets.length === 0) continue;

            // Must have R4 (client pubkey) and R5 (encrypted payload)
            const r4Hex = box.additionalRegisters['R4'];
            const r5Hex = box.additionalRegisters['R5'];
            if (!r4Hex || !r5Hex) continue;

            try {
                const clientPubkey = decodeCollByte(r4Hex);
                if (clientPubkey.length !== 33) continue; // must be compressed pubkey

                const encryptedPayload = decodeCollByte(r5Hex);
                if (encryptedPayload.length === 0) continue;

                results.push({
                    box,
                    beaconTokenId: box.assets[0]!.tokenId,
                    clientPubkeyHex: Buffer.from(clientPubkey).toString('hex'),
                    encryptedPayloadHex: Buffer.from(encryptedPayload).toString('hex'),
                });
            } catch {
                // Skip boxes with unparseable registers
                continue;
            }
        }

        return results;
    }
}
