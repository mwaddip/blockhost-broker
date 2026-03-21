import type { JSONRpcProvider } from 'opnet';
import { RequestsContract, type OnChainRequest } from './contract.js';

/** Target block interval on OPNet (seconds). */
const BLOCK_INTERVAL_S = 600; // 10 minutes

/** Start frequent polling this many seconds before the expected next block. */
const EARLY_POLL_S = 60;

/** Interval for frequent polling near expected block time. */
const ACTIVE_POLL_MS = 10_000; // 10 seconds

/** Interval for idle polling (well before next block expected). */
const IDLE_POLL_MS = 60_000; // 1 minute

/** Maximum backoff when RPC is unreachable. */
const MAX_BACKOFF_MS = 5 * 60_000; // 5 minutes

/**
 * Block-aware poller for the BrokerRequests contract.
 *
 * Instead of polling at a fixed interval, it tracks the last block time
 * and adjusts:
 * - Idle phase: poll every 60s (just monitoring, unlikely new data)
 * - Active phase: poll every 10s when within 60s of expected next block
 *
 * Any poll that finds new requests also triggers an immediate re-poll
 * on the next cycle (in case multiple requests landed in the same block).
 */
export class RequestPoller {
    private lastProcessedId: bigint = 0n;
    private lastBlockHeight: bigint = 0n;
    private lastBlockTimeMs: number = 0;
    private timer: ReturnType<typeof setTimeout> | null = null;
    private running = false;
    private consecutiveErrors = 0;

    constructor(
        private provider: JSONRpcProvider,
        private contract: RequestsContract,
        private onNewRequests: (requests: OnChainRequest[]) => Promise<void>,
        private onStateChange?: (lastProcessedId: bigint) => void,
    ) {}

    /** Set the starting point (e.g. restored from persistent state). */
    setLastProcessedId(id: bigint): void {
        this.lastProcessedId = id;
    }

    /** Start the polling loop. */
    start(): void {
        if (this.running) return;
        this.running = true;
        console.log('[poller] Starting block-aware polling');
        this.scheduleNext(0); // immediate first poll
    }

    /** Stop the polling loop. */
    stop(): void {
        this.running = false;
        if (this.timer) {
            clearTimeout(this.timer);
            this.timer = null;
        }
    }

    /** Single poll cycle. Returns number of new requests found. */
    private async poll(): Promise<number> {
        // Update block tracking
        await this.updateBlockInfo();

        const count = await this.contract.getRequestCount();

        if (count <= this.lastProcessedId) {
            return 0;
        }

        const newRequests: OnChainRequest[] = [];
        for (let id = this.lastProcessedId + 1n; id <= count; id++) {
            try {
                const req = await this.contract.getRequest(id);
                newRequests.push(req);
            } catch (err) {
                console.error(`[poller] Failed to fetch request ${id}:`, err);
                break;
            }
        }

        if (newRequests.length === 0) {
            return 0;
        }

        // Deduplicate: keep only the latest request per NFT contract
        const byNft = new Map<string, OnChainRequest>();
        for (const req of newRequests) {
            byNft.set(req.nftContract, req);
        }
        const deduplicated = Array.from(byNft.values());

        await this.onNewRequests(deduplicated);

        // Advance to the total count (includes deduplicated/skipped requests)
        this.lastProcessedId = count;
        this.onStateChange?.(this.lastProcessedId);

        return deduplicated.length;
    }

    private async updateBlockInfo(): Promise<void> {
        const height = await this.provider.getBlockNumber();
        if (height !== this.lastBlockHeight) {
            const block = await this.provider.getBlock(height);
            this.lastBlockHeight = height;
            this.lastBlockTimeMs = Number(block.time);
            console.log(
                `[poller] Block ${height} (${new Date(this.lastBlockTimeMs).toISOString()})`,
            );
        }
    }

    private getNextPollDelayMs(): number {
        if (this.lastBlockTimeMs === 0) {
            // No block info yet — poll frequently until we get one
            return ACTIVE_POLL_MS;
        }

        const nowMs = Date.now();
        const blockAgeS = (nowMs - this.lastBlockTimeMs) / 1000;
        const timeToNextBlockS = BLOCK_INTERVAL_S - blockAgeS;

        if (timeToNextBlockS <= EARLY_POLL_S) {
            // Near expected block time — poll actively
            return ACTIVE_POLL_MS;
        }

        // Well before next block — idle polling, but don't sleep longer
        // than the time until the active window starts
        const timeToActiveMs = (timeToNextBlockS - EARLY_POLL_S) * 1000;
        return Math.min(IDLE_POLL_MS, timeToActiveMs);
    }

    private scheduleNext(delayMs: number): void {
        if (!this.running) return;
        this.timer = setTimeout(async () => {
            this.timer = null;
            if (!this.running) return;

            let foundNew = 0;
            try {
                foundNew = await this.poll();
                this.consecutiveErrors = 0;
                if (foundNew > 0) {
                    console.log(`[poller] Processed ${foundNew} new request(s)`);
                }
            } catch (err) {
                this.consecutiveErrors++;
                const msg = err instanceof Error ? err.message : String(err);
                // One-liner on first error, then only every 30th to avoid log spam
                if (this.consecutiveErrors === 1 || this.consecutiveErrors % 30 === 0) {
                    console.error(`[poller] RPC error (${this.consecutiveErrors}x): ${msg}`);
                }
            }

            let nextDelay: number;
            if (this.consecutiveErrors > 0) {
                // Exponential backoff: 10s, 20s, 40s, 80s, ... capped at 5min
                nextDelay = Math.min(
                    ACTIVE_POLL_MS * Math.pow(2, this.consecutiveErrors - 1),
                    MAX_BACKOFF_MS,
                );
            } else if (foundNew > 0) {
                // Found requests — poll again soon (same block might have more)
                nextDelay = ACTIVE_POLL_MS;
            } else {
                nextDelay = this.getNextPollDelayMs();
            }
            this.scheduleNext(nextDelay);
        }, delayMs);
    }
}
