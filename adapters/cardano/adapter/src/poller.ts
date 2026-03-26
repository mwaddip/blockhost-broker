/**
 * Polls for request UTXOs at the broker validator address.
 *
 * Scans for UTXOs carrying the request beacon token, decodes their
 * inline datums, and emits new (unprocessed) requests to the handler.
 */

export interface UtxoRef {
    txHash: string;
    outputIndex: number;
}

export interface RequestUtxo {
    ref: UtxoRef;
    nftPolicyId: string;
    clientPkh: string;
    encryptedPayload: string;   // hex
    lovelace: string;
}

type RequestHandler = (requests: RequestUtxo[]) => Promise<void>;
type StateChangeHandler = (processedRefs: Set<string>) => void;

function refKey(ref: UtxoRef): string {
    return `${ref.txHash}#${ref.outputIndex}`;
}

export class RequestPoller {
    private processedRefs = new Set<string>();
    private timer: ReturnType<typeof setTimeout> | null = null;
    private consecutiveErrors = 0;
    private pollIntervalMs = 20_000;
    private static readonly MAX_BACKOFF_MS = 5 * 60_000;

    constructor(
        private koiosUrl: string,
        private blockfrostApiKey: string | null,
        private validatorAddress: string,
        private beaconPolicyId: string,
        private onNewRequests: RequestHandler,
        private onStateChange?: StateChangeHandler,
    ) {}

    setProcessedRefs(refs: Set<string>): void {
        this.processedRefs = refs;
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
                const utxos = await this.fetchRequestUtxos();
                const newRequests = utxos.filter((u) => !this.processedRefs.has(refKey(u.ref)));

                if (newRequests.length > 0) {
                    console.log(`[poller] Found ${newRequests.length} new request(s)`);
                    await this.onNewRequests(newRequests);

                    for (const req of newRequests) {
                        this.processedRefs.add(refKey(req.ref));
                    }
                    this.onStateChange?.(this.processedRefs);
                }

                this.consecutiveErrors = 0;
                this.scheduleNext(this.pollIntervalMs);
            } catch (err) {
                this.consecutiveErrors++;
                const msg = err instanceof Error ? err.message : String(err);
                if (this.consecutiveErrors === 1 || this.consecutiveErrors % 30 === 0) {
                    console.error(`[poller] RPC error (${this.consecutiveErrors}x): ${msg}`);
                }
                const backoff = Math.min(
                    this.pollIntervalMs * Math.pow(2, this.consecutiveErrors - 1),
                    RequestPoller.MAX_BACKOFF_MS,
                );
                this.scheduleNext(backoff);
            }
        }, delayMs);
    }

    private async fetchRequestUtxos(): Promise<RequestUtxo[]> {
        if (this.blockfrostApiKey) {
            return this.fetchFromBlockfrost();
        }
        return this.fetchFromKoios();
    }

    private async fetchFromKoios(): Promise<RequestUtxo[]> {
        const url = `${this.koiosUrl}/address_utxos`;
        const resp = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                _addresses: [this.validatorAddress],
                _extended: true,
            }),
        });
        if (!resp.ok) {
            throw new Error(`Koios ${resp.status}: ${await resp.text()}`);
        }

        const utxos: any[] = await resp.json();
        return this.filterAndDecode(utxos, 'koios');
    }

    private async fetchFromBlockfrost(): Promise<RequestUtxo[]> {
        // Blockfrost requires paginated queries
        const baseUrl = this.blockfrostApiKey!.includes('preview')
            ? 'https://cardano-preview.blockfrost.io/api/v0'
            : this.blockfrostApiKey!.includes('preprod')
              ? 'https://cardano-preprod.blockfrost.io/api/v0'
              : 'https://cardano-mainnet.blockfrost.io/api/v0';

        const url = `${baseUrl}/addresses/${this.validatorAddress}/utxos`;
        const resp = await fetch(url, {
            headers: { 'project_id': this.blockfrostApiKey! },
        });
        if (!resp.ok) {
            throw new Error(`Blockfrost ${resp.status}: ${await resp.text()}`);
        }

        const utxos: any[] = await resp.json();
        return this.filterAndDecode(utxos, 'blockfrost');
    }

    private filterAndDecode(utxos: any[], source: 'koios' | 'blockfrost'): RequestUtxo[] {
        const results: RequestUtxo[] = [];

        for (const utxo of utxos) {
            // Check for request beacon token
            const hasBeacon = this.hasRequestBeacon(utxo, source);
            if (!hasBeacon) continue;

            // Decode inline datum
            const datum = this.decodeDatum(utxo, source);
            if (!datum) continue;

            const ref: UtxoRef = source === 'koios'
                ? { txHash: utxo.tx_hash, outputIndex: utxo.tx_index }
                : { txHash: utxo.tx_hash, outputIndex: utxo.output_index };

            results.push({
                ref,
                nftPolicyId: datum.nftPolicyId,
                clientPkh: datum.clientPkh,
                encryptedPayload: datum.encryptedPayload,
                lovelace: source === 'koios' ? utxo.value : utxo.amount?.[0]?.quantity ?? '0',
            });
        }

        return results;
    }

    private hasRequestBeacon(utxo: any, source: 'koios' | 'blockfrost'): boolean {
        const requestBeaconHex = Buffer.from('request').toString('hex'); // 72657175657374
        if (source === 'koios') {
            const assets = utxo.asset_list ?? [];
            return assets.some(
                (a: any) => a.policy_id === this.beaconPolicyId && a.asset_name === requestBeaconHex,
            );
        } else {
            const amounts = utxo.amount ?? [];
            const beaconUnit = this.beaconPolicyId + Buffer.from('request').toString('hex');
            return amounts.some((a: any) => a.unit === beaconUnit);
        }
    }

    private decodeDatum(
        utxo: any,
        source: 'koios' | 'blockfrost',
    ): { nftPolicyId: string; clientPkh: string; encryptedPayload: string } | null {
        try {
            let datumValue: any;

            if (source === 'koios') {
                // Koios returns inline_datum.value for extended queries
                datumValue = utxo.inline_datum?.value;
            } else {
                // Blockfrost returns inline_datum as CBOR — would need additional parsing
                // For now, use Koios as the primary source
                return null;
            }

            if (!datumValue) return null;

            // RequestDatum { nft_policy_id, client_pkh, encrypted_payload }
            // Koios returns the datum value as a JSON object with constructor/fields
            const fields = datumValue.fields ?? [];
            if (fields.length < 3) return null;

            return {
                nftPolicyId: fields[0].bytes ?? '',
                clientPkh: fields[1].bytes ?? '',
                encryptedPayload: fields[2].bytes ?? '',
            };
        } catch {
            return null;
        }
    }
}
