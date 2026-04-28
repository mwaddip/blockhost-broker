/**
 * Broker REST API client.
 *
 * POST /v1/allocations — request a new allocation or update an existing one.
 * Schema is documented in BROKER_INTERFACE.md and facts/COMMON_INTERFACE.md §7.
 */

export interface AllocationResponse {
    prefix: string;
    gateway: string;
    broker_pubkey: string;
    broker_endpoint: string;
}

export interface AllocationRequestOptions {
    brokerApiUrl: string;
    source: string;
    /** Lease duration in seconds. 0 or negative = no lease (broker default applies). */
    leaseDuration?: number;
}

export async function requestAllocation(
    wgPubkey: string,
    nftContract: string,
    opts: AllocationRequestOptions,
): Promise<AllocationResponse> {
    const url = `${opts.brokerApiUrl}/v1/allocations`;
    const body = JSON.stringify({
        wg_pubkey: wgPubkey,
        nft_contract: nftContract,
        source: opts.source,
        ...(opts.leaseDuration && opts.leaseDuration > 0 && { lease_duration: opts.leaseDuration }),
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
