/**
 * Lightweight Ergo API client — Explorer queries + ergo-relay signing/broadcast.
 *
 * Based on blockhost-engine-ergo/src/ergo/provider.ts, stripped to the
 * subset needed by the broker adapter.
 */

export interface ErgoBox {
    boxId: string;
    transactionId: string;
    index: number;
    value: bigint;
    ergoTree: string;
    creationHeight: number;
    assets: Array<{ tokenId: string; amount: bigint }>;
    additionalRegisters: Record<string, string>;
}

interface ExplorerBoxResponse {
    boxId: string;
    transactionId: string;
    index: number;
    value: number | string;
    ergoTree: string;
    creationHeight: number;
    assets: Array<{ tokenId: string; amount: number | string }>;
    additionalRegisters: Record<string, { serializedValue: string } | string>;
}

interface ExplorerBoxListResponse {
    items: ExplorerBoxResponse[];
    total: number;
}

function normalizeBox(raw: ExplorerBoxResponse): ErgoBox {
    const regs: Record<string, string> = {};
    for (const [key, val] of Object.entries(raw.additionalRegisters)) {
        if (typeof val === 'string') regs[key] = val;
        else if (val && typeof val === 'object' && 'serializedValue' in val) regs[key] = val.serializedValue;
    }
    return {
        boxId: raw.boxId,
        transactionId: raw.transactionId,
        index: raw.index,
        value: BigInt(raw.value),
        ergoTree: raw.ergoTree,
        creationHeight: raw.creationHeight,
        assets: raw.assets.map(a => ({ tokenId: a.tokenId, amount: BigInt(a.amount) })),
        additionalRegisters: regs,
    };
}

/** Fetch unspent boxes at an address. */
export async function getUnspentBoxes(explorerUrl: string, address: string): Promise<ErgoBox[]> {
    const all: ErgoBox[] = [];
    const limit = 500;
    let offset = 0;
    while (true) {
        const url = `${explorerUrl}/api/v1/boxes/unspent/byAddress/${address}?offset=${offset}&limit=${limit}`;
        const resp = await fetch(url, { headers: { Accept: 'application/json' } });
        if (!resp.ok) throw new Error(`Explorer ${resp.status}: ${await resp.text()}`);
        const data = (await resp.json()) as ExplorerBoxListResponse;
        all.push(...data.items.map(normalizeBox));
        if (data.items.length < limit) break;
        offset += limit;
    }
    return all;
}

/** Fetch unspent boxes by token ID. */
export async function getBoxesByTokenId(explorerUrl: string, tokenId: string): Promise<ErgoBox[]> {
    const all: ErgoBox[] = [];
    let offset = 0;
    const limit = 100; // Explorer caps at 100 for this endpoint
    while (true) {
        const url = `${explorerUrl}/api/v1/boxes/byTokenId/${tokenId}?offset=${offset}&limit=${limit}`;
        const resp = await fetch(url, { headers: { Accept: 'application/json' } });
        if (!resp.ok) throw new Error(`Explorer ${resp.status}: ${await resp.text()}`);
        const data = (await resp.json()) as ExplorerBoxListResponse;
        const unspent = data.items.filter(b => !(b as any).spentTransactionId);
        all.push(...unspent.map(normalizeBox));
        if (data.items.length < limit) break;
        offset += limit;
    }
    return all;
}

/** Get current blockchain height. */
export async function getHeight(explorerUrl: string): Promise<number> {
    const url = `${explorerUrl}/api/v1/info`;
    const resp = await fetch(url, { headers: { Accept: 'application/json' } });
    if (!resp.ok) throw new Error(`Explorer ${resp.status}: ${await resp.text()}`);
    const data = (await resp.json()) as { height: number };
    return data.height;
}

/** Sign an unsigned transaction via ergo-relay. */
export async function signTx(
    relayUrl: string,
    unsignedTx: unknown,
    secrets: string[],
    inputBoxes: ErgoBox[],
    height: number,
): Promise<unknown> {
    // Fleet SDK's toPlainObject() only includes { boxId, extension } in inputs.
    // ergo-relay needs full box data for script evaluation context.
    const tx: any = typeof (unsignedTx as any)?.toPlainObject === 'function'
        ? (unsignedTx as any).toPlainObject()
        : unsignedTx;

    if (Array.isArray(tx.inputs)) {
        const boxMap = new Map(inputBoxes.map(b => [b.boxId, b]));
        tx.inputs = tx.inputs.map((input: any) => {
            const full = boxMap.get(input.boxId);
            if (!full) return input;
            return {
                boxId: full.boxId,
                transactionId: full.transactionId,
                index: full.index,
                value: full.value,
                ergoTree: full.ergoTree,
                creationHeight: full.creationHeight,
                assets: full.assets,
                additionalRegisters: full.additionalRegisters,
                extension: input.extension ?? {},
            };
        });
    }

    const body = { tx, secrets: { dlog: secrets }, height };
    const resp = await fetch(`${relayUrl}/wallet/transaction/sign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body, (_k, v) => typeof v === 'bigint' ? v.toString() : v),
    });
    if (!resp.ok) {
        const text = await resp.text().catch(() => '');
        throw new Error(`ergo-relay sign failed (${resp.status}): ${text}`);
    }
    return resp.json();
}

/**
 * Broadcast a signed transaction.
 * Tries ergo-relay first, falls back to Explorer mempool API.
 */
export async function submitTx(relayUrl: string, signedTx: unknown, explorerUrl?: string): Promise<string> {
    const txJson = JSON.stringify(signedTx, (_k, v) => typeof v === 'bigint' ? v.toString() : v);

    // Try ergo-relay P2P broadcast first
    try {
        const resp = await fetch(`${relayUrl}/transactions`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: txJson,
            signal: AbortSignal.timeout(30_000),
        });
        if (resp.ok) {
            const data = await resp.json() as { id: string } | string;
            return typeof data === 'string' ? data : data.id;
        }
        // 400 = tx rejected by sigma-rust (bad tx, not a connectivity issue)
        if (resp.status === 400) {
            const text = await resp.text().catch(() => '');
            throw new Error(`Transaction rejected: ${text}`);
        }
        // 503 or other = relay can't reach peers, try fallback
    } catch (err) {
        if (err instanceof Error && err.message.startsWith('Transaction rejected')) throw err;
        // Network error or timeout — try fallback
    }

    // Fallback: Explorer mempool submission
    if (explorerUrl) {
        const resp = await fetch(`${explorerUrl}/api/v1/mempool/transactions/submit`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: txJson,
            signal: AbortSignal.timeout(60_000),
        });
        if (resp.ok) {
            const data = await resp.json() as { id: string } | string;
            console.log('[submit] Broadcast via Explorer fallback');
            return typeof data === 'string' ? data : data.id;
        }
        const text = await resp.text().catch(() => '');
        throw new Error(`Broadcast failed (relay + explorer): ${text}`);
    }

    throw new Error('Broadcast failed: ergo-relay unavailable and no explorer fallback configured');
}

// ── Register decoding helpers ───────────────────────────────────────

/** Decode a Coll[Byte] register value from Sigma-serialized hex. */
export function decodeCollByte(hex: string): Uint8Array {
    // Format: 0e + VLQ(length) + raw bytes
    const bytes = hexToBytes(hex);
    if (bytes[0] !== 0x0e) throw new Error(`Expected Coll[Byte] (0x0e), got 0x${bytes[0]!.toString(16)}`);
    let pos = 1;
    let length = 0;
    let shift = 0;
    while (pos < bytes.length) {
        const b = bytes[pos]!;
        length |= (b & 0x7f) << shift;
        pos++;
        if ((b & 0x80) === 0) break;
        shift += 7;
    }
    return bytes.slice(pos, pos + length);
}

function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}
