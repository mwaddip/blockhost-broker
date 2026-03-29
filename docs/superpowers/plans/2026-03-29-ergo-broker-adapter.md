# Ergo Broker Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an Ergo adapter (server-side) and client plugin for the blockhost-broker multichain architecture, following the same patterns as the Cardano and OPNet adapters.

**Architecture:** Single guard script (ErgoScript) at a P2S address controls request/response boxes. Adapter polls Explorer API for request boxes, POSTs to broker API, delivers encrypted response on-chain via Fleet SDK + ergo-relay. Client submits request tx, watches for response, outputs standard JSON. On-chain registry (singleton NFT) stores broker config.

**Tech Stack:** Fleet SDK (`@fleet-sdk/core`, `@fleet-sdk/serializer`), ergo-relay (signing + P2P broadcast), Ergo Explorer API, `@noble/curves` + `@noble/hashes` + `@noble/ciphers` (crypto), esbuild (bundler).

**Spec:** `docs/superpowers/specs/2026-03-29-ergo-broker-adapter-design.md`

**Reference implementations:**
- Cardano adapter: `adapters/cardano/adapter/src/` (closest pattern match)
- Cardano client: `adapters/cardano/client/src/`
- Ergo engine contracts: `/home/mwaddip/projects/blockhost-ergo/blockhost-engine-ergo/src/ergo/contracts.ts` (ErgoTree template + byte surgery)
- Ergo engine provider: `/home/mwaddip/projects/blockhost-ergo/blockhost-engine-ergo/src/ergo/provider.ts` (Explorer API + ergo-relay signing)

**Key design note — R4 type change:** The spec says R4 is `SigmaProp`. The implementation stores R4 as `Coll[Byte]` (33-byte compressed public key) instead. Reason: `Coll[Byte]` supports straightforward equality comparison in ErgoScript (`successor.R4 == SELF.R4`) and simpler serialization. The script uses `decodePoint()` to convert to GroupElement when needed for `proveDlog()`.

**Key design note — Two spending paths (not three):** The spec has three paths (Respond, Cleanup, Refund). The implementation collapses Cleanup and Refund into a single client path: `proveDlog(clientPk)`. The client can always spend their box (cancel a request OR cleanup a response). The deadline in R6 is informational — the client software uses it to decide whether to retry. This is simpler and more user-friendly than enforcing a deadline on-chain.

---

### Task 1: Guard Script — ErgoScript source + compilation

Write the ErgoScript guard contract and compile it to an ErgoTree template using the Ergo node API (one-time dev step). Store the compiled template as a hex constant.

**Files:**
- Create: `adapters/ergo/contracts/guard.es` (ErgoScript source — reference only)
- Create: `adapters/ergo/contracts/compile-guard.ts` (compilation script)
- Create: `adapters/ergo/contracts/contracts.ts` (compiled template + byte surgery)

- [ ] **Step 1: Write the guard script ErgoScript source**

Create `adapters/ergo/contracts/guard.es`:

```ergoscript
{
  // Broker request/response guard script.
  //
  // Parameterized with operator's compressed public key (constant 0).
  // Two spending paths:
  //   1. Respond: operator signs, beacon carried to successor box
  //   2. Client:  client signs (cancel request or cleanup response)
  //
  // Register layout:
  //   R4: Coll[Byte] — client compressed public key (33 bytes)
  //   R5: Coll[Byte] — encrypted payload (request) or response (response)
  //   tokens(0): beacon token (amount = 1)

  val operatorPk = decodePoint(fromBase64("$$OPERATOR_PK_BASE64$$"))
  val clientPkBytes = SELF.R4[Coll[Byte]].get
  val clientPk = decodePoint(clientPkBytes)
  val beaconId = SELF.tokens(0)._1

  // Path 1: Operator responds — creates successor with same beacon + script + client PK
  val successor = OUTPUTS(0)
  val beaconPreserved = successor.tokens.size > 0 &&
                        successor.tokens(0)._1 == beaconId &&
                        successor.tokens(0)._2 == 1L
  val sameScript = successor.propositionBytes == SELF.propositionBytes
  val clientPreserved = successor.R4[Coll[Byte]].get == clientPkBytes

  val respondPath = sigmaProp(beaconPreserved && sameScript && clientPreserved) && proveDlog(operatorPk)

  // Path 2: Client spends (cancel request or cleanup response)
  val clientPath = proveDlog(clientPk)

  respondPath || clientPath
}
```

- [ ] **Step 2: Write the compilation script**

Create `adapters/ergo/contracts/compile-guard.ts`:

```typescript
/**
 * One-time compilation script for the broker guard ErgoScript.
 *
 * Compiles via an Ergo node's /script/p2sAddress endpoint, extracts
 * the ErgoTree hex, and writes it as a template constant.
 *
 * Usage:
 *   ERGO_NODE=http://213.239.193.208:9052 npx tsx compile-guard.ts
 *
 * The template uses the secp256k1 generator point as the operator PK
 * placeholder (same convention as blockhost-engine-ergo).
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { ErgoAddress, Network } from '@fleet-sdk/core';

const TEMPLATE_PK_HEX = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const TEMPLATE_PK_BASE64 = Buffer.from(TEMPLATE_PK_HEX, 'hex').toString('base64');

async function main() {
    const nodeUrl = process.env.ERGO_NODE;
    if (!nodeUrl) {
        console.error('Set ERGO_NODE to an Ergo node URL (e.g. http://213.239.193.208:9052)');
        process.exit(1);
    }

    // Read and parameterize the ErgoScript source
    const source = readFileSync('guard.es', 'utf-8')
        .replace('$$OPERATOR_PK_BASE64$$', TEMPLATE_PK_BASE64);

    console.log('Compiling guard script...');
    const resp = await fetch(`${nodeUrl}/script/p2sAddress`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source }),
    });

    if (!resp.ok) {
        const text = await resp.text();
        console.error(`Compilation failed (${resp.status}): ${text}`);
        process.exit(1);
    }

    const { address } = (await resp.json()) as { address: string };
    console.log(`P2S address: ${address}`);

    // Extract ErgoTree hex from the address
    const ergoTree = ErgoAddress.fromBase58(address).ergoTree;
    console.log(`ErgoTree (${ergoTree.length / 2} bytes): ${ergoTree}`);

    // Write the template
    const output = {
        ergoTreeTemplate: ergoTree,
        templatePkHex: TEMPLATE_PK_HEX,
        compiledWith: nodeUrl,
        compiledAt: new Date().toISOString(),
    };

    writeFileSync('guard-template.json', JSON.stringify(output, null, 2) + '\n');
    console.log('Written to guard-template.json');
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
```

- [ ] **Step 3: Write the contracts module with byte surgery**

Create `adapters/ergo/contracts/contracts.ts`:

```typescript
/**
 * Compiled guard script ErgoTree template + byte surgery.
 *
 * Same pattern as blockhost-engine-ergo/src/ergo/contracts.ts:
 * pre-compiled ErgoTree with a template public key, substituted
 * at deploy time via byte surgery. No compiler or JRE needed.
 */

import { ErgoAddress, Network } from '@fleet-sdk/core';

/**
 * Template public key (secp256k1 generator point).
 * Searched for in the ErgoTree constants and replaced with the actual operator PK.
 */
const TEMPLATE_PK_HEX = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

/**
 * Pre-compiled guard script ErgoTree (hex).
 *
 * Compiled from guard.es using an Ergo node. Contains the template PK
 * as a Coll[Byte] constant. Two spending paths:
 *   1. Respond: operator signs + beacon preserved in successor
 *   2. Client:  client signs (cancel or cleanup)
 *
 * PLACEHOLDER — replaced after running compile-guard.ts
 */
export const GUARD_ERGO_TREE_TEMPLATE = 'COMPILE_ME';

// ── VLQ parsing ─────────────────────────────────────────────────────

function readVLQ(bytes: Uint8Array, offset: number): [number, number] {
    let result = 0;
    let shift = 0;
    let pos = offset;
    while (pos < bytes.length) {
        const byte = bytes[pos]!;
        result |= (byte & 0x7f) << shift;
        pos++;
        if ((byte & 0x80) === 0) break;
        shift += 7;
    }
    return [result, pos];
}

// ── Byte surgery ────────────────────────────────────────────────────

function findPkConstant(
    ergoTreeBytes: Uint8Array,
    templatePkBytes: Uint8Array,
): { offset: number; length: number } | null {
    const header = ergoTreeBytes[0]!;
    if ((header & 0x10) === 0) {
        throw new Error('ErgoTree does not have segregated constants');
    }

    let pos = 1;
    let numConstants: number;
    [numConstants, pos] = readVLQ(ergoTreeBytes, pos);

    for (let i = 0; i < numConstants; i++) {
        const typeByte = ergoTreeBytes[pos]!;
        pos++;

        if (typeByte === 0x01) {
            pos++; // SBoolean
        } else if (typeByte === 0x04) {
            [, pos] = readVLQ(ergoTreeBytes, pos); // SInt
        } else if (typeByte === 0x05) {
            [, pos] = readVLQ(ergoTreeBytes, pos); // SLong
        } else if (typeByte === 0x0e) {
            let length: number;
            [length, pos] = readVLQ(ergoTreeBytes, pos);
            if (length === 33) {
                const candidate = ergoTreeBytes.slice(pos, pos + 33);
                let match = true;
                for (let j = 0; j < 33; j++) {
                    if (candidate[j] !== templatePkBytes[j]) { match = false; break; }
                }
                if (match) return { offset: pos, length: 33 };
            }
            pos += length;
        } else if (typeByte === 0x08) {
            // SGroupElement — 33 bytes compressed point
            pos += 33;
        } else {
            throw new Error(`Unknown constant type 0x${typeByte.toString(16)} at position ${pos - 1}`);
        }
    }

    return null;
}

/**
 * Substitute the operator PK into the pre-compiled guard ErgoTree template.
 */
export function getGuardErgoTree(operatorPkHex: string): string {
    if (operatorPkHex.length !== 66) {
        throw new Error(`Expected 66 hex char compressed public key, got ${operatorPkHex.length}`);
    }

    const treeBytes = hexToBytes(GUARD_ERGO_TREE_TEMPLATE);
    const templatePkBytes = hexToBytes(TEMPLATE_PK_HEX);
    const operatorPkBytes = hexToBytes(operatorPkHex);

    const loc = findPkConstant(treeBytes, templatePkBytes);
    if (!loc) {
        throw new Error('Template PK not found in ErgoTree constants section');
    }

    const result = new Uint8Array(treeBytes);
    for (let i = 0; i < 33; i++) {
        result[loc.offset + i] = operatorPkBytes[i]!;
    }

    return bytesToHex(result);
}

/**
 * Compute the P2S address from an ErgoTree hex string.
 */
export function guardAddress(ergoTreeHex: string, mainnet = false): string {
    const network = mainnet ? Network.Mainnet : Network.Testnet;
    return ErgoAddress.fromErgoTree(ergoTreeHex, network).encode(network);
}

/**
 * Derive the P2PK address from a compressed public key.
 */
export function p2pkAddress(pubKeyHex: string, mainnet = false): string {
    const network = mainnet ? Network.Mainnet : Network.Testnet;
    return ErgoAddress.fromPublicKey(pubKeyHex, network).encode(network);
}

// ── Hex helpers ─────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
```

- [ ] **Step 4: Compile the guard script**

Run the compile script against a testnet Ergo node:

```bash
cd adapters/ergo/contracts
npm init -y && npm install @fleet-sdk/core
ERGO_NODE=http://213.239.193.208:9052 npx tsx compile-guard.ts
```

Copy the `ergoTreeTemplate` value from `guard-template.json` into `contracts.ts`, replacing `'COMPILE_ME'`.

- [ ] **Step 5: Commit**

```bash
git add adapters/ergo/contracts/
git commit -m "feat(ergo): add guard script ErgoTree template"
```

---

### Task 2: Adapter — Package scaffold + config

Set up the adapter package with dependencies, TypeScript config, esbuild, and environment config loader.

**Files:**
- Create: `adapters/ergo/adapter/package.json`
- Create: `adapters/ergo/adapter/tsconfig.json`
- Create: `adapters/ergo/adapter/src/config.ts`

- [ ] **Step 1: Create package.json**

Create `adapters/ergo/adapter/package.json`:

```json
{
    "name": "blockhost-adapter-ergo",
    "version": "0.1.0",
    "type": "module",
    "scripts": {
        "build": "esbuild src/main.ts --bundle --platform=node --format=esm --outfile=dist/main.js --target=node22 --banner:js=\"import { createRequire } from 'module'; const require = createRequire(import.meta.url);\"",
        "start": "node dist/main.js",
        "dev": "tsx src/main.ts",
        "typecheck": "tsc --noEmit"
    },
    "dependencies": {
        "@fleet-sdk/core": "^0.8.2",
        "@fleet-sdk/common": "^0.8.2",
        "@fleet-sdk/serializer": "^0.8.2",
        "@noble/ciphers": "^2.1.1",
        "@noble/curves": "^2.0.1",
        "@noble/hashes": "^2.0.1"
    },
    "devDependencies": {
        "@types/node": "^22.0.0",
        "esbuild": "^0.27.3",
        "tsx": "^4.0.0",
        "typescript": "^5.9.3"
    }
}
```

- [ ] **Step 2: Create tsconfig.json**

Create `adapters/ergo/adapter/tsconfig.json`:

```json
{
    "compilerOptions": {
        "strict": true,
        "module": "ESNext",
        "target": "ESNext",
        "moduleResolution": "bundler",
        "esModuleInterop": true,
        "outDir": "dist",
        "rootDir": "src",
        "declaration": true,
        "sourceMap": true,
        "skipLibCheck": true
    },
    "include": ["src"]
}
```

- [ ] **Step 3: Write config.ts**

Create `adapters/ergo/adapter/src/config.ts`:

```typescript
/**
 * Adapter configuration — loaded from environment variables.
 * Same pattern as the Cardano adapter config.
 */

export interface AdapterConfig {
    explorerUrl: string;
    relayUrl: string;
    operatorPrivateKey: string;
    eciesPrivateKey: string;
    guardAddress: string;
    registryNftId: string;
    brokerApiUrl: string;
    source: string;
    leaseDuration: number;
    pollIntervalMs: number;
    stateFile: string;
    network: 'testnet' | 'mainnet';
}

function requireEnv(name: string, fallback?: string): string {
    const val = process.env[name] ?? fallback;
    if (!val) {
        console.error(`Missing required environment variable: ${name}`);
        process.exit(1);
    }
    return val;
}

export function loadConfig(): AdapterConfig {
    const network = requireEnv('ERGO_NETWORK', 'testnet') as 'testnet' | 'mainnet';
    const explorerBase = network === 'mainnet'
        ? 'https://api.ergoplatform.com'
        : 'https://api-testnet.ergoplatform.com';

    return {
        explorerUrl: requireEnv('EXPLORER_URL', explorerBase),
        relayUrl: requireEnv('RELAY_URL', 'http://127.0.0.1:9064'),
        operatorPrivateKey: requireEnv('OPERATOR_PRIVATE_KEY'),
        eciesPrivateKey: requireEnv('ECIES_PRIVATE_KEY'),
        guardAddress: requireEnv('GUARD_ADDRESS'),
        registryNftId: requireEnv('REGISTRY_NFT_ID'),
        brokerApiUrl: requireEnv('BROKER_API_URL', 'http://127.0.0.1:8080'),
        source: requireEnv('ADAPTER_SOURCE', `ergo-${network}`),
        leaseDuration: parseInt(requireEnv('LEASE_DURATION', '0'), 10),
        pollIntervalMs: parseInt(requireEnv('POLL_INTERVAL_MS', '15000'), 10),
        stateFile: requireEnv(
            'STATE_FILE',
            `/var/lib/blockhost-broker/adapter-ergo-${network}.state`,
        ),
        network,
    };
}
```

- [ ] **Step 4: Install deps and verify typecheck**

```bash
cd adapters/ergo/adapter && npm install && npx tsc --noEmit
```

Expected: no type errors (config.ts is self-contained).

- [ ] **Step 5: Commit**

```bash
git add adapters/ergo/adapter/package.json adapters/ergo/adapter/tsconfig.json adapters/ergo/adapter/src/config.ts
git commit -m "feat(ergo): adapter scaffold with config"
```

---

### Task 3: Adapter — Crypto + Explorer API

ECIES encryption (identical to Cardano adapter) and lightweight Explorer/ergo-relay API wrapper.

**Files:**
- Create: `adapters/ergo/adapter/src/crypto.ts`
- Create: `adapters/ergo/adapter/src/ergo-api.ts`

- [ ] **Step 1: Write crypto.ts**

Create `adapters/ergo/adapter/src/crypto.ts`. This is the same ECIES + compact ECDH-AES-GCM + response serialization as the Cardano adapter (`adapters/cardano/adapter/src/crypto.ts`). Copy that file verbatim — the encryption scheme is chain-agnostic.

The key exports are:
- `EciesEncryption` class (ECIES decrypt request, compact encrypt response)
- `serializeResponse(resp)` → 63-byte binary
- `ResponsePayload` / `RequestPayload` types

- [ ] **Step 2: Write ergo-api.ts**

Create `adapters/ergo/adapter/src/ergo-api.ts`:

```typescript
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

/** Broadcast a signed transaction via ergo-relay. */
export async function submitTx(relayUrl: string, signedTx: unknown): Promise<string> {
    const resp = await fetch(`${relayUrl}/transactions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(signedTx, (_k, v) => typeof v === 'bigint' ? v.toString() : v),
    });
    if (!resp.ok) {
        const text = await resp.text().catch(() => '');
        throw new Error(`ergo-relay broadcast failed (${resp.status}): ${text}`);
    }
    const data = await resp.json() as { id: string } | string;
    return typeof data === 'string' ? data : data.id;
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
```

- [ ] **Step 3: Verify typecheck**

```bash
cd adapters/ergo/adapter && npx tsc --noEmit
```

- [ ] **Step 4: Commit**

```bash
git add adapters/ergo/adapter/src/crypto.ts adapters/ergo/adapter/src/ergo-api.ts
git commit -m "feat(ergo): adapter crypto and Explorer/ergo-relay API"
```

---

### Task 4: Adapter — Poller

Polls the guard script address via Explorer API for unspent boxes carrying a beacon token in `tokens(0)`.

**Files:**
- Create: `adapters/ergo/adapter/src/poller.ts`

- [ ] **Step 1: Write poller.ts**

Create `adapters/ergo/adapter/src/poller.ts`:

```typescript
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
```

- [ ] **Step 2: Verify typecheck**

```bash
cd adapters/ergo/adapter && npx tsc --noEmit
```

- [ ] **Step 3: Commit**

```bash
git add adapters/ergo/adapter/src/poller.ts
git commit -m "feat(ergo): adapter poller for request boxes"
```

---

### Task 5: Adapter — Tx Builder

Builds and submits response transactions using Fleet SDK + ergo-relay.

**Files:**
- Create: `adapters/ergo/adapter/src/tx-builder.ts`

- [ ] **Step 1: Write tx-builder.ts**

Create `adapters/ergo/adapter/src/tx-builder.ts`:

```typescript
/**
 * Builds and submits response transactions on Ergo.
 *
 * Consumes a request box, carries the beacon token to a new response
 * box at the same guard script address, with encrypted response in R5.
 *
 * Uses Fleet SDK for tx building, ergo-relay for signing + broadcast.
 */

import {
    TransactionBuilder,
    OutputBuilder,
    SAFE_MIN_BOX_VALUE,
} from '@fleet-sdk/core';
import { SColl, SByte } from '@fleet-sdk/serializer';
import { getUnspentBoxes, getHeight, signTx, submitTx, type ErgoBox } from './ergo-api.js';
import type { RequestBox } from './poller.js';

export class ResponseTxBuilder {
    constructor(
        private explorerUrl: string,
        private relayUrl: string,
        private operatorAddress: string,
        private operatorPrivateKey: string,
        private guardAddress: string,
        private guardErgoTree: string,
    ) {}

    /**
     * Build, sign, and submit a response transaction.
     *
     * Transaction structure:
     *   Input 0: request box (at guard address, carries beacon)
     *   Output 0: response box (at guard address, same beacon, R5 = encrypted response)
     *   Output 1: change to operator
     *   Output 2: miner fee
     */
    async submitResponse(
        request: RequestBox,
        encryptedResponse: Uint8Array,
    ): Promise<string> {
        console.log(`[tx-builder] Building response for beacon ${request.beaconTokenId.slice(0, 16)}...`);

        const height = await getHeight(this.explorerUrl);

        // Fetch operator's UTXOs to fund the transaction fee
        const operatorBoxes = await getUnspentBoxes(this.explorerUrl, this.operatorAddress);
        if (operatorBoxes.length === 0) {
            throw new Error('No UTXOs available for operator address');
        }

        // Convert ErgoBox to Fleet SDK input format
        const requestInput = toFleetBox(request.box);
        const funderInputs = operatorBoxes.map(toFleetBox);

        // Build R4 (carry forward client pubkey) and R5 (encrypted response)
        const r4 = SColl(SByte, Uint8Array.from(Buffer.from(request.clientPubkeyHex, 'hex'))).toHex();
        const r5 = SColl(SByte, encryptedResponse).toHex();

        // Build the response output: same guard script, same beacon, new R5
        const responseOutput = new OutputBuilder(SAFE_MIN_BOX_VALUE, this.guardAddress)
            .addTokens({ tokenId: request.beaconTokenId, amount: 1n })
            .setAdditionalRegisters({ R4: r4, R5: r5 });

        // Build unsigned transaction
        const unsignedTx = new TransactionBuilder(height)
            .from([requestInput, ...funderInputs])
            .to(responseOutput)
            .sendChangeTo(this.operatorAddress)
            .payMinFee()
            .build();

        // Sign via ergo-relay
        const allInputBoxes = [request.box, ...operatorBoxes];
        const signedTx = await signTx(
            this.relayUrl,
            unsignedTx,
            [this.operatorPrivateKey],
            allInputBoxes,
            height,
        );

        // Broadcast via ergo-relay
        const txId = await submitTx(this.relayUrl, signedTx);
        console.log(`[tx-builder] Response tx submitted: ${txId}`);
        return txId;
    }
}

/** Convert our ErgoBox type to Fleet SDK's Box format. */
function toFleetBox(box: ErgoBox): any {
    return {
        boxId: box.boxId,
        transactionId: box.transactionId,
        index: box.index,
        value: box.value.toString(),
        ergoTree: box.ergoTree,
        creationHeight: box.creationHeight,
        assets: box.assets.map(a => ({
            tokenId: a.tokenId,
            amount: a.amount.toString(),
        })),
        additionalRegisters: box.additionalRegisters,
    };
}
```

- [ ] **Step 2: Verify typecheck**

```bash
cd adapters/ergo/adapter && npx tsc --noEmit
```

- [ ] **Step 3: Commit**

```bash
git add adapters/ergo/adapter/src/tx-builder.ts
git commit -m "feat(ergo): adapter response tx builder"
```

---

### Task 6: Adapter — Main orchestrator

Wires config, poller, crypto, and tx-builder together. Handles graceful shutdown and persistent state.

**Files:**
- Create: `adapters/ergo/adapter/src/main.ts`

- [ ] **Step 1: Write main.ts**

Create `adapters/ergo/adapter/src/main.ts`:

```typescript
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
import { EciesEncryption, serializeResponse, type ResponsePayload } from './crypto.js';
import { RequestPoller, type RequestBox } from './poller.js';
import { ResponseTxBuilder } from './tx-builder.js';
import { secp256k1 } from '@noble/curves/secp256k1';
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

// ── Broker API client ──────────────────────────────────────────────

interface AllocationResponse {
    prefix: string;
    gateway: string;
    broker_pubkey: string;
    broker_endpoint: string;
}

async function requestAllocation(wgPubkey: string): Promise<AllocationResponse> {
    const url = `${config.brokerApiUrl}/v1/allocations`;
    const body = JSON.stringify({
        wg_pubkey: wgPubkey,
        nft_contract: config.guardAddress,
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
            allocation = await requestAllocation(payload.wgPubkey);
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
const operatorPubkeyHex = Buffer.from(
    secp256k1.getPublicKey(config.operatorPrivateKey, true),
).toString('hex');
const operatorAddress = p2pkAddress(operatorPubkeyHex, isMainnet);

const txBuilder = new ResponseTxBuilder(
    config.explorerUrl,
    config.relayUrl,
    operatorAddress,
    config.operatorPrivateKey,
    config.guardAddress,
    '', // guardErgoTree — not needed for tx building, only for address derivation
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
```

- [ ] **Step 2: Build the adapter**

```bash
cd adapters/ergo/adapter && npm run build
```

Expected: `dist/main.js` created.

- [ ] **Step 3: Commit**

```bash
git add adapters/ergo/adapter/src/main.ts
git commit -m "feat(ergo): adapter main orchestrator"
```

---

### Task 7: Client — Package scaffold + crypto + API

Set up the client package with the same crypto and API modules.

**Files:**
- Create: `adapters/ergo/client/package.json`
- Create: `adapters/ergo/client/tsconfig.json`
- Create: `adapters/ergo/client/src/crypto.ts`
- Create: `adapters/ergo/client/src/ergo-api.ts`

- [ ] **Step 1: Create package.json**

Create `adapters/ergo/client/package.json`:

```json
{
    "name": "blockhost-client-ergo",
    "version": "0.1.0",
    "type": "module",
    "scripts": {
        "build": "esbuild src/main.ts --bundle --platform=node --format=esm --outfile=dist/main.js --target=node22 --banner:js=\"import { createRequire } from 'module'; const require = createRequire(import.meta.url);\"",
        "start": "node dist/main.js",
        "dev": "tsx src/main.ts",
        "typecheck": "tsc --noEmit"
    },
    "dependencies": {
        "@fleet-sdk/core": "^0.8.2",
        "@fleet-sdk/common": "^0.8.2",
        "@fleet-sdk/serializer": "^0.8.2",
        "@noble/ciphers": "^2.1.1",
        "@noble/curves": "^2.0.1",
        "@noble/hashes": "^2.0.1"
    },
    "devDependencies": {
        "@types/node": "^22.0.0",
        "esbuild": "^0.27.3",
        "tsx": "^4.0.0",
        "typescript": "^5.9.3"
    }
}
```

- [ ] **Step 2: Create tsconfig.json**

Same as adapter — copy `adapters/ergo/adapter/tsconfig.json`.

- [ ] **Step 3: Copy crypto.ts and ergo-api.ts from adapter**

Copy `adapters/ergo/adapter/src/crypto.ts` → `adapters/ergo/client/src/crypto.ts`.

Copy `adapters/ergo/adapter/src/ergo-api.ts` → `adapters/ergo/client/src/ergo-api.ts`.

The client additionally needs ECIES encryption (request payload), compact decryption (response), and WireGuard keypair generation. These are already in the Cardano client's `crypto.ts` — merge those functions into the client's copy:

Add to `adapters/ergo/client/src/crypto.ts` (from Cardano client):

```typescript
// ── Client-side additions ───────────────────────────────────────────

import { x25519 } from '@noble/curves/ed25519';
import { randomBytes } from 'crypto';

export interface TunnelConfig {
    prefix: string;
    gateway: string;
    brokerPubkey: string;
    brokerEndpoint: string;
}

export function generateWgKeypair(): {
    privateKey: Uint8Array; privateKeyBase64: string;
    publicKey: Uint8Array; publicKeyBase64: string;
} {
    const privateKey = x25519.utils.randomPrivateKey();
    const publicKey = x25519.scalarMultBase(privateKey);
    return {
        privateKey,
        privateKeyBase64: Buffer.from(privateKey).toString('base64'),
        publicKey,
        publicKeyBase64: Buffer.from(publicKey).toString('base64'),
    };
}

export function generateServerKeypair(): {
    privateKey: Uint8Array;
    publicKeyCompressed: Uint8Array;
} {
    const priv = secp256k1.utils.randomPrivateKey();
    const pub = secp256k1.getPublicKey(priv, true);
    return { privateKey: priv, publicKeyCompressed: pub };
}

export function serializeRequestPayload(wgPubkey: Uint8Array, serverPubCompressed: Uint8Array): Uint8Array {
    const buf = new Uint8Array(65);
    buf.set(wgPubkey, 0);
    buf.set(serverPubCompressed, 32);
    return buf;
}

export function eciesEncrypt(plaintext: Uint8Array, recipientPub: Uint8Array): Uint8Array {
    const ephPriv = secp256k1.utils.randomPrivateKey();
    const ephPub = secp256k1.getPublicKey(ephPriv, false); // uncompressed 65 bytes
    const shared = secp256k1.getSharedSecret(ephPriv, recipientPub);
    const aesKey = hkdf(sha256, shared.slice(1), undefined, undefined, 32);
    const iv = randomBytes(16);
    const cipher = gcm(aesKey, iv);
    const encrypted = cipher.encrypt(plaintext);
    // eciespy format: [65 ephPub][16 tag][16 iv][ciphertext]
    const ciphertext = encrypted.slice(0, encrypted.length - 16);
    const tag = encrypted.slice(encrypted.length - 16);
    const result = new Uint8Array(65 + 16 + 16 + ciphertext.length);
    result.set(ephPub, 0);
    result.set(tag, 65);
    result.set(iv, 65 + 16);
    result.set(ciphertext, 65 + 16 + 16);
    return result;
}

export function decryptCompact(
    encrypted: Uint8Array,
    senderPrivkey: Uint8Array,
    recipientPubkey: Uint8Array,
): Uint8Array {
    const { aesKey, iv } = deriveKeyAndIv(senderPrivkey, recipientPubkey);
    const decipher = gcm(aesKey, iv);
    return decipher.decrypt(encrypted);
}

export function deserializeResponse(data: Uint8Array): TunnelConfig {
    let offset = 0;
    const wgKey = Buffer.from(data.slice(offset, offset + 32)).toString('base64');
    offset += 32;
    const ip = `${data[offset]}.${data[offset+1]}.${data[offset+2]}.${data[offset+3]}`;
    offset += 4;
    const port = (data[offset]! << 8) | data[offset+1]!;
    offset += 2;
    const mask = data[offset]!;
    offset += 1;
    const prefixBytes = data.slice(offset, offset + 16);
    offset += 16;
    const gwHostBytes = data.slice(offset, offset + 8);

    const prefix = formatIpv6(prefixBytes) + '/' + mask;
    const gwFull = new Uint8Array(16);
    gwFull.set(prefixBytes.slice(0, 8), 0);
    gwFull.set(gwHostBytes, 8);
    const gateway = formatIpv6(gwFull);

    return {
        prefix,
        gateway,
        brokerPubkey: wgKey,
        brokerEndpoint: `${ip}:${port}`,
    };
}

function formatIpv6(bytes: Uint8Array): string {
    const groups: string[] = [];
    for (let i = 0; i < 16; i += 2) {
        groups.push(((bytes[i]! << 8) | bytes[i+1]!).toString(16));
    }
    return groups.join(':').replace(/(^|:)0(:0)*(:|$)/, '::').replace(/:::+/, '::');
}
```

- [ ] **Step 4: Install deps and verify typecheck**

```bash
cd adapters/ergo/client && npm install && npx tsc --noEmit
```

- [ ] **Step 5: Commit**

```bash
git add adapters/ergo/client/
git commit -m "feat(ergo): client scaffold with crypto and API"
```

---

### Task 8: Client — Tx Builder

Builds request transactions (mint beacon + send to guard address with encrypted payload) and cleanup transactions (consume response box, burn beacon).

**Files:**
- Create: `adapters/ergo/client/src/tx-builder.ts`

- [ ] **Step 1: Write tx-builder.ts**

Create `adapters/ergo/client/src/tx-builder.ts`:

```typescript
/**
 * Client-side transaction building for Ergo.
 *
 * - Request tx: mint beacon token, send to guard address with client pubkey
 *   in R4 and encrypted payload in R5
 * - Cleanup tx: consume response box, burn beacon token
 *
 * Uses Fleet SDK for tx building, ergo-relay for signing + broadcast.
 */

import {
    TransactionBuilder,
    OutputBuilder,
    SAFE_MIN_BOX_VALUE,
} from '@fleet-sdk/core';
import { SColl, SByte } from '@fleet-sdk/serializer';
import {
    getUnspentBoxes,
    getHeight,
    signTx,
    submitTx,
    type ErgoBox,
} from './ergo-api.js';

export class ClientTxBuilder {
    constructor(
        private explorerUrl: string,
        private relayUrl: string,
        private clientAddress: string,
        private clientPrivateKey: string,
        private clientPubkeyHex: string,
        private guardAddress: string,
    ) {}

    /**
     * Build and submit a request transaction.
     *
     * Mints a beacon token (amount=1, ID = first input box ID),
     * sends it to the guard address with R4 (client pubkey) and R5 (encrypted payload).
     *
     * Returns the tx ID and beacon token ID.
     */
    async submitRequest(encryptedPayload: Uint8Array): Promise<{
        txId: string;
        beaconTokenId: string;
    }> {
        const height = await getHeight(this.explorerUrl);

        // Fetch client's UTXOs
        const clientBoxes = await getUnspentBoxes(this.explorerUrl, this.clientAddress);
        if (clientBoxes.length === 0) {
            throw new Error('No UTXOs available for client address');
        }

        const inputs = clientBoxes.map(toFleetBox);

        // Beacon token ID will be the first input's box ID
        const beaconTokenId = clientBoxes[0]!.boxId;

        // Build registers
        const r4 = SColl(SByte, Uint8Array.from(Buffer.from(this.clientPubkeyHex, 'hex'))).toHex();
        const r5 = SColl(SByte, encryptedPayload).toHex();

        // Build request output at guard address
        const requestOutput = new OutputBuilder(SAFE_MIN_BOX_VALUE, this.guardAddress)
            .mintToken({
                amount: 1n,
                name: 'blockhost-request',
            })
            .setAdditionalRegisters({ R4: r4, R5: r5 });

        const unsignedTx = new TransactionBuilder(height)
            .from(inputs)
            .to(requestOutput)
            .sendChangeTo(this.clientAddress)
            .payMinFee()
            .build();

        const signedTx = await signTx(
            this.relayUrl,
            unsignedTx,
            [this.clientPrivateKey],
            clientBoxes,
            height,
        );

        const txId = await submitTx(this.relayUrl, signedTx);
        console.error(`[tx] Request tx: ${txId}, beacon: ${beaconTokenId}`);
        return { txId, beaconTokenId };
    }

    /**
     * Build and submit a cleanup transaction.
     *
     * Consumes the response box (client signs) and burns the beacon token.
     * Returns ERG to client address.
     */
    async cleanupResponse(responseBox: ErgoBox, beaconTokenId: string): Promise<string> {
        const height = await getHeight(this.explorerUrl);

        // May need additional client boxes for fee
        const clientBoxes = await getUnspentBoxes(this.explorerUrl, this.clientAddress);
        const inputs = [toFleetBox(responseBox), ...clientBoxes.map(toFleetBox)];
        const allBoxes = [responseBox, ...clientBoxes];

        const unsignedTx = new TransactionBuilder(height)
            .from(inputs)
            .burnTokens({ tokenId: beaconTokenId, amount: 1n })
            .sendChangeTo(this.clientAddress)
            .payMinFee()
            .build();

        const signedTx = await signTx(
            this.relayUrl,
            unsignedTx,
            [this.clientPrivateKey],
            allBoxes,
            height,
        );

        const txId = await submitTx(this.relayUrl, signedTx);
        console.error(`[tx] Cleanup tx: ${txId}`);
        return txId;
    }
}

function toFleetBox(box: ErgoBox): any {
    return {
        boxId: box.boxId,
        transactionId: box.transactionId,
        index: box.index,
        value: box.value.toString(),
        ergoTree: box.ergoTree,
        creationHeight: box.creationHeight,
        assets: box.assets.map(a => ({
            tokenId: a.tokenId,
            amount: a.amount.toString(),
        })),
        additionalRegisters: box.additionalRegisters,
    };
}
```

- [ ] **Step 2: Verify typecheck**

```bash
cd adapters/ergo/client && npx tsc --noEmit
```

- [ ] **Step 3: Commit**

```bash
git add adapters/ergo/client/src/tx-builder.ts
git commit -m "feat(ergo): client request and cleanup tx builder"
```

---

### Task 9: Client — Main entry point

Subprocess mode: parse args, load key, fetch registry, submit request, watch for response, output JSON.

**Files:**
- Create: `adapters/ergo/client/src/main.ts`

- [ ] **Step 1: Write main.ts**

Create `adapters/ergo/client/src/main.ts`:

```typescript
/**
 * BlockHost Ergo client — subprocess mode.
 *
 * Submits a request box to the guard address, watches for the
 * broker's response box, and outputs tunnel configuration
 * as a single JSON line to stdout.
 *
 * Usage:
 *   node dist/main.js request \
 *     --explorer-url https://api-testnet.ergoplatform.com \
 *     --signing-key /path/to/key.hex \
 *     --registry-nft-id abc123...
 */

import { existsSync, readFileSync, writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
    eciesEncrypt,
    decryptCompact,
    deserializeResponse,
    generateWgKeypair,
    generateServerKeypair,
    serializeRequestPayload,
} from './crypto.js';
import { ClientTxBuilder } from './tx-builder.js';
import {
    getBoxesByTokenId,
    decodeCollByte,
    type ErgoBox,
} from './ergo-api.js';
import { p2pkAddress } from '../../contracts/contracts.js';

// ── Logging ─────────────────────────────────────────────────────────

function log(msg: string): void {
    process.stderr.write(`[ergo-client] ${msg}\n`);
}

function fatal(msg: string): never {
    process.stderr.write(`[ergo-client] FATAL: ${msg}\n`);
    process.exit(1);
}

// ── Arg parsing ─────────────────────────────────────────────────────

interface Args {
    command: string;
    explorerUrl: string;
    relayUrl: string;
    signingKey: string;
    registryNftId: string;
    timeoutMs: number;
}

function parseArgs(): Args {
    const argv = process.argv.slice(2);
    const command = argv[0];

    if (!command || command === '--help') {
        process.stderr.write(
            `Usage: node dist/main.js request [options]\n\n` +
            `  --explorer-url URL    Explorer API URL\n` +
            `  --relay-url URL       ergo-relay URL (default: http://127.0.0.1:9064)\n` +
            `  --signing-key PATH    Hex private key file\n` +
            `  --registry-nft-id ID  Registry NFT token ID (64 hex chars)\n` +
            `  --timeout N           Response timeout in seconds (default: 600)\n`,
        );
        process.exit(command ? 0 : 1);
    }

    function getFlag(names: string[], fallback?: string): string {
        for (const name of names) {
            const idx = argv.indexOf(name);
            if (idx !== -1 && idx + 1 < argv.length) return argv[idx + 1]!;
        }
        if (fallback !== undefined) return fallback;
        fatal(`Missing required argument: ${names.join(' | ')}`);
    }

    return {
        command,
        explorerUrl: getFlag(['--explorer-url', '--rpc-url'], 'https://api-testnet.ergoplatform.com'),
        relayUrl: getFlag(['--relay-url'], 'http://127.0.0.1:9064'),
        signingKey: getFlag(['--signing-key']),
        registryNftId: getFlag(['--registry-nft-id']),
        timeoutMs: Number(getFlag(['--timeout'], '600')) * 1000,
    };
}

// ── Key loading ─────────────────────────────────────────────────────

function loadSigningKey(keyOrPath: string): { privKeyHex: string; pubKeyHex: string; address: string } {
    let content: string;
    if (existsSync(keyOrPath)) {
        content = readFileSync(keyOrPath, 'utf-8').trim();
    } else {
        content = keyOrPath;
    }
    if (content.startsWith('0x')) content = content.slice(2);
    if (content.length !== 64) {
        fatal(`Signing key must be 32 bytes hex (64 chars), got ${content.length}`);
    }

    const pubKey = Buffer.from(secp256k1.getPublicKey(content, true)).toString('hex');
    const addr = p2pkAddress(pubKey, false); // testnet by default
    return { privKeyHex: content, pubKeyHex: pubKey, address: addr };
}

// ── Registry ────────────────────────────────────────────────────────

interface RegistryInfo {
    operatorPubkeyHex: string;
    eciesPubkeyHex: string;
    guardErgoTreeHex: string;
    guardAddress: string;
}

async function fetchRegistry(explorerUrl: string, nftId: string): Promise<RegistryInfo> {
    const boxes = await getBoxesByTokenId(explorerUrl, nftId);
    if (boxes.length === 0) throw new Error('Registry NFT not found');

    // Take the box that actually holds the NFT
    const registryBox = boxes.find(b => b.assets.some(a => a.tokenId === nftId && a.amount === 1n));
    if (!registryBox) throw new Error('Registry NFT box not found');

    const r4 = registryBox.additionalRegisters['R4'];
    const r5 = registryBox.additionalRegisters['R5'];
    const r6 = registryBox.additionalRegisters['R6'];
    if (!r4 || !r5 || !r6) throw new Error('Registry box missing registers');

    const operatorPubkey = decodeCollByte(r4);
    const eciesPubkey = decodeCollByte(r5);
    const guardErgoTree = decodeCollByte(r6);

    if (operatorPubkey.length !== 33) throw new Error(`Invalid operator pubkey length: ${operatorPubkey.length}`);
    if (eciesPubkey.length !== 33) throw new Error(`Invalid ECIES pubkey length: ${eciesPubkey.length}`);

    const guardErgoTreeHex = Buffer.from(guardErgoTree).toString('hex');
    const { ErgoAddress, Network } = await import('@fleet-sdk/core');
    const guardAddress = ErgoAddress.fromErgoTree(guardErgoTreeHex, Network.Testnet).encode(Network.Testnet);

    return {
        operatorPubkeyHex: Buffer.from(operatorPubkey).toString('hex'),
        eciesPubkeyHex: Buffer.from(eciesPubkey).toString('hex'),
        guardErgoTreeHex,
        guardAddress,
    };
}

// ── Recovery ────────────────────────────────────────────────────────

const RECOVERY_FILE = '/var/lib/blockhost/ergo-recovery.json';

interface RecoveryState {
    beaconTokenId: string;
    serverPrivkeyHex: string;
    brokerPubkeyHex: string;
    guardAddress: string;
    operatorPubkeyHex: string;
    wgPrivateKeyBase64: string;
    wgPublicKeyBase64: string;
    explorerUrl: string;
    savedAt: string;
}

function saveRecoveryState(state: RecoveryState): void {
    mkdirSync(dirname(RECOVERY_FILE), { recursive: true });
    writeFileSync(RECOVERY_FILE, JSON.stringify(state, null, 2));
    log(`Recovery state saved`);
}

function loadRecoveryState(): RecoveryState | null {
    if (!existsSync(RECOVERY_FILE)) return null;
    try { return JSON.parse(readFileSync(RECOVERY_FILE, 'utf-8')); } catch { return null; }
}

function clearRecoveryState(): void {
    try { if (existsSync(RECOVERY_FILE)) unlinkSync(RECOVERY_FILE); } catch {}
}

// ── Response watcher ────────────────────────────────────────────────

const RESPONSE_POLL_MS = 10_000;

async function watchForResponse(
    explorerUrl: string,
    beaconTokenId: string,
    serverPrivkey: Uint8Array,
    brokerPub: Uint8Array,
    timeoutMs: number,
): Promise<{ config: ReturnType<typeof deserializeResponse>; responseBox: ErgoBox }> {
    log(`Watching for response (beacon=${beaconTokenId.slice(0, 16)}..., timeout=${timeoutMs / 1000}s)`);
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
        try {
            const boxes = await getBoxesByTokenId(explorerUrl, beaconTokenId);

            for (const box of boxes) {
                // Must have R5 (encrypted response)
                const r5Hex = box.additionalRegisters['R5'];
                if (!r5Hex) continue;

                const encrypted = decodeCollByte(r5Hex);
                try {
                    const plaintext = decryptCompact(encrypted, serverPrivkey, brokerPub);
                    log(`Response found in box ${box.boxId.slice(0, 16)}...`);
                    return { config: deserializeResponse(plaintext), responseBox: box };
                } catch {
                    // Decryption failed — might be the request box (our own encrypted payload),
                    // or a response encrypted for someone else. Skip.
                }
            }
        } catch (e) {
            log(`Query failed, will retry: ${e}`);
        }

        await new Promise(r => setTimeout(r, RESPONSE_POLL_MS));
    }

    throw new Error('Timed out waiting for broker response');
}

// ── Request command ─────────────────────────────────────────────────

async function cmdRequest(args: Args): Promise<void> {
    // Check for recovery
    const recovery = loadRecoveryState();
    if (recovery) {
        log('Found recovery state, attempting re-scan...');
        const serverPriv = Uint8Array.from(Buffer.from(recovery.serverPrivkeyHex, 'hex'));
        const brokerPub = Uint8Array.from(Buffer.from(recovery.brokerPubkeyHex, 'hex'));
        try {
            const { config } = await watchForResponse(
                recovery.explorerUrl,
                recovery.beaconTokenId,
                serverPriv,
                brokerPub,
                60_000,
            );
            clearRecoveryState();
            process.stdout.write(JSON.stringify({
                prefix: config.prefix,
                gateway: config.gateway,
                broker_pubkey: config.brokerPubkey,
                broker_endpoint: config.brokerEndpoint,
                wg_private_key: recovery.wgPrivateKeyBase64,
                wg_public_key: recovery.wgPublicKeyBase64,
                broker_wallet: p2pkAddress(recovery.operatorPubkeyHex, false),
            }) + '\n');
            return;
        } catch {
            log('Recovery scan found no response, proceeding fresh');
            clearRecoveryState();
        }
    }

    // 1. Load signing key
    const key = loadSigningKey(args.signingKey);
    log(`Client: ${key.address}`);

    // 2. Fetch registry
    log('Fetching registry...');
    const registry = await fetchRegistry(args.explorerUrl, args.registryNftId);
    log(`Guard: ${registry.guardAddress}`);

    // 3. Generate keypairs
    const wgKeys = generateWgKeypair();
    const serverKeys = generateServerKeypair();
    log(`WG pubkey: ${wgKeys.publicKeyBase64}`);

    // 4. Encrypt request payload
    const payload = serializeRequestPayload(wgKeys.publicKey, serverKeys.publicKeyCompressed);
    const eciesPub = Buffer.from(registry.eciesPubkeyHex, 'hex');
    const eciesPubUncompressed = secp256k1.ProjectivePoint.fromHex(eciesPub).toRawBytes(false);
    const encrypted = eciesEncrypt(payload, eciesPubUncompressed);
    log(`Encrypted payload: ${encrypted.length} bytes`);

    // 5. Submit request tx
    const txBuilder = new ClientTxBuilder(
        args.explorerUrl,
        args.relayUrl,
        key.address,
        key.privKeyHex,
        key.pubKeyHex,
        registry.guardAddress,
    );

    log('Submitting request transaction...');
    const { beaconTokenId } = await txBuilder.submitRequest(encrypted);

    // 6. Save recovery state
    saveRecoveryState({
        beaconTokenId,
        serverPrivkeyHex: Buffer.from(serverKeys.privateKey).toString('hex'),
        brokerPubkeyHex: Buffer.from(eciesPubUncompressed).toString('hex'),
        guardAddress: registry.guardAddress,
        operatorPubkeyHex: registry.operatorPubkeyHex,
        wgPrivateKeyBase64: wgKeys.privateKeyBase64,
        wgPublicKeyBase64: wgKeys.publicKeyBase64,
        explorerUrl: args.explorerUrl,
        savedAt: new Date().toISOString(),
    });

    // 7. Watch for response
    try {
        const { config, responseBox } = await watchForResponse(
            args.explorerUrl,
            beaconTokenId,
            serverKeys.privateKey,
            eciesPubUncompressed,
            args.timeoutMs,
        );

        clearRecoveryState();

        process.stdout.write(JSON.stringify({
            prefix: config.prefix,
            gateway: config.gateway,
            broker_pubkey: config.brokerPubkey,
            broker_endpoint: config.brokerEndpoint,
            wg_private_key: wgKeys.privateKeyBase64,
            wg_public_key: wgKeys.publicKeyBase64,
            broker_wallet: p2pkAddress(registry.operatorPubkeyHex, false),
        }) + '\n');

        // 8. Cleanup response box (best effort)
        try {
            await txBuilder.cleanupResponse(responseBox, beaconTokenId);
        } catch (e) {
            log(`Cleanup failed (non-fatal): ${e}`);
        }
    } catch (e) {
        log(`Watch failed: ${e} — recovery state preserved`);
        throw e;
    }
}

// ── Entry ───────────────────────────────────────────────────────────

const args = parseArgs();
if (args.command === 'request') {
    cmdRequest(args).catch(err => fatal(String(err)));
} else {
    fatal(`Unknown command: ${args.command}`);
}
```

- [ ] **Step 2: Build the client**

```bash
cd adapters/ergo/client && npm run build
```

Expected: `dist/main.js` created.

- [ ] **Step 3: Commit**

```bash
git add adapters/ergo/client/src/main.ts
git commit -m "feat(ergo): client main entry point"
```

---

### Task 10: Registry deploy script

Mints the singleton registry NFT with broker config in registers R4-R6.

**Files:**
- Create: `adapters/ergo/deploy-registry.ts`

- [ ] **Step 1: Write deploy-registry.ts**

Create `adapters/ergo/deploy-registry.ts`:

```typescript
/**
 * Deploy the broker registry NFT on Ergo.
 *
 * Mints a singleton NFT (amount=1) with broker config in registers:
 *   R4: Coll[Byte] — operator compressed public key (33 bytes)
 *   R5: Coll[Byte] — ECIES compressed public key (33 bytes)
 *   R6: Coll[Byte] — guard script ErgoTree bytes
 *
 * Usage:
 *   DEPLOYER_KEY=<hex> OPERATOR_PK=<hex> ECIES_PK=<hex> \
 *     EXPLORER_URL=https://api-testnet.ergoplatform.com \
 *     npx tsx deploy-registry.ts
 */

import {
    TransactionBuilder,
    OutputBuilder,
    SAFE_MIN_BOX_VALUE,
} from '@fleet-sdk/core';
import { SColl, SByte } from '@fleet-sdk/serializer';
import { secp256k1 } from '@noble/curves/secp256k1';
import { getUnspentBoxes, getHeight, signTx, submitTx } from './adapter/src/ergo-api.js';
import { getGuardErgoTree, p2pkAddress } from './contracts/contracts.js';

function requireEnv(name: string): string {
    const val = process.env[name];
    if (!val) { console.error(`Missing: ${name}`); process.exit(1); }
    return val;
}

async function main() {
    const deployerKeyHex = requireEnv('DEPLOYER_KEY');
    const operatorPkHex = requireEnv('OPERATOR_PK');
    const eciesPkHex = requireEnv('ECIES_PK');
    const explorerUrl = requireEnv('EXPLORER_URL');
    const relayUrl = process.env.RELAY_URL ?? 'http://127.0.0.1:9064';

    // Derive deployer address
    const deployerPub = Buffer.from(secp256k1.getPublicKey(deployerKeyHex, true)).toString('hex');
    const deployerAddr = p2pkAddress(deployerPub, false);
    console.log(`Deployer: ${deployerAddr}`);

    // Derive guard ErgoTree from operator PK
    const guardErgoTree = getGuardErgoTree(operatorPkHex);
    console.log(`Guard ErgoTree: ${guardErgoTree.slice(0, 40)}... (${guardErgoTree.length / 2} bytes)`);

    // Fetch deployer UTXOs
    const boxes = await getUnspentBoxes(explorerUrl, deployerAddr);
    if (boxes.length === 0) throw new Error('No UTXOs for deployer');

    const height = await getHeight(explorerUrl);
    const inputs = boxes.map(b => ({
        boxId: b.boxId, transactionId: b.transactionId, index: b.index,
        value: b.value.toString(), ergoTree: b.ergoTree,
        creationHeight: b.creationHeight,
        assets: b.assets.map(a => ({ tokenId: a.tokenId, amount: a.amount.toString() })),
        additionalRegisters: b.additionalRegisters,
    }));

    // Registry NFT token ID = first input box ID
    const nftId = boxes[0]!.boxId;

    // Build registers
    const r4 = SColl(SByte, Uint8Array.from(Buffer.from(operatorPkHex, 'hex'))).toHex();
    const r5 = SColl(SByte, Uint8Array.from(Buffer.from(eciesPkHex, 'hex'))).toHex();
    const r6 = SColl(SByte, Uint8Array.from(Buffer.from(guardErgoTree, 'hex'))).toHex();

    const registryOutput = new OutputBuilder(SAFE_MIN_BOX_VALUE, deployerAddr)
        .mintToken({ amount: 1n, name: 'BlockHost Broker Registry', description: 'Broker config singleton' })
        .setAdditionalRegisters({ R4: r4, R5: r5, R6: r6 });

    const unsignedTx = new TransactionBuilder(height)
        .from(inputs)
        .to(registryOutput)
        .sendChangeTo(deployerAddr)
        .payMinFee()
        .build();

    const signedTx = await signTx(relayUrl, unsignedTx, [deployerKeyHex], boxes, height);
    const txId = await submitTx(relayUrl, signedTx);

    console.log(`Registry NFT minted!`);
    console.log(`  TX: ${txId}`);
    console.log(`  NFT ID: ${nftId}`);
    console.log(`\nAdd to registry-ergo-testnet.json:`);
    console.log(JSON.stringify({
        registry_nft_id: nftId,
        explorer_url: explorerUrl,
        network: 'ergo-testnet',
    }, null, 2));
}

main().catch(err => { console.error(err); process.exit(1); });
```

- [ ] **Step 2: Commit**

```bash
git add adapters/ergo/deploy-registry.ts
git commit -m "feat(ergo): registry NFT deploy script"
```

---

### Task 11: Integration — chain dispatch, .deb, wizard, broker manager

Wire the Ergo adapter into the broker's multichain infrastructure.

**Files:**
- Modify: `scripts/broker-chains.json`
- Modify: `scripts/build-deb.sh`
- Modify: `scripts/wizard/broker.json`
- Create: `registry-ergo-testnet.json`
- Modify: `blockhost-broker-manager/manager/broker.py`
- Modify: `blockhost-broker-manager/manager/app.py`
- Modify: `blockhost-broker-manager/manager/templates/dashboard.html`

- [ ] **Step 1: Add Ergo to broker-chains.json**

Add an Ergo entry to `scripts/broker-chains.json`. Ergo testnet P2PK addresses start with `3` and are 51 chars. Mainnet P2PK addresses start with `9` and are 51 chars. P2S addresses start with other prefixes. For the match pattern, use Ergo's Base58 address format:

```json
{
    "name": "ergo",
    "match": "^[1-9A-HJ-NP-Za-km-z]{40,60}$",
    "adapter": "node",
    "adapter_args": [
        "/opt/blockhost/adapters/ergo/client/dist/main.js",
        "request"
    ],
    "timeout": 600,
    "explorer_url": "https://api-testnet.ergoplatform.com",
    "registry_nft_id": ""
}
```

Note: `registry_nft_id` is filled in after deploying the registry NFT.

- [ ] **Step 2: Add Ergo client to build-deb.sh**

Add after the Cardano client section in `scripts/build-deb.sh`:

```bash
# Ergo client (esbuild bundle — single file, no node_modules needed)
ERGO_CLIENT="${REPO_ROOT}/adapters/ergo/client"
if [ -d "$ERGO_CLIENT/src" ]; then
    echo "Building Ergo client plugin..."
    DEST="build/${PKG_NAME}/opt/blockhost/adapters/ergo/client"
    mkdir -p "$DEST/dist"

    if [ ! -d "$ERGO_CLIENT/node_modules" ]; then
        (cd "$ERGO_CLIENT" && npm ci --ignore-scripts)
    fi

    (cd "$ERGO_CLIENT" && npm run build)
    cp "$ERGO_CLIENT/dist/main.js" "$DEST/dist/"
fi
```

Update the `.deb` description to include Ergo:
```
 Includes chain client plugins:
  - EVM (builtin, Python)
  - OPNet (Bitcoin L1, TypeScript subprocess)
  - Cardano (TypeScript subprocess)
  - Ergo (TypeScript subprocess)
```

- [ ] **Step 3: Add Ergo to wizard/broker.json**

Add to the `chains` object in `scripts/wizard/broker.json`:

```json
"ergo": {
    "wallet_pattern": "^[1-9A-HJ-NP-Za-km-z]{40,60}$",
    "contract_validation": "^[1-9A-HJ-NP-Za-km-z]{40,60}$",
    "fields": [
        {
            "name": "broker_registry",
            "type": "text",
            "label": "Registry NFT ID",
            "placeholder": "64 hex chars...",
            "hint": "The Ergo token ID of the broker registry NFT.",
            "has_auto_fetch": true
        }
    ]
}
```

- [ ] **Step 4: Create registry-ergo-testnet.json**

Create `registry-ergo-testnet.json`:

```json
{
    "registry_nft_id": "",
    "explorer_url": "https://api-testnet.ergoplatform.com",
    "network": "ergo-testnet"
}
```

Placeholder — filled in after registry deployment.

- [ ] **Step 5: Add Ergo wallet info to broker manager**

Add to `blockhost-broker-manager/manager/broker.py`:

```python
@dataclass
class ErgoWalletInfo:
    address: str
    balance_erg: float
    explorer_url: str

def get_ergo_wallet_info() -> Optional[ErgoWalletInfo]:
    """Fetch Ergo operator wallet balance via Explorer API."""
    config = get_broker_config()
    ergo_section = config.get('ergo', {})
    address = ergo_section.get('operator_address', '')
    explorer_url = ergo_section.get('explorer_url', 'https://api-testnet.ergoplatform.com')

    if not address:
        return None

    try:
        resp = requests.get(
            f"{explorer_url}/api/v1/addresses/{address}/balance/total",
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        nano_erg = int(data.get('confirmed', {}).get('nanoErgs', 0))
        return ErgoWalletInfo(
            address=address,
            balance_erg=nano_erg / 1_000_000_000,
            explorer_url=explorer_url,
        )
    except Exception:
        return ErgoWalletInfo(address=address, balance_erg=0.0, explorer_url=explorer_url)
```

Wire it into `app.py` (in the dashboard route, alongside existing wallet info fetches):

```python
ergo_wallet = broker.get_ergo_wallet_info()
```

Pass `ergo_wallet=ergo_wallet` to the template.

Add to `dashboard.html` (after the Cardano wallet section):

```html
{% if ergo_wallet %}
<div class="card mb-4">
    <div class="card-header"><h5 class="mb-0">Ergo Operator Wallet</h5></div>
    <div class="card-body">
        <table class="table table-sm mb-0">
            <tr>
                <td>Address</td>
                <td><code>{{ ergo_wallet.address }}</code></td>
            </tr>
            <tr>
                <td>Balance</td>
                <td>{{ "%.4f"|format(ergo_wallet.balance_erg) }} ERG</td>
            </tr>
        </table>
    </div>
</div>
{% endif %}
```

- [ ] **Step 6: Commit**

```bash
git add scripts/broker-chains.json scripts/build-deb.sh scripts/wizard/broker.json \
    registry-ergo-testnet.json \
    blockhost-broker-manager/manager/broker.py \
    blockhost-broker-manager/manager/app.py \
    blockhost-broker-manager/manager/templates/dashboard.html
git commit -m "feat(ergo): integration with chain dispatch, .deb, wizard, and manager"
```

---

## Task Dependencies

```
Task 1 (guard script) ──────────────────┐
                                         ├── Task 10 (registry deploy)
Task 2 (adapter scaffold) ──┐           │
Task 3 (adapter crypto+api)─┤           │
Task 4 (adapter poller) ────┼── Task 6 (adapter main)
Task 5 (adapter tx builder)─┘           │
                                         ├── Task 11 (integration)
Task 7 (client scaffold) ───┐           │
Task 8 (client tx builder) ─┼── Task 9 (client main)
                             │
```

Tasks 2-5 and 7-8 can run in parallel. Task 1 must complete first (guard template needed by contracts.ts). Tasks 6, 9, 10 depend on their predecessors. Task 11 can run after Tasks 6 and 9.

## Testing Approach

No unit tests — consistent with Cardano and OPNet adapters. Testing is done by deploying to Ergo testnet:

1. Compile guard script → store template
2. Deploy registry NFT (deploy-registry.ts)
3. Deploy adapter to broker server
4. Run client on a test VM
5. Verify end-to-end: request → allocation → response → tunnel config JSON

## Post-Implementation Checklist

- [ ] Guard script compiled and template stored
- [ ] Registry NFT deployed on testnet, ID recorded in `registry-ergo-testnet.json`
- [ ] Adapter builds to single JS bundle
- [ ] Client builds to single JS bundle
- [ ] Adapter deploys to broker server, polls correctly
- [ ] Client outputs correct JSON with all 7 required fields
- [ ] `.deb` package includes Ergo client
- [ ] Broker manager dashboard shows Ergo wallet
- [ ] `broker-chains.json` dispatches Ergo addresses correctly
