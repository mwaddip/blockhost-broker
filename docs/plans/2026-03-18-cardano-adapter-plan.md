# Cardano Adapter Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Cardano as the third supported chain for the broker, with Aiken validators, a server adapter, and a client adapter.

**Architecture:** Three independent subsystems — (1) Aiken smart contracts for on-chain request/response lifecycle with beacon tokens, (2) a Node.js server adapter that polls for request UTXOs and responds via Cardano transactions, (3) a Node.js client adapter invoked as a subprocess by `broker-client`. All follow the existing OPNet adapter patterns.

**Tech Stack:** Aiken (validators), TypeScript/Node.js + esbuild (adapters), MeshJS (Cardano tx building), Koios REST API (chain indexer), same ECIES crypto as OPNet (`@noble/curves`, `@noble/ciphers`, `@noble/hashes`).

**Spec:** `docs/plans/2026-03-18-cardano-adapter-design.md`

**Reference implementation:** `adapters/opnet/` (mirror the structure and patterns)

---

## Chunk 1: Aiken Smart Contracts

### Task 1: Project scaffolding and shared types

**Files:**
- Create: `adapters/cardano/contracts/aiken.toml`
- Create: `adapters/cardano/contracts/lib/types.ak`

- [ ] **Step 1: Initialize Aiken project**

```bash
cd adapters/cardano/contracts
aiken new blockhost/broker --dest .
```

If `aiken` is not installed: `cargo install aiken` or download from https://github.com/aiken-lang/aiken/releases.

Edit `aiken.toml` to set:
```toml
name = "blockhost/broker"
version = "0.1.0"
license = "MIT"
description = "Blockhost broker validators for Cardano"

[repository]
user = "mwaddip"
project = "blockhost-broker"
platform = "github"
```

- [ ] **Step 2: Define shared datum types**

Create `lib/types.ak`:

```aiken
/// Registry datum — held in a single reference UTXO.
pub type RegistryDatum {
  operator_pkh: ByteArray,
  ecies_pubkey: ByteArray,
  capacity_status: Int,
  region: ByteArray,
  requests_validator_hash: ByteArray,
  beacon_policy_id: ByteArray,
}

/// Request datum — created by client at the broker validator address.
pub type RequestDatum {
  nft_policy_id: ByteArray,
  client_pkh: ByteArray,
  encrypted_payload: ByteArray,
}

/// Response datum — created by broker when consuming a request.
pub type ResponseDatum {
  client_pkh: ByteArray,
  encrypted_response: ByteArray,
}

/// Redeemer actions for the broker validator.
/// Note: there is no CreateRequest — sending to a script address does not
/// invoke the spend validator in Cardano's EUTXO model. Request creation
/// is validated entirely by the beacon minting policy.
pub type BrokerAction {
  ConsumeRequest
  ConsumeResponse
}

/// Redeemer actions for the registry validator.
pub type RegistryAction {
  UpdateRegistry
}

/// Redeemer actions for the beacon minting policy.
pub type BeaconAction {
  MintRequestBeacon
  BurnRequestBeacon
  MintResponseBeacon
  BurnResponseBeacon
}
```

- [ ] **Step 3: Verify it compiles**

```bash
aiken check
```

Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add adapters/cardano/contracts/
git commit -m "feat(cardano): scaffold Aiken project with shared datum types"
```

---

### Task 2: Registry validator

**Files:**
- Create: `adapters/cardano/contracts/validators/registry.ak`

- [ ] **Step 1: Write registry validator**

Create `validators/registry.ak`:

```aiken
use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use cardano/transaction.{Transaction, InlineDatum, Output}
use types.{RegistryDatum, RegistryAction}

/// Registry validator: holds a single reference UTXO with broker info.
/// Only the operator can update it (must re-produce at same address with valid datum).
validator registry {
  spend(
    datum: Option<RegistryDatum>,
    redeemer: RegistryAction,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(d) = datum
    when redeemer is {
      UpdateRegistry -> {
        // Must be signed by the operator
        let signed = list.has(tx.extra_signatories, d.operator_pkh)

        // Must produce exactly one output back to the same address
        let own_input = transaction.find_input(tx.inputs, own_ref)
        expect Some(input) = own_input
        let own_address = input.output.address

        let continuing_outputs =
          list.filter(
            tx.outputs,
            fn(o: Output) { o.address == own_address },
          )

        let has_continuing = list.length(continuing_outputs) == 1

        // The continuing output must have an inline datum
        expect [continuing_output] = continuing_outputs
        expect InlineDatum(_) = continuing_output.datum

        signed && has_continuing
      }
    }
  }

  else(_) {
    fail
  }
}
```

- [ ] **Step 2: Verify it compiles**

```bash
aiken check
```

- [ ] **Step 3: Commit**

```bash
git add validators/registry.ak
git commit -m "feat(cardano): add registry validator"
```

---

### Task 3: Broker (request/response) validator

**Files:**
- Create: `adapters/cardano/contracts/validators/broker.ak`

- [ ] **Step 1: Write broker validator**

Create `validators/broker.ak`:

```aiken
use aiken/collection/list
use cardano/transaction.{Transaction, InlineDatum, Output, OutputReference, Input}
use cardano/assets.{PolicyId}
use types.{RequestDatum, ResponseDatum, BrokerAction}

/// Broker validator: handles request/response UTXO lifecycle.
///
/// Sending to this address (creating request UTXOs) does not invoke this
/// validator — that's handled by the beacon minting policy which validates
/// datum structure, NFT presence, and output destination.
///
/// This validator only fires when consuming UTXOs at this address:
/// - ConsumeRequest: broker operator consumes request, produces response
/// - ConsumeResponse: client cleans up response UTXO
validator broker(operator_pkh: ByteArray, beacon_policy_id: ByteArray) {
  spend(
    datum: Option<Data>,
    redeemer: BrokerAction,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    when redeemer is {
      ConsumeRequest -> {
        // Must be signed by broker operator
        let signed = list.has(tx.extra_signatories, operator_pkh)

        // The consumed UTXO must carry a request beacon (prevents
        // using this redeemer to consume response UTXOs and bypass
        // the client signature check in ConsumeResponse)
        let own_input = transaction.find_input(tx.inputs, own_ref)
        expect Some(input) = own_input
        let has_request_beacon =
          assets.quantity_of(input.output.value, beacon_policy_id, "request") == 1

        // Must produce a response UTXO at this validator address
        let own_address = input.output.address

        let response_outputs =
          list.filter(
            tx.outputs,
            fn(o: Output) { o.address == own_address },
          )
        let has_response = list.length(response_outputs) >= 1

        signed && has_request_beacon && has_response
      }

      ConsumeResponse -> {
        // Must be signed by the client_pkh from the response datum
        expect Some(raw_datum) = datum
        expect response: ResponseDatum = raw_datum
        list.has(tx.extra_signatories, response.client_pkh)
      }
    }
  }

  else(_) {
    fail
  }
}
```

Note: The `operator_pkh` is a validator parameter — set at deployment time. This links the validator to a specific broker operator.

- [ ] **Step 2: Verify it compiles**

```bash
aiken check
```

- [ ] **Step 3: Commit**

```bash
git add validators/broker.ak
git commit -m "feat(cardano): add broker request/response validator"
```

---

### Task 4: Beacon minting policy

**Files:**
- Create: `adapters/cardano/contracts/validators/beacon.ak`

- [ ] **Step 1: Write beacon minting policy**

Create `validators/beacon.ak`:

```aiken
use aiken/collection/list
use cardano/transaction.{Transaction, InlineDatum, Output, Mint}
use cardano/assets
use types.{RequestDatum, ResponseDatum, BeaconAction}

/// Token names for the two beacon types.
const request_beacon_name = "request"
const response_beacon_name = "response"

/// Beacon minting policy, parameterized with the broker validator hash.
/// Ensures beacons are only minted/burned alongside valid UTXOs at the validator.
validator beacon(broker_validator_hash: ByteArray, operator_pkh: ByteArray) {
  mint(redeemer: BeaconAction, policy_id: PolicyId, tx: Transaction) {
    // Helper: check that an output goes to the broker validator address
    let validator_credential =
      cardano/address.Script(broker_validator_hash)

    let outputs_at_validator =
      list.filter(
        tx.outputs,
        fn(o: Output) { o.address.payment_credential == validator_credential },
      )

    when redeemer is {
      MintRequestBeacon -> {
        // Must mint exactly 1 request beacon
        let minted = assets.tokens(tx.mint, policy_id)
        let mint_count =
          assets.quantity_of(minted, request_beacon_name)
        let only_one = mint_count == 1

        // Must produce exactly one UTXO at the validator with inline datum
        let has_output = list.length(outputs_at_validator) >= 1

        // The output must carry the beacon token
        let output_has_beacon =
          list.any(
            outputs_at_validator,
            fn(o: Output) {
              assets.quantity_of(o.value, policy_id, request_beacon_name) == 1
            },
          )

        // The output must have an NFT from the declared policy in the tx inputs
        // (anti-spam: checked via the datum's nft_policy_id field)
        expect Some(beacon_output) =
          list.find(
            outputs_at_validator,
            fn(o: Output) {
              assets.quantity_of(o.value, policy_id, request_beacon_name) == 1
            },
          )
        expect InlineDatum(raw) = beacon_output.datum
        expect req: RequestDatum = raw

        let nft_in_inputs =
          list.any(
            tx.inputs,
            fn(i: Input) {
              assets.quantity_of(i.output.value, req.nft_policy_id, "") > 0
                || assets.policies(i.output.value)
                  |> list.has(req.nft_policy_id)
            },
          )

        only_one && has_output && output_has_beacon && nft_in_inputs
      }

      BurnRequestBeacon -> {
        // Must be signed by broker operator
        let signed = list.has(tx.extra_signatories, operator_pkh)

        // Must burn exactly 1 request beacon
        let minted = assets.tokens(tx.mint, policy_id)
        let burn_count =
          assets.quantity_of(minted, request_beacon_name)
        let burns_one = burn_count == -1

        signed && burns_one
      }

      MintResponseBeacon -> {
        // Must be signed by broker operator
        let signed = list.has(tx.extra_signatories, operator_pkh)

        // Must mint exactly 1 response beacon
        let minted = assets.tokens(tx.mint, policy_id)
        let mint_count =
          assets.quantity_of(minted, response_beacon_name)
        let only_one = mint_count == 1

        // Must produce a UTXO at the validator with the beacon
        let output_has_beacon =
          list.any(
            outputs_at_validator,
            fn(o: Output) {
              assets.quantity_of(o.value, policy_id, response_beacon_name) == 1
            },
          )

        signed && only_one && output_has_beacon
      }

      BurnResponseBeacon -> {
        // Must burn exactly 1 response beacon
        let minted = assets.tokens(tx.mint, policy_id)
        let burn_count =
          assets.quantity_of(minted, response_beacon_name)
        let burns_one = burn_count == -1

        // Must consume a response UTXO from the broker validator
        // (the spend validator's ConsumeResponse enforces client_pkh signature)
        let consumes_validator_utxo =
          list.any(
            tx.inputs,
            fn(i: Input) {
              i.output.address.payment_credential == validator_credential
                && assets.quantity_of(i.output.value, policy_id, response_beacon_name) == 1
            },
          )

        burns_one && consumes_validator_utxo
      }
    }
  }

  else(_) {
    fail
  }
}
```

- [ ] **Step 2: Build the full project**

```bash
aiken build
```

Expected: compiles with no errors. Produces `plutus.json` blueprint.

- [ ] **Step 3: Commit**

```bash
git add validators/beacon.ak
git commit -m "feat(cardano): add beacon minting policy"
```

---

### Task 5: Build and verify full contract suite

- [ ] **Step 1: Run full build**

```bash
cd adapters/cardano/contracts
aiken build
```

Verify `plutus.json` is generated with all three validators.

- [ ] **Step 2: Run Aiken tests (if any property tests are written)**

```bash
aiken check
```

- [ ] **Step 3: Commit blueprint**

```bash
git add plutus.json
git commit -m "feat(cardano): build contract blueprint"
```

---

## Chunk 2: Shared Crypto Module

The server adapter and client adapter share ECIES encryption/decryption code. This is identical to the OPNet crypto module (same ECDH scheme, same key derivation, same AES-GCM). Rather than duplicating, create it as part of the adapter and the client can import the same patterns.

### Task 6: Server adapter project scaffolding

**Files:**
- Create: `adapters/cardano/adapter/package.json`
- Create: `adapters/cardano/adapter/tsconfig.json`
- Create: `adapters/cardano/adapter/src/crypto.ts`

- [ ] **Step 1: Create package.json**

```json
{
    "name": "blockhost-adapter-cardano",
    "version": "0.1.0",
    "type": "module",
    "scripts": {
        "build": "esbuild src/main.ts --bundle --platform=node --format=esm --outfile=dist/main.js --target=node22 --banner:js=\"import { createRequire } from 'module'; const require = createRequire(import.meta.url);\"",
        "start": "node dist/main.js",
        "dev": "tsx src/main.ts",
        "typecheck": "tsc --noEmit"
    },
    "dependencies": {
        "@meshsdk/core": "^1.9.0",
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

Note: MeshJS (`@meshsdk/core`) replaces the OPNet-specific packages. The noble crypto stack stays the same.

- [ ] **Step 2: Create tsconfig.json**

Copy from `adapters/opnet/adapter/tsconfig.json` (identical config).

- [ ] **Step 3: Create crypto.ts**

Copy `adapters/opnet/adapter/src/crypto.ts` and adapt:
- Keep: `EciesEncryption` class (ECIES decrypt, compact encrypt for responses)
- Keep: `RequestPayload` and `ResponsePayload` interfaces
- Keep: `deriveKeyAndIv`, `encryptCompact` functions
- Remove: OPNet-specific imports
- The crypto is pure `@noble/*` — no chain-specific dependencies

The `RequestPayload` and `ResponsePayload` interfaces are identical:

```typescript
export interface RequestPayload {
    wgPubkey: string;        // WireGuard pubkey (base64)
    serverPubkey: string;    // Ephemeral secp256k1 pubkey (hex)
}

export interface ResponsePayload {
    prefix: string;
    gateway: string;
    brokerPubkey: string;    // WireGuard pubkey (base64)
    brokerEndpoint: string;  // "IP:port"
}
```

- [ ] **Step 4: Install dependencies and verify build**

```bash
cd adapters/cardano/adapter
npm install
npx tsc --noEmit
```

- [ ] **Step 5: Commit**

```bash
git add adapters/cardano/adapter/
git commit -m "feat(cardano): scaffold adapter project with crypto module"
```

---

## Chunk 3: Server Adapter

### Task 7: Config module

**Files:**
- Create: `adapters/cardano/adapter/src/config.ts`

- [ ] **Step 1: Write config.ts**

Follow the OPNet config pattern. Environment variables:

```typescript
export interface AdapterConfig {
    koiosUrl: string;
    blockfrostApiKey: string | null;   // If set, use Blockfrost instead of Koios
    operatorSigningKey: string;        // Ed25519 signing key (hex or bech32)
    eciesPrivateKey: string;           // Broker ECIES private key (hex)
    validatorAddress: string;          // Broker validator bech32 address
    beaconPolicyId: string;            // Beacon minting policy ID (hex)
    brokerApiUrl: string;              // Default: http://127.0.0.1:8080
    source: string;                    // e.g. "cardano-preprod"
    leaseDuration: number;             // 0 = no expiry
    pollIntervalMs: number;            // Default: 20000
    blueprintPath: string;             // Path to Aiken plutus.json (compiled script CBORs)
    stateFile: string;                 // Default: /var/lib/blockhost-broker/adapter-cardano-{network}.state
    network: string;                   // "preprod" or "mainnet"
}

export function loadConfig(): AdapterConfig;
```

- [ ] **Step 2: Commit**

```bash
git add src/config.ts
git commit -m "feat(cardano): add adapter config module"
```

---

### Task 8: Poller module

**Files:**
- Create: `adapters/cardano/adapter/src/poller.ts`

- [ ] **Step 1: Write poller.ts**

Cardano blocks are ~20s (vs OPNet's ~10min), so the polling is simpler — just poll at a fixed interval.

```typescript
export interface UtxoRef {
    txHash: string;
    outputIndex: number;
}

export interface RequestUtxo {
    ref: UtxoRef;
    nftPolicyId: string;
    clientPkh: string;
    encryptedPayload: string;   // hex
    lovelace: string;           // ADA amount in the UTXO
}

export class RequestPoller {
    constructor(
        private koiosUrl: string,
        private blockfrostApiKey: string | null,
        private validatorAddress: string,
        private beaconPolicyId: string,
        private onNewRequests: (requests: RequestUtxo[]) => Promise<void>,
        private onStateChange?: (processedRefs: Set<string>) => void,
    );

    setProcessedRefs(refs: Set<string>): void;
    start(intervalMs: number): void;
    stop(): void;
}
```

**Polling algorithm:**
1. Query Koios `GET /address_utxos?_address={validatorAddress}` (or Blockfrost `GET /addresses/{address}/utxos`)
2. Filter UTXOs that contain the request beacon token (`beaconPolicyId` + `"request"` token name)
3. For each UTXO not in `processedRefs`:
   - Decode inline datum as `RequestDatum`
   - Emit to `onNewRequests`

- [ ] **Step 2: Commit**

```bash
git add src/poller.ts
git commit -m "feat(cardano): add UTXO poller for request beacons"
```

---

### Task 9: Transaction builder module

**Files:**
- Create: `adapters/cardano/adapter/src/tx-builder.ts`

- [ ] **Step 1: Write tx-builder.ts**

Uses MeshJS to build the response transaction:

```typescript
export class ResponseTxBuilder {
    constructor(
        private operatorSigningKey: string,
        private validatorAddress: string,
        private beaconPolicyId: string,
        private validatorScriptCbor: string,   // from plutus.json blueprint
        private beaconPolicyCbor: string,      // from plutus.json blueprint
        private koiosUrl: string,
        private blockfrostApiKey: string | null,
        private network: string,
    );

    /**
     * Build and submit response transaction:
     * - Consumes request UTXO (with ConsumeRequest redeemer)
     * - Burns request beacon
     * - Mints response beacon
     * - Produces response UTXO at validator with ResponseDatum
     */
    async submitResponse(
        requestUtxo: RequestUtxo,
        encryptedResponse: Uint8Array,
    ): Promise<string>;  // Returns tx hash
}
```

The transaction builder reads the compiled validators from the Aiken `plutus.json` blueprint (the CBOR-encoded scripts).

- [ ] **Step 2: Commit**

```bash
git add src/tx-builder.ts
git commit -m "feat(cardano): add response transaction builder"
```

---

### Task 10: Main adapter entry point

**Files:**
- Create: `adapters/cardano/adapter/src/main.ts`

- [ ] **Step 1: Write main.ts**

Follow the OPNet adapter's `main.ts` structure exactly:

```typescript
// 1. Load config
// 2. Load persistent state (set of processed UTXO refs)
// 3. Initialize services (poller, crypto, tx-builder)
// 4. Define request handler:
//    a. Decrypt request payload (ECIES)
//    b. POST to broker REST API /v1/allocations
//    c. Encrypt response (compact ECDH-AES-GCM)
//    d. Build and submit response transaction
// 5. Start poller
// 6. Handle graceful shutdown (SIGINT, SIGTERM)
```

**State file format** (differs from OPNet — uses UTXO refs instead of sequential IDs):

```typescript
interface AdapterState {
    processedRefs: string[];  // Array of "txHash#outputIndex" strings
}
```

- [ ] **Step 2: Build and verify**

```bash
npm run build
```

Expected: builds without errors.

- [ ] **Step 3: Commit**

```bash
git add src/main.ts
git commit -m "feat(cardano): add adapter main entry point"
```

---

## Chunk 4: Client Adapter

### Task 11: Client project scaffolding

**Files:**
- Create: `adapters/cardano/client/package.json`
- Create: `adapters/cardano/client/tsconfig.json`
- Create: `adapters/cardano/client/src/crypto.ts`

- [ ] **Step 1: Create package.json**

```json
{
    "name": "blockhost-client-cardano",
    "version": "0.1.0",
    "type": "module",
    "scripts": {
        "build": "esbuild src/main.ts --bundle --platform=node --format=esm --outfile=dist/main.js --target=node22 --banner:js=\"import { createRequire } from 'module'; const require = createRequire(import.meta.url);\"",
        "start": "node dist/main.js",
        "dev": "tsx src/main.ts",
        "typecheck": "tsc --noEmit"
    },
    "dependencies": {
        "@meshsdk/core": "^1.9.0",
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

Same as adapter.

- [ ] **Step 3: Create crypto.ts**

Same ECIES scheme as OPNet client's `crypto.ts`:
- `eciesEncrypt` — full ECIES for request payload
- `decryptCompact` — compact ECDH-AES-GCM for response
- `deserializeResponse` — binary response → `TunnelConfig`
- `generateWgKeypair` — x25519
- `generateServerKeypair` / `serverKeypairFromHex` — secp256k1
- `serializeRequestPayload` — [32 WG pubkey + 33 server pubkey]

The response deserialization is identical to OPNet (63-byte binary layout).

- [ ] **Step 4: Install and verify**

```bash
npm install
npx tsc --noEmit
```

- [ ] **Step 5: Commit**

```bash
git add adapters/cardano/client/
git commit -m "feat(cardano): scaffold client project with crypto module"
```

---

### Task 12: Client transaction builder

**Files:**
- Create: `adapters/cardano/client/src/tx-builder.ts`

- [ ] **Step 1: Write tx-builder.ts**

```typescript
export class ClientTxBuilder {
    constructor(
        private signingKey: string,         // Client's ed25519 signing key
        private validatorAddress: string,
        private beaconPolicyId: string,
        private beaconPolicyCbor: string,   // From blueprint
        private koiosUrl: string,
        private blockfrostApiKey: string | null,
        private network: string,
    );

    /**
     * Build and submit a request transaction:
     * - Send min ADA to validator address with RequestDatum
     * - Mint request beacon
     * - Include NFT as a regular input (anti-spam — beacon policy checks tx.inputs)
     */
    async submitRequest(
        nftPolicyId: string,
        clientPkh: string,
        encryptedPayload: Uint8Array,
    ): Promise<string>;  // Returns tx hash

    /**
     * Build and submit cleanup transaction:
     * - Consume response UTXO (ConsumeResponse redeemer)
     * - Burn response beacon
     * - Return ADA to client
     */
    async cleanupResponse(
        responseUtxoRef: { txHash: string; outputIndex: number },
    ): Promise<string>;  // Returns tx hash
}
```

- [ ] **Step 2: Commit**

```bash
git add src/tx-builder.ts
git commit -m "feat(cardano): add client transaction builder"
```

---

### Task 13: Client main entry point

**Files:**
- Create: `adapters/cardano/client/src/main.ts`

- [ ] **Step 1: Write main.ts**

Follow the OPNet client's `main.ts` structure:

```typescript
// Arg parsing (same flags as OPNet plus Cardano-specific ones):
interface Args {
    command: string;
    koiosUrl: string;
    blockfrostApiKey: string | null;
    signingKey: string;            // Ed25519 signing key file or hex
    nftPolicyId: string;           // 56-char hex
    registryAddress: string;       // Bech32 registry validator address
    timeoutMs: number;
    serverKey: string | null;      // Persistent ECIES private key
}

// Recovery state (same pattern as OPNet):
interface RecoveryState {
    serverPrivkeyHex: string;
    brokerPubkeyHex: string;
    requestTxHash: string;         // tx hash of the submitted request
    wgPrivateKeyBase64: string;
    wgPublicKeyBase64: string;
    savedAt: string;
}

const RECOVERY_FILE = '/var/lib/blockhost/cardano-recovery.json';
```

**Flow:**
1. Check for recovery state → attempt recovery (scan for response UTXO)
2. Query registry reference UTXO → extract broker info
3. Check capacity status
4. Generate keypairs (WG + ECIES server)
5. Encrypt request payload
6. Submit request transaction (mint request beacon, include NFT)
7. Save recovery state
8. Watch for response UTXO at validator (beacon scan)
9. Decrypt response
10. Cleanup response UTXO (optional)
11. Clear recovery state
12. Output JSON to stdout

**Response watcher** — simpler than OPNet (no block scanning, just UTXO query):

```typescript
async function watchForResponse(
    koiosUrl: string,
    validatorAddress: string,
    beaconPolicyId: string,
    clientPkh: string,
    serverPrivkey: Uint8Array,
    brokerPubkey: Uint8Array,
    timeoutMs: number,
): Promise<TunnelConfig> {
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
        // Query UTXOs at validator with response beacon
        const utxos = await withTimeout(
            queryUtxos(koiosUrl, validatorAddress),
            RPC_CALL_TIMEOUT_MS,
            'queryUtxos',
        );

        // Filter for response beacons with matching client_pkh
        for (const utxo of utxos) {
            if (!hasResponseBeacon(utxo, beaconPolicyId)) continue;
            const datum = decodeResponseDatum(utxo);
            if (datum.client_pkh !== clientPkh) continue;

            // Decrypt and return
            const plaintext = decryptCompact(
                datum.encrypted_response,
                serverPrivkey,
                brokerPubkey,
            );
            return deserializeResponse(plaintext);
        }

        await new Promise(r => setTimeout(r, RESPONSE_POLL_MS));
    }

    throw new Error('Timed out waiting for broker response');
}
```

Note: This is simpler than OPNet's block-scanning approach because Cardano UTXOs can be queried directly by address — no need to scan blocks.

`withTimeout` wrapper: identical to OPNet client's implementation.

- [ ] **Step 2: Build and verify**

```bash
npm run build
node dist/main.js
```

Expected: prints usage and exits (no args provided).

- [ ] **Step 3: Commit**

```bash
git add src/main.ts
git commit -m "feat(cardano): add client main entry point with recovery"
```

---

## Chunk 5: Deployment and Integration

### Task 14: Deployment scripts

**Files:**
- Create: `adapters/cardano/deploy/package.json`
- Create: `adapters/cardano/deploy/deploy-validators.ts`
- Create: `adapters/cardano/deploy/register-broker.ts`

- [ ] **Step 1: Create package.json**

```json
{
    "name": "blockhost-cardano-deploy",
    "version": "0.1.0",
    "type": "module",
    "dependencies": {
        "@meshsdk/core": "^1.9.0"
    },
    "devDependencies": {
        "tsx": "^4.0.0",
        "typescript": "^5.9.3"
    }
}
```

- [ ] **Step 2: Write deploy-validators.ts**

Script to deploy the three validators to preprod:
1. Read compiled scripts from `../contracts/plutus.json`
2. Build reference script transactions (store validators as reference scripts on-chain)
3. Submit and output the script addresses and policy IDs

- [ ] **Step 3: Write register-broker.ts**

Script to create the registry reference UTXO:
1. Build a transaction that sends ADA to the registry validator address
2. Attach `RegistryDatum` as inline datum (operator pkh, ECIES pubkey, capacity status, etc.)
3. Submit and output the UTXO reference

- [ ] **Step 4: Commit**

```bash
git add adapters/cardano/deploy/
git commit -m "feat(cardano): add deployment scripts"
```

---

### Task 15: Chain dispatch and registry config

**Files:**
- Modify: `scripts/broker-chains.json`
- Create: `registry-cardano-preprod.json`

- [ ] **Step 1: Add Cardano entry to broker-chains.json**

Add to the existing array:

```json
{
    "name": "cardano",
    "match": "^[0-9a-fA-F]{56}$",
    "adapter": "node",
    "adapter_args": ["/opt/blockhost/adapters/cardano/client/dist/main.js", "request"],
    "timeout": 600,
    "koios_url": "https://preprod.koios.rest/api/v1",
    "registry_address": "",
    "beacon_policy_id": ""
}
```

Note: `registry_address` and `beacon_policy_id` are populated after contract deployment. The `broker-client.py` dispatch logic passes chain settings as CLI args to the adapter subprocess (e.g. `--koios-url`, `--registry-address`, `--beacon-policy`). The client reads `registry-cardano-preprod.json` as a fallback if these are not provided via CLI.

- [ ] **Step 2: Create registry-cardano-preprod.json**

```json
{
    "registry_address": "",
    "beacon_policy_id": "",
    "network": "cardano-preprod"
}
```

Note: addresses are populated after deploying contracts to preprod.

- [ ] **Step 3: Commit**

```bash
git add scripts/broker-chains.json registry-cardano-preprod.json
git commit -m "feat(cardano): add chain dispatch config and registry placeholder"
```

---

### Task 16: Facts submodule update

- [ ] **Step 1: Update facts submodule pointer**

```bash
cd facts && git checkout origin/main && cd ..
git add facts
git commit -m "chore: update facts submodule"
```

---

### Task 17: Final build and integration test

- [ ] **Step 1: Build all components**

```bash
cd adapters/cardano/contracts && aiken build
cd ../adapter && npm install && npm run build
cd ../client && npm install && npm run build
cd ../deploy && npm install
```

- [ ] **Step 2: Verify client loads**

```bash
node adapters/cardano/client/dist/main.js
```

Expected: prints usage.

- [ ] **Step 3: Verify adapter loads (will fail on missing env vars)**

```bash
node adapters/cardano/adapter/dist/main.js 2>&1
```

Expected: `Missing required environment variable: ...`

- [ ] **Step 4: Commit all lockfiles**

```bash
git add adapters/cardano/
git commit -m "feat(cardano): final build verification"
```

---

## Deployment Sequence (Post-Implementation)

After all code is written and building:

1. Deploy validators to preprod using `deploy/deploy-validators.ts`
2. Create registry UTXO using `deploy/register-broker.ts`
3. Update `registry-cardano-preprod.json` with actual addresses
4. Deploy adapter to broker server (`scp dist/main.js`, create systemd unit + env file)
5. Deploy client to Blockhost ISO build
6. End-to-end test: client request → adapter response → tunnel config
