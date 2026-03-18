# Cardano Adapter Design

> Broker adapter for Cardano-based IPv6 prefix allocation.
> Covers on-chain contracts (Aiken), server adapter, and client adapter.

## Overview

Cardano becomes the third chain supported by the broker, alongside EVM and OPNet. The design follows the existing external adapter pattern: a long-running server adapter polls the chain and calls the broker REST API, while a client adapter runs as a subprocess invoked by `broker-client`.

The on-chain component uses Cardano-native patterns: UTXO-based request/response lifecycle, beacon tokens for discovery, and reference inputs for registry lookup.

## On-Chain Contracts (Aiken)

Three contracts:

### 1. Registry Validator

A single reference UTXO holding broker info.

**Datum:**
```
RegistryDatum {
  operator_pkh: PubKeyHash,
  ecies_pubkey: ByteArray,        -- broker's ECIES encryption public key (hex)
  capacity_status: Int,           -- 0 = available, 1 = limited, 2 = closed
  region: ByteArray,              -- e.g. "eu-west"
  requests_validator_hash: ByteArray,  -- script hash of the request/response validator
  beacon_policy_id: ByteArray,    -- policy ID of the beacon minting policy
}
```

**Spending logic:** Only the broker operator (identified by `operator_pkh`) can update this UTXO. The datum must be preserved at the same address (the UTXO is updated in place).

**Client usage:** Read as a reference input (no contention). Client extracts broker info without consuming the UTXO. Registry updates consume and recreate the UTXO — client transactions referencing the old UTXO will fail. Since registry updates are infrequent (operator-initiated), the client retries once on reference-input-not-found.

### 2. Request/Response Validator

The main validator address where request and response UTXOs live.

**Request datum:**
```
RequestDatum {
  nft_policy_id: PolicyId,        -- anti-spam: must be included as input
  client_pkh: PubKeyHash,         -- requesting client's pub key hash
  encrypted_payload: ByteArray,   -- ECIES-encrypted request (wg pubkey + server pubkey)
}
```

**Response datum:**
```
ResponseDatum {
  client_pkh: PubKeyHash,         -- matches the original request
  encrypted_response: ByteArray,  -- ECIES-encrypted allocation (encrypted to client's serverPubkey)
}
```

**Spending conditions:**

| Action | Who | Requirements |
|--------|-----|-------------|
| Create request | Client | Must include NFT with `nft_policy_id` as tx input. Must mint request beacon. Datum must be valid `RequestDatum`. |
| Consume request (produce response) | Broker operator | Must be signed by `operator_pkh` from registry. Must burn request beacon. Must mint response beacon. Must produce response UTXO at same validator with valid `ResponseDatum`. |
| Consume response (cleanup) | Client | Must be signed by the `client_pkh` in the response datum. Must burn response beacon. |

### 3. Beacon Minting Policy

Two token names under a single policy ID:

- `"request"` — minted when creating a request UTXO, burned when broker consumes it
- `"response"` — minted when broker produces a response UTXO, burned when client cleans up

**Minting conditions:**

The beacon minting policy is **parameterized with the request/response validator hash**. All mint conditions verify that the output carrying the beacon token is sent to the address derived from this hash.

| Token | Mint | Burn |
|-------|------|------|
| `"request"` | Exactly one UTXO with valid `RequestDatum` must be produced at the validator address (verified by parameterized hash) | Broker operator signature required |
| `"response"` | Broker operator signature required; exactly one UTXO with valid `ResponseDatum` must be produced at the validator address (verified by parameterized hash) | Signed by the `client_pkh` in the datum |

### Anti-Spam

The request validator requires an NFT with the declared `nft_policy_id` to be present as a transaction input. This proves the client holds the NFT at submission time. The NFT is not locked — it returns to the client in the same transaction. This mirrors the EVM/OPNet approach where the contract checks NFT ownership.

The NFT gate isn't deep trust — anyone can deploy their own policy. It makes spam cost something (policy deployment + minting).

### Minimum ADA

Cardano requires minimum ADA (~2 ADA) for every UTXO. Request UTXOs must include this minimum. The broker's response UTXO also requires minimum ADA. When the client consumes the response UTXO (cleanup), the ADA is returned to the client.

### Rollback Handling

If the adapter's response transaction is rolled back, the response UTXO will not exist on-chain. The client will time out and retry. The broker allocation remains, but re-requesting with the same NFT policy ID triggers the broker's dedup logic (same `nft_contract` = same prefix returned, WG key swapped). No manual intervention needed.

## Server Adapter

**Architecture:** TypeScript/Node.js, same pattern as the OPNet adapter. Long-running process, polls chain, calls broker REST API.

**Dependencies:** MeshJS (transaction building), Koios (chain indexer, default) or Blockfrost (optional, if API key provided).

### Flow

1. Poll for UTXOs at the validator address holding a request beacon token
2. For each new request UTXO:
   a. Read the datum (`nft_policy_id`, `client_pkh`, `encrypted_payload`)
   b. Decrypt the payload (ECIES — same scheme as OPNet adapter)
   c. POST to `http://127.0.0.1:8080/v1/allocations` with `{ wg_pubkey, nft_contract, source: "cardano-{network}" }`
   d. Build a transaction:
      - Consume the request UTXO
      - Burn the request beacon
      - Mint a response beacon
      - Produce a response UTXO at the validator with the allocation datum
   e. Sign with the operator key and submit
3. Track processed UTXOs in a state file (`/var/lib/blockhost-broker/adapter-cardano-{network}.state`)

### State Management

The adapter tracks which request UTXOs it has processed by storing their transaction hashes. On restart, it skips UTXOs it has already handled.

Unlike OPNet (which uses sequential request IDs), Cardano UTXOs are identified by `tx_hash#output_index`. The state file stores a set of processed UTXO references.

### Configuration

Environment file: `/etc/blockhost-broker/cardano-adapter-{network}.env`

```
KOIOS_URL=https://preprod.koios.rest/api/v1
BLOCKFROST_API_KEY=                         # optional — if set, uses Blockfrost instead of Koios
OPERATOR_SIGNING_KEY=<ed25519 signing key>
ECIES_PRIVATE_KEY=<hex>
VALIDATOR_ADDRESS=addr_test1...
BEACON_POLICY_ID=<hex>
BROKER_API_URL=http://127.0.0.1:8080
ADAPTER_SOURCE=cardano-preprod
LEASE_DURATION=0
POLL_INTERVAL_MS=20000
```

`LEASE_DURATION=0` means no expiry — the adapter omits the `lease_duration` field from the broker API call (same convention as the OPNet adapter).

### Systemd

Template service: `blockhost-cardano-adapter@.service`

```ini
[Unit]
Description=Blockhost Cardano Adapter (%i)
After=network.target blockhost-broker.service
Requires=blockhost-broker.service

[Service]
Type=simple
EnvironmentFile=/etc/blockhost-broker/cardano-adapter-%i.env
ExecStart=/usr/bin/node /opt/blockhost/adapters/cardano/adapter/dist/main.js
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Client Adapter

**Architecture:** TypeScript/Node.js, bundled with esbuild. Runs as a subprocess invoked by `broker-client` via chain dispatch.

**Dependencies:** MeshJS (transaction building), Koios (chain indexer, default) or Blockfrost (optional, if API key provided).

### Flow

1. Query the registry reference UTXO — extract broker info (ECIES pubkey, capacity status, validator hash, beacon policy)
2. Check capacity status — bail if closed (status = 2), warn if limited (status = 1)
3. Generate WireGuard keypair + ECIES server keypair
4. Encrypt the request payload (WG pubkey + server pubkey) with the broker's ECIES key
5. Build and submit a transaction:
   - Send ADA to the validator address with `RequestDatum`
   - Mint a request beacon
   - Include NFT with the declared policy ID as an input
6. Save recovery state to `/var/lib/blockhost/cardano-recovery.json`
7. Watch for a response UTXO at the validator address:
   - Holding a response beacon
   - With `client_pkh` matching the client
8. Read the response datum, extract allocation info
9. Optionally consume the response UTXO (burn response beacon) to clean up
10. Clear recovery state
11. Output JSON to stdout:
    ```json
    {
      "prefix": "...",
      "gateway": "...",
      "broker_pubkey": "...",
      "broker_endpoint": "...",
      "wg_private_key": "...",
      "wg_public_key": "..."
    }
    ```

### Recovery Mechanism

Same as the OPNet client. On timeout:
- Recovery file is preserved with server private key, broker ECIES pubkey, and the transaction hash of the request
- On next invocation, the client checks for the recovery file first
- If found, scans for the response UTXO before submitting a new request
- If response found, returns the allocation immediately
- If not found within 60s, clears recovery state and proceeds with a fresh request

### Timeout Guard

All chain queries wrapped with `withTimeout(promise, 30_000, label)` to prevent SDK connection stalls (same fix applied to OPNet client).

### Chain Dispatch

Addition to `broker-chains.json`:

```json
{
  "name": "cardano",
  "match": "^[0-9a-fA-F]{56}$",
  "adapter": "node",
  "adapter_args": ["/opt/blockhost/adapters/cardano/client/dist/main.js", "request"],
  "timeout": 600,
  "koios_url": "https://preprod.koios.rest/api/v1"
}
```

Koios is the default provider (no API key required). If `BLOCKFROST_API_KEY` is set in the environment, the adapter uses Blockfrost instead.

The 56-char hex match pattern corresponds to Cardano policy IDs, which distinguishes from EVM (40-char `0x`-prefixed) and OPNet (64-char `0x`-prefixed).

Timeout is 600s (10 minutes) — Cardano blocks are ~20 seconds, much faster than OPNet's ~10 minutes.

## Encryption

Same ECIES scheme as OPNet for both request and response:

- **Request encryption:** Full ECIES (eciespy-compatible) with the broker's ECIES public key. The request payload contains the WireGuard public key (32 bytes) and a compressed secp256k1 server public key (33 bytes).
- **Response encryption:** Compact ECDH-derived AES-GCM, encrypted to the client's server public key (from the request payload). Same scheme as OPNet's OP_RETURN responses. The encrypted blob (~160 bytes) is stored in the response datum's `encrypted_response` field.

Response encryption is necessary because Cardano datums are public on-chain. Without it, allocated prefixes would be permanently linked to Cardano addresses, creating a prefix-to-identity map. This aligns the confidentiality model with EVM and OPNet where responses are encrypted.

## File Structure

```
adapters/cardano/
├── contracts/                    # Aiken validators
│   ├── aiken.toml
│   ├── validators/
│   │   ├── registry.ak           # Registry reference UTXO validator
│   │   ├── broker.ak             # Request/response validator
│   │   └── beacon.ak             # Beacon minting policy
│   └── lib/
│       └── types.ak              # Shared datum types
├── adapter/                      # Server adapter (Node.js)
│   ├── package.json
│   ├── tsconfig.json
│   ├── src/
│   │   ├── main.ts
│   │   ├── config.ts
│   │   ├── poller.ts
│   │   ├── crypto.ts
│   │   └── tx-builder.ts
│   └── dist/
│       └── main.js
├── client/                       # Client adapter (Node.js)
│   ├── package.json
│   ├── tsconfig.json
│   ├── src/
│   │   ├── main.ts
│   │   ├── crypto.ts
│   │   └── tx-builder.ts
│   └── dist/
│       └── main.js
└── deploy/                       # Deployment scripts
    ├── deploy-validators.ts
    ├── register-broker.ts
    └── package.json
```

## Registry Configuration

New file: `registry-cardano-preprod.json`

```json
{
  "registry_address": "addr_test1...",
  "beacon_policy_id": "...",
  "network": "cardano-preprod"
}
```

The client uses this to find the registry reference UTXO, from which it reads the full broker configuration.

## Networks

- **Preprod** — Cardano preprod testnet (development/testing)
- **Mainnet** — Cardano mainnet (production)
