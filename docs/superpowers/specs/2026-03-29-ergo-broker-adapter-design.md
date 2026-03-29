# Ergo Broker Adapter & Client — Design Spec

## Overview

An Ergo adapter (server-side) and client plugin for the blockhost-broker multichain architecture. Follows the same pattern as the Cardano and OPNet adapters: adapter polls for on-chain requests, POSTs to the broker's `/v1/allocations` API, delivers an encrypted response on-chain; client submits a request transaction, watches for the response, and outputs the standard tunnel config JSON.

## Smart Contracts

### Guard Script

Single ErgoScript contract at a P2S address, parameterized with the operator's public key. Three spending paths:

| Path | Condition | Purpose |
|------|-----------|---------|
| **Respond** | `operatorPk` | Operator consumes request box, carries beacon to response box |
| **Cleanup** | `clientPk` (from R4) | Client consumes response box after reading it, burns beacon |
| **Refund** | `clientPk && HEIGHT > deadline` (R6) | Client reclaims funds if operator never responds |

Pre-compiled ErgoTree template. Operator PK substituted at deploy time via byte surgery (same pattern as the engine's subscription guard in `blockhost-engine-ergo`).

### Registry

On-chain singleton NFT state box. Deployer wallet owns it (can update by spending and recreating). Client discovers it by known NFT token ID (published in `registry-ergo-*.json`).

**Register layout:**

| Register | Type | Content |
|----------|------|---------|
| R4 | `Coll[Byte]` | Operator compressed public key (33 bytes) |
| R5 | `Coll[Byte]` | ECIES compressed public key (33 bytes) |
| R6 | `Coll[Byte]` | Guard script ErgoTree bytes |

## Box Schemas

### Request Box (at guard script address)

Created by the client. Consumed by the adapter.

| Field | Type | Content |
|-------|------|---------|
| `value` | `Long` | Min box value (~0.001 ERG) |
| `tokens(0)` | `(TokenId, 1L)` | Beacon token (minted in this tx, amount=1) |
| `ergoTree` | — | Guard script |
| `R4` | `SigmaProp` | Client's public key (refund/cleanup identity) |
| `R5` | `Coll[Byte]` | ECIES-encrypted payload (32B WG pubkey + 33B ephemeral ECIES pubkey) |
| `R6` | `Int` | Deadline block height (refund enabled after this) |

### Response Box (at guard script address)

Created by the adapter (same tx that consumes the request box). Consumed by the client for cleanup.

| Field | Type | Content |
|-------|------|---------|
| `value` | `Long` | Min box value |
| `tokens(0)` | `(TokenId, 1L)` | Same beacon token (carried from request box) |
| `ergoTree` | — | Guard script |
| `R4` | `SigmaProp` | Client's public key (carried forward from request) |
| `R5` | `Coll[Byte]` | Encrypted response (compact ECDH-AES-GCM, 79 bytes) |

### Beacon Token Lifecycle

1. **Client mints** beacon in request tx (token ID = first input box ID, amount = 1)
2. **Adapter carries** beacon from request box to response box (no new mint)
3. **Client burns** beacon when consuming response box (cleanup)

One beacon per request. Token ID is unique, used by client to locate its response.

## Deduplication Key (`nft_contract`)

The guard script P2S address. Unique per deployment (parameterized with operator PK), verifiable on-chain. Passed by the adapter to `POST /v1/allocations` as the `nft_contract` field.

## Encryption

Same scheme as Cardano and OPNet adapters:

- **Request**: ECIES (eciespy format) using broker's ECIES public key. Payload: 32B WireGuard pubkey + 33B compressed ephemeral ECIES pubkey = 65 bytes plaintext.
- **Response**: Compact ECDH-AES-GCM. Both sides derive key from ECDH(broker_priv, client_ephemeral_pub). Payload: 63 bytes plaintext (WG key + endpoint + prefix + gateway), encrypted to 79 bytes (ciphertext + tag).

## Tech Stack

| Component | Library | Purpose |
|-----------|---------|---------|
| Tx building | `@fleet-sdk/core` | Build unsigned transactions |
| Signing | ergo-relay (`127.0.0.1:9064`) | Sign via `/wallet/transaction/sign` |
| Broadcast | ergo-relay | Submit via `/transactions` |
| UTXO queries | Ergo Explorer API | Fetch boxes by address / token ID |
| Crypto | `@noble/curves`, `@noble/hashes` | ECIES, ECDH, AES-GCM, key derivation |
| Mnemonic | `@scure/bip39` | If needed in future (client currently uses raw hex key) |
| Bundler | esbuild | Single `.js` output per component |

No WASM, no JRE, no Ergo node dependency.

## Adapter (Server-Side)

### File Structure

```
adapters/ergo/adapter/
├── src/
│   ├── main.ts        — orchestrator, config loading, graceful shutdown
│   ├── poller.ts      — polls guard script address via Explorer API
│   ├── tx-builder.ts  — builds response tx (Fleet SDK), signs/broadcasts via ergo-relay
│   ├── config.ts      — environment variable config loader
│   └── crypto.ts      — ECIES decrypt request, compact ECDH-AES-GCM encrypt response
├── esbuild.config.mjs
├── package.json
└── tsconfig.json
```

### Flow

1. Load config from env: Explorer URL, ergo-relay URL, operator private key (hex), ECIES private key (hex), guard script address, registry NFT token ID, network (testnet/mainnet)
2. Fetch registry box by NFT token ID → extract operator PK, ECIES PK, guard script ErgoTree
3. Poll Explorer for unspent boxes at guard script address
4. Filter for boxes with a beacon token in `tokens(0)` and valid register structure (R4=SigmaProp, R5=Coll[Byte], R6=Int)
5. Skip already-processed beacon token IDs (persistent state file)
6. Decode R5 → ECIES-decrypt → extract WG pubkey + ephemeral ECIES pubkey
7. POST to `http://127.0.0.1:8080/v1/allocations` with `{ wg_pubkey, nft_contract: guardScriptAddress, source: "ergo-testnet" }`
8. Encrypt response (compact ECDH-AES-GCM) using ephemeral ECIES pubkey from request
9. Build response tx with Fleet SDK:
   - Input: request box (spend via operatorPk)
   - Output: response box at guard script address with beacon in tokens(0), client PK in R4, encrypted response in R5
10. Sign via ergo-relay `/wallet/transaction/sign` with operator private key
11. Broadcast via ergo-relay `/transactions`
12. Record beacon token ID in state file

### Persistent State

File: `/var/lib/blockhost-broker/adapter-ergo-{network}.state`

```json
{
  "processedBeacons": ["tokenId1", "tokenId2", ...]
}
```

### Error Handling

Exponential backoff on Explorer/ergo-relay errors (20s base, 5min cap). Log every 30th consecutive error (prevent journal flooding).

## Client (Subprocess)

### File Structure

```
adapters/ergo/client/
├── src/
│   ├── main.ts        — entry point, subprocess mode, JSON to stdout
│   └── tx-builder.ts  — builds request tx + cleanup tx
├── esbuild.config.mjs
├── package.json
└── tsconfig.json
```

### Flow

1. Parse CLI args: explorer-url, signing-key (hex file path), registry-nft-id, network, timeout
2. Read raw hex private key → derive compressed public key → derive P2PK address
3. Fetch registry box by NFT token ID → extract operator PK, ECIES PK, guard script address
4. Generate WireGuard keypair (X25519) and ephemeral ECIES keypair (secp256k1)
5. Encrypt request payload (65 bytes) with broker's ECIES pubkey
6. Build request tx with Fleet SDK:
   - Input: client's UTXOs (for funding + beacon mint)
   - Output: request box at guard script address with beacon in tokens(0), client SigmaProp in R4, encrypted payload in R5, deadline in R6
   - Beacon token minted (amount=1, token ID = first input box ID)
7. Sign via ergo-relay, broadcast via ergo-relay
8. Save recovery state (beacon token ID, ECIES private key, timestamp)
9. Poll Explorer for unspent boxes by beacon token ID
10. When response box found: decode R5 → decrypt (compact ECDH-AES-GCM) → extract tunnel config
11. Output JSON to stdout:
    ```json
    {
      "prefix": "2a11:6c7:f04:...",
      "gateway": "2a11:6c7:f04:...",
      "broker_pubkey": "base64...",
      "broker_endpoint": "95.179.128.177:51820",
      "wg_private_key": "base64...",
      "wg_public_key": "base64...",
      "broker_wallet": "9f..."
    }
    ```
12. Build cleanup tx: consume response box (clientPk), burn beacon
13. Sign and broadcast cleanup tx

### `broker_wallet`

Derived from the operator's compressed public key (from registry R4) as a P2PK address.

### Recovery

State file: `/var/lib/blockhost/ergo-recovery.json`

```json
{
  "beaconTokenId": "...",
  "eciesPrivateKey": "...",
  "guardScriptAddress": "...",
  "operatorPkh": "...",
  "timestamp": 1234567890
}
```

On startup, if recovery state exists and is recent (< timeout), skip request submission and go straight to polling for response by beacon token ID. 60-second recovery timeout.

### Signing Key

Raw hex private key file (no mnemonic derivation). Client reads file, derives secp256k1 public key and Ergo P2PK address.

## Integration Points

### Registry Config

File: `registry-ergo-testnet.json`

```json
{
  "registry_nft_id": "<64-char hex token ID>",
  "explorer_url": "https://api-testnet.ergoplatform.com",
  "network": "ergo-testnet"
}
```

### Chain Dispatch

Add to `scripts/broker-chains.json`:

```json
{
  "name": "ergo",
  "match": "^9[a-zA-Z1-9]{50}$",
  "adapter": "node",
  "adapter_args": ["/opt/blockhost/adapters/ergo/client/dist/main.js", "request"],
  "timeout": 600,
  "explorer_url": "https://api-testnet.ergoplatform.com",
  "registry_nft_id": "<token ID>"
}
```

### Client Packaging

Update `scripts/build-deb.sh` to include:
- `/opt/blockhost/adapters/ergo/client/dist/main.js`

### Adapter Deployment

- Bundle: `/opt/blockhost/adapters/ergo/adapter/dist/main.js`
- Service: `blockhost-ergo-adapter@{network}.service`
- Env: `/etc/blockhost-broker/ergo-adapter-{network}.env`

### Broker Manager

Add Ergo wallet info section to dashboard (Explorer API for balance query).

### Broker Config

Add `[ergo]` section to `/etc/blockhost-broker/config.toml`:

```toml
[ergo]
operator_address = "9f..."
explorer_url = "https://api-testnet.ergoplatform.com"
```

## Contract Deployment Sequence

1. Compile guard script ErgoTree template (dev time, one-off)
2. Substitute operator PK via byte surgery → guard script ErgoTree + P2S address
3. Deployer mints registry NFT (singleton, amount=1) with operator PK, ECIES PK, guard ErgoTree in registers
4. Record registry NFT token ID in `registry-ergo-testnet.json`
5. Deploy adapter with guard script address + registry NFT ID in env
6. Deploy client with registry NFT ID in broker-chains.json
