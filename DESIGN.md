# blockhost-broker Design Document

## Overview

blockhost-broker is a multichain IPv6 tunnel broker that sub-allocates prefixes from an upstream provider to Blockhost installations. Authentication happens on-chain — clients submit encrypted requests to smart contracts, the broker monitors those contracts, provisions allocations, and delivers encrypted responses. No API keys or bearer tokens.

The broker supports multiple blockchains through an adapter architecture: EVM (Ethereum) is built into the Rust daemon, while additional chains (OPNet/Bitcoin) run as external adapter processes that talk to the broker's REST API.

## Architecture

```
                        Internet
                            |
                            v
                    ┌───────────────┐
                    │   Route64.org │
                    │  (upstream)   │
                    └───────┬───────┘
                            │ SIT (6in4) tunnel
                            │ /64 routed to broker
                            v
┌──────────────────────────────────────────────────────────────────┐
│                      blockhost-broker                             │
│                                                                   │
│  ┌────────────┐  ┌──────────┐  ┌────────────┐  ┌──────────────┐  │
│  │  EVM       │  │   IPAM   │  │ WireGuard  │  │    DNS       │  │
│  │  Monitor   │  │ (SQLite) │  │  Manager   │  │   Server     │  │
│  └─────┬──────┘  └────┬─────┘  └─────┬──────┘  └──────────────┘  │
│        │              │              │                            │
│        └──────────────┼──────────────┘                            │
│                       │                                           │
│                 ┌─────┴──────┐                                    │
│                 │  REST API  │ ◄──── OPNet Adapter (external)     │
│                 │  (Axum)   │ ◄──── Future adapters               │
│                 └────────────┘                                    │
└──────────────────────────────────────────────────────────────────┘
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
          v                 v                 v
     ┌─────────┐       ┌─────────┐       ┌─────────┐
     │Blockhost│       │Blockhost│       │Blockhost│
     │ Host A  │       │ Host B  │       │ Host C  │
     │  /120   │       │  /120   │       │  /120   │
     └────┬────┘       └────┬────┘       └────┬────┘
          │                 │                 │
         VMs               VMs               VMs
```

### Traffic Flow

```
Internet → Route64 (SIT) → upstream tunnel → [NDP Proxy] → wg-broker → Client
```

The broker sits between an upstream IPv6 tunnel provider and downstream WireGuard clients. Each client gets a /120 prefix (256 addresses) from the broker's /64 upstream allocation.

## Components

### Broker Daemon (Rust)

Single binary with subcommands:

| Command | Description |
|---------|-------------|
| `run` | Main daemon — API server, on-chain monitor, DNS, WireGuard management |
| `check-config` | Validate config and print settings |
| `generate-key` | Create ECIES keypair |
| `wallet` | Ethereum wallet operations (generate, address, balance) |
| `deploy-contracts` | Deploy BrokerRequests contract |
| `setup` | Interactive setup wizard |
| `detect-ipv6` | Find IPv6 interfaces with global addresses |
| `status` | Show broker status |
| `allocations` | List/show allocations |

When running, the daemon starts these subsystems concurrently:
1. **REST API** (Axum) — internal management and adapter integration
2. **EVM Monitor** — polls Ethereum contracts for new requests
3. **WireGuard Manager** — dynamic peer add/remove via `wg set`
4. **DNS Server** (optional) — authoritative, synthesizes AAAA records
5. **IPAM** — SQLite-backed prefix allocation

### Multichain Adapter Architecture

The EVM monitor is built into the daemon. Additional chains use external adapter processes:

```
┌──────────────────┐     POST /v1/allocations     ┌──────────────────┐
│  OPNet Adapter   │ ──────────────────────────► │                  │
│  (Node.js)       │                              │  Broker Daemon   │
│                  │ ◄────── JSON response ────── │  (Rust)          │
│  Polls OPNet     │                              │                  │
│  contract,       │     Owns:                    │  Owns:           │
│  delivers via    │     - Contract polling        │  - IPAM          │
│  OP_RETURN       │     - ECIES encrypt/decrypt  │  - WireGuard     │
└──────────────────┘     - Response delivery       │  - DNS           │
                                                  │  - SQLite        │
                                                  └──────────────────┘
```

**Adapter responsibilities**: poll chain-specific contracts, decrypt requests, call broker API, encrypt and deliver responses using the chain's native mechanism.

**Broker core responsibilities**: IPAM, WireGuard peer management, NDP proxy, DNS, SQLite, allocation lifecycle. Chain-agnostic — doesn't know or care which chain requested the allocation.

Each adapter identifies itself via the `source` field (e.g. `"evm:0x145e..."`, `"opnet-regtest"`), and can set a `lease_duration` for auto-expiry.

### Broker Manager (Python/Flask)

Web dashboard at port 8443 for operators. Wallet-based authentication (MetaMask nonce signing). View and release leases, check wallet balance. Separate package, talks to the broker's REST API.

### Broker Client (Python)

Runs on Blockhost servers (Proxmox). Single entry point (`broker-client.py`) with chain dispatch via `broker-chains.json` config. EVM path is built-in (Python); OPNet path invokes a Node.js subprocess. After allocation, configures WireGuard and saves the result to `/etc/blockhost/broker-allocation.json`.

## V3 Contract Design

### What V3 Simplified

V3 (current) is a fundamental simplification over V2:

| Aspect | V2 | V3 |
|--------|----|----|
| Response delivery | Stored on-chain via `submitResponse()` | Direct ETH tx to requester (EVM) or OP_RETURN (OPNet) |
| Release | On-chain `releaseAllocation()` | Local-only (remove WG peer + delete DB row) |
| Capacity tracking | `totalCapacity`, `_activeCount`, `_pendingCount` counters | `capacityStatus` uint8 (0=available, 1=limited, 2=closed) |
| Contract functions | 10+ including `submitResponse`, `releaseAllocation`, `markExpired`, `getAvailableCapacity` | 4: `submitRequest`, `getRequest`, `getRequestCount`, `setCapacityStatus` |
| Request struct | id, requester, nftContract, encryptedPayload, submittedAt, respondedAt, responsePayload, status enum | id, requester, nftContract, encryptedPayload, submittedAt |

The key insight: responses and releases don't need to be on-chain. The broker is the only party that needs to track allocations (it controls the WireGuard interface). Putting responses on-chain was expensive and added complexity for no trust benefit.

### Request/Response Flow (EVM)

```
Client                          Blockchain                    Broker
  │                                │                            │
  │  submitRequest(nft, payload)   │                            │
  │ ─────────────────────────────► │                            │
  │                                │  poll getRequestCount()    │
  │                                │ ◄────────────────────────  │
  │                                │  getRequest(id)            │
  │                                │ ◄────────────────────────  │
  │                                │                            │
  │                                │        ┌──────────────┐    │
  │                                │        │ Verify NFT   │    │
  │                                │        │ Allocate /120│    │
  │                                │        │ Add WG peer  │    │
  │                                │        └──────────────┘    │
  │                                │                            │
  │  direct ETH tx with response   │                            │
  │ ◄──────────────────────────────┼──────────────────────────  │
  │                                │                            │
  │  [decrypt, configure WG]       │                            │
```

### Request/Response Flow (OPNet)

```
Client                     OPNet (Bitcoin)               Adapter              Broker API
  │                            │                           │                     │
  │  submitRequest(payload)    │                           │                     │
  │ ─────────────────────────► │                           │                     │
  │                            │  poll getRequestCount()   │                     │
  │                            │ ◄────────────────────────  │                     │
  │                            │  getRequest(id)           │                     │
  │                            │ ◄────────────────────────  │                     │
  │                            │                           │                     │
  │                            │          ┌────────────────┤                     │
  │                            │          │ Decrypt, POST  │ /v1/allocations     │
  │                            │          │ ──────────────►│ ──────────────────► │
  │                            │          │ ◄──────────────│ ◄────── allocation  │
  │                            │          │ Encrypt, send  │                     │
  │                            │          └────────────────┤                     │
  │                            │                           │                     │
  │  OP_RETURN (72B encrypted) │                           │                     │
  │ ◄──────────────────────────┼────────────────────────── │                     │
```

### Encryption

| Purpose | EVM | OPNet |
|---------|-----|-------|
| Request encryption | ECIES (secp256k1), client → broker pubkey | Same |
| Response encryption | ECIES (secp256k1), broker → client pubkey | ECDH-AES-256-GCM (compact, 72B on-chain) |
| Response delivery | Direct ETH tx: `[8B request_id][ECIES ciphertext]` | OP_RETURN: `[1B version][71B ECDH-AES encrypted]` |
| WireGuard tunnel | Curve25519 (separate key, inside encrypted payload) | Same |

OPNet uses compact ECDH-AES instead of full ECIES because Bitcoin OP_RETURN is limited to ~80 bytes. The shared secret is derived deterministically (no ephemeral key transmitted).

### NFT Ownership Verification

Before processing a request, the broker verifies:
1. NFT contract has code deployed (`getCode != 0x`)
2. Sender owns the contract (`Ownable.owner() == msg.sender`)
3. Contract supports ERC-721 (`supportsInterface(0x80ac58cd)`)

### Re-Request and Key Rotation

If a request arrives for an NFT contract that already has an allocation:
- The WireGuard pubkey is swapped (old peer removed, new added)
- Same prefix is returned
- The on-chain contract overwrites the old request (no revert)

This enables key rotation without losing the prefix. Useful after server re-install.

### Post-Approval Verification

After provisioning an allocation, the broker monitors for a WireGuard handshake. If no handshake within 120 seconds, the allocation is auto-released. This handles cases where the client never received or couldn't decrypt the response.

### Lease Expiry

Allocations can have an `expires_at` timestamp:
- Test contract allocations auto-expire after 24 hours
- External adapters can set `lease_duration` (e.g. OPNet regtest defaults to 86400s)
- The monitor periodically checks and releases expired allocations

## DNS Server

Built-in authoritative DNS server that synthesizes AAAA records from the upstream prefix. Purely synthetic — no database lookups.

`{hex}.{domain}` → `{prefix}::{hex}`

Example: `101.vm.blockhost.io` → `2a11:6c7:f04:276::101`

Supports multiple domains (primary + `extra_domains`), UDP and TCP, SOA/NS/glue records. Disabled by default.

Clients use DNS names for TLS certificate validation: each VM derives its FQDN from its offset in the allocated prefix and the broker's DNS zone.

## NDP Proxy

Some tunnel providers (e.g. Route64 SIT tunnels) use NDP to discover which addresses are in use within the delegated prefix, rather than routing the entire prefix statically. The broker handles this by adding NDP proxy entries on the upstream interface for every address in each allocated prefix.

This is transparent — the broker adds/removes proxy entries automatically when peers are added/removed. Only needed when `upstream_interface` is configured. Not needed for providers with proper prefix routing (e.g. Hurricane Electric).

Limitation: NDP proxy is practical only for small allocations (/120 = 256 entries per peer). Larger prefixes would need proper routing from upstream.

## Database

SQLite with two active tables:

| Table | Purpose |
|-------|---------|
| `allocations` | Active prefix allocations (prefix, pubkey, nft_contract, source, timestamps, expiry) |
| `state` | Per-contract last processed request ID (for polling) |

Legacy `tokens` and `audit_log` tables exist in the schema but are not used by V3 on-chain auth.

Key constraints: `prefix` and `pubkey` are both UNIQUE. `nft_contract` is not unique in the schema but is treated as a logical key for re-requests.

## Security Model

- **No API authentication**: REST API is bound to localhost. External access only through WireGuard tunnel or local adapter processes.
- **On-chain identity**: All allocation requests authenticated via NFT contract ownership.
- **ECIES encryption**: Request and response payloads encrypted end-to-end. WireGuard keys never transmitted in plaintext.
- **Peer isolation**: Each WireGuard peer is restricted to their allocated prefix via `allowed-ips`. No peer-to-peer routing.
- **Minimal attack surface**: No response storage on-chain, no release transactions, no capacity counters to manipulate.
- **Handshake verification**: Allocations auto-released if client never connects (120s timeout).
- **Stale response detection**: EVM responses prefixed with request ID — client can detect responses from a previous broker ECIES key without attempting decryption.

## Deployment

### Package Structure

**Broker server** (`blockhost-broker`):
- `/usr/bin/blockhost-broker` — Rust daemon
- `/etc/blockhost-broker/` — config.toml + key files
- `/var/lib/blockhost-broker/ipam.db` — SQLite database
- OPNet adapter plugin: `/opt/blockhost/adapters/opnet/adapter/dist/main.js`
- Systemd: `blockhost-broker.service` + `blockhost-opnet-adapter@.service` (template)

**Broker client** (`blockhost-broker-client`):
- `/opt/blockhost-client/broker-client.py` — Python client with chain dispatch
- `/etc/blockhost/broker-chains.json` — Chain config (dpkg conffile)
- OPNet client plugin: `/opt/blockhost/adapters/opnet/client/dist/main.js`

### Required Capabilities

- `CAP_NET_ADMIN` — WireGuard peer management, IPv6 routing, NDP proxy
- `CAP_NET_BIND_SERVICE` — DNS on port 53

## Interface Specification

For detailed API schemas, database schema, OP_RETURN binary layout, config reference, systemd units, and file locations, see **[BROKER_INTERFACE.md](BROKER_INTERFACE.md)**.

## Future Considerations

- Multiple upstream providers (failover)
- Additional chain adapters (Cardano, Solana, etc.)
- Geographic distribution (multiple broker instances)
- Prefix delegation for larger operators (/48 allocations)
- Usage metering per allocation
