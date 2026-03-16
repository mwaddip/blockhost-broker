# blockhost-broker Interface Specification

> Authoritative contract for everything blockhost-broker exposes to adapters, clients, and operators.
> Derived from source code audit (2026-02-25). When code and this doc disagree, investigate both.

---

## 1. REST API

**Framework**: Axum (Rust)
**Default listen**: `0.0.0.0:8080` (intended for `127.0.0.1` or internal network — no authentication)

All endpoints return JSON. Error responses use `{"error": "..."}`.

### Routes

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/v1/status` | Broker capacity and peer counts |
| POST | `/v1/allocations` | Create or re-request an allocation |
| GET | `/v1/allocations` | List all allocations |
| GET | `/v1/allocations/{prefix}` | Get a single allocation |
| DELETE | `/v1/allocations/{prefix}` | Release an allocation |
| GET | `/v1/config` | Client configuration (fetched through tunnel) |

---

### GET /health

No parameters, no authentication.

**Response (200):**

```json
{
  "status": "healthy",
  "version": "0.2.0"
}
```

`version` is the Cargo package version at build time.

---

### GET /v1/status

**Response (200):**

```json
{
  "upstream_prefix": "2a11:6c7:f04:276::/64",
  "allocation_size": 120,
  "total_allocations": 65535,
  "used_allocations": 42,
  "available_allocations": 65493,
  "active_peers": 10,
  "idle_peers": 5
}
```

| Field | Type | Description |
|-------|------|-------------|
| `upstream_prefix` | string | Broker's upstream IPv6 prefix |
| `allocation_size` | int | Prefix length handed to clients (e.g. 120 = /120) |
| `total_allocations` | int | Theoretical max from prefix math |
| `used_allocations` | int | Currently allocated |
| `available_allocations` | int | `total - used` |
| `active_peers` | int | WireGuard handshake within 5 minutes |
| `idle_peers` | int | Handshake exists but older than 5 minutes |

---

### POST /v1/allocations

Creates a new allocation, or updates the WireGuard pubkey for an existing one (same `nft_contract`).

**Request:**

```json
{
  "wg_pubkey": "base64-wireguard-public-key",
  "nft_contract": "0x...",
  "source": "opnet-regtest",
  "is_test": false,
  "lease_duration": 86400
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `wg_pubkey` | string | yes | — | Base64 WireGuard public key (44 chars) |
| `nft_contract` | string | yes | — | NFT contract address (lowercased internally for dedup) |
| `source` | string | no | `""` | Adapter identifier (e.g. `"opnet-regtest"`, `"evm-sepolia"`) |
| `is_test` | bool | no | `false` | If true, auto-expires in 24 hours |
| `lease_duration` | int\|null | no | `null` | Seconds until expiry. `null` = no expiry (unless `is_test`) |

**Response (201 Created):**

```json
{
  "prefix": "2a11:6c7:f04:276::100/120",
  "gateway": "2a11:6c7:f04:276::2",
  "broker_pubkey": "base64-wireguard-public-key",
  "broker_endpoint": "95.179.128.177:51820"
}
```

These four fields are the **canonical allocation response**. Consumers parse them via `load_broker_allocation()` in blockhost-common (see `facts/COMMON_INTERFACE.md` section 7). Any schema change here breaks all provisioners.

| Field | Type | Description |
|-------|------|-------------|
| `prefix` | string | Allocated IPv6 CIDR (e.g. `2a11:6c7:f04:276::100/120`) |
| `gateway` | string | Broker's IPv6 address (tunnel gateway) |
| `broker_pubkey` | string | Broker's WireGuard public key (base64) |
| `broker_endpoint` | string | Broker's WireGuard endpoint (`ipv4:port`) |

**Re-request behavior**: If the `nft_contract` already has an allocation, the WireGuard pubkey is swapped (old peer removed, new peer added) and the same prefix is returned. This enables key rotation without losing the prefix.

**Errors:**

| Status | Condition |
|--------|-----------|
| 409 Conflict | WireGuard pubkey already allocated to a different NFT contract |
| 503 Service Unavailable | No prefixes available in pool |
| 500 Internal Server Error | Database or WireGuard failure (allocation rolled back) |

---

### GET /v1/allocations

**Response (200):** Array of `AllocationInfo` (see below).

### GET /v1/allocations/{prefix}

`{prefix}` is a URL-encoded IPv6 CIDR (e.g. `2a11%3A6c7%3Af04%3A276%3A%3A100%2F120`).

**Response (200):**

```json
{
  "prefix": "2a11:6c7:f04:276::100/120",
  "pubkey": "base64-wg-pubkey",
  "endpoint": null,
  "nft_contract": "0x...",
  "source": "opnet-regtest",
  "allocated_at": "2026-02-25T14:30:00+00:00",
  "last_seen_at": null,
  "expires_at": "2026-02-26T14:30:00+00:00",
  "status": "active"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `prefix` | string | Allocated IPv6 CIDR |
| `pubkey` | string | Client's WireGuard public key |
| `endpoint` | string\|null | Client's WireGuard endpoint (if known) |
| `nft_contract` | string | NFT contract address |
| `source` | string | Adapter that created this allocation |
| `allocated_at` | string | ISO 8601 / RFC 3339 timestamp |
| `last_seen_at` | string\|null | Last WireGuard handshake time |
| `expires_at` | string\|null | Expiry timestamp (null = no expiry) |
| `status` | string | `"active"`, `"idle"`, or `"never_connected"` |

**Status derivation:**
- `active` — WireGuard handshake within last 5 minutes
- `idle` — Has handshake in history, but not recent
- `never_connected` — No handshake ever recorded

**Errors:** 400 (invalid prefix format), 404 (not found).

### DELETE /v1/allocations/{prefix}

Releases the allocation. Side effects:
1. Removes WireGuard peer
2. Removes IPv6 route from WireGuard interface
3. Removes NDP proxy entries (if `upstream_interface` configured)
4. Deletes from IPAM database

**Response:** 204 No Content.

**Errors:** 400 (invalid prefix), 404 (not found).

---

### GET /v1/config

Intended to be fetched by clients **through the WireGuard tunnel** after allocation.

**Response (200):**

```json
{
  "dns_zone": "blockhost.thawaras.org"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `dns_zone` | string | Broker's authoritative DNS zone. Empty string if DNS disabled. |

---

## 2. WireGuard Tunnel

**Protocol**: WireGuard (UDP)
**Default port**: 51820
**Interface name**: `wg-broker`

### Peer Management

Peers are added/removed dynamically without restarting WireGuard.

**Add peer** (on allocation):

```bash
wg set wg-broker peer <base64-pubkey> allowed-ips <prefix>
ip -6 route add <prefix> dev wg-broker
# If upstream_interface configured:
ip -6 neigh add proxy <addr> dev <upstream_interface>   # for each address in prefix
```

**Remove peer** (on release):

```bash
ip -6 route del <prefix> dev wg-broker
ip -6 neigh del proxy <addr> dev <upstream_interface>   # for each address
wg set wg-broker peer <base64-pubkey> remove
```

### Peer Status Query

```bash
wg show wg-broker dump
```

Output is tab-separated, one line per peer:

```
<pubkey>  <endpoint>  <allowed-ips>  <latest-handshake>  <rx-bytes>  <tx-bytes>
```

A peer is considered **active** if `latest-handshake` is within 300 seconds (5 minutes).

### NDP Proxy

Required when the upstream tunnel provider (e.g. Route64) expects NDP for address resolution within the /64. When `upstream_interface` is set, the broker adds proxy NDP entries for every address in each allocated prefix (up to 256 for /120 allocations).

Not needed for providers that support proper prefix routing (e.g. Hurricane Electric).

---

## 3. DNS Server

**Protocol**: UDP and TCP (RFC 7766 with 2-byte length prefix)
**Default listen**: `0.0.0.0:53`
**Disabled by default** — requires `[dns] enabled = true`

### Synthetic AAAA Records

Any query for `{hex_label}.{domain}` returns an AAAA record pointing to `{upstream_prefix}::{hex_label}`.

**Example:**

| Query | Response |
|-------|----------|
| `101.blockhost.thawaras.org AAAA` | `2a11:6c7:f04:276::101` |
| `ff.blockhost.thawaras.org AAAA` | `2a11:6c7:f04:276::ff` |
| `a0b1.blockhost.thawaras.org AAAA` | `2a11:6c7:f04:276::a0b1` |

**Label rules:**
- Must be valid hex (0-9, a-f, case-insensitive)
- Must not be `"0"` (zero host rejected → NXDOMAIN)
- Must fit within the prefix's host bits (e.g. for /64 prefix, max 16 hex chars)

**Address resolution:**

```
host_value = parse_hex(label)
address = upstream_prefix_network_bits | host_value
```

If `host_value` exceeds the host range for the prefix → NXDOMAIN.

### Infrastructure Records

| Query | Type | Response |
|-------|------|----------|
| `{domain}` | SOA | `mname=ns1.{domain}`, `rname=hostmaster.{domain}`, serial=1, refresh=3600, retry=600, expire=86400, minimum=300 |
| `{domain}` | NS | `ns1.{domain}` |
| `ns1.{domain}` | A | `{ns_ipv4}` from config (glue record) |

### Multi-Domain Support

The `extra_domains` config array allows serving identical synthetic records for additional domains. All domains use the same upstream prefix.

### Error Responses

| Response | Condition |
|----------|-----------|
| NXDOMAIN | Invalid hex label, label is `"0"`, or value exceeds host range |
| NODATA | Valid name but unsupported record type (e.g. AAAA for apex) |
| REFUSED | Query domain not in zone |

### RFC Compliance

- Echoes question section in response
- EDNS OPT record echoed if present in query
- AA (authoritative answer) flag set
- RD flag echoed if present
- Supports TCP (RFC 7766)

---

## 4. On-Chain Authentication (EVM)

**Blockchain**: Ethereum Sepolia (chain ID 11155111)
**Polling interval**: Configurable, default 5000ms (range: 1000–60000ms)

### Smart Contracts

**BrokerRegistry** (global, one per network):
- Stores list of available brokers with pubkey, region, capacity, requests contract address
- Client queries this to discover brokers

**BrokerRequests** (per-broker instance):
- Handles allocation requests for a specific broker
- Overwrite semantics: duplicate `nft_contract` expires old request, creates new one

#### Key Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `submitRequest` | `(address nftContract, bytes encryptedPayload) → uint256` | Client submits encrypted request, returns request ID |
| `getRequest` | `(uint256 requestId) → (uint256, address, address, bytes, uint256)` | Returns (id, requester, nftContract, encryptedPayload, timestamp) |
| `getRequestCount` | `() → uint256` | Total requests ever submitted (used for polling) |
| `capacityStatus` | `() → uint8` | 0=available, 1=limited, 2=closed |

### Monitor Polling Loop

1. Query `getRequestCount()` for primary, legacy, and test contracts
2. For each new request (from `last_processed + 1` to `count`):
   a. Fetch via `getRequest(id)`
   b. Decrypt payload with broker's ECIES private key
   c. Allocate prefix via internal API (`POST /v1/allocations`)
   d. Encrypt response with client's `serverPubkey`
   e. Submit response as direct Ethereum transaction
3. Store `last_processed = count` per contract in metadata table
4. Sleep `poll_interval_ms`, repeat

**Deduplication**: When multiple requests arrive from the same `nft_contract`, only the latest is processed (deduplicated in the same poll cycle).

### ECIES Encryption

**Curve**: secp256k1

**Request payload** (encrypted by client to broker's ECIES pubkey):

```json
{
  "wgPubkey": "base64-wireguard-public-key",
  "nftContract": "0x...",
  "serverPubkey": "hex-ecies-public-key"
}
```

**Response payload** (encrypted by broker to client's `serverPubkey`):

```json
{
  "prefix": "2a11:6c7:f04:276::100/120",
  "gateway": "2a11:6c7:f04:276::2",
  "brokerPubkey": "base64-wireguard-public-key",
  "brokerEndpoint": "95.179.128.177:51820",
  "dnsZone": "blockhost.thawaras.org"
}
```

**Response on-chain format**: `[8 bytes request_id big-endian u64][ECIES ciphertext]`

The request ID prefix lets clients detect stale responses without attempting decryption.

### Post-Approval Tunnel Verification

After approving a request, the broker monitors for WireGuard handshake. If no handshake within 2 minutes, the allocation is auto-released (IPAM + WireGuard + on-chain).

### Test Contract

Allocations from the test contract are marked `is_test = true` and auto-expire after 24 hours. The monitor periodically queries and releases expired test allocations.

---

## 5. On-Chain Authentication (OPNet)

**Blockchain**: Bitcoin (OPNet Tapscript-encoded calldata)
**Architecture**: External adapter process → broker REST API

Unlike the EVM monitor (built into the broker daemon), the OPNet adapter is a separate Node.js process that polls the OPNet BrokerRequests contract and calls the broker's REST API to create allocations.

### Adapter Flow

1. Poll `getRequestCount()` on the OPNet BrokerRequests contract
2. Fetch new requests, decrypt payload with broker's ECIES private key
3. `POST /v1/allocations` to the broker API (localhost:8080)
4. Encrypt response and deliver via Bitcoin OP_RETURN transaction

### OP_RETURN Response Delivery

The response is delivered as a Bitcoin transaction with an OP_RETURN output. The client finds it by attempting decryption — AES-GCM tag verification serves as authentication.

**OP_RETURN layout (80 bytes):**

```
[1 byte  version (0x01)]
[79 bytes encrypted payload]
```

**Encrypted payload (79 bytes):**

AES-256-GCM ciphertext (63 bytes) + authentication tag (16 bytes).

**Plaintext layout (63 bytes):**

| Offset | Size | Field |
|--------|------|-------|
| 0 | 32 | Broker WireGuard public key (raw bytes from base64) |
| 32 | 4 | Broker endpoint IPv4 (4 octets) |
| 36 | 2 | Broker endpoint port (big-endian) |
| 38 | 1 | Prefix mask length (e.g. 120) |
| 39 | 16 | Prefix network address (IPv6, 16 bytes) |
| 55 | 8 | Gateway host part (lower 64 bits of gateway IPv6) |

### Compact Encryption

No ephemeral key transmitted — both sides derive the same shared secret:

```
shared = ECDH(broker_ecies_privkey, client_serverPubkey)
ikm = shared[1:]                          # skip 0x04 prefix byte
aes_key = HKDF-SHA256(ikm, info="blockhost-aes-key", len=32)
iv = HKDF-SHA256(ikm, info="blockhost-aes-iv", len=12)
ciphertext || tag = AES-256-GCM(aes_key, iv, plaintext)
```

The client performs the inverse: `ECDH(client_ecies_privkey, broker_ecies_pubkey)` produces the same shared secret.

### UTXO Chaining

When multiple requests arrive in the same poll cycle, the adapter chains Bitcoin transactions: the change output from each broadcast is used as the input for the next. This avoids double-spend conflicts when the UTXO provider hasn't yet reflected mempool spends.

### Persistent State

The adapter stores `{"lastProcessedId": "<bigint>"}` in a JSON state file to avoid reprocessing requests across restarts. Default path: `/var/lib/blockhost-broker/adapter-opnet-{network}.state`.

### Adapter Configuration

Environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPNET_RPC_URL` | no | `https://regtest.opnet.org` | OPNet JSON-RPC URL |
| `OPNET_BROKER_REQUESTS_PUBKEY` | yes | — | BrokerRequests contract tweaked pubkey (0x-prefixed) |
| `OPNET_OPERATOR_MNEMONIC` | yes | — | Operator mnemonic (signs OP_RETURN transactions) |
| `BROKER_ECIES_PRIVATE_KEY` | yes | — | ECIES private key (hex, decrypts request payloads) |
| `BROKER_API_URL` | no | `http://127.0.0.1:8080` | Broker REST API URL |
| `ADAPTER_SOURCE` | no | `opnet-{network}` | Source identifier for allocations |
| `LEASE_DURATION` | no | `86400` (regtest), `0` (others) | Lease duration in seconds |
| `STATE_FILE` | no | `/var/lib/blockhost-broker/adapter-opnet-{network}.state` | Persistent state file path |

### Deployment

The adapter is bundled with esbuild into a single `dist/main.js` file. Deployment requires only Node.js and the bundle:

```bash
# On broker server
node /opt/blockhost/adapters/opnet/adapter/dist/main.js
```

Systemd template unit: `blockhost-opnet-adapter@.service` with `%i` for per-network env files.

---

## 6. Configuration

### `/etc/blockhost-broker/config.toml`

```toml
[broker]
upstream_prefix = "2a11:6c7:f04:276::/64"   # IPv6 CIDR, from tunnel provider
allocation_size = 120                         # 64–128, prefix length for clients
broker_ipv6 = "2a11:6c7:f04:276::2"         # Broker's own address in the prefix
max_allocations = 65535                       # Optional capacity limit

[wireguard]
interface = "wg-broker"                       # WireGuard interface name
listen_port = 51820
private_key_file = "/etc/blockhost-broker/wg-private.key"
public_endpoint = "95.179.128.177:51820"     # Advertised to clients
upstream_interface = "sit-tunnel"             # Optional, for NDP proxy

[api]
listen_host = "0.0.0.0"
listen_port = 8080

[database]
path = "/var/lib/blockhost-broker/ipam.db"   # SQLite

[dns]
enabled = true
domain = "blockhost.thawaras.org"            # Required if enabled; no trailing dot
listen = "0.0.0.0:53"
ttl = 300
ns_ipv4 = "95.179.128.177"                  # Glue A record for ns1.{domain}
extra_domains = ["vm.example.io"]            # Additional domains, same records

[onchain]
enabled = true
rpc_url = "https://ethereum-sepolia-rpc.publicnode.com"
chain_id = 11155111
private_key_file = "/etc/blockhost-broker/operator.key"
ecies_private_key_file = "/etc/blockhost-broker/ecies.key"
registry_contract = "0x..."
requests_contract = "0x..."
legacy_requests_contracts = []               # Old contracts to keep monitoring
test_requests_contract = "0x..."             # Auto-expire allocations
poll_interval_ms = 5000                      # 1000–60000
```

### Key Files

| File | Format | Purpose |
|------|--------|---------|
| `/etc/blockhost-broker/wg-private.key` | Raw WireGuard key | WireGuard interface private key |
| `/etc/blockhost-broker/operator.key` | Hex private key | Ethereum operator wallet (signs on-chain txs) |
| `/etc/blockhost-broker/ecies.key` | Hex private key (secp256k1) | Decrypts client request payloads |

All key files must be mode `0600`.

---

## 7. Database (SQLite IPAM)

**Path**: `/var/lib/blockhost-broker/ipam.db`

### Schema

```sql
CREATE TABLE allocations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    prefix        TEXT NOT NULL UNIQUE,
    prefix_index  INTEGER NOT NULL,
    pubkey        TEXT NOT NULL UNIQUE,
    endpoint      TEXT,
    nft_contract  TEXT NOT NULL,
    source        TEXT,
    allocated_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen_at  DATETIME,
    is_test       BOOLEAN DEFAULT 0,
    expires_at    DATETIME
);

CREATE TABLE metadata (
    contract_address TEXT PRIMARY KEY,
    last_processed_id INTEGER DEFAULT 0
);
```

| Table | Purpose |
|-------|---------|
| `allocations` | Active IPv6 prefix allocations |
| `metadata` | Per-contract last processed request ID (for polling) |

### Key Constraints

- `prefix` is UNIQUE — one prefix per allocation
- `pubkey` is UNIQUE — one WireGuard key per allocation
- `nft_contract` is not unique in the schema but is treated as a logical key for re-requests (lookup by `nft_contract` returns existing allocation)

---

## 8. Client-Side Output

### `/etc/blockhost/broker-allocation.json`

Written by the broker-client after a successful allocation. Read by blockhost-common's `load_broker_allocation()`.

```json
{
  "prefix": "2a11:6c7:f04:276::100/120",
  "gateway": "2a11:6c7:f04:276::2",
  "broker_pubkey": "base64-wireguard-public-key",
  "broker_endpoint": "95.179.128.177:51820",
  "dns_zone": "blockhost.thawaras.org"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `prefix` | string | yes | Allocated IPv6 CIDR |
| `gateway` | string | yes | Broker gateway IPv6 |
| `broker_pubkey` | string | yes | Broker WireGuard public key |
| `broker_endpoint` | string | yes | Broker WireGuard endpoint |
| `dns_zone` | string | no | Broker DNS zone (empty or absent = no DNS) |

**Consumers**: `load_broker_allocation()` in blockhost-common, VM provisioners (IPv6 pool + FQDN derivation via `{offset:x}.{dns_zone}`).

The four required fields (`prefix`, `gateway`, `broker_pubkey`, `broker_endpoint`) match the `POST /v1/allocations` response schema. `dns_zone` is fetched separately via `GET /v1/config` through the tunnel.

---

## 9. Systemd Service

### blockhost-broker.service

```ini
[Unit]
Description=Blockhost IPv6 Tunnel Broker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=blockhost
Group=blockhost
ExecStart=/usr/bin/blockhost-broker run
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ReadWritePaths=/var/lib/blockhost-broker
ReadWritePaths=/etc/wireguard
ConfigurationDirectory=blockhost-broker
StateDirectory=blockhost-broker

[Install]
WantedBy=multi-user.target
```

**Required capabilities:**
- `CAP_NET_ADMIN` — WireGuard peer management + IPv6 routing + NDP proxy
- `CAP_NET_BIND_SERVICE` — DNS on port 53

### blockhost-opnet-adapter@.service

Systemd template unit for OPNet adapters (`%i` = network name).

```ini
[Unit]
Description=Blockhost OPNet Adapter (%i)
After=network.target blockhost-broker.service
Requires=blockhost-broker.service

[Service]
Type=simple
EnvironmentFile=/etc/blockhost-broker/opnet-adapter-%i.env
ExecStart=/usr/bin/node /opt/blockhost/adapters/opnet/adapter/dist/main.js
Restart=on-failure
RestartSec=10
WorkingDirectory=/opt/blockhost/adapters/opnet/adapter

[Install]
WantedBy=multi-user.target
```

---

## 10. Installed File Locations

### Broker Daemon

```
/usr/bin/blockhost-broker
/etc/blockhost-broker/
  ├── config.toml              # Main configuration
  ├── operator.key             # Ethereum operator private key (0600)
  ├── ecies.key                # ECIES private key (0600)
  ├── wg-private.key           # WireGuard private key (0600)
  └── wg-public.key            # WireGuard public key
/var/lib/blockhost-broker/
  └── ipam.db                  # SQLite database
/lib/systemd/system/
  └── blockhost-broker.service
```

### OPNet Adapter

```
/opt/blockhost/adapters/opnet/adapter/
  └── dist/main.js             # Bundled adapter (esbuild, single file)
/etc/blockhost-broker/
  └── opnet-adapter-{network}.env  # Per-network environment variables
/var/lib/blockhost-broker/
  └── adapter-opnet-{network}.state  # Persistent polling state
/lib/systemd/system/
  └── blockhost-opnet-adapter@.service
```

### Broker Client (on Blockhost hosts)

```
/opt/blockhost-client/
  ├── broker-client.py         # Python client script
  └── venv/                    # Virtual environment
/usr/bin/broker-client         # Wrapper script
/etc/blockhost/
  ├── server.key               # Persistent ECIES private key
  └── broker-allocation.json   # Current allocation (written on success)
```

---

## 11. Consumers

| Consumer | Interfaces Used | Notes |
|----------|----------------|-------|
| **EVM on-chain monitor** | IPAM + WireGuard (internal) | Built into broker daemon, polls Ethereum contracts |
| **OPNet adapter** | REST API (`POST /v1/allocations`) | External process, delivers responses via OP_RETURN |
| **Broker manager** | REST API (all endpoints) | Web UI for operators, Flask app on port 8443 |
| **Broker client** | On-chain contracts + WireGuard tunnel + `GET /v1/config` | Python client on Blockhost hosts |
| **blockhost-common** | `broker-allocation.json` | `load_broker_allocation()` reads the four required fields |
| **VM provisioners** | `broker-allocation.json` (via common) | IPv6 pool derivation, FQDN via `{offset:x}.{dns_zone}` |
| **Let's Encrypt / DNS** | DNS AAAA records | Clients use `{hex}.{dns_zone}` for certificate validation |

---

## 12. Known Issues

### DESIGN.md drift

`DESIGN.md` describes the original architecture and has diverged from the current implementation in several areas:
- API paths show `/v1/allocate` (singular); actual is `/v1/allocations` (plural)
- Token-based authentication described but removed in V3 (on-chain auth only)
- Database schema shows `tokens` and `audit_log` tables; actual has `allocations` and `metadata` only
- `wg-quick save` described for persistence; actual uses dynamic `wg set` only
- CLI tool `blockhost-broker-ctl` described but not implemented

### Source field defaults

If `source` is not provided in `POST /v1/allocations`, it defaults to empty string `""`. The EVM monitor sets it to `"evm:{contract_address}"`. Adapters should always set a meaningful source.

### No authentication on REST API

The REST API has no authentication. It is intended to be bound to localhost or an internal network. External adapters (like OPNet) connect to `127.0.0.1:8080`. The broker manager has its own wallet-based authentication.
