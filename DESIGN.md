# blockhost-broker Design Document

## Overview

blockhost-broker is a lightweight IPv6 tunnel broker that sub-allocates IPv6 prefixes from an upstream provider (Route64.org) to Blockhost installations. It enables Blockhost VMs to have public IPv6 connectivity without requiring each operator to set up their own tunnel broker account.

## Architecture

```
                    Internet
                        │
                        ▼
                ┌───────────────┐
                │   Route64.org │
                │  (upstream)   │
                └───────┬───────┘
                        │ SIT (6in4) tunnel
                        │ /64 routed to broker
                        ▼
┌─────────────────────────────────────────────────────────┐
│                   blockhost-broker                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │  API Server │  │    IPAM     │  │ WireGuard Mgmt  │  │
│  │   (Axum)    │◄─┤  (SQLite)   │◄─┤   (wg tools)    │  │
│  └──────┬──────┘  └─────────────┘  └────────┬────────┘  │
│         │                                    │          │
│         └──────────► REST API ◄──────────────┘          │
└─────────────────────────┬───────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
   ┌─────────┐       ┌─────────┐       ┌─────────┐
   │Blockhost│       │Blockhost│       │Blockhost│
   │ Host A  │       │ Host B  │       │ Host C  │
   │  /64    │       │  /64    │       │  /64    │
   └────┬────┘       └────┬────┘       └────┬────┘
        │                 │                 │
       VMs               VMs               VMs
```

## Components

### 1. On-Chain Monitor (Primary Mode)

The broker primarily operates in on-chain mode, monitoring the blockchain for allocation requests.

**Flow:**
1. Lazy polls `BrokerRequests.getRequestCount()` every 5 seconds
2. Fetches new requests via `getRequest(id)`
3. Verifies NFT contract ownership
4. Allocates prefix, adds WireGuard peer
5. Submits response on-chain (request ID prefix + ECIES encrypted payload)
6. Starts 2-minute tunnel verification — releases allocation if no WireGuard handshake

### 2. Internal API Server (Secondary)

Axum-based REST server for local management (127.0.0.1:8080 by default).

**Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | /health | Health check endpoint |
| GET | /api/allocations | List allocations |
| GET | /api/status | Broker status |

### 2. IPAM Module

Manages IPv6 prefix allocations using SQLite.

**Responsibilities:**
- Track allocated and available /64 prefixes
- Map allocations to tokens and WireGuard public keys
- Handle allocation lifecycle (create, query, release)
- Prevent duplicate allocations

### 3. WireGuard Manager

Interfaces with WireGuard to manage downstream peers.

**Responsibilities:**
- Add peers dynamically via `wg set`
- Remove peers on deallocation
- Sync configuration to disk for persistence
- Query peer status (handshake times, transfer stats)

### 4. Authentication

Bearer token authentication for API access.

**Token Properties:**
- SHA-256 hashed in database
- Configurable allocation limit per token (default: 1)
- Admin tokens for management operations
- Tokens generated via CLI tool

---

## Data Models

### Configuration (`/etc/blockhost-broker/config.toml`)

```toml
[broker]
# Upstream prefix allocated from Route64
upstream_prefix = "2a11:6c7:f04:276::/64"

# Size of allocations to hand out (/120 = 256 addresses per host)
allocation_size = 120

# Broker's own IPv6 address (first address in prefix)
broker_ipv6 = "2a11:6c7:f04:276::1"

[wireguard]
# Interface name for downstream peers
interface = "wg-broker"

# Listen port
listen_port = 51820

# Private key file path
private_key_file = "/etc/blockhost-broker/wg-private.key"

# Public endpoint for clients to connect to
public_endpoint = "198.51.100.1:51820"

# Upstream interface for NDP proxy (e.g., sit1, tb25255R64)
# Required when tunnel provider expects NDP for address resolution
upstream_interface = "tb25255R64"

[api]
# Listen address
listen = "0.0.0.0:8080"

# Enable HTTPS (recommended for production)
tls_enabled = false
tls_cert = ""
tls_key = ""

[database]
# SQLite database path
path = "/var/lib/blockhost-broker/ipam.db"

[logging]
level = "info"
file = "/var/log/blockhost-broker/broker.log"
```

### Database Schema

```sql
-- Allocations table (on-chain mode uses nft_contract instead of token_hash)
CREATE TABLE allocations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prefix TEXT UNIQUE NOT NULL,           -- e.g., "2a11:6c7:f04:276::100/120"
    prefix_index INTEGER UNIQUE NOT NULL,  -- index within upstream prefix
    pubkey TEXT NOT NULL,                  -- WireGuard public key
    endpoint TEXT,                         -- Optional: client endpoint
    nft_contract TEXT NOT NULL,            -- NFT contract address (on-chain auth)
    allocated_at TEXT NOT NULL,            -- ISO 8601 timestamp
    last_seen_at TEXT                      -- Last handshake time
);

CREATE INDEX idx_allocations_nft_contract ON allocations(nft_contract);
CREATE INDEX idx_allocations_pubkey ON allocations(pubkey);

-- Tokens table (for legacy/offline mode)
CREATE TABLE tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT UNIQUE NOT NULL,       -- SHA-256 of token
    name TEXT,                             -- Human-readable name
    max_allocations INTEGER DEFAULT 1,     -- Max allocations this token can create
    is_admin BOOLEAN DEFAULT FALSE,        -- Admin privileges
    created_at TEXT NOT NULL,
    expires_at TEXT,                       -- Optional expiration
    revoked BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_tokens_hash ON tokens(token_hash);

-- Audit log
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,                  -- allocate, release, etc.
    nft_contract TEXT,                     -- NFT contract (on-chain mode)
    prefix TEXT,
    details TEXT                           -- JSON blob
);

-- State table (for lazy polling)
CREATE TABLE state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
-- Used to store last_processed_id for request polling
```

---

## API Specification

### Authentication

All endpoints except `/health` require a Bearer token:

```
Authorization: Bearer <token>
```

### POST /v1/allocate

Request a new IPv6 /64 allocation.

**Request:**
```json
{
    "pubkey": "base64-encoded-wireguard-public-key",
    "endpoint": "203.0.113.45:51820"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| pubkey | string | Yes | WireGuard public key (base64) |
| endpoint | string | No | Client's WireGuard endpoint (host:port). Optional because most Blockhost hosts are behind NAT - they connect outbound to the broker, and WireGuard learns the return path automatically. Only needed if the host has a static public IP and the broker should initiate connections. |

**Response (201 Created):**
```json
{
    "prefix": "2001:db8:abcd:0a00::/64",
    "gateway": "2001:db8:abcd::1",
    "broker_pubkey": "base64-encoded-broker-public-key",
    "broker_endpoint": "198.51.100.1:51820",
    "allocated_at": "2025-01-15T10:30:00Z"
}
```

**Errors:**
- `400 Bad Request` - Invalid pubkey format
- `401 Unauthorized` - Invalid or missing token
- `403 Forbidden` - Token allocation limit reached
- `409 Conflict` - Pubkey already has an allocation
- `503 Service Unavailable` - No prefixes available

### GET /v1/allocate/{prefix}

Query an existing allocation.

**Path Parameters:**
- `prefix` - URL-encoded prefix (e.g., `2001%3Adb8%3Aabcd%3A0a00%3A%3A%2F64`)

**Response (200 OK):**
```json
{
    "prefix": "2001:db8:abcd:0a00::/64",
    "pubkey": "base64-encoded-wireguard-public-key",
    "endpoint": "203.0.113.45:51820",
    "allocated_at": "2025-01-15T10:30:00Z",
    "last_seen_at": "2025-01-15T12:45:00Z",
    "status": "active"
}
```

**Status Values:**
- `active` - Recent handshake (within 5 minutes)
- `idle` - No recent handshake
- `never_connected` - No handshake ever recorded

**Errors:**
- `401 Unauthorized` - Invalid token
- `403 Forbidden` - Token doesn't own this allocation
- `404 Not Found` - Prefix not allocated

### DELETE /v1/allocate/{prefix}

Release an allocation.

**Response (204 No Content):** Success, no body.

**Errors:**
- `401 Unauthorized` - Invalid token
- `403 Forbidden` - Token doesn't own this allocation
- `404 Not Found` - Prefix not allocated

### GET /v1/status

Get broker status (admin only).

**Response (200 OK):**
```json
{
    "upstream_prefix": "2001:db8:abcd::/56",
    "total_allocations": 256,
    "used_allocations": 12,
    "available_allocations": 244,
    "active_peers": 10,
    "idle_peers": 2
}
```

### GET /health

Health check (no authentication required).

**Response (200 OK):**
```json
{
    "status": "healthy",
    "version": "1.0.0",
    "uptime_seconds": 86400
}
```

---

## NDP Proxy Management

When using tunnel providers like Route64 that expect NDP for address resolution within the allocated /64, the broker must advertise client addresses via NDP proxy.

### How It Works

1. When a peer is added, the broker adds NDP proxy entries for all addresses in the allocated prefix (up to 256 addresses for /120 allocations)
2. When a peer is removed, the corresponding NDP proxy entries are cleaned up
3. The upstream router sees the addresses as "on-link" and routes traffic to the broker

### Configuration

```toml
[wireguard]
upstream_interface = "tb25255R64"  # SIT tunnel interface to Route64
```

### System Requirements

The Debian package automatically configures these, but for manual setup:

```bash
# Enable IPv6 forwarding
sysctl -w net.ipv6.conf.all.forwarding=1

# Enable NDP proxy
sysctl -w net.ipv6.conf.all.proxy_ndp=1

# Make persistent
cat > /etc/sysctl.d/99-blockhost-broker.conf << EOF
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.all.proxy_ndp = 1
EOF
```

### UFW Configuration

If using UFW, allow forwarding between interfaces:

```bash
ufw allow 51820/udp comment "WireGuard"
ufw route allow in on wg-broker out on tb25255R64
ufw route allow in on tb25255R64 out on wg-broker
```

### Why NDP Proxy Instead of Routing?

Proper tunnel brokers route prefixes to your endpoint. However, some providers (like Route64 with SIT tunnels) expect all addresses within the /64 to be resolved via NDP, as if they were directly on-link. NDP proxy makes allocated addresses appear to be on the upstream interface, allowing the provider to route traffic to them.

For providers that support proper prefix routing (like Hurricane Electric), NDP proxy is not needed - just configure `upstream_interface` to be empty or omit it.

---

## WireGuard Management

### Network Architecture

The broker uses two interfaces:

1. **SIT tunnel (`tb*`)** - Upstream connection to Route64 for IPv6 transit
2. **WireGuard interface (`wg-broker`)** - Downstream connections to Blockhost hosts

```
Internet ← SIT tunnel ← Broker → WireGuard → Blockhost Hosts
                         ↓
                    Routes between
                    SIT and WireGuard
```

**Upstream (SIT to Route64) - configured once:**
```bash
ip tunnel add tb25255R64 mode sit remote 118.91.187.67 local 95.179.128.177 ttl 255
ip link set tb25255R64 up
ip -6 addr add 2a11:6c7:f04:276::2/64 dev tb25255R64
ip -6 route add ::/0 dev tb25255R64
sysctl -w net.ipv6.conf.all.forwarding=1
```

**Downstream (WireGuard for Blockhost hosts) - managed by broker:**
```bash
# Generate keypair
wg genkey | tee /etc/blockhost-broker/wg-private.key | wg pubkey > /etc/blockhost-broker/wg-public.key
chmod 600 /etc/blockhost-broker/wg-private.key

# Create interface (no address needed - we route TO peers, not through this interface)
ip link add dev wg-broker type wireguard
wg set wg-broker listen-port 51820 private-key /etc/blockhost-broker/wg-private.key
ip link set wg-broker up

# Peers added dynamically by broker API, e.g.:
# wg set wg-broker peer <host-pubkey> allowed-ips 2a11:6c7:f04:276::100/120
```

### Dynamic Peer Management

Peers are added/removed without restarting WireGuard:

**Add peer:**
```bash
wg set wg-broker peer <pubkey> allowed-ips 2001:db8:abcd:0a00::/64 endpoint <endpoint>
```

**Remove peer:**
```bash
wg set wg-broker peer <pubkey> remove
```

**Query peer status:**
```bash
wg show wg-broker dump
```

### Configuration Persistence

On each peer change, sync to disk:

```bash
wg-quick save wg-broker
# Or manually:
wg showconf wg-broker > /etc/wireguard/wg-broker.conf
```

---

## Security Considerations

### Network Security

1. **API Access**
   - HTTPS recommended for production
   - Rate limiting: 10 requests/minute per IP
   - Fail2ban integration for repeated auth failures

2. **WireGuard**
   - Each peer isolated to their /64 via AllowedIPs
   - No peer-to-peer routing (broker is hub)
   - Cryptographic authentication via public keys

3. **Token Security**
   - Tokens stored as SHA-256 hashes
   - Minimum 32 bytes entropy
   - Revocation supported

### Input Validation

- WireGuard public keys: Validate base64, 32 bytes decoded
- Endpoints: Validate IP:port format, reject private IPs for endpoint
- Prefixes: Strict parsing, must be within upstream allocation

### Audit Trail

All allocation changes logged with timestamp, token hash, and action.

---

## Deployment

### System Requirements

- Linux with WireGuard kernel module
- 512MB RAM minimum
- Static IPv4 address
- Ethereum wallet with testnet ETH (for on-chain transactions)

### Broker Package Contents

```
/usr/bin/blockhost-broker              # Main Rust daemon
/etc/blockhost-broker/config.toml      # Configuration
/etc/blockhost-broker/operator.key     # Ethereum operator wallet
/etc/blockhost-broker/ecies.key        # ECIES encryption key
/etc/blockhost-broker/wg-private.key   # WireGuard private key
/var/lib/blockhost-broker/ipam.db      # SQLite database
/lib/systemd/system/blockhost-broker.service
```

### Manager Package Contents

```
/opt/blockhost-broker-manager/         # Python Flask app
/etc/blockhost-broker-manager/auth.json       # Authorized wallets
/etc/blockhost-broker-manager/ssl/cert.pem    # Self-signed certificate
/etc/blockhost-broker-manager/ssl/key.pem
/lib/systemd/system/blockhost-broker-manager.service
```

### Client Package Contents

```
/opt/blockhost-client/broker-client.py    # Python client script
/opt/blockhost-client/venv/               # Virtual environment
/usr/bin/broker-client                    # Wrapper script
/etc/blockhost/                           # Config directory
/etc/blockhost/server.key                 # Persistent ECIES private key
/etc/blockhost/allocation.json            # Current allocation details
```

### systemd Service

```ini
[Unit]
Description=Blockhost IPv6 Tunnel Broker
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStartPre=/usr/bin/blockhost-broker --check-config
ExecStart=/usr/bin/blockhost-broker
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/blockhost-broker /var/log/blockhost-broker /etc/wireguard
PrivateTmp=yes
CapabilityBoundingSet=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

### CLI Tool Usage

```bash
# Token management
blockhost-broker-ctl token create --name "host-alpha" --max-allocations 1
blockhost-broker-ctl token list
blockhost-broker-ctl token revoke <token-id>

# Allocation management
blockhost-broker-ctl allocations list
blockhost-broker-ctl allocations show <prefix>
blockhost-broker-ctl allocations revoke <prefix>

# Status
blockhost-broker-ctl status
blockhost-broker-ctl peers

# Database maintenance
blockhost-broker-ctl db backup /path/to/backup.db
blockhost-broker-ctl db vacuum
```

---

## Client Integration

### Blockhost Host Setup

The Blockhost host calls the broker API during initialization:

```python
import requests
import subprocess

BROKER_URL = "https://broker.blockhost.io"
BROKER_TOKEN = "..."  # From operator

def setup_ipv6_tunnel():
    # Generate WireGuard keypair
    private_key = subprocess.check_output(["wg", "genkey"]).decode().strip()
    public_key = subprocess.check_output(
        ["wg", "pubkey"],
        input=private_key.encode()
    ).decode().strip()

    # Request allocation from broker
    resp = requests.post(
        f"{BROKER_URL}/v1/allocate",
        headers={"Authorization": f"Bearer {BROKER_TOKEN}"},
        json={
            "pubkey": public_key,
            "endpoint": f"{get_public_ip()}:51820"
        }
    )
    resp.raise_for_status()
    allocation = resp.json()

    # Configure WireGuard
    configure_wireguard(
        private_key=private_key,
        address=f"{allocation['prefix'].replace('/64', '1/64')}",
        peer_pubkey=allocation['broker_pubkey'],
        peer_endpoint=allocation['broker_endpoint'],
        peer_allowed_ips="::/0"
    )

    # Save allocation for VM provisioning
    save_allocation(allocation['prefix'])
```

### VM IPv6 Assignment

When provisioning a VM, assign an address from the /64:

```python
def assign_vm_ipv6(vm_id: int, prefix: str) -> str:
    """
    Assign IPv6 to VM from host's /64 allocation.

    Uses VM ID to generate deterministic address.
    Host uses ::1, VMs get ::100 onwards.
    """
    import ipaddress
    network = ipaddress.IPv6Network(prefix)
    # VM addresses start at ::100 (256 decimal)
    vm_addr = network[256 + vm_id]
    return str(vm_addr)
```

---

## On-Chain Authentication Mode

When enabled, the broker uses blockchain-based verification instead of bearer tokens. This ties broker access to Blockhost host NFT contract ownership.

### Architecture (On-Chain Mode)

```
┌─────────────────────────────────────────────────────────────────────┐
│                     BLOCKCHAIN (Sepolia)                            │
│  ┌──────────────────┐        ┌──────────────────┐                   │
│  │  BrokerRegistry  │        │  BrokerRequests  │                   │
│  │  (global)        │        │  (per broker)    │                   │
│  └──────────────────┘        └──────────────────┘                   │
└─────────────────────────────────────────────────────────────────────┘
         ▲                              ▲  │
         │ Query                        │  │ Response
         │ brokers                      │  │
         │                    Submit    │  ▼
┌────────┴──────────────────────────────┴─────────────────────────────┐
│  BLOCKHOST SERVER (Proxmox)                  broker-client.py       │
│  - Queries registry, submits encrypted request                      │
│  - Polls for response, decrypts, configures WireGuard              │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              │ WireGuard tunnel
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  BROKER DAEMON (VPS)                         blockhost-broker       │
│  - Monitors BrokerRequests for new requests                         │
│  - Verifies NFT contract ownership                                  │
│  - Provisions allocation, adds WireGuard peer                       │
│  - Submits encrypted response on-chain                              │
└─────────────────────────────────────────────────────────────────────┘
```

### Smart Contracts

**BrokerRegistry** (global):
- Stores list of available brokers
- Broker pubkey, region, capacity, requests contract address

**BrokerRequests** (per-broker):
- Handles allocation requests for a specific broker
- Verifies NFT contract ownership before accepting requests

### Verification Logic

1. **NFT contract exists** - `getCode(nftContract) != 0x`
2. **Sender owns contract** - `Ownable(nftContract).owner() == msg.sender`
3. **Is ERC721** - `supportsInterface(0x80ac58cd) == true`

### Re-Request Handling

If a request comes from the same NFT contract as an existing allocation:
- The broker updates the WireGuard public key to the new one
- The same prefix allocation is returned
- The old WireGuard peer is removed, new one added

This enables key rotation without losing the allocated prefix.

### Response Payload Format

Response payloads stored on-chain are prefixed with the request ID:

```
[8 bytes: request_id as big-endian u64][ECIES encrypted payload]
```

This allows the client to detect stale responses (e.g., after server re-install with a new ECIES key) without attempting decryption. The client compares the embedded request ID against the current on-chain request ID — a mismatch indicates the response belongs to a previous request cycle.

### Post-Approval Tunnel Verification

After approving a request, the broker tracks the allocation for tunnel verification. If no WireGuard handshake is detected within 2 minutes:
- The allocation is released (WireGuard peer removed, IPAM freed, on-chain release)
- This allows the client to submit a fresh request with a new key

This handles the case where a server was re-installed (new ECIES keypair), the client detects the stale response, and needs the old allocation released before it can re-request.

### Stale Response Recovery (Client)

When the client finds an existing approved allocation on-chain:
1. Extracts the request ID prefix from the response payload
2. If the embedded ID doesn't match the current request ID → stale response
3. If IDs match but decryption fails → also stale
4. In both cases, the client resets and submits a new request
5. The broker's tunnel verification will auto-release the stale allocation

### Encryption

| Purpose | Curve | Notes |
|---------|-------|-------|
| Request encryption | secp256k1 | ECIES, encrypt with broker pubkey |
| Response encryption | secp256k1 | ECIES, encrypt with server pubkey |
| WireGuard tunnel | Curve25519 | Separate key, inside encrypted payload |

### Configuration

```toml
[onchain]
enabled = true
rpc_url = "https://ethereum-sepolia-rpc.publicnode.com"
chain_id = 11155111
private_key_file = "/etc/blockhost-broker/deployer.key"
ecies_private_key_file = "/etc/blockhost-broker/ecies.key"
requests_contract = "0x..."
poll_interval_ms = 5000
```

### Client/Server Separation

- **Broker Daemon (blockhost-broker)**: Rust service on broker VPS, monitors blockchain, provisions allocations
- **Broker Manager (blockhost-broker-manager)**: Web UI for broker operators, wallet-based auth, lease management
- **Broker Client (blockhost-broker-client)**: Python script for Proxmox servers, submits requests, configures WireGuard

### Client ECIES Key

The broker-client uses a persistent ECIES key (`/etc/blockhost/server.key`) rather than ephemeral keys:
- Generated once during first request
- Used to decrypt broker responses
- Enables recovery of already-approved requests (e.g., after client restart before processing response)
- Must be backed up if prefix allocation needs to be recovered

### Broker Manager Web Interface

The manager provides a web-based dashboard at `https://<broker-ip>:8443`:

**Authentication:**
1. User clicks "Connect Wallet"
2. Server generates unique nonce
3. User signs nonce with MetaMask
4. Server verifies signature, checks wallet is in authorized list
5. Session created with configurable expiry (default: 1 hour, set via `SESSION_LIFETIME_HOURS` env var)

**Features:**
- View all active leases (prefix, pubkey, NFT contract, timestamp)
- Release leases (on-chain + WireGuard + database cleanup)
- Wallet info display (address, balance, network) with low-balance warning
- ETH top-up via MetaMask integration
- Self-signed HTTPS certificate

**Configuration:**
```json
// /etc/blockhost-broker-manager/auth.json
{
  "authorized_wallets": [
    "0xe35B5D114eFEA216E6BB5Ff15C261d25dB9E2cb9"
  ]
}
```

---

## Future Enhancements

1. **Multiple Upstreams** - Failover between tunnel providers
2. **Usage Metering** - Track bandwidth per allocation
3. ~~**Web Dashboard** - Visual monitoring interface~~ (IMPLEMENTED: blockhost-broker-manager)
4. ~~**Blockchain Integration** - Tie allocations to on-chain identity~~ (IMPLEMENTED)
5. **Prefix Delegation** - Support /48 allocations for larger operators
6. **Geographic Distribution** - Multiple broker instances

---

## Appendix: Prefix Calculation

Given upstream `/64` prefix `2a11:6c7:f04:276::/64`:

- Bits 0-63: Network prefix (fixed)
- Bits 64-119: Subnet ID for /120 allocations (56 bits = 72 quadrillion subnets)
- Bits 120-127: Host ID within /120 (256 addresses per allocation)

For practical purposes, we use a sequential index for allocations:

**Subnet allocation (using /120, 256 addresses each):**
```
Index 0:   2a11:6c7:f04:276::0/120     (RESERVED - broker infrastructure)
Index 1:   2a11:6c7:f04:276::100/120   (first allocation, addresses ::100-::1ff)
Index 2:   2a11:6c7:f04:276::200/120   (addresses ::200-::2ff)
...
Index 255: 2a11:6c7:f04:276::ff00/120  (addresses ::ff00-::ffff)
```

Using just the last 16 bits for indexing gives 256 allocations, each with 256 addresses.
For more allocations, we can extend into higher bits of the interface ID.

```python
import ipaddress

def get_subnet(upstream: str, index: int, prefix_len: int = 120) -> str:
    """Calculate /120 subnet from /64 and index."""
    network = ipaddress.IPv6Network(upstream)
    if prefix_len < network.prefixlen:
        raise ValueError(f"Allocation size must be >= {network.prefixlen}")

    # Calculate subnet size and offset
    subnet_size = 1 << (128 - prefix_len)  # 256 for /120
    subnet_start = int(network.network_address) + (index * subnet_size)

    # Verify we're still within the upstream prefix
    if subnet_start + subnet_size > int(network.network_address) + (1 << (128 - network.prefixlen)):
        raise ValueError("Index out of range for upstream prefix")

    return str(ipaddress.IPv6Network((subnet_start, prefix_len)))
```
