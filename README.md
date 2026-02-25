# blockhost-broker

Multichain IPv6 tunnel broker with on-chain authentication for Blockhost servers.

Allocates IPv6 prefixes to Blockhost servers (Proxmox) via WireGuard tunnels. Authentication is handled on-chain through NFT contract ownership verification — no API keys or bearer tokens needed. Supports multiple blockchains: EVM (Ethereum) is built into the broker daemon, additional chains (OPNet/Bitcoin) run as external adapter processes.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        BLOCKCHAINS                              │
│                                                                 │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │  BrokerRegistry  │  │  BrokerRequests  │  │ BrokerReqs   │  │
│  │  (EVM, global)   │  │  (EVM, per-broker)│  │ (OPNet)      │  │
│  └──────────────────┘  └──────────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────────┘
         ▲                        ▲                    ▲
         │ discover               │ request            │ request
         │ brokers                │                    │
┌────────┴────────────────────────┴────────────────────┴─────────┐
│  BLOCKHOST SERVER (Proxmox)                                     │
│                                                                 │
│  broker-client:                                                 │
│  1. Queries registry for brokers with capacity                  │
│  2. Submits encrypted request on-chain (EVM or OPNet)           │
│  3. Receives encrypted response, configures WireGuard           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ WireGuard
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  BROKER (VPS)                                                    │
│                                                                  │
│  Broker Daemon (Rust):                                           │
│  - Built-in EVM monitor: polls contracts, responds via ETH tx   │
│  - REST API for external adapters                                │
│  - IPAM, WireGuard, DNS, NDP proxy                              │
│                                                                  │
│  OPNet Adapter (Node.js):                                        │
│  - Polls OPNet contract, calls broker API                        │
│  - Delivers response via OP_RETURN transaction                   │
└─────────────────────────────────────────────────────────────────┘
```

## Running Your Own Broker

### 1. Prerequisites

- A Linux VPS with a static IPv4 address (for WireGuard endpoint)
- An IPv6 prefix routed or tunneled to your VPS (see below)
- WireGuard kernel module (`wireguard-tools` package)
- Rust toolchain (for building from source)
- An Ethereum wallet funded with Sepolia ETH (the **operator wallet** — owns the BrokerRequests contract)

### 2. Getting IPv6 Address Space

You need at least a /64 prefix routed to your VPS. Options:

**Route64** (free SIT tunnels) — https://route64.org
- Sign up, create a SIT tunnel pointed at your VPS IPv4
- You'll get a /64 prefix (e.g., `2a11:6c7:f04:276::/64`)
- Route64 uses NDP for address resolution, so NDP proxy is required (the broker handles this automatically)

**Hurricane Electric** (free 6in4 tunnels) — https://tunnelbroker.net
- Provides /64 and /48 prefixes with proper routing
- No NDP proxy needed — set `upstream_interface` to empty or omit it

**Native IPv6 from your hosting provider**
- Some VPS providers assign a /64 or /48 natively
- No tunnel setup needed, no NDP proxy needed

### 3. Server Setup

Install WireGuard and enable IPv6 forwarding:

```bash
apt install wireguard-tools

# Enable IPv6 forwarding and NDP proxy (if using tunnel provider with NDP)
cat > /etc/sysctl.d/99-blockhost-broker.conf << EOF
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.all.proxy_ndp = 1
EOF
sysctl --system
```

If using a SIT tunnel (e.g., Route64), set it up:

```bash
ip tunnel add <tunnel-name> mode sit remote <provider-ipv4> local <your-ipv4> ttl 255
ip link set <tunnel-name> up
ip -6 addr add <your-ipv6>::2/64 dev <tunnel-name>
ip -6 route add ::/0 dev <tunnel-name>
```

Create a WireGuard interface (no address needed — the broker routes to peers):

```bash
wg genkey | tee /etc/blockhost-broker/wg-private.key | wg pubkey > /etc/blockhost-broker/wg-public.key
chmod 600 /etc/blockhost-broker/wg-private.key

ip link add dev wg-broker type wireguard
wg set wg-broker listen-port 51820 private-key /etc/blockhost-broker/wg-private.key
ip link set wg-broker up
```

If using UFW, allow WireGuard and forwarding:

```bash
ufw allow 51820/udp comment "WireGuard"
ufw route allow in on wg-broker out on <tunnel-interface>
ufw route allow in on <tunnel-interface> out on wg-broker
```

### 4. Deploy BrokerRequests Contract

After building the broker (step 5), deploy your BrokerRequests contract:

```bash
blockhost-broker deploy-contracts \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com \
  --chain-id 11155111 \
  --operator-key /etc/blockhost-broker/operator.key \
  --ecies-key /etc/blockhost-broker/ecies.key \
  --region eu-west \
  --capacity 256
```

This will:
1. Show your operator wallet address and balance
2. Deploy the BrokerRequests contract (owned by your operator wallet)
3. Print a deployment summary with your ECIES public key and a config snippet

If the wallet has insufficient balance, it will print the address to fund and exit.

After deployment, contact the registry owner to register your broker. Provide them with:
- Operator address
- BrokerRequests contract address
- ECIES public key (printed in the deployment summary)

### 5. Build and Install the Broker

```bash
cd blockhost-broker-rs
cargo build --release

# Create config directory
sudo mkdir -p /etc/blockhost-broker /var/lib/blockhost-broker

# Generate ECIES keypair (used for encrypted request/response payloads)
sudo ./target/release/blockhost-broker generate-key -o /etc/blockhost-broker/ecies.key

# Generate operator wallet key (or copy an existing one)
sudo ./target/release/blockhost-broker wallet generate -o /etc/blockhost-broker/operator.key

# Install binary
sudo cp target/release/blockhost-broker /usr/bin/
```

### 6. Configure the Broker

Create `/etc/blockhost-broker/config.toml`:

```toml
[broker]
upstream_prefix = "2a11:6c7:f04:276::/64"  # Your IPv6 prefix
allocation_size = 120                        # /120 = 256 addresses per client
broker_ipv6 = "2a11:6c7:f04:276::2"         # Broker's own address in the prefix
max_allocations = 256                        # Capacity limit

[wireguard]
interface = "wg-broker"
listen_port = 51820
private_key_file = "/etc/blockhost-broker/wg-private.key"
public_endpoint = "your-server-ip:51820"
upstream_interface = "tb25255R64"  # SIT tunnel interface (omit if not using NDP proxy)

[api]
listen_host = "127.0.0.1"
listen_port = 8080

[database]
path = "/var/lib/blockhost-broker/ipam.db"

[dns]
enabled = true
domain = "vm.blockhost.io"
listen = "0.0.0.0:53"
ttl = 300
ns_ipv4 = "95.179.128.177"         # Glue A record for ns1.{domain}
extra_domains = ["blockhost.thawaras.org"]  # Additional domains (optional)

[onchain]
enabled = true
rpc_url = "https://ethereum-sepolia-rpc.publicnode.com"
chain_id = 11155111
private_key_file = "/etc/blockhost-broker/operator.key"
ecies_private_key_file = "/etc/blockhost-broker/ecies.key"
registry_contract = "0x..."    # From deploy output
requests_contract = "0x..."    # From deploy output
poll_interval_ms = 5000
```

**Key configuration choices:**

| Setting | Description |
|---------|-------------|
| `allocation_size` | Prefix length per client. `/120` gives 256 addresses each (fits NDP proxy limit). `/64` gives a full subnet per client but requires proper routing from upstream. |
| `max_allocations` | Capacity limit. Omit for unlimited. |
| `upstream_interface` | Set to your tunnel interface name for NDP proxy. Omit if upstream does proper prefix routing. |

#### NDP Proxy (additional configuration for some providers)

Some tunnel providers (e.g. Route64, some SIT tunnels) use NDP (Neighbor Discovery Protocol) to learn which addresses are in use on your prefix. Without NDP proxy, the provider won't know how to route traffic to addresses the broker allocates to clients — packets will arrive at your VPS but never reach the WireGuard peers.

**You need NDP proxy if** your provider assigns a prefix (e.g. `/64`) and expects your server to respond to NDP neighbor solicitations for each address in use. This is common with SIT tunnels and some native IPv6 setups where the provider doesn't add static routes for your prefix.

**You do NOT need NDP proxy if** your provider routes the entire prefix to your server statically (e.g. Hurricane Electric tunnels, most VPS providers with native `/48` or `/64` delegations).

When `upstream_interface` is set in the config, the broker automatically adds and removes NDP proxy entries on that interface as peers are added and removed. No manual `ip -6 neigh add proxy` commands are needed.

To verify NDP proxy is working after allocating a prefix:
```bash
# Should show proxy entries for allocated addresses
ip -6 neigh show proxy dev <upstream-interface>
```

If you're unsure whether your provider requires NDP, try allocating a test prefix with `upstream_interface` omitted. If the client can't reach the broker's gateway address through the tunnel, add the upstream interface and try again.

### 7. Run the Broker

```bash
# Test configuration
blockhost-broker check-config

# Run directly
blockhost-broker run

# Or set up as a systemd service (recommended)
```

Example systemd unit (`/etc/systemd/system/blockhost-broker.service`):

```ini
[Unit]
Description=Blockhost IPv6 Tunnel Broker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/blockhost-broker run
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/blockhost-broker /etc/wireguard
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now blockhost-broker
sudo journalctl -u blockhost-broker -f   # Watch logs
```

### 8. Broker Manager (Web UI)

Optional web dashboard for managing leases.

```bash
sudo dpkg -i blockhost-broker-manager_0.2.0_all.deb
sudo systemctl enable --now blockhost-broker-manager
```

Access at `https://<broker-ip>:8443` (self-signed certificate).

Configure authorized wallets in `/etc/blockhost-broker-manager/auth.json`:

```json
{
  "authorized_wallets": [
    "0xYourWalletAddress"
  ]
}
```

Features:
- Wallet-based authentication (MetaMask/Web3 nonce signing)
- View and release active leases
- Wallet balance display with low-balance warning
- ETH top-up via MetaMask
- Configurable session expiry (`SESSION_LIFETIME_HOURS`, default: 1 hour)

### 9. DNS Server (Optional)

The broker includes a built-in authoritative DNS server that synthesizes AAAA records for allocated prefixes. It resolves `<hex>.<domain>` to `<upstream_prefix>::<hex>` — purely synthetic, no database lookup.

For example, with prefix `2a11:6c7:f04:276::/64` and domain `vm.blockhost.io`:
- `101.vm.blockhost.io` → `2a11:6c7:f04:276::101`
- `2.vm.blockhost.io` → `2a11:6c7:f04:276::2`
- `ff.vm.blockhost.io` → `2a11:6c7:f04:276::ff`

Supports multiple domains via the `extra_domains` config array, UDP and TCP (RFC 7766), and SOA/NS/glue records.

**NS delegation setup at your registrar:**

```
vm.blockhost.io.       NS    ns1.vm.blockhost.io.
ns1.vm.blockhost.io.   A     <your-broker-ip>
```

**Verify:**

```bash
dig AAAA 101.vm.blockhost.io @<broker-ip>
dig SOA vm.blockhost.io @<broker-ip>
dig NS vm.blockhost.io @<broker-ip>
```

If using UFW, allow DNS:

```bash
ufw allow 53/udp comment "DNS"
ufw allow 53/tcp comment "DNS (TCP)"
```

## Broker Client

The `broker-client` runs on Blockhost servers (Proxmox) to request IPv6 allocations. It supports multiple chains through a plugin architecture configured via `broker-chains.json`.

### Installation

```bash
sudo dpkg -i blockhost-broker-client_0.5.0_all.deb
```

The package includes:
- Python client with EVM support (builtin)
- OPNet client plugin (Node.js, requires `nodejs >= 18`)
- Chain config at `/etc/blockhost/broker-chains.json`

### Usage

```bash
# Request an allocation (discovers brokers from on-chain registry)
# EVM (default — wallet address starts with 0x, 40 hex chars):
broker-client request --nft-contract 0x... --wallet-key /path/to/key

# OPNet (auto-detected — 64-char hex pubkey or opr1... address):
broker-client request --nft-contract 0x<64-char-pubkey> --wallet-key /path/to/mnemonic

# Check current allocation
broker-client status

# List available brokers and their capacity
broker-client list-brokers

# Install persistent WireGuard config (survives reboot)
broker-client install

# Release allocation (local cleanup)
broker-client release --wallet-key /path/to/key [--cleanup-wg]
```

The client automatically:
- Detects the chain from the NFT contract address format
- Dispatches to the appropriate chain plugin (EVM builtin, or OPNet Node.js subprocess)
- Fetches the registry address from GitHub (`registry.json`)
- Encrypts the request with the broker's ECIES public key
- Polls for the encrypted response and configures WireGuard
- Detects stale responses (e.g., after server re-install) and re-requests

### How It Works

**EVM path:**
1. Client queries `BrokerRegistry` for active brokers, picks one with capacity
2. Generates a WireGuard keypair and encrypts it (along with an ECIES public key) with the broker's public key
3. Submits the encrypted payload on-chain via `BrokerRequests.submitRequest()`
4. Broker decrypts, verifies NFT ownership, allocates prefix, sends response as a direct ETH transaction to the client
5. Client decrypts the response, configures WireGuard, saves allocation

**OPNet path:**
1. Same discovery and encryption as EVM, but on the OPNet (Bitcoin L1) chain
2. Submits request to OPNet BrokerRequests contract
3. OPNet adapter (on the broker server) picks up the request, calls broker REST API
4. Adapter delivers the encrypted response via Bitcoin OP_RETURN transaction (72 bytes, ECDH-AES-256-GCM)
5. Client watches for OP_RETURN, decrypts, configures WireGuard

Re-requesting from the same NFT contract overwrites the old request — useful for key rotation or recovery after re-install.

## Contract Addresses

### EVM (Sepolia Testnet)

**V3 (active):**
- **BrokerRegistry**: `0x5F779652623c85343c5914d9E07FADCbD9Aa1f2e`
- **BrokerRequests** (eu-west): `0x145EBeA3830b4eCF3C06E0ccde9Ec5dd89dfE50e`

**Test (CI — allocations auto-expire in 24h):**
- **BrokerRegistry**: `0x26b9baa877628801535F5Af08548e3EC7D3ceb39`
- **BrokerRequests**: `0x70f0eAe36fB4d2FdDEf42b89c734a865D317B8B4`

The registry address is published at:
https://raw.githubusercontent.com/mwaddip/blockhost-broker/main/registry.json

### OPNet (Regtest)

- **BrokerRegistry**: `opr1sqzkhywm0a726u5wuwr9p22nxgcgug6yaeqmmjwva`
- **BrokerRequests**: `opr1sqp49unertjhqhaxv3gmfgt74046d4jkh8u79j68j`

The registry config is at:
https://raw.githubusercontent.com/mwaddip/blockhost-broker/main/registry-opnet-regtest.json

## Security

- All request/response payloads are ECIES encrypted (secp256k1)
- WireGuard private keys are generated locally, never transmitted in plaintext
- NFT ownership verification ensures only legitimate Blockhost installations can request allocations
- Broker endpoint is only revealed inside encrypted responses
- Invalid requests are silently rejected (no information leakage)
- Manager uses wallet-based auth with nonce signing (non-replayable)
- REST API bound to localhost — no external access without WireGuard tunnel
- Allocations auto-released if client never establishes WireGuard handshake (120s timeout)

## Documentation

- **[DESIGN.md](DESIGN.md)** — Architecture and design decisions
- **[BROKER_INTERFACE.md](BROKER_INTERFACE.md)** — Detailed interface specification (API schemas, database schema, config reference, binary formats)

## Community

Join the Blockhost Telegram group: https://t.me/BlockHostOS

If you'd like to run a broker and be added to the registry, head there for questions and information.

## License

MIT
