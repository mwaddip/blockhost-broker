# blockhost-broker

IPv6 tunnel broker with on-chain authentication for Blockhost servers.

Allocates IPv6 prefixes to Blockhost servers (Proxmox) via WireGuard tunnels. Authentication is handled on-chain through NFT contract ownership verification — no API keys or bearer tokens needed.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     BLOCKCHAIN (Sepolia)                        │
│  ┌──────────────────┐        ┌──────────────────┐               │
│  │  BrokerRegistry  │        │  BrokerRequests  │               │
│  │  (global)        │        │  (per broker)    │               │
│  └──────────────────┘        └──────────────────┘               │
└─────────────────────────────────────────────────────────────────┘
         ▲                              ▲
         │ discover brokers             │ request/response
         │                              │
┌────────┴──────────────────────────────┴─────────────────────────┐
│  BLOCKHOST SERVER (Proxmox)                                     │
│                                                                 │
│  broker-client:                                                 │
│  1. Queries registry for brokers with capacity                  │
│  2. Submits encrypted request on-chain                          │
│  3. Receives encrypted response, configures WireGuard           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ WireGuard
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  BROKER DAEMON (VPS)                                            │
│                                                                 │
│  - Monitors BrokerRequests contract for new requests            │
│  - Verifies NFT contract ownership                              │
│  - Allocates IPv6 prefix, adds WireGuard peer                   │
│  - Submits encrypted response on-chain                          │
└─────────────────────────────────────────────────────────────────┘
```

## Running Your Own Broker

### 1. Prerequisites

- A Linux VPS with a static IPv4 address (for WireGuard endpoint)
- An IPv6 prefix routed or tunneled to your VPS (see below)
- WireGuard kernel module (`wireguard-tools` package)
- Rust toolchain (for building from source)
- Foundry (for deploying smart contracts)
- Two Ethereum wallets funded with Sepolia ETH:
  - **Deployer wallet** — owns the BrokerRegistry, registers brokers
  - **Operator wallet** — owns the BrokerRequests contract, signs on-chain responses

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

### 4. Deploy Smart Contracts

Install [Foundry](https://book.getfoundry.sh/getting-started/installation) and set up environment variables:

```bash
export DEPLOYER_PRIVATE_KEY=0x...   # Deployer wallet (registry owner)
export OPERATOR_PRIVATE_KEY=0x...   # Operator wallet (requests contract owner)
export ECIES_PUBKEY=0x...           # 65-byte uncompressed secp256k1 pubkey (see step 5)
export BROKER_REGION="eu-west"      # Your region identifier
export BROKER_CAPACITY=256          # Max concurrent leases (0 = unlimited)
```

Build, test, and deploy:

```bash
cd contracts-foundry
forge build
forge test
forge script script/DeployV2.s.sol --rpc-url $RPC_URL --broadcast
```

The deploy script performs three phases:
1. Deployer wallet deploys `BrokerRegistry`
2. Operator wallet deploys `BrokerRequests`
3. Deployer wallet calls `registerBroker()` to register the operator

Note the contract addresses from the output — you'll need them for configuration.

### 5. Build and Install the Broker

```bash
cd blockhost-broker-rs
cargo build --release

# Create config directory
sudo mkdir -p /etc/blockhost-broker /var/lib/blockhost-broker

# Generate ECIES keypair (used for encrypted request/response payloads)
sudo ./target/release/blockhost-broker generate-key -o /etc/blockhost-broker/ecies.key

# Copy operator wallet key (the private key for on-chain transactions)
sudo cp /path/to/operator.key /etc/blockhost-broker/operator.key
sudo chmod 600 /etc/blockhost-broker/operator.key /etc/blockhost-broker/ecies.key

# Install binary
sudo cp target/release/blockhost-broker /usr/bin/
```

To get the ECIES public key (needed for contract deployment):

```python
python3 -c "
from coincurve import PrivateKey
sk = PrivateKey(open('/etc/blockhost-broker/ecies.key').read().strip().encode())
print(sk.public_key.format(compressed=False).hex())
"
```

### 6. Configure the Broker

Create `/etc/blockhost-broker/config.toml`:

```toml
[broker]
upstream_prefix = "2a11:6c7:f04:276::/64"  # Your IPv6 prefix
allocation_size = 120                        # /120 = 256 addresses per client
broker_ipv6 = "2a11:6c7:f04:276::2"         # Broker's own address in the prefix
max_allocations = 256                        # Capacity limit (synced on-chain)

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
| `max_allocations` | Synced to on-chain `totalCapacity`. Clients check this before requesting. Omit for unlimited. |
| `upstream_interface` | Set to your tunnel interface name for NDP proxy. Omit if upstream does proper prefix routing. |

### 7. Run the Broker

```bash
# Test configuration
blockhost-broker -c /etc/blockhost-broker/config.toml check-config

# Run directly
blockhost-broker -c /etc/blockhost-broker/config.toml run

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
ExecStart=/usr/bin/blockhost-broker -c /etc/blockhost-broker/config.toml run
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/blockhost-broker /etc/wireguard
CapabilityBoundingSet=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now blockhost-broker
sudo journalctl -u blockhost-broker -f   # Watch logs
```

On startup, the broker:
- Syncs `max_allocations` to on-chain `totalCapacity` (if configured)
- Migrates any legacy per-contract state
- Begins polling for new requests on the primary and any legacy contracts

### 8. Broker Manager (Web UI)

Optional web dashboard for managing leases.

```bash
sudo dpkg -i blockhost-broker-manager_0.1.0_all.deb
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

## Broker Client

The `broker-client` runs on Blockhost servers (Proxmox) to request IPv6 allocations.

### Installation

```bash
sudo dpkg -i blockhost-broker-client_0.3.0_all.deb
```

### Usage

```bash
# Request an allocation (discovers brokers from on-chain registry)
broker-client request --nft-contract 0x... --wallet-key /path/to/key

# Check current allocation
broker-client status

# List available brokers and their capacity
broker-client list-brokers

# Install persistent WireGuard config (survives reboot)
broker-client install

# Release allocation (on-chain + local cleanup)
broker-client release --wallet-key /path/to/key [--cleanup-wg]
```

The client automatically:
- Fetches the registry address from GitHub (`registry.json`)
- Selects a broker with available capacity
- Encrypts the request with the broker's ECIES public key
- Polls for the encrypted response and configures WireGuard
- Detects stale responses (e.g., after server re-install) and re-requests

### How It Works

1. Client queries `BrokerRegistry` for active brokers, picks one with capacity
2. Generates a WireGuard keypair and encrypts it (along with an ECIES public key) with the broker's public key
3. Submits the encrypted payload on-chain via `BrokerRequests.submitRequest()`
4. Broker verifies NFT contract ownership, allocates a prefix, and responds on-chain
5. Client decrypts the response, configures WireGuard, and saves the allocation to `/etc/blockhost/broker-allocation.json`

Re-requesting from the same NFT contract overwrites the old request — useful for key rotation or recovery after re-install.

## Contract Addresses (Sepolia Testnet)

**V2 (active):**
- **BrokerRegistry**: `0x4e020bf35a1b2939E359892D22d96B4A2DAEb93e`
- **BrokerRequests** (eu-west): `0xDE6f2cBB6de279e9f95Cd07B18411d26FEa51546`

**V1 (legacy, still monitored):**
- **BrokerRequests**: `0xCD75c00dBB3F05cF27f16699591f4256a798e694`

The registry address is published at:
https://raw.githubusercontent.com/mwaddip/blockhost-broker/main/registry.json

## Security

- All request/response payloads are ECIES encrypted (secp256k1)
- WireGuard private keys are generated locally, never transmitted
- NFT ownership verification ensures only legitimate Blockhost installations can request allocations
- Broker endpoint is only revealed inside encrypted responses
- Invalid requests are silently rejected (no information leakage)
- Manager uses wallet-based auth with nonce signing (non-replayable)

## License

MIT
