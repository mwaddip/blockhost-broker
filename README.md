# blockhost-broker

IPv6 tunnel broker with on-chain authentication for Blockhost servers.

## Overview

This broker allocates IPv6 prefixes to Blockhost servers (Proxmox) via WireGuard tunnels. Authentication is handled on-chain through NFT contract ownership verification, eliminating the need for API keys or bearer tokens.

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
         │ query                        │ request/response
         │                              │
┌────────┴──────────────────────────────┴─────────────────────────┐
│  BLOCKHOST SERVER (Proxmox)                                     │
│                                                                 │
│  broker-client:                                                 │
│  1. Submits encrypted request on-chain                          │
│  2. Receives encrypted response with allocation                 │
│  3. Configures WireGuard tunnel                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ WireGuard
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  BROKER DAEMON (VPS)                                            │
│                                                                 │
│  - Monitors BrokerRequests contract for new requests            │
│  - Verifies NFT contract ownership                              │
│  - Allocates prefix, adds WireGuard peer                        │
│  - Submits encrypted response on-chain                          │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### Smart Contracts (V2)

- **BrokerRegistry** - Global registry of available brokers (owner-managed, supports re-registration)
- **BrokerRequests** - Per-broker contract for allocation requests/responses
  - Overwrite semantics: re-submitting from the same NFT contract overwrites the old request (no revert)
  - On-chain capacity tracking: `totalCapacity`, `_activeCount`, `_pendingCount`, `getAvailableCapacity()`
  - Supersession guard: prevents approving overwritten requests

### Broker Daemon

Rust service that runs on the broker VPS:
- Lazy polling for pending requests (no unbounded loops)
- Verifies requester owns an ERC721 NFT contract (Blockhost installation proof)
- Manages WireGuard peers and SQLite-based IPAM
- Silent rejections (invalid requests simply expire)
- Responds with ECIES-encrypted allocation details

## Installation

### From Debian Package

Download the latest release and install:

```bash
sudo dpkg -i blockhost-broker_0.1.0_amd64.deb
```

The package includes an interactive setup wizard that will:
1. Generate or import an Ethereum private key
2. Check wallet balance and prompt for funding if needed
3. Deploy the BrokerRequests contract
4. Auto-detect IPv6 interfaces
5. Configure allocation sizes
6. Set up WireGuard

To reconfigure:
```bash
sudo dpkg-reconfigure blockhost-broker
```

### From Source

```bash
cd blockhost-broker-rs
cargo build --release

# Generate ECIES keypair
./target/release/blockhost-broker generate-key -o /etc/blockhost-broker/ecies.key

# Run interactive setup
sudo ./target/release/blockhost-broker setup

# Or run daemon directly
./target/release/blockhost-broker -c /etc/blockhost-broker/config.toml run
```

## CLI Commands

```
blockhost-broker [OPTIONS] [COMMAND]

Commands:
  run              Run the broker daemon
  check-config     Validate configuration and exit
  generate-key     Generate a new ECIES keypair
  setup            Interactive setup wizard
  detect-ipv6      Detect IPv6 interfaces
  wallet           Wallet management (generate, address, balance)
  deploy-requests  Deploy BrokerRequests contract
  token            Token management commands
  status           Show broker status
  allocations      List allocations
```

## Configuration

Configuration file: `/etc/blockhost-broker/config.toml`

```toml
[broker]
upstream_prefix = "2001:db8::/48"  # Your IPv6 allocation
allocation_size = 64               # Prefix length per client
broker_ipv6 = "2001:db8::1"        # Broker's own address

[wireguard]
interface = "wg-broker"
listen_port = 51820
private_key_file = "/etc/blockhost-broker/wg-private.key"
public_endpoint = "your-server.example.com:51820"
upstream_interface = "sit1"  # For NDP proxy (e.g., sit1, tb25255R64)

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
registry_contract = "0x..."   # BrokerRegistry address
requests_contract = "0x..."   # This broker's BrokerRequests address
poll_interval_ms = 5000
legacy_requests_contracts = ["0x..."]  # Old BrokerRequests addresses to keep monitoring
```

## On-Chain Authentication Flow

1. **Client** queries `BrokerRegistry` for available brokers, selecting one with available capacity
2. **Client** generates WireGuard keypair and ECIES keypair
3. **Client** encrypts request payload with broker's public key
4. **Client** calls `BrokerRequests.submitRequest(nftContract, encryptedPayload)`
   - If the NFT contract already has a request, the contract overwrites it (old request marked Expired)
5. **Broker** detects request via lazy polling
6. **Broker** verifies:
   - NFT contract exists and is ERC721
   - `Ownable.owner() == msg.sender`
7. **Broker** allocates prefix, adds WireGuard peer
8. **Broker** encrypts response with client's public key
9. **Broker** prepends 8-byte request ID prefix to encrypted payload
10. **Broker** calls `BrokerRequests.submitResponse(requestId, prefixedPayload)`
11. **Broker** starts 2-minute tunnel verification timer
12. **Client** strips request ID prefix, decrypts response, configures WireGuard

Invalid requests are silently rejected (no on-chain response, request expires).

**Re-requests:** If a client submits a new request from the same NFT contract, the contract overwrites the old request on-chain. The broker updates the WireGuard public key and returns the same allocation. This allows key rotation without losing the allocated prefix.

**Stale response detection:** After a server re-install (new ECIES key), the client detects the stale on-chain response via the request ID prefix mismatch and immediately submits a new request (the V2 contract handles the overwrite). The broker's tunnel verification auto-releases the old allocation after 2 minutes if no WireGuard handshake occurs.

**Capacity-aware selection:** The client calls `getAvailableCapacity()` on each broker's contract and skips brokers with no capacity, falling back to the next available broker in the registry.

## Contract Addresses (Sepolia Testnet)

**V2 (active):**
- **BrokerRegistry**: `0x4e020bf35a1b2939E359892D22d96B4A2DAEb93e`
- **BrokerRequests** (eu-west broker): `0xDE6f2cBB6de279e9f95Cd07B18411d26FEa51546`

**V1 (legacy, still monitored):**
- **BrokerRequests**: `0xCD75c00dBB3F05cF27f16699591f4256a798e694`

The registry address is published at:
https://raw.githubusercontent.com/mwaddip/blockhost-broker/main/registry.json

## Smart Contract Deployment

Using Foundry:

```bash
cd contracts-foundry
forge build
forge test

# Deploy V2 contracts (registry + requests + register broker)
forge script script/DeployV2.s.sol --rpc-url $RPC_URL --broadcast
```

The `DeployV2.s.sol` script performs a 3-phase deployment:
1. Deployer key deploys `BrokerRegistry`
2. Operator key deploys `BrokerRequests`
3. Deployer key calls `registerBroker()` to register the operator

## Broker Client

The `broker-client` is a standalone Python script for Proxmox servers to request allocations.

### Installation

```bash
sudo dpkg -i blockhost-broker-client_0.1.0_all.deb
```

### Commands

```bash
# Request a new allocation
broker-client request --nft-contract 0x... --wallet-key /path/to/key

# Check allocation status
broker-client status

# List available brokers
broker-client list-brokers

# Install persistent WireGuard config
broker-client install

# Release allocation (on-chain + local cleanup)
broker-client release --wallet-key /path/to/key [--cleanup-wg]
```

The client fetches the registry address automatically from GitHub.

## Broker Manager (Web UI)

A web-based management interface for broker operators.

### Features

- Wallet-based authentication (MetaMask/Web3)
- Configurable session expiry (default: 1 hour, set via `SESSION_LIFETIME_HOURS`)
- View active leases
- Release leases with one click
- Wallet info display (address, balance, network) with low-balance warning
- ETH top-up via MetaMask integration

### Installation

```bash
sudo dpkg -i blockhost-broker-manager_0.1.0_all.deb
sudo systemctl start blockhost-broker-manager
```

Access at `https://<broker-ip>:8443` (self-signed certificate).

### Configuration

Authorized wallets: `/etc/blockhost-broker-manager/auth.json`

```json
{
  "authorized_wallets": [
    "0xe35B5D114eFEA216E6BB5Ff15C261d25dB9E2cb9"
  ]
}
```

## NDP Proxy

When using a tunnel provider that expects NDP for address resolution (like Route64 SIT tunnels), the broker automatically manages NDP proxy entries:

- Adds proxy entries for all addresses in allocated prefixes (up to 256 per allocation)
- Removes entries when allocations are released
- Requires `upstream_interface` to be set in config

The Debian package automatically configures:
- `net.ipv6.conf.all.forwarding = 1`
- `net.ipv6.conf.all.proxy_ndp = 1`
- UFW rules for WireGuard port and interface forwarding

## Security

- All request/response payloads are ECIES encrypted (secp256k1)
- WireGuard keys are generated locally, private keys never transmitted
- NFT ownership verification ensures only legitimate Blockhost installations can request allocations
- Broker endpoint is only revealed in encrypted responses
- Silent rejections prevent information leakage about rejection reasons
- Manager uses wallet-based auth with nonce signing (non-replayable)

## License

MIT
