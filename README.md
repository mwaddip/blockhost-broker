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

### Smart Contracts

- **BrokerRegistry** - Global registry of available brokers (owner-managed)
- **BrokerRequests** - Per-broker contract for allocation requests/responses

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

[api]
listen_host = "127.0.0.1"
listen_port = 8080

[database]
path = "/var/lib/blockhost-broker/ipam.db"

[onchain]
enabled = true
rpc_url = "https://ethereum-sepolia-rpc.publicnode.com"
chain_id = 11155111
private_key_file = "/etc/blockhost-broker/deployer.key"
ecies_private_key_file = "/etc/blockhost-broker/ecies.key"
requests_contract = "0x..."
poll_interval_ms = 5000
```

## On-Chain Authentication Flow

1. **Client** queries `BrokerRegistry` for available brokers
2. **Client** generates WireGuard keypair and ECIES keypair
3. **Client** encrypts request payload with broker's public key
4. **Client** calls `BrokerRequests.submitRequest(nftContract, encryptedPayload)`
5. **Broker** detects request via lazy polling
6. **Broker** verifies:
   - NFT contract exists and is ERC721
   - `Ownable.owner() == msg.sender`
7. **Broker** allocates prefix, adds WireGuard peer
8. **Broker** encrypts response with client's public key
9. **Broker** calls `BrokerRequests.submitResponse(requestId, encryptedPayload)`
10. **Client** decrypts response, configures WireGuard

Invalid requests are silently rejected (no on-chain response, request expires).

## Contract Addresses (Sepolia Testnet)

- **BrokerRegistry**: `0x0E5b567E7d5C5c36D8fD70DE8129c35B473d0Aaf`

## Smart Contract Deployment

Using Foundry:

```bash
cd contracts-foundry
forge build
forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
```

## Security

- All request/response payloads are ECIES encrypted (secp256k1)
- WireGuard keys are generated locally, private keys never transmitted
- NFT ownership verification ensures only legitimate Blockhost installations can request allocations
- Broker endpoint is only revealed in encrypted responses
- Silent rejections prevent information leakage about rejection reasons

## License

MIT
