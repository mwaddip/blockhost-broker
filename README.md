# blockhost-broker

IPv6 tunnel broker with on-chain authentication for Blockhost servers.

## Overview

This broker allocates /120 IPv6 prefixes to Blockhost servers (Proxmox) via WireGuard tunnels. Authentication is handled on-chain through NFT contract ownership verification, eliminating the need for API keys or bearer tokens.

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
│  broker-client.py:                                              │
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
│  - Allocates /120 prefix, adds WireGuard peer                   │
│  - Submits encrypted response on-chain                          │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### Smart Contracts

- **BrokerRegistry** - Global registry of available brokers
- **BrokerRequests** - Per-broker contract for allocation requests/responses

### Broker Daemon

Python service that runs on the broker VPS:
- Monitors blockchain for pending requests
- Verifies requester owns an ERC721 NFT contract (Blockhost installation proof)
- Manages WireGuard peers and IPAM
- Responds with encrypted allocation details

### Client Script

Standalone Python script for Blockhost servers:
- Queries broker registry
- Submits encrypted allocation requests
- Configures persistent WireGuard tunnel

## Installation

### Broker Daemon

```bash
# Install package
pip install -e .

# Generate ECIES keypair for encrypted communications
blockhost-broker --generate-ecies-key /etc/blockhost-broker/ecies.key

# Copy and edit configuration
cp config.example.toml /etc/blockhost-broker/config.toml

# Run daemon
blockhost-broker -c /etc/blockhost-broker/config.toml
```

### Client (Blockhost Server)

```bash
# Install dependencies
pip install -r scripts/requirements.txt

# Copy script
cp scripts/broker-client.py /usr/local/bin/

# Request allocation and install persistent WireGuard config
broker-client.py --registry-contract 0x... request \
    --nft-contract 0xYourNFTContract \
    --wallet-key /etc/blockhost/deployer.key

broker-client.py install
```

## Configuration

See `config.example.toml` for all options. Key settings:

```toml
[broker]
upstream_prefix = "2a11:6c7:f04::/48"  # Your IPv6 allocation
allocation_size = 120                   # /120 per client

[wireguard]
interface = "wg-broker"
listen_port = 51820
public_endpoint = "YOUR_SERVER_IP:51820"

[onchain]
enabled = true
requests_contract = "0x..."  # Your BrokerRequests contract
```

## On-Chain Authentication Flow

1. **Client** queries `BrokerRegistry` for available brokers
2. **Client** generates WireGuard keypair and ECIES keypair
3. **Client** encrypts request payload with broker's public key
4. **Client** calls `BrokerRequests.submitRequest(nftContract, encryptedPayload)`
5. **Broker** detects request via event polling
6. **Broker** verifies:
   - NFT contract exists and is ERC721
   - `Ownable.owner() == msg.sender`
7. **Broker** allocates prefix, adds WireGuard peer
8. **Broker** encrypts response with client's public key
9. **Broker** calls `BrokerRequests.submitResponse(requestId, approved, encryptedPayload)`
10. **Client** decrypts response, configures WireGuard

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

## License

MIT
