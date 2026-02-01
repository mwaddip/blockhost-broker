# Blockhost Broker Client Scripts

This directory contains client-side scripts that run on Blockhost servers (Proxmox).
These scripts are standalone and do not depend on the `blockhost-broker` package.

## broker-client.py

A standalone script for requesting IPv6 prefix allocations from brokers via on-chain authentication.

### Installation

Copy the script and install dependencies:

```bash
# On the Proxmox server
pip install -r requirements.txt
cp broker-client.py /usr/local/bin/blockhost-broker-client
chmod +x /usr/local/bin/blockhost-broker-client
```

### Prerequisites

1. **Wallet with ETH**: You need a wallet with Sepolia ETH for gas fees
2. **NFT Contract**: Your Blockhost installation must have deployed an AccessCredentialNFT contract
3. **WireGuard**: The `wg` command must be available

### Quick Start (One-Time Setup)

```bash
# 1. Request allocation from broker (submits on-chain, waits for approval)
sudo broker-client.py \
    --registry-contract 0x4bfA5E3B23ea65451f5f430B573930ff5FfF5074 \
    request \
    --nft-contract 0xYourNFTContract \
    --wallet-key /etc/blockhost/deployer.key

# 2. Install persistent WireGuard config (survives reboot)
sudo broker-client.py install
```

That's it. IPv6 connectivity is now available and will persist across reboots.

### Usage

#### List Available Brokers

```bash
# Sepolia testnet
broker-client.py --registry-contract 0x4bfA5E3B23ea65451f5f430B573930ff5FfF5074 list-brokers
```

#### Request Allocation

```bash
# Using broker registry (automatic broker selection) - Sepolia
broker-client.py \
    --registry-contract 0x4bfA5E3B23ea65451f5f430B573930ff5FfF5074 \
    request \
    --nft-contract 0xYourNFTContract \
    --wallet-key /etc/blockhost/deployer.key \
    --configure-wg

# Using specific broker directly (without registry) - Sepolia
broker-client.py \
    request \
    --nft-contract 0xYourNFTContract \
    --wallet-key /etc/blockhost/deployer.key \
    --requests-contract 0x43880eA324BF7842A72a9ed0680B3dd1cD6CD7C8 \
    --broker-pubkey <65-byte-hex-pubkey> \
    --configure-wg
```

#### Install Persistent WireGuard Tunnel (Recommended)

After requesting an allocation, install persistent WireGuard configuration:

```bash
# Install wg-quick config and enable systemd service (requires root)
sudo broker-client.py install
```

This:
- Creates `/etc/wireguard/wg-broker.conf`
- Starts the WireGuard interface
- Enables `wg-quick@wg-broker` service for boot persistence
- Verifies connectivity to the broker

**This is the recommended approach** - set up once and forget.

#### Configure WireGuard Tunnel (Non-persistent)

For testing or temporary setups:

```bash
# Configure from saved allocation (requires root, does NOT survive reboot)
sudo broker-client.py configure
```

#### Check Status

```bash
broker-client.py status

# Or check on-chain status
broker-client.py \
    status \
    --nft-contract 0xYourNFTContract \
    --requests-contract 0xBrokerRequestsContract
```

### Configuration

The script stores allocation configuration in `/etc/blockhost/broker-allocation.json`:

```json
{
  "prefix": "2a11:6c7:f04:276::100/120",
  "gateway": "2a11:6c7:f04:276::2",
  "broker_pubkey": "...",
  "broker_endpoint": "95.179.128.177:51820",
  "nft_contract": "0x...",
  "request_id": 1,
  "wg_private_key": "...",
  "wg_public_key": "...",
  "allocated_at": "2024-01-15T12:00:00"
}
```

### Environment Variables

- `ETH_RPC_URL`: Ethereum RPC URL (default: Sepolia public node)
- `ETH_CHAIN_ID`: Chain ID (default: 11155111 for Sepolia)
- `BROKER_REGISTRY_CONTRACT`: BrokerRegistry contract address

### How It Works

1. **Query Registry**: Finds available brokers (or uses directly specified broker)
2. **Generate Keys**: Creates WireGuard keypair and ECIES keypair for response encryption
3. **Submit Request**: Sends encrypted request to broker's BrokerRequests contract
4. **Wait for Response**: Polls blockchain for broker's response (40-75 seconds)
5. **Decrypt Response**: Decrypts allocation details using ECIES
6. **Configure WireGuard**: Sets up tunnel to broker (optional)
7. **Save Config**: Stores allocation for future reference

### Security

- WireGuard keys are generated locally and private key never leaves the server
- Request payload is encrypted with broker's public key (ECIES/secp256k1)
- Response is encrypted with server's ephemeral public key
- Wallet private key is only used for transaction signing
