# Claude Code Notes - blockhost-broker

## Environment Setup

Environment variables should be in `~/projects/sharedenv/blockhost.env` (not committed):
- `DEPLOYER_PRIVATE_KEY` - Wallet private key for deployments
- `BLOCKHOST_NFT` - AccessCredentialNFT contract address
- `BLOCKHOST_CONTRACT` - Main Blockhost contract address
- `SEPOLIA_RPC` - Sepolia RPC endpoint

## Deployed Contracts (Sepolia Testnet)

### v2 (Lazy Polling / No Unbounded Loops)
- **BrokerRegistry**: `0x0E5b567E7d5C5c36D8fD70DE8129c35B473d0Aaf`
- **BrokerRequests**: `0xb7C329cFD95ADC4eE3413918864d4506540f7341`

### v1 (Legacy - has unbounded loops)
- **BrokerRegistry**: `0x4bfA5E3B23ea65451f5f430B573930ff5FfF5074`
- **BrokerRequests**: `0x43880eA324BF7842A72a9ed0680B3dd1cD6CD7C8`

## Development

```bash
# Activate virtual environment
source .venv/bin/activate

# Run broker daemon
blockhost-broker -c config.toml

# Run client (on Proxmox server)
broker-client.py request --help
broker-client.py install --help
```

## Architecture

See DESIGN.md for the on-chain authentication flow.
