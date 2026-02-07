# Claude Code Notes - blockhost-broker

## SPECIAL.md (HIGHEST PRIORITY)

**Read and internalize `SPECIAL.md` at the start of every session.** It defines priority weights — where to invest extra scrutiny beyond standard professional practice. All stats at 5 = normal competence. Stats above 5 = extra focus.

This submodule has a single profile — all components share it:

**S7 P8 E8 C4 I7 A6 L7** — Network allocation over encrypted channel.

Extra focus areas: Security (P8 — encrypted channel, trust boundary with external broker), Reliability (E8 — tunnel must survive, reconnect, not lose state), Robustness (S7 — validate everything from the broker, it's external).

See `SPECIAL.md` for full stat definitions and the priority allocation model.

## Environment Setup

Environment variables should be in `~/projects/sharedenv/blockhost.env` (not committed):
- `DEPLOYER_PRIVATE_KEY` - Wallet private key for deployments
- `BLOCKHOST_NFT` - AccessCredentialNFT contract address
- `BLOCKHOST_CONTRACT` - Main Blockhost contract address
- `SEPOLIA_RPC` - Sepolia RPC endpoint

## Deployed Contracts (Sepolia Testnet)

**Currently Active:**
- **BrokerRegistry**: `0x0E5b567E7d5C5c36D8fD70DE8129c35B473d0Aaf`
- **BrokerRequests**: `0xCD75c00dBB3F05cF27f16699591f4256a798e694`

Registry config fetched from: https://raw.githubusercontent.com/mwaddip/blockhost-broker/main/registry.json

## Broker Server (95.179.128.177)

- **Broker Daemon**: Port 51820 (WireGuard), internal API on 127.0.0.1:8080
- **Broker Manager**: https://95.179.128.177:8443 (web UI for lease management)
- **Operator Wallet**: `0x6A5973DDe7E57686122Eb12DA85389c53fe2EE4b`

## Development

```bash
# Build Rust broker
cd blockhost-broker-rs
cargo build --release

# Deploy to server
scp target/release/blockhost-broker linuxuser@95.179.128.177:/tmp/
ssh linuxuser@95.179.128.177 'sudo mv /tmp/blockhost-broker /usr/bin/ && sudo systemctl restart blockhost-broker'

# Run client (on Proxmox server)
broker-client request --nft-contract 0x... --wallet-key /path/to/key
broker-client status
broker-client release --wallet-key /path/to/key
broker-client install
```

## Important: Client/Server Compatibility

**Whenever the broker daemon or smart contracts are updated, the broker-client must be tested and updated if necessary.**

Components that must stay in sync:
- `scripts/broker-client.py` - Client ABI definitions must match deployed contracts
- `blockhost-broker-rs/src/eth/contracts.rs` - Rust broker ABI must match contracts (uses JSON ABI file)
- `blockhost-broker-rs/contracts/abi/*.json` - JSON ABI files for contract bindings
- `contracts/` - Solidity contract source

Common breaking changes to watch for:
- Contract function signature changes
- Struct return types (must use tuple format in ABI)
- New/removed status codes

## Project Structure

```
blockhost-broker/
├── blockhost-broker-rs/       # Rust broker daemon
├── blockhost-broker-manager/  # Web management interface (Python/Flask)
├── scripts/
│   ├── broker-client.py       # Client for Proxmox servers
│   └── build-deb.sh           # Client .deb builder
├── contracts/                 # Solidity sources
├── contracts-foundry/         # Foundry project for deployment
└── registry.json              # Remote config for registry address
```

## Architecture

See DESIGN.md for the on-chain authentication flow.
