# Claude Code Notes - blockhost-broker

## SPECIAL.md (HIGHEST PRIORITY)

**Read and internalize `SPECIAL.md` at the start of every session.** It defines priority weights — where to invest extra scrutiny beyond standard professional practice. All stats at 5 = normal competence. Stats above 5 = extra focus.

This submodule has a single profile — all components share it:

**S7 P8 E8 C4 I7 A6 L7** — Network allocation over encrypted channel.

Extra focus areas: Security (P8 — encrypted channel, trust boundary with external broker), Reliability (E8 — tunnel must survive, reconnect, not lose state), Robustness (S7 — validate everything from the broker, it's external).

See `SPECIAL.md` for full stat definitions and the priority allocation model.

## Environment Setup

Environment variables should be in `~/projects/sharedenv/blockhost.env` (not committed):
- `DEPLOYER_PRIVATE_KEY` - Wallet private key for deployments (registry owner)
- `OPERATOR_PRIVATE_KEY` - Operator wallet private key (BrokerRequests owner)
- `BLOCKHOST_NFT` - AccessCredentialNFT contract address
- `BLOCKHOST_CONTRACT` - Main Blockhost contract address
- `SEPOLIA_RPC` - Sepolia RPC endpoint

## Deployed Contracts (Sepolia Testnet)

**Currently Active (V2):**
- **BrokerRegistry**: `0x4e020bf35a1b2939E359892D22d96B4A2DAEb93e`
- **BrokerRequests**: `0xDE6f2cBB6de279e9f95Cd07B18411d26FEa51546`

**Legacy (V1 — still monitored by broker):**
- **BrokerRegistry**: `0x0E5b567E7d5C5c36D8fD70DE8129c35B473d0Aaf`
- **BrokerRequests**: `0xCD75c00dBB3F05cF27f16699591f4256a798e694`

**Test (CI — allocations auto-expire in 24h):**
- **BrokerRegistry**: `0x2C454Add607817c292f02DE37074c7Fb5F5BfCD8`
- **BrokerRequests**: `0x91cABa74E1e3005074bDF882BBf59c7CbC61a410`

V2 adds overwrite-on-duplicate, capacity tracking, and re-registration support. Deployed via `contracts-foundry/script/DeployV2.s.sol`.

Registry config fetched from: https://raw.githubusercontent.com/mwaddip/blockhost-broker/main/registry.json
Test registry config fetched from: https://raw.githubusercontent.com/mwaddip/blockhost-broker/main/registry-testnet.json

## Broker Server (95.179.128.177)

- **Broker Daemon**: Port 51820 (WireGuard), internal API on 127.0.0.1:8080
- **Broker Manager**: https://95.179.128.177:8443 (web UI for lease management)
- **Operator Wallet**: `0x6A5973DDe7E57686122Eb12DA85389c53fe2EE4b` (key: `/etc/blockhost-broker/operator.key` — contract owner, used for on-chain txs)
- **Deployer Wallet**: `0xe35B5D114eFEA216E6BB5Ff15C261d25dB9E2cb9` (key: `/etc/blockhost-broker/deployer.key` — NOT the contract owner)

## Development

```bash
# Build Rust broker
cd blockhost-broker-rs
cargo build --release

# Deploy to server
scp target/release/blockhost-broker linuxuser@95.179.128.177:/tmp/
ssh linuxuser@95.179.128.177 'sudo mv /tmp/blockhost-broker /usr/bin/ && sudo systemctl restart blockhost-broker'

# Deploy V2 contracts (Foundry)
cd contracts-foundry
forge build && forge test
forge script script/DeployV2.s.sol --rpc-url $SEPOLIA_RPC --broadcast

# Run client (on Proxmox server)
broker-client request --nft-contract 0x... --wallet-key /path/to/key
broker-client status
broker-client release --wallet-key /path/to/key
broker-client install
```

## Important: Deploy After Server Changes

**Any commit that modifies a server-side component (`blockhost-broker-rs/`) must be followed by building the release binary and deploying it to the broker server:**

```bash
cd blockhost-broker-rs && cargo build --release
scp target/release/blockhost-broker linuxuser@95.179.128.177:/tmp/
ssh linuxuser@95.179.128.177 'sudo mv /tmp/blockhost-broker /usr/bin/ && sudo systemctl restart blockhost-broker'
```

Verify the service is healthy after deploy with `sudo systemctl status blockhost-broker`.

## Important: Client/Server Compatibility

**Whenever the broker daemon or smart contracts are updated, the broker-client must be tested and updated if necessary.**

Components that must stay in sync:
- `scripts/broker-client.py` - Client ABI definitions must match deployed contracts
- `blockhost-broker-rs/src/eth/contracts.rs` - Rust broker ABI must match contracts (uses JSON ABI file)
- `blockhost-broker-rs/contracts/abi/*.json` - JSON ABI files for contract bindings
- `contracts-foundry/src/` - Solidity contract source (canonical)
- `registry.json` - Must point to the active BrokerRegistry address
- `registry-testnet.json` - Must point to the test BrokerRegistry address

Common breaking changes to watch for:
- Contract function signature changes
- Struct return types (must use tuple format in ABI)
- New/removed status codes

V2 contract additions (must be present in both Rust ABI JSON and Python client ABI):
- `getAvailableCapacity()`, `totalCapacity()`, `_activeCount()`, `_pendingCount()`, `setTotalCapacity(uint256)`

The broker config supports `legacy_requests_contracts` — a list of old BrokerRequests addresses that the broker continues to monitor (read-only polling, no new approvals). This keeps existing allocations visible during migration.

The broker config supports `test_requests_contract` — a single BrokerRequests address used for CI/integration testing. Allocations from this contract are tagged `is_test=1` and auto-expire after 24 hours.

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
├── registry.json              # Remote config for registry address
└── registry-testnet.json      # Remote config for test registry address
```

## Interface Contract (REFERENCE)

**`COMMON_INTERFACE.md` documents how the broker-allocation.json file is consumed by blockhost-common.** Read section 7 before changing the allocation JSON schema — consumers parse it via `load_broker_allocation()` and expect keys: `prefix`, `gateway`, `broker_pubkey`, `broker_endpoint`. If the schema changes, common and all provisioners break.

## Architecture

See DESIGN.md for the on-chain authentication flow.
