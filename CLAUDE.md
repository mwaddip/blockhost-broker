# Claude Code Notes - blockhost-broker

## SPECIAL.md (HIGHEST PRIORITY)

**Read and internalize `SPECIAL.md` at the start of every session.** It defines priority weights — where to invest extra scrutiny beyond standard professional practice. All stats at 5 = normal competence. Stats above 5 = extra focus.

This submodule has a single profile — all components share it:

**S7 P8 E8 C4 I7 A6 L7** — Network allocation over encrypted channel.

Extra focus areas: Security (P8 — encrypted channel, trust boundary with external broker), Reliability (E8 — tunnel must survive, reconnect, not lose state), Robustness (S7 — validate everything from the broker, it's external).

See `SPECIAL.md` for full stat definitions and the priority allocation model.

## Environment Setup

EVM environment variables in `~/projects/sharedenv/blockhost.env` (not committed):
- `DEPLOYER_PRIVATE_KEY` - Wallet private key for deployments (registry owner)
- `OPERATOR_PRIVATE_KEY` - Operator wallet private key (BrokerRequests owner)
- `BLOCKHOST_NFT` - AccessCredentialNFT contract address
- `BLOCKHOST_CONTRACT` - Main Blockhost contract address
- `RPC_URL` - Sepolia RPC endpoint

OPNet environment variables in `~/projects/sharedenv/opnet-regtest.env` (not committed):
- `OPNET_RPC_URL` - OPNet JSON-RPC URL
- `OPNET_BROKER_REQUESTS_PUBKEY` - BrokerRequests contract tweaked pubkey
- `OPNET_OPERATOR_MNEMONIC` - Operator mnemonic
- `BROKER_ECIES_PRIVATE_KEY` - ECIES private key (hex)

Ergo environment variables in `~/projects/sharedenv/ergo-testnet.env` (not committed):
- `DEPLOYER_MNEMONIC` - Deployer BIP39 mnemonic (registry owner)
- `DEPLOYER_ADDRESS` - Deployer P2PK address
- `ERGO_NODE_URL` - Local Ergo node (`http://127.0.0.1:9052`)
- `ERGO_EXPLORER_URL` - Explorer API URL

## Deployed Contracts (Sepolia Testnet)

**Currently Active (V3):**
- **BrokerRegistry**: `0x5F779652623c85343c5914d9E07FADCbD9Aa1f2e`
- **BrokerRequests**: `0x145EBeA3830b4eCF3C06E0ccde9Ec5dd89dfE50e`

**Test (CI — allocations auto-expire in 24h):**
- **BrokerRegistry**: `0x26b9baa877628801535F5Af08548e3EC7D3ceb39`
- **BrokerRequests**: `0x70f0eAe36fB4d2FdDEf42b89c734a865D317B8B4`

V3: minimal contracts — responses delivered via direct ETH tx (not stored on-chain), release is local-only, capacity tracked by uint8 status flag. Deployed via `contracts-foundry/script/DeployV2.s.sol` (DeployV3 contract).

Registry config fetched from: https://raw.githubusercontent.com/mwaddip/blockhost-broker/main/registry.json
Test registry config fetched from: https://raw.githubusercontent.com/mwaddip/blockhost-broker/main/registry-testnet.json

## Broker Server (95.179.128.177)

- **Broker Daemon**: Port 51820 (WireGuard), internal API on 127.0.0.1:8080
- **Broker Manager**: https://95.179.128.177:8443 (web UI for lease management)
- **Operator Wallet**: `0x6A5973DDe7E57686122Eb12DA85389c53fe2EE4b` (key: `/etc/blockhost-broker/operator.key` — contract owner, used for on-chain txs)
- **Deployer Wallet**: `0xe35B5D114eFEA216E6BB5Ff15C261d25dB9E2cb9` (key: `/etc/blockhost-broker/deployer.key` — NOT the contract owner)
- **Ergo Operator Wallet**: `3Wvkg6K6nsLMz3KB7LXteGJ9zcVbHWSsGbrfFV4PBjKCVwh7JGAV` (key: `/etc/blockhost-broker/ergo-operator.key`)
- **Ergo ECIES Key**: `/etc/blockhost-broker/ergo-ecies.key`

## Development

```bash
# Build Rust broker
cd blockhost-broker-rs
cargo build --release

# Deploy broker to server
scp target/release/blockhost-broker linuxuser@95.179.128.177:/tmp/
ssh linuxuser@95.179.128.177 'sudo mv /tmp/blockhost-broker /usr/bin/ && sudo systemctl restart blockhost-broker'

# Deploy V3 EVM contracts (Foundry)
cd contracts-foundry
forge build && forge test
forge script script/DeployV2.s.sol --rpc-url $RPC_URL --broadcast

# Build and deploy OPNet adapter
cd adapters/opnet/adapter && npm run build
scp dist/main.js linuxuser@95.179.128.177:/tmp/adapter-main.js
ssh linuxuser@95.179.128.177 'sudo cp /tmp/adapter-main.js /opt/blockhost/adapters/opnet/adapter/dist/main.js && sudo systemctl restart blockhost-opnet-adapter@regtest'

# Build and deploy Ergo adapter
cd adapters/ergo/adapter && npm run build
scp dist/main.js linuxuser@95.179.128.177:/tmp/ergo-adapter-main.js
ssh linuxuser@95.179.128.177 'sudo cp /tmp/ergo-adapter-main.js /opt/blockhost/adapters/ergo/adapter/dist/main.js && sudo systemctl restart blockhost-ergo-adapter@testnet'

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
- `scripts/broker-client.py` - Client ABI definitions must match deployed EVM contracts
- `blockhost-broker-rs/src/eth/contracts.rs` - Rust broker ABI must match EVM contracts (uses JSON ABI file)
- `blockhost-broker-rs/contracts/abi/*.json` - JSON ABI files for EVM contract bindings
- `contracts-foundry/src/` - EVM Solidity contract source (canonical)
- `adapters/opnet/contracts/` - OPNet AssemblyScript contract source
- `adapters/opnet/adapter/src/contract.ts` - Adapter's typed wrapper must match OPNet contracts
- `adapters/opnet/client/src/` - Client must match OPNet contracts + OP_RETURN format
- `registry.json` - Must point to the active EVM BrokerRegistry address
- `registry-testnet.json` - Must point to the test EVM BrokerRegistry address
- `registry-opnet-regtest.json` - Must point to the OPNet regtest BrokerRegistry address
- `adapters/ergo/contracts/contracts.ts` - Guard ErgoTree template (compiled from guard.es)
- `adapters/ergo/adapter/src/` - Adapter must match guard script register layout
- `adapters/ergo/client/src/` - Client must match guard script register layout + response format
- `registry-ergo-testnet.json` - Must point to the Ergo testnet registry NFT ID
- `scripts/broker-chains.json` - Chain dispatch config shipped by client .deb

Common breaking changes to watch for:
- Contract function signature changes (EVM or OPNet)
- Struct return types (must use tuple format in EVM ABI)
- OP_RETURN binary format changes (adapter + client must match)
- New/removed status codes

## Project Structure

```
blockhost-broker/
├── adapters/
│   ├── ergo/
│   │   ├── adapter/              # Ergo adapter (polls Explorer → POST /v1/allocations → response box)
│   │   ├── client/               # Ergo client (request box → watch response → JSON stdout)
│   │   ├── contracts/            # Guard script ErgoTree template + byte surgery
│   │   └── deploy-registry.ts    # Registry NFT minting script
│   ├── cardano/
│   │   ├── adapter/              # Cardano adapter (polls Koios/Blockfrost → POST /v1/allocations → response datum)
│   │   ├── client/               # Cardano client (request datum → watch response → JSON stdout)
│   │   └── contracts/            # Aiken validators + parameterized scripts
│   └── opnet/
│       ├── adapter/              # OPNet adapter (polls contract → POST /v1/allocations → OP_RETURN)
│       ├── client/               # OPNet client (submit request → watch OP_RETURN → JSON stdout)
│       └── contracts/            # OPNet AssemblyScript contracts + deploy scripts
├── blockhost-broker-rs/          # Rust broker daemon
├── blockhost-broker-manager/     # Web management interface (Python/Flask)
├── contracts-foundry/            # EVM Solidity contracts (Foundry)
├── scripts/
│   ├── broker-client.py          # Client for Proxmox servers (chain dispatch)
│   ├── build-deb.sh              # Client .deb builder
│   ├── broker-chains.json        # Chain config shipped by .deb (EVM + OPNet + Cardano + Ergo)
│   └── broker-chains.json.example
├── facts/                        # Interface contracts submodule (READ-ONLY)
├── BROKER_INTERFACE.md           # Authoritative broker interface specification
├── registry.json                 # EVM production registry config
├── registry-testnet.json         # EVM test registry config
├── registry-opnet-regtest.json   # OPNet regtest registry config
└── registry-ergo-testnet.json    # Ergo testnet registry config
```

## Interface Contract (REFERENCE — READ-ONLY)

Interface contracts live in the `facts/` submodule (`blockhost-facts` repo) — one source of truth, no local copies.

**DO NOT edit files inside `facts/`.** This submodule is managed externally and is outside this repo's domain. If changes appear needed:
1. First try `git submodule update --remote facts` — the change may already exist upstream.
2. If not, report the needed change to the user. Do not commit directly to the submodule.

| Contract | Path |
|----------|------|
| Provisioner Interface | `facts/PROVISIONER_INTERFACE.md` |
| Common Interface | `facts/COMMON_INTERFACE.md` |

**Read `facts/COMMON_INTERFACE.md` section 7 before changing the allocation JSON schema** — consumers parse it via `load_broker_allocation()` and expect keys: `prefix`, `gateway`, `broker_pubkey`, `broker_endpoint`. If the schema changes, common and all provisioners break.

## Architecture

See DESIGN.md for architecture overview and design decisions.
See BROKER_INTERFACE.md for detailed API schemas, database schema, config reference, and binary formats.

### Multichain

- EVM path is built into the Rust daemon (`blockhost-broker-rs/src/eth/`)
- Additional chains use external adapter processes that POST to `http://127.0.0.1:8080/v1/allocations`
- Each adapter is a long-running process with chain-specific tooling (Node.js for OPNet, Cardano, Ergo)
- Ergo adapter uses Fleet SDK for tx building, Explorer API for queries
- Adapter owns: contract polling, encryption/decryption, response delivery
- Broker core owns: IPAM, WireGuard, DNS, SQLite, allocation lifecycle
