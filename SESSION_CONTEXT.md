# Claude Session Context
<!-- Machine-readable context for continuity across conversation compactions -->

## Active Infrastructure

### Broker Server: 95.179.128.177
- **Operator Wallet**: 0x6A5973DDe7E57686122Eb12DA85389c53fe2EE4b
- **Deployer Wallet**: 0xe35B5D114eFEA216E6BB5Ff15C261d25dB9E2cb9
- **BrokerRegistry (V3)**: 0x5F779652623c85343c5914d9E07FADCbD9Aa1f2e
- **BrokerRequests (V3)**: 0x145EBeA3830b4eCF3C06E0ccde9Ec5dd89dfE50e
- **Test BrokerRegistry (CI)**: 0x26b9baa877628801535F5Af08548e3EC7D3ceb39
- **Test BrokerRequests (CI)**: 0x70f0eAe36fB4d2FdDEf42b89c734a865D317B8B4
- **Upstream Interface**: tb25255R64 (SIT tunnel to Route64)
- **WireGuard Interface**: wg-broker
- **IPv6 Prefix**: 2a11:6c7:f04:276::/64
- **Allocation Size**: /120 (256 addresses each)
- **Max Allocations**: 256
- **API**: 0.0.0.0:8080 (port 8080 blocked from internet by ufw default deny; accessible via localhost + wg-broker clients)

### OPNet Infrastructure (regtest)
- **Deployer Address**: `0x24e650213736672eb653864ca38ccd200bcaff23c97983085937beec7fea9b87`
- **Deployer P2TR**: `bcrt1pla3gltr0wn0x3p7wacg4sk8etxzsz9qvga2ytflvmnhqh3wr7zds5v37sh`
- **Operator Address**: `0x0e285b6b323abbab63185e65836ee2878360fe0af12bbd990e3802c6eb41eb00`
- **Operator P2TR**: `bcrt1pntant9fjgxq8rezkw33cut9036dre0ya8qkzqwg6pvjfjeqtae6qpv65ja`
- **BrokerRegistry**: `opr1sqzkhywm0a726u5wuwr9p22nxgcgug6yaeqmmjwva` (pubkey: `0x36cd9b40a888ba905bb3a52fb28f56ef1ffdb9c61a858a83687268e68114a2c7`)
- **BrokerRequests**: `opr1sqp49unertjhqhaxv3gmfgt74046d4jkh8u79j68j` (pubkey: `0x6b3a088cef5d36c405ddd1cc8069e006d6571478378255b074c9079d1786a01b`)
- **Broker registered**: brokerId=1, encryptionPubkey=`02eac77a552ada6c01a25f0a995f8c5d813ff95a27d141de4f30c611f8202e7ead`, region=`eu-west` (same key as server's `/etc/blockhost-broker/ecies.key`)
- **RPC URL**: `https://regtest.opnet.org`
- **Operator mnemonic on server**: `/etc/blockhost-broker/operator-opnet.mnemonic`
- **Env file**: `~/projects/sharedenv/opnet-regtest.env`
- **Key derivation**: always use `mnemonic.deriveOPWallet(AddressTypes.P2TR, 0)` (NOT `mnemonic.derive()`)

### Key Files on Server
- Config: `/etc/blockhost-broker/config.toml`
- Database: `/var/lib/blockhost-broker/ipam.db`
- EVM keys: `/etc/blockhost-broker/{operator.key,ecies.key,wg-private.key}`
- OPNet key: `/etc/blockhost-broker/operator-opnet.mnemonic`

### DNS Domains
- **Primary zone**: `vm.blockhost.io`
- **Legacy zone**: `blockhost.thawaras.org` (kept as `extra_domains`)
- Delegation: `vm.blockhost.io NS ns1.vm.blockhost.io` + glue `A 95.179.128.177` (at Njalla)

### Web Server (blockhost.io)
- **nginx** on port 443 with Let's Encrypt cert (auto-renews)
- **Webroot**: `/var/www/blockhost.io/`

## Current Branch
- `feature/opnet` — all OPNet multichain work
- Latest commit: `1031377` (pushed 2026-02-25)
- Clean build, zero warnings

## Project Structure (post-restructure)
```
blockhost-broker/
├── adapters/
│   └── opnet/
│       ├── adapter/       # OPNet adapter (polls contract → POST /v1/allocations → OP_RETURN)
│       ├── client/        # OPNet client (submit request → watch OP_RETURN → JSON stdout)
│       └── contracts/     # OPNet AssemblyScript contracts + deploy scripts
├── blockhost-broker-rs/   # Rust broker daemon
├── blockhost-broker-manager/  # Web management UI (Python/Flask)
├── contracts-foundry/     # EVM Solidity contracts (Foundry)
├── scripts/
│   ├── broker-client.py   # Client for Proxmox servers (chain dispatch)
│   ├── build-deb.sh       # Client .deb builder (includes OPNet client plugin)
│   ├── broker-chains.json # Working chain config (shipped by .deb as conffile)
│   └── broker-chains.json.example  # Example (kept for reference)
├── facts/                 # Interface contracts submodule (READ-ONLY)
├── BROKER_INTERFACE.md    # Authoritative broker interface spec (→ facts repo)
├── registry.json          # Production EVM registry config
├── registry-testnet.json  # Test EVM registry config
└── registry-opnet-regtest.json  # OPNet regtest registry config
```

## Multichain Architecture

### Design
- EVM path stays native in Rust (`src/eth/`)
- Additional chains via external adapter processes using HTTP API
- Adapters POST to `http://127.0.0.1:8080/v1/allocations` — no persistent connections
- Each adapter is a long-running process with chain-specific tooling (Node.js for OPNet)
- Adapter owns: contract polling, encryption/decryption, response delivery
- Broker core owns: IPAM, WireGuard, DNS, SQLite, allocation lifecycle

### API Endpoints
- `GET /health` — health check (no auth)
- `GET /v1/status` — broker status (prefix info, allocation counts, peer counts)
- `GET /v1/allocations` — list all allocations (includes `source`, `expires_at`)
- `POST /v1/allocations` — create allocation (used by adapters: `{wg_pubkey, nft_contract, source, is_test, lease_duration}`)
- `GET /v1/allocations/{prefix}` — get specific allocation
- `DELETE /v1/allocations/{prefix}` — release allocation
- `GET /v1/config` — static broker config fetched post-tunnel (`{dns_zone}`)

### Allocation Fields
- `source` — identifies adapter instance (e.g. `"evm:0x145e..."`, `"opnet-regtest"`)
- `lease_duration` — optional, seconds until expiry. Regtest defaults to 86400 (1 day)
- `expires_at` — computed from lease_duration, or 24h for `is_test` allocations
- Legacy allocations default `source` to `"evm"`

### OPNet Adapter (`adapters/opnet/adapter/`)
**Status**: Deployed to server, processing requests. UTXO chaining working for back-to-back deliveries.

Files:
- `src/config.ts` — env-based config (source auto-derived from network, lease_duration defaults 86400 for regtest, stateFile for persistence)
- `src/contract.ts` — typed BrokerRequests wrapper
- `src/poller.ts` — block-aware polling (idle 60s, active 10s near expected block), onStateChange callback
- `src/crypto.ts` — ECIES encrypt/decrypt (eciespy-compatible, @noble/curves)
- `src/delivery.ts` — OP_RETURN response delivery (55B binary, ECDH-AES, 72B on-chain), UTXO chaining with scriptPubKey
- `src/main.ts` — polls → decrypt → POST /v1/allocations → deliver OP_RETURN, persistent state (lastProcessedId)
- `src/test-e2e.ts` — end-to-end mock test

**Bundling**: esbuild → single `dist/main.js` (2.9MB). Runs under plain `node`, no `tsx`/`node_modules` needed at runtime.

**Systemd**: `blockhost-opnet-adapter@regtest.service` → `node /opt/blockhost/adapters/opnet/adapter/dist/main.js`

**State file**: `/var/lib/blockhost-broker/adapter-opnet-regtest.state` (JSON: `{"lastProcessedId":"7"}`)

**UTXO chaining**: After broadcasting, tracks change UTXO (txid, vout, value, scriptPubKey) for next delivery. Avoids RBF conflicts when multiple requests arrive in same poll cycle.

Env vars: `OPNET_RPC_URL`, `OPNET_BROKER_REQUESTS_PUBKEY`, `OPNET_OPERATOR_MNEMONIC`, `BROKER_ECIES_PRIVATE_KEY`, `BROKER_API_URL`, `ADAPTER_SOURCE`, `LEASE_DURATION`, `STATE_FILE`

### OPNet Client (`adapters/opnet/client/`)
**Status**: On-chain flow working (submit request + watch for OP_RETURN response). Esbuild-bundled to `dist/main.js`.

### Client Architecture
- `broker-client.py` is the single entry point for all chains
- Chain dispatch via `broker-chains.json` config — maps chain names to subprocess commands
- OPNet module outputs JSON to stdout: `{prefix, gateway, brokerPubkey, brokerEndpoint, wgPrivateKey, wgPublicKey}`
- `broker-client.py` handles all WireGuard setup, routing, install, release, status
- After tunnel up, fetches `http://[gateway]:8080/v1/config` for dns_zone

### Packaging
- **Server deb** (`blockhost-broker-rs/build-deb.sh`): broker binary + OPNet adapter plugin + systemd template unit
  - `blockhost-opnet-adapter@.service` — template for multi-instance: `@regtest`, `@testnet`, `@mainnet`
  - Env files: `/etc/blockhost-broker/opnet-adapter-{instance}.env`
- **Client deb** (`scripts/build-deb.sh`): broker-client.py + OPNet client plugin (esbuild bundle)
  - Ships working `broker-chains.json` as dpkg conffile (EVM builtin + OPNet node subprocess)
  - OPNet client: single `dist/main.js` bundle, no `node_modules` shipped

## V3 Contract Architecture (2026-02-25)

### What Changed from V2
Fundamental simplification across all components. Net -2000 lines.

**Contracts (BrokerRequests):**
- Removed: `submitResponse`, `releaseAllocation`, `markExpired`, `RequestStatus` enum, `responsePayload`/`respondedAt` fields, `totalCapacity`/`_activeCount`/`_pendingCount`, `getAvailableCapacity`, `requestExpirationTime`
- Added: `capacityStatus` uint8 (0=available, 1=limited, 2=closed), `setCapacityStatus()` owner-only
- `submitRequest()` overwrites on same NFT (kept from V2)
- Request struct: `{id, requester, nftContract, encryptedPayload, submittedAt}`

**Response delivery:**
- EVM: Broker sends direct ETH transaction to requester address with `[8B request_id BE][ECIES payload]`
- OPNet: Adapter sends OP_RETURN with `[1B version][71B ECDH-AES encrypted]` (55B plaintext)
- No on-chain storage of responses

**Release:**
- Local-only: remove WireGuard peer + delete DB row
- No on-chain release call anywhere
- Broker detects lost peers via WireGuard handshake timeout (120s verification)

### Deployment
- V3 EVM contracts deployed to Sepolia
- V3 OPNet contracts deployed to regtest
- Broker binary deployed and running on server (latest: 2026-02-25 with source/lease_duration)
- OPNet adapter deployed as systemd service (regtest), state persisted, UTXO chaining working
- Manager deployed and running on server
- `registry.json`, `registry-testnet.json`, and `registry-opnet-regtest.json` committed
- `BROKER_INTERFACE.md` written (authoritative spec, ready to move to facts repo)
- No legacy contracts monitored

## Architecture Notes

### Traffic Flow
```
Internet → Route64 (SIT) → tb25255R64 → [NDP Proxy] → wg-broker → Client
```

### NDP Proxy Limitation
- Only works for allocations ≤256 addresses (/120 or smaller)
- Larger prefixes would need proper routing from upstream
- Route64 only offers BGP/proper routing to ASN holders

## Deployment Commands
```bash
# Build and deploy broker
cd blockhost-broker-rs && cargo build --release
scp target/release/blockhost-broker linuxuser@95.179.128.177:/tmp/
ssh linuxuser@95.179.128.177 'sudo mv /tmp/blockhost-broker /usr/bin/ && sudo systemctl restart blockhost-broker'

# Deploy manager files
scp -r blockhost-broker-manager/manager/ linuxuser@95.179.128.177:/tmp/manager-update/
ssh linuxuser@95.179.128.177 'sudo cp -r /tmp/manager-update/manager/* /opt/blockhost-broker-manager/manager/ && sudo systemctl restart blockhost-broker-manager && rm -rf /tmp/manager-update'

# Deploy V3 EVM contracts
cd contracts-foundry && forge build && forge test
DEPLOYER_PRIVATE_KEY=0x... OPERATOR_PRIVATE_KEY=0x... ECIES_PUBKEY=0x... \
  forge script script/DeployV2.s.sol:DeployV3 --rpc-url $RPC_URL --broadcast

# Deploy OPNet contracts
source ~/projects/sharedenv/opnet-regtest.env
cd adapters/opnet/contracts/deploy
npm run deploy:registry   # deployer wallet
npm run deploy:requests   # operator wallet
npx tsx register-broker.ts  # register broker on registry

# Run OPNet adapter (dev)
source ~/projects/sharedenv/opnet-regtest.env
cd adapters/opnet/adapter && npx tsx src/main.ts

# Deploy OPNet adapter to server
cd adapters/opnet/adapter && npm run build
scp dist/main.js linuxuser@95.179.128.177:/tmp/adapter-main.js
ssh linuxuser@95.179.128.177 'sudo cp /tmp/adapter-main.js /opt/blockhost/adapters/opnet/adapter/dist/main.js && sudo systemctl restart blockhost-opnet-adapter@regtest'

# Build debs
cd blockhost-broker-rs && bash build-deb.sh   # server
cd scripts && bash build-deb.sh               # client

# Check broker status
ssh linuxuser@95.179.128.177 'sudo systemctl status blockhost-broker'
ssh linuxuser@95.179.128.177 'curl -s http://127.0.0.1:8080/v1/status'
ssh linuxuser@95.179.128.177 'curl -s http://127.0.0.1:8080/v1/allocations | python3 -m json.tool'
```

## Known Issues / Quirks
- Route64 SIT tunnels expect NDP, not routing (hence NDP proxy workaround)
- UFW `route allow` rules needed for forwarding between interfaces
- Broker's own IP (::2) is on both tb25255R64 and wg-broker (routing asymmetry for self-tests)
- Stale NDP proxy entries not cleaned up on allocation release (accumulate over time)
- Stale WG routes for released allocations linger on wg-broker interface
- OPNet key derivation: `deriveOPWallet(P2TR, 0)` gives different address than `derive(0,0,false)` — always use `deriveOPWallet`

## Community
- Telegram: https://t.me/BlockHostOS

## Last Updated
2026-02-25 (adapter deployed with state persistence + UTXO chaining, esbuild bundling, broker-chains.json shipped by .deb, BROKER_INTERFACE.md written, registry-opnet-regtest.json added)
