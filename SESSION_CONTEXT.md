# Claude Session Context
<!-- Machine-readable context for continuity across conversation compactions -->

## Active Infrastructure

### Broker Server: 95.179.128.177
- **Operator Wallet**: 0x6A5973DDe7E57686122Eb12DA85389c53fe2EE4b
- **Deployer Wallet**: 0xe35B5D114eFEA216E6BB5Ff15C261d25dB9E2cb9
- **BrokerRequests Contract (V2)**: 0xDE6f2cBB6de279e9f95Cd07B18411d26FEa51546
- **BrokerRegistry (V2)**: 0x4e020bf35a1b2939E359892D22d96B4A2DAEb93e
- **Legacy BrokerRequests (V1)**: 0xCD75c00dBB3F05cF27f16699591f4256a798e694
- **Upstream Interface**: tb25255R64 (SIT tunnel to Route64)
- **WireGuard Interface**: wg-broker
- **IPv6 Prefix**: 2a11:6c7:f04:276::/64
- **Allocation Size**: /120 (256 addresses each)
- **Max Allocations**: 256 (on-chain totalCapacity)

### Key Files on Server
- Config: `/etc/blockhost-broker/config.toml`
- Database: `/var/lib/blockhost-broker/ipam.db`
- Keys: `/etc/blockhost-broker/{operator.key,deployer.key,ecies.key,wg-private.key}`

## Recent Implementation Details

### Contract V2 — Overwrite + Capacity (2026-02-08)
- **BrokerRequests V2**: `submitRequest()` overwrites instead of reverting on duplicate NFT
  - Old request → Expired, counters decremented, new request created
  - Capacity tracking: `totalCapacity`, `_activeCount`, `_pendingCount`, `getAvailableCapacity()`
  - `setTotalCapacity()` — owner-only setter
  - `submitResponse()` has supersession guard: `nftContractToRequestId[nft] == requestId`
  - `releaseAllocation()` clears `nftContractToRequestId` but does NOT change request status
  - `markExpired()` updates counters
- **BrokerRegistry V2**: `registerBroker()` supports re-registration (deactivates old entry)
- **Deploy script**: `contracts-foundry/script/DeployV2.s.sol` — 3-phase deploy (deployer→registry, operator→requests, deployer→registerBroker)
- **Rust broker**: Multi-contract monitoring (primary + legacy), per-contract `last_processed_id`, capacity sync on startup, rollback on failed `submit_approval`, stale `pending_verification` cleanup on re-request
- **Python client v0.3.0**: Capacity-aware broker selection via `getAvailableCapacity()`, no stale-release polling loop (V2 overwrite), V1 ECIES fallback (try raw payload if prefix-stripped decrypt fails)

### Capacity Configuration
- `[broker] max_allocations = 256` in config.toml — synced to on-chain `totalCapacity` on startup
- If omitted, on-chain `totalCapacity` stays 0 (unlimited)
- `theoretical_max_allocations()` in config.rs is the IPAM index ceiling (prefix math), NOT on-chain capacity
- Client calls `getAvailableCapacity()` per broker to select one with room

### NDP Proxy (2026-02-07)
- Route64 SIT tunnels require NDP proxy (not proper prefix routing)
- Broker adds NDP proxy entries for ALL addresses in allocated prefix (up to 256)
- Sysctl: `net.ipv6.conf.all.forwarding=1`, `net.ipv6.conf.all.proxy_ndp=1`
- Config option: `[wireguard] upstream_interface = "tb25255R64"`
- Functions: `add_ndp_proxy_for_prefix()`, `remove_ndp_proxy_for_prefix()` in wg/manager.rs

### Re-Request Handling
- Same NFT contract can submit new request (V2 contract overwrites old on-chain)
- Broker updates WireGuard pubkey, returns SAME allocation
- Removes stale `pending_verifications` for the old request
- Enables key rotation without losing prefix
- See: `process_request()` in eth/monitor.rs, `update_allocation_pubkey()` in db/ipam.rs

### Request ID Prefix + Tunnel Verification (2026-02-08)
- Response payloads: `[8 bytes request_id BE][ECIES ciphertext]`
- Client detects stale responses via prefix mismatch (e.g., after server re-install with new ECIES key)
- **V1 fallback**: If prefix-stripped decrypt fails, client retries with raw payload (handles V1 servers or cached old clients)
- Broker tracks approved allocations in `pending_verifications` (PendingVerification struct)
- After 2 minutes: checks `wg.get_peer_status()` — no handshake → releases allocation (WG + IPAM + on-chain)
- Client helper: `_extract_request_id_prefix()` in broker-client.py
- Broker: `check_pending_verifications()` in eth/monitor.rs, called each poll cycle

### Broker-Client
- Uses persistent `/etc/blockhost/server.key` for ECIES (not ephemeral)
- Records `broker_wallet` from ResponseSubmitted event transaction
- Saves to `/etc/blockhost/broker-allocation.json`
- Deb package: `scripts/build-deb.sh` → `blockhost-broker-client_0.3.0_all.deb`

### Broker-Manager (Web UI)
- Session expiry: configurable via `SESSION_LIFETIME_HOURS` (default: 1 hour)
- Shows wallet info: address, balance, network, low-balance warning
- ETH top-up via MetaMask integration

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

# Deploy V2 contracts
cd contracts-foundry && forge build && forge test
DEPLOYER_PRIVATE_KEY=0x... OPERATOR_PRIVATE_KEY=0x... ECIES_PUBKEY=0x... \
  forge script script/DeployV2.s.sol --rpc-url $RPC_URL --broadcast

# Build client deb
cd scripts && bash build-deb.sh

# Check broker status
ssh linuxuser@95.179.128.177 'sudo systemctl status blockhost-broker'
ssh linuxuser@95.179.128.177 'sudo journalctl -u blockhost-broker -f'

# Check NDP proxy entries
ssh linuxuser@95.179.128.177 'ip -6 neigh show proxy | wc -l'

# Check WireGuard peers
ssh linuxuser@95.179.128.177 'sudo wg show wg-broker'
```

## Known Issues / Quirks
- Route64 SIT tunnels expect NDP, not routing (hence NDP proxy workaround)
- UFW `route allow` rules needed for forwarding between interfaces
- Broker's own IP (::2) is on both tb25255R64 and wg-broker (routing asymmetry for self-tests)
- `releaseAllocation()` clears `nftContractToRequestId` mapping but leaves request status as Approved — subsequent client lookups via `nftContractToRequestId` return 0, so they submit fresh

## V2 Deployment Complete (2026-02-08)
1. `forge test` — all 45 tests passing
2. `DeployV2.s.sol` deployed to Sepolia
3. `registry.json` updated with new registry address
4. Server config updated with V2 addresses + legacy list + `max_allocations = 256`
5. Rust binary deployed to 95.179.128.177
6. Legacy `last_processed_id` migrated to per-contract key (value 40 for V1 contract)
7. On-chain `totalCapacity` set to 256
8. CI failure diagnosed: cached old client, not an ECIES interop issue; V1 fallback added as safety net

## Last Updated
2026-02-08
