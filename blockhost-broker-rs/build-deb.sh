#!/bin/bash
# Build Debian package for blockhost-broker.
#
# Includes:
#   - Rust broker daemon          → /usr/bin/blockhost-broker
#   - Cardano, Ergo, OPNet adapters as bundled dist/main.js (no node_modules,
#     no TS source) → /opt/blockhost/adapters/<chain>/adapter/dist/main.js
#   - systemd unit + template for each adapter
#   - example env files for each adapter
#   - Cardano contracts (parameterized-scripts.json) needed at runtime
#
# `dpkg -i` is meant to be a clean drop-in replacement for the older
# scp-based deploy: existing config and state are preserved, active
# services are restarted in place.

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
ARCH=$(dpkg --print-architecture)
PKG_NAME="blockhost-broker_${VERSION}_${ARCH}"
PKG_DIR="build/${PKG_NAME}"

echo "Building blockhost-broker v${VERSION} for ${ARCH}..."

# ── Build artifacts ─────────────────────────────────────────────────

cargo build --release

build_adapter() {
    local chain="$1"
    local adapter_dir="${REPO_ROOT}/adapters/${chain}/adapter"

    echo "Building ${chain} adapter bundle..."
    if [ ! -d "$adapter_dir/node_modules" ]; then
        (cd "$adapter_dir" && npm ci --ignore-scripts)
    fi
    (cd "$adapter_dir" && npm run build)

    if [ ! -f "$adapter_dir/dist/main.js" ]; then
        echo "ERROR: ${chain} adapter build did not produce dist/main.js"
        exit 1
    fi
}

build_adapter cardano
build_adapter ergo
build_adapter opnet

# ── Package skeleton ────────────────────────────────────────────────

rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/lib/systemd/system"
mkdir -p "$PKG_DIR/etc/blockhost-broker"
mkdir -p "$PKG_DIR/var/lib/blockhost-broker"

# Core broker binary + service unit + config example
cp target/release/blockhost-broker "$PKG_DIR/usr/bin/"
cp debian/blockhost-broker.service "$PKG_DIR/lib/systemd/system/"
cp debian/config.toml.example "$PKG_DIR/etc/blockhost-broker/"

# ── Adapter bundles ─────────────────────────────────────────────────
#
# Each adapter is a single self-contained dist/main.js produced by esbuild.
# No node_modules at runtime — esbuild has bundled every dependency.

for chain in cardano ergo opnet; do
    DEST="$PKG_DIR/opt/blockhost/adapters/${chain}/adapter/dist"
    mkdir -p "$DEST"
    cp "${REPO_ROOT}/adapters/${chain}/adapter/dist/main.js" "$DEST/main.js"
done

# Cardano runtime data (parameterized scripts read at startup)
mkdir -p "$PKG_DIR/opt/blockhost/adapters/cardano/contracts"
cp "${REPO_ROOT}/adapters/cardano/contracts/parameterized-scripts.json" \
   "$PKG_DIR/opt/blockhost/adapters/cardano/contracts/"

# ── systemd unit templates ──────────────────────────────────────────
#
# Operators enable a per-network instance, e.g.:
#   systemctl enable --now blockhost-cardano-adapter@preprod
# The instance name maps to the env file: cardano-adapter-preprod.env

write_adapter_unit() {
    local chain="$1"
    local desc="$2"
    cat > "$PKG_DIR/lib/systemd/system/blockhost-${chain}-adapter@.service" << EOF
[Unit]
Description=${desc} Adapter (%i)
After=network.target blockhost-broker.service
Requires=blockhost-broker.service

[Service]
Type=simple
EnvironmentFile=/etc/blockhost-broker/${chain}-adapter-%i.env
ExecStart=/usr/bin/node /opt/blockhost/adapters/${chain}/adapter/dist/main.js
Restart=on-failure
RestartSec=10
WorkingDirectory=/opt/blockhost/adapters/${chain}/adapter
StandardOutput=journal
StandardError=journal
SyslogIdentifier=blockhost-${chain}-adapter-%i

[Install]
WantedBy=multi-user.target
EOF
}

write_adapter_unit cardano "Blockhost Cardano"
write_adapter_unit ergo    "Blockhost Ergo"
write_adapter_unit opnet   "Blockhost OPNet"

# ── Example env files ───────────────────────────────────────────────

cat > "$PKG_DIR/etc/blockhost-broker/cardano-adapter-preprod.env.example" << 'EOF'
# Cardano adapter — preprod
CARDANO_NETWORK=preprod
KOIOS_URL=https://preprod.koios.rest/api/v1
OPERATOR_MNEMONIC=word1 word2 ...
ECIES_PRIVATE_KEY=...
VALIDATOR_ADDRESS=addr_test1...
BEACON_POLICY_ID=...
REGISTRY_ADDRESS=addr_test1...
BROKER_API_URL=http://127.0.0.1:8080
ADAPTER_SOURCE=cardano-preprod
LEASE_DURATION=0
POLL_INTERVAL_MS=20000
SCRIPTS_PATH=/opt/blockhost/adapters/cardano/contracts/parameterized-scripts.json
# Optional: set to use Blockfrost instead of Koios for UTXO/datum/submit
# BLOCKFROST_API_KEY=preprod...
EOF

cat > "$PKG_DIR/etc/blockhost-broker/ergo-adapter-testnet.env.example" << 'EOF'
# Ergo adapter — testnet
ERGO_NETWORK=testnet
ERGO_EXPLORER_URL=https://api-testnet.ergoplatform.com
ERGO_NODE_URL=http://127.0.0.1:9052
OPERATOR_KEY_FILE=/etc/blockhost-broker/ergo-operator.key
ECIES_KEY_FILE=/etc/blockhost-broker/ergo-ecies.key
REGISTRY_NFT_ID=...
BROKER_API_URL=http://127.0.0.1:8080
ADAPTER_SOURCE=ergo-testnet
LEASE_DURATION=0
POLL_INTERVAL_MS=15000
EOF

cat > "$PKG_DIR/etc/blockhost-broker/opnet-adapter-testnet.env.example" << 'EOF'
# OPNet adapter — testnet
OPNET_RPC_URL=https://testnet.opnet.org
OPNET_BROKER_REQUESTS_PUBKEY=0x...
OPNET_OPERATOR_MNEMONIC=word1 word2 ...
BROKER_ECIES_PRIVATE_KEY=...
BROKER_API_URL=http://127.0.0.1:8080
ADAPTER_SOURCE=opnet-testnet
LEASE_DURATION=0
EOF

# ── Control files ───────────────────────────────────────────────────

cat > "$PKG_DIR/DEBIAN/control" << EOF
Package: blockhost-broker
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Pre-Depends: debconf (>= 0.5) | debconf-2.0
Depends: wireguard-tools, nodejs (>= 18)
Maintainer: Blockhost <contact@blockhost.io>
Description: IPv6 tunnel broker for Blockhost network
 blockhost-broker is a daemon that manages IPv6 prefix allocations
 for Blockhost servers using on-chain authentication via NFT
 contract ownership verification.
 .
 Bundled chain adapters (each shipped as a self-contained dist/main.js):
  - Cardano (TyphonJS + Blockfrost/Koios)
  - Ergo (Fleet SDK + Explorer API)
  - OPNet (Bitcoin L1 smart contracts via OPNet RPC)
 .
 Features:
  - On-chain authentication via smart contracts (EVM + OPNet + Ergo + Cardano)
  - ECIES encryption for secure communication
  - WireGuard peer management
  - SQLite-based IPAM database
  - REST API for allocation management
  - Built-in authoritative DNS server
EOF

cp debian/templates "$PKG_DIR/DEBIAN/"
cp debian/config "$PKG_DIR/DEBIAN/"
cp debian/postinst "$PKG_DIR/DEBIAN/"

# ── Permissions ─────────────────────────────────────────────────────

chmod 755 "$PKG_DIR/usr/bin/blockhost-broker"
chmod 644 "$PKG_DIR/lib/systemd/system/"*.service
chmod 644 "$PKG_DIR/etc/blockhost-broker/"*.example
chmod 750 "$PKG_DIR/var/lib/blockhost-broker"
chmod 755 "$PKG_DIR/DEBIAN/config"
chmod 755 "$PKG_DIR/DEBIAN/postinst"
chmod 644 "$PKG_DIR/DEBIAN/templates"

find "$PKG_DIR/opt/blockhost" -type f -exec chmod 644 {} \;
find "$PKG_DIR/opt/blockhost" -type d -exec chmod 755 {} \;

# ── Build ───────────────────────────────────────────────────────────

dpkg-deb --build "$PKG_DIR"

echo ""
echo "Package built: ${PKG_DIR}.deb"
echo ""
echo "Install (drop-in replacement, preserves config/state, restarts active services):"
echo "  sudo dpkg -i ${PKG_DIR}.deb"
echo ""
echo "Adapters are enabled per-network instance:"
echo "  sudo systemctl enable --now blockhost-cardano-adapter@preprod"
echo "  sudo systemctl enable --now blockhost-ergo-adapter@testnet"
echo "  sudo systemctl enable --now blockhost-opnet-adapter@testnet"
