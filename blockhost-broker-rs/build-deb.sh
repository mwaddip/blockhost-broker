#!/bin/bash
# Build Debian package for blockhost-broker
#
# Includes the Rust broker daemon and all chain adapter plugins.

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Get version from Cargo.toml
VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
ARCH=$(dpkg --print-architecture)
PKG_NAME="blockhost-broker_${VERSION}_${ARCH}"

echo "Building blockhost-broker v${VERSION} for ${ARCH}..."

# Build release binary
cargo build --release

# ── Package structure ────────────────────────────────────────────────

rm -rf "build/${PKG_NAME}"
mkdir -p "build/${PKG_NAME}/DEBIAN"
mkdir -p "build/${PKG_NAME}/usr/bin"
mkdir -p "build/${PKG_NAME}/lib/systemd/system"
mkdir -p "build/${PKG_NAME}/etc/blockhost-broker"
mkdir -p "build/${PKG_NAME}/var/lib/blockhost-broker"

# Core broker
cp target/release/blockhost-broker "build/${PKG_NAME}/usr/bin/"
cp debian/blockhost-broker.service "build/${PKG_NAME}/lib/systemd/system/"
cp debian/config.toml.example "build/${PKG_NAME}/etc/blockhost-broker/"

# ── Chain adapter plugins ────────────────────────────────────────────

# OPNet adapter
OPNET_ADAPTER="${REPO_ROOT}/adapters/opnet/adapter"
if [ -d "$OPNET_ADAPTER/src" ]; then
    echo "Including OPNet adapter plugin..."
    DEST="build/${PKG_NAME}/opt/blockhost/adapters/opnet/adapter"
    mkdir -p "$DEST/src"

    # Install dependencies if needed
    if [ ! -d "$OPNET_ADAPTER/node_modules" ]; then
        (cd "$OPNET_ADAPTER" && npm ci --ignore-scripts)
    fi

    cp -r "$OPNET_ADAPTER/src/"*.ts "$DEST/src/"
    cp "$OPNET_ADAPTER/package.json" "$DEST/"
    cp "$OPNET_ADAPTER/tsconfig.json" "$DEST/"
    cp -r "$OPNET_ADAPTER/node_modules" "$DEST/"

    # Systemd template service (instance = network name)
    # Usage: systemctl enable blockhost-opnet-adapter@regtest
    cat > "build/${PKG_NAME}/lib/systemd/system/blockhost-opnet-adapter@.service" << 'EOF'
[Unit]
Description=Blockhost OPNet Adapter (%i)
After=network.target blockhost-broker.service
Requires=blockhost-broker.service

[Service]
Type=simple
EnvironmentFile=/etc/blockhost-broker/opnet-adapter-%i.env
ExecStart=/usr/bin/npx --prefix /opt/blockhost/adapters/opnet/adapter tsx src/main.ts
Restart=on-failure
RestartSec=10
User=blockhost-broker
WorkingDirectory=/opt/blockhost/adapters/opnet/adapter

[Install]
WantedBy=multi-user.target
EOF

    # Example env
    cat > "build/${PKG_NAME}/etc/blockhost-broker/opnet-adapter-regtest.env.example" << 'EOF'
# OPNet adapter — regtest
OPNET_RPC_URL=https://regtest.opnet.org
OPNET_BROKER_REQUESTS_PUBKEY=0x...
OPNET_OPERATOR_MNEMONIC=word1 word2 ...
BROKER_ECIES_PRIVATE_KEY=...
BROKER_API_URL=http://127.0.0.1:8080
EOF
fi

# (Future adapters would be added here)

# ── Control files ────────────────────────────────────────────────────

cat > "build/${PKG_NAME}/DEBIAN/control" << EOF
Package: blockhost-broker
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Pre-Depends: debconf (>= 0.5) | debconf-2.0
Depends: wireguard-tools
Recommends: nodejs (>= 18)
Maintainer: Blockhost <contact@blockhost.io>
Description: IPv6 tunnel broker for Blockhost network
 blockhost-broker is a daemon that manages IPv6 prefix allocations
 for Blockhost servers using on-chain authentication via NFT
 contract ownership verification.
 .
 Includes chain adapter plugins:
  - OPNet (Bitcoin L1 smart contracts)
 .
 Features:
  - On-chain authentication via smart contracts (EVM + OPNet)
  - ECIES encryption for secure communication
  - WireGuard peer management
  - SQLite-based IPAM database
  - REST API for allocation management
  - Built-in authoritative DNS server
EOF

cp debian/templates "build/${PKG_NAME}/DEBIAN/"
cp debian/config "build/${PKG_NAME}/DEBIAN/"
cp debian/postinst "build/${PKG_NAME}/DEBIAN/"

# ── Permissions ──────────────────────────────────────────────────────

chmod 755 "build/${PKG_NAME}/usr/bin/blockhost-broker"
chmod 644 "build/${PKG_NAME}/lib/systemd/system/"*.service
chmod 644 "build/${PKG_NAME}/etc/blockhost-broker/"*.example
chmod 750 "build/${PKG_NAME}/var/lib/blockhost-broker"
chmod 755 "build/${PKG_NAME}/DEBIAN/config"
chmod 755 "build/${PKG_NAME}/DEBIAN/postinst"
chmod 644 "build/${PKG_NAME}/DEBIAN/templates"

if [ -d "build/${PKG_NAME}/opt/blockhost" ]; then
    find "build/${PKG_NAME}/opt/blockhost" -type f -exec chmod 644 {} \;
    find "build/${PKG_NAME}/opt/blockhost" -type d -exec chmod 755 {} \;
fi

# ── Build ────────────────────────────────────────────────────────────

dpkg-deb --build "build/${PKG_NAME}"

echo ""
echo "Package built: build/${PKG_NAME}.deb"
echo ""
echo "To install (interactive setup):"
echo "  sudo dpkg -i build/${PKG_NAME}.deb"
echo ""
echo "To reconfigure:"
echo "  sudo dpkg-reconfigure blockhost-broker"
echo ""
echo "To install non-interactively (preseeding):"
echo "  echo 'blockhost-broker blockhost-broker/private-key-action select generate' | sudo debconf-set-selections"
echo "  sudo DEBIAN_FRONTEND=noninteractive dpkg -i build/${PKG_NAME}.deb"
