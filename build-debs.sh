#!/bin/bash
# Build .deb packages for blockhost-broker and blockhost-broker-client
# Usage: ./build-debs.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build-deb"
VERSION="0.1.0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo "Building blockhost-broker packages v${VERSION}"
echo "============================================="

# Clean previous builds
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Check dependencies
for cmd in dpkg-deb fakeroot; do
    if ! command -v $cmd &> /dev/null; then
        echo -e "${RED}Error: $cmd is required. Install with: apt install dpkg fakeroot${NC}"
        exit 1
    fi
done

# =============================================================================
# Build blockhost-broker (server)
# =============================================================================
echo ""
echo "Building blockhost-broker (server)..."

SERVER_PKG="$BUILD_DIR/blockhost-broker_${VERSION}_all"
mkdir -p "$SERVER_PKG/DEBIAN"
mkdir -p "$SERVER_PKG/usr/bin"
mkdir -p "$SERVER_PKG/usr/lib/python3/dist-packages"
mkdir -p "$SERVER_PKG/usr/share/blockhost-broker"
mkdir -p "$SERVER_PKG/etc/blockhost-broker"
mkdir -p "$SERVER_PKG/var/lib/blockhost-broker"
mkdir -p "$SERVER_PKG/lib/systemd/system"

# Control file
cat > "$SERVER_PKG/DEBIAN/control" << EOF
Package: blockhost-broker
Version: ${VERSION}
Section: net
Priority: optional
Architecture: all
Depends: python3 (>= 3.10), python3-web3, python3-pydantic, python3-fastapi, python3-uvicorn, wireguard-tools
Maintainer: Blockhost <info@blockhost.io>
Description: IPv6 tunnel broker daemon with on-chain authentication
 Broker daemon that allocates IPv6 prefixes to Blockhost servers via
 WireGuard tunnels. Uses blockchain-based authentication through NFT
 contract ownership verification.
EOF

# postinst script
cat > "$SERVER_PKG/DEBIAN/postinst" << 'EOF'
#!/bin/sh
set -e

if [ "$1" = "configure" ]; then
    # Create config from example if not exists
    if [ ! -f /etc/blockhost-broker/config.toml ]; then
        cp /usr/share/blockhost-broker/config.example.toml \
           /etc/blockhost-broker/config.toml
        chmod 600 /etc/blockhost-broker/config.toml
        echo "Installed example config to /etc/blockhost-broker/config.toml"
        echo "Please edit this file before starting the service."
    fi

    # Generate WireGuard key if not exists
    if [ ! -f /etc/blockhost-broker/wg-private.key ]; then
        wg genkey > /etc/blockhost-broker/wg-private.key
        chmod 600 /etc/blockhost-broker/wg-private.key
        wg pubkey < /etc/blockhost-broker/wg-private.key \
           > /etc/blockhost-broker/wg-public.key
        echo "Generated WireGuard keypair in /etc/blockhost-broker/"
    fi

    # Reload systemd
    systemctl daemon-reload || true
fi
EOF
chmod 755 "$SERVER_PKG/DEBIAN/postinst"

# Copy Python package
cp -r "$SCRIPT_DIR/src/blockhost_broker" "$SERVER_PKG/usr/lib/python3/dist-packages/"

# Create entry point script
cat > "$SERVER_PKG/usr/bin/blockhost-broker" << 'EOF'
#!/usr/bin/python3
import sys
from blockhost_broker.main import main
sys.exit(main())
EOF
chmod 755 "$SERVER_PKG/usr/bin/blockhost-broker"

# Copy example config
cp "$SCRIPT_DIR/config.example.toml" "$SERVER_PKG/usr/share/blockhost-broker/"

# Systemd service
cat > "$SERVER_PKG/lib/systemd/system/blockhost-broker.service" << EOF
[Unit]
Description=Blockhost IPv6 Tunnel Broker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/blockhost-broker -c /etc/blockhost-broker/config.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Build server package
fakeroot dpkg-deb --build "$SERVER_PKG"
echo -e "${GREEN}Built: ${SERVER_PKG}.deb${NC}"

# =============================================================================
# Build blockhost-broker-client
# =============================================================================
echo ""
echo "Building blockhost-broker-client..."

CLIENT_PKG="$BUILD_DIR/blockhost-broker-client_${VERSION}_all"
mkdir -p "$CLIENT_PKG/DEBIAN"
mkdir -p "$CLIENT_PKG/usr/bin"
mkdir -p "$CLIENT_PKG/etc/blockhost"

# Control file
cat > "$CLIENT_PKG/DEBIAN/control" << EOF
Package: blockhost-broker-client
Version: ${VERSION}
Section: net
Priority: optional
Architecture: all
Depends: python3 (>= 3.10), python3-web3, python3-eciespy, wireguard-tools
Maintainer: Blockhost <info@blockhost.io>
Description: Blockhost broker client for IPv6 prefix allocation
 Client script for Blockhost servers (Proxmox) to request IPv6 prefix
 allocations from brokers via on-chain authentication.
EOF

# postinst
cat > "$CLIENT_PKG/DEBIAN/postinst" << 'EOF'
#!/bin/sh
set -e

if [ "$1" = "configure" ]; then
    mkdir -p /etc/blockhost
    echo "blockhost-broker-client installed."
    echo ""
    echo "Usage:"
    echo "  1. Request allocation:"
    echo "     blockhost-broker-client --registry-contract 0x... request \\"
    echo "         --nft-contract 0x... --wallet-key /etc/blockhost/deployer.key"
    echo ""
    echo "  2. Install persistent WireGuard config:"
    echo "     blockhost-broker-client install"
fi
EOF
chmod 755 "$CLIENT_PKG/DEBIAN/postinst"

# Copy client script
cp "$SCRIPT_DIR/scripts/broker-client.py" "$CLIENT_PKG/usr/bin/blockhost-broker-client"
chmod 755 "$CLIENT_PKG/usr/bin/blockhost-broker-client"

# Build client package
fakeroot dpkg-deb --build "$CLIENT_PKG"
echo -e "${GREEN}Built: ${CLIENT_PKG}.deb${NC}"

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "============================================="
echo -e "${GREEN}Build complete!${NC}"
echo ""
echo "Packages:"
ls -lh "$BUILD_DIR"/*.deb
echo ""
echo "Install with:"
echo "  dpkg -i ${BUILD_DIR}/blockhost-broker_${VERSION}_all.deb"
echo "  dpkg -i ${BUILD_DIR}/blockhost-broker-client_${VERSION}_all.deb"
echo ""
echo "Fix dependencies with:"
echo "  apt-get install -f"
