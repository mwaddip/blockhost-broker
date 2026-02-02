#!/bin/bash
# Build Debian package for blockhost-broker (Rust)

set -e

# Get version from Cargo.toml
VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
ARCH=$(dpkg --print-architecture)
PKG_NAME="blockhost-broker_${VERSION}_${ARCH}"

echo "Building blockhost-broker v${VERSION} for ${ARCH}..."

# Build release binary
cargo build --release

# Create package directory structure
rm -rf "build/${PKG_NAME}"
mkdir -p "build/${PKG_NAME}/DEBIAN"
mkdir -p "build/${PKG_NAME}/usr/bin"
mkdir -p "build/${PKG_NAME}/lib/systemd/system"
mkdir -p "build/${PKG_NAME}/etc/blockhost-broker"
mkdir -p "build/${PKG_NAME}/var/lib/blockhost-broker"

# Copy binary and service files
cp target/release/blockhost-broker "build/${PKG_NAME}/usr/bin/"
cp debian/blockhost-broker.service "build/${PKG_NAME}/lib/systemd/system/"
cp debian/config.toml.example "build/${PKG_NAME}/etc/blockhost-broker/"

# Create control file with debconf dependency
cat > "build/${PKG_NAME}/DEBIAN/control" << EOF
Package: blockhost-broker
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Pre-Depends: debconf (>= 0.5) | debconf-2.0
Depends: wireguard-tools
Maintainer: Blockhost <contact@blockhost.io>
Description: IPv6 tunnel broker for Blockhost network
 blockhost-broker is a daemon that manages IPv6 prefix allocations
 for Blockhost servers using on-chain authentication via NFT
 contract ownership verification.
 .
 Features:
  - On-chain authentication via Ethereum smart contracts
  - ECIES encryption for secure communication
  - WireGuard peer management
  - SQLite-based IPAM database
  - Interactive debconf setup wizard
EOF

# Copy debconf files
cp debian/templates "build/${PKG_NAME}/DEBIAN/"
cp debian/config "build/${PKG_NAME}/DEBIAN/"
cp debian/postinst "build/${PKG_NAME}/DEBIAN/"

# Set permissions
chmod 755 "build/${PKG_NAME}/usr/bin/blockhost-broker"
chmod 644 "build/${PKG_NAME}/lib/systemd/system/blockhost-broker.service"
chmod 644 "build/${PKG_NAME}/etc/blockhost-broker/config.toml.example"
chmod 750 "build/${PKG_NAME}/var/lib/blockhost-broker"
chmod 755 "build/${PKG_NAME}/DEBIAN/config"
chmod 755 "build/${PKG_NAME}/DEBIAN/postinst"
chmod 644 "build/${PKG_NAME}/DEBIAN/templates"

# Build package
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
