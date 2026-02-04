#!/bin/bash
# Build Debian package for blockhost-broker-manager

set -e

VERSION="0.1.0"
PKG_NAME="blockhost-broker-manager_${VERSION}_all"

echo "Building blockhost-broker-manager v${VERSION}..."

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Create package directory structure
rm -rf "build/${PKG_NAME}"
mkdir -p "build/${PKG_NAME}/DEBIAN"
mkdir -p "build/${PKG_NAME}/opt/blockhost-broker-manager/manager/templates"
mkdir -p "build/${PKG_NAME}/opt/blockhost-broker-manager/static/css"
mkdir -p "build/${PKG_NAME}/etc/blockhost-broker-manager"
mkdir -p "build/${PKG_NAME}/lib/systemd/system"

# Copy application files
cp -r manager/*.py "build/${PKG_NAME}/opt/blockhost-broker-manager/manager/"
cp -r manager/templates/* "build/${PKG_NAME}/opt/blockhost-broker-manager/manager/templates/"
cp -r static/css/* "build/${PKG_NAME}/opt/blockhost-broker-manager/static/css/"
cp requirements.txt "build/${PKG_NAME}/opt/blockhost-broker-manager/"

# Copy Debian files
cp debian/control "build/${PKG_NAME}/DEBIAN/"
cp debian/postinst "build/${PKG_NAME}/DEBIAN/"
cp debian/blockhost-broker-manager.service "build/${PKG_NAME}/lib/systemd/system/"

# Create default auth.json with the authorized wallet
cat > "build/${PKG_NAME}/etc/blockhost-broker-manager/auth.json" << 'EOF'
{
  "authorized_wallets": [
    "0xe35B5D114eFEA216E6BB5Ff15C261d25dB9E2cb9"
  ]
}
EOF

# Set permissions
chmod 755 "build/${PKG_NAME}/DEBIAN/postinst"
chmod 644 "build/${PKG_NAME}/lib/systemd/system/blockhost-broker-manager.service"
chmod 640 "build/${PKG_NAME}/etc/blockhost-broker-manager/auth.json"
find "build/${PKG_NAME}/opt/blockhost-broker-manager" -type f -exec chmod 644 {} \;
find "build/${PKG_NAME}/opt/blockhost-broker-manager" -type d -exec chmod 755 {} \;

# Build package
dpkg-deb --build "build/${PKG_NAME}"

echo ""
echo "Package built: build/${PKG_NAME}.deb"
echo ""
echo "To install:"
echo "  sudo dpkg -i build/${PKG_NAME}.deb"
