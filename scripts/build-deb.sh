#!/bin/bash
# Build Debian package for blockhost-broker-client

set -e

VERSION="0.1.0"
PKG_NAME="blockhost-broker-client_${VERSION}_all"

echo "Building blockhost-broker-client v${VERSION}..."

# Create package directory structure
rm -rf "build/${PKG_NAME}"
mkdir -p "build/${PKG_NAME}/DEBIAN"
mkdir -p "build/${PKG_NAME}/opt/blockhost-client"
mkdir -p "build/${PKG_NAME}/usr/bin"
mkdir -p "build/${PKG_NAME}/etc/blockhost"

# Copy files
cp broker-client.py "build/${PKG_NAME}/opt/blockhost-client/"
cp requirements.txt "build/${PKG_NAME}/opt/blockhost-client/"
cp debian/broker-client-wrapper "build/${PKG_NAME}/usr/bin/broker-client"
cp debian/control "build/${PKG_NAME}/DEBIAN/"
cp debian/postinst "build/${PKG_NAME}/DEBIAN/"

# Set permissions
chmod 755 "build/${PKG_NAME}/opt/blockhost-client/broker-client.py"
chmod 644 "build/${PKG_NAME}/opt/blockhost-client/requirements.txt"
chmod 755 "build/${PKG_NAME}/usr/bin/broker-client"
chmod 755 "build/${PKG_NAME}/DEBIAN/postinst"
chmod 750 "build/${PKG_NAME}/etc/blockhost"

# Build package
dpkg-deb --build "build/${PKG_NAME}"

echo ""
echo "Package built: build/${PKG_NAME}.deb"
echo ""
echo "To install:"
echo "  sudo dpkg -i build/${PKG_NAME}.deb"
