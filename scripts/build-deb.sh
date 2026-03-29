#!/bin/bash
# Build Debian package for blockhost-broker-client
#
# Includes the Python client and all chain client plugins.

set -e

VERSION="0.5.0"
PKG_NAME="blockhost-broker-client_${VERSION}_all"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building blockhost-broker-client v${VERSION}..."

# ── Package structure ────────────────────────────────────────────────

rm -rf "build/${PKG_NAME}"
mkdir -p "build/${PKG_NAME}/DEBIAN"
mkdir -p "build/${PKG_NAME}/opt/blockhost-client"
mkdir -p "build/${PKG_NAME}/usr/bin"
mkdir -p "build/${PKG_NAME}/etc/blockhost"
mkdir -p "build/${PKG_NAME}/usr/share/blockhost"
mkdir -p "build/${PKG_NAME}/usr/lib/python3/dist-packages/blockhost/broker"

# Core client
cp broker-client.py "build/${PKG_NAME}/opt/blockhost-client/"
cp requirements.txt "build/${PKG_NAME}/opt/blockhost-client/"
cp debian/broker-client-wrapper "build/${PKG_NAME}/usr/bin/broker-client"

# Chain config (conffile — dpkg won't overwrite user edits on upgrade)
cp broker-chains.json "build/${PKG_NAME}/etc/blockhost/"

# ── Chain client plugins ─────────────────────────────────────────────

# OPNet client (esbuild bundle — single file, no node_modules needed)
OPNET_CLIENT="${REPO_ROOT}/adapters/opnet/client"
if [ -d "$OPNET_CLIENT/src" ]; then
    echo "Building OPNet client plugin..."
    DEST="build/${PKG_NAME}/opt/blockhost/adapters/opnet/client"
    mkdir -p "$DEST/dist"

    # Install dependencies if needed
    if [ ! -d "$OPNET_CLIENT/node_modules" ]; then
        (cd "$OPNET_CLIENT" && npm ci --ignore-scripts)
    fi

    # Apply patches (patch-package; skipped by --ignore-scripts above)
    (cd "$OPNET_CLIENT" && npx patch-package)

    # Bundle into a single JS file
    (cd "$OPNET_CLIENT" && npm run build)
    cp "$OPNET_CLIENT/dist/main.js" "$DEST/dist/"
fi

# Cardano client (esbuild bundle — single file, no node_modules needed)
CARDANO_CLIENT="${REPO_ROOT}/adapters/cardano/client"
if [ -d "$CARDANO_CLIENT/src" ]; then
    echo "Building Cardano client plugin..."
    DEST="build/${PKG_NAME}/opt/blockhost/adapters/cardano/client"
    mkdir -p "$DEST/dist"

    if [ ! -d "$CARDANO_CLIENT/node_modules" ]; then
        (cd "$CARDANO_CLIENT" && npm ci --ignore-scripts)
    fi

    (cd "$CARDANO_CLIENT" && npx patch-package)
    (cd "$CARDANO_CLIENT" && npm run build)
    cp "$CARDANO_CLIENT/dist/main.js" "$DEST/dist/"
fi

# Cardano parameterized scripts (needed by client at runtime)
CARDANO_SCRIPTS="${REPO_ROOT}/adapters/cardano/contracts/parameterized-scripts.json"
if [ -f "$CARDANO_SCRIPTS" ]; then
    mkdir -p "build/${PKG_NAME}/opt/blockhost/adapters/cardano/contracts"
    cp "$CARDANO_SCRIPTS" "build/${PKG_NAME}/opt/blockhost/adapters/cardano/contracts/"
fi

# Ergo client (esbuild bundle — single file, no node_modules needed)
ERGO_CLIENT="${REPO_ROOT}/adapters/ergo/client"
if [ -d "$ERGO_CLIENT/src" ]; then
    echo "Building Ergo client plugin..."
    DEST="build/${PKG_NAME}/opt/blockhost/adapters/ergo/client"
    mkdir -p "$DEST/dist"

    if [ ! -d "$ERGO_CLIENT/node_modules" ]; then
        (cd "$ERGO_CLIENT" && npm ci --ignore-scripts)
    fi

    (cd "$ERGO_CLIENT" && npm run build)
    cp "$ERGO_CLIENT/dist/main.js" "$DEST/dist/"
fi

# ── Wizard integration hook ──────────────────────────────────────────

# Manifest: discovered by the installer wizard at startup
cp wizard/broker.json "build/${PKG_NAME}/usr/share/blockhost/"

# Python module: blockhost.broker.wizard_hook (namespace package — no __init__.py)
cp wizard/wizard_hook.py "build/${PKG_NAME}/usr/lib/python3/dist-packages/blockhost/broker/"

# ── Control files ────────────────────────────────────────────────────

cat > "build/${PKG_NAME}/DEBIAN/control" << EOF
Package: blockhost-broker-client
Version: ${VERSION}
Section: net
Priority: optional
Architecture: all
Depends: python3 (>= 3.8), python3-venv, wireguard-tools
Recommends: nodejs (>= 18)
Maintainer: Blockhost <contact@blockhost.io>
Description: Blockhost broker client for Proxmox servers
 Client for requesting IPv6 prefix allocations from blockhost-broker
 via on-chain authentication.
 .
 Includes chain client plugins:
  - EVM (builtin, Python)
  - OPNet (Bitcoin L1, TypeScript subprocess)
  - Cardano (TypeScript subprocess)
  - Ergo (TypeScript subprocess)
 .
 This package is installed on Proxmox servers that need IPv6
 connectivity through the Blockhost network.
EOF

cp debian/postinst "build/${PKG_NAME}/DEBIAN/"

# ── Permissions ──────────────────────────────────────────────────────

chmod 755 "build/${PKG_NAME}/opt/blockhost-client/broker-client.py"
chmod 644 "build/${PKG_NAME}/opt/blockhost-client/requirements.txt"
chmod 755 "build/${PKG_NAME}/usr/bin/broker-client"
chmod 755 "build/${PKG_NAME}/DEBIAN/postinst"
chmod 750 "build/${PKG_NAME}/etc/blockhost"
chmod 644 "build/${PKG_NAME}/etc/blockhost/broker-chains.json"

if [ -d "build/${PKG_NAME}/opt/blockhost/adapters" ]; then
    find "build/${PKG_NAME}/opt/blockhost/adapters" -type f -exec chmod 644 {} \;
    find "build/${PKG_NAME}/opt/blockhost/adapters" -type d -exec chmod 755 {} \;
fi

chmod 644 "build/${PKG_NAME}/usr/share/blockhost/broker.json"
chmod 644 "build/${PKG_NAME}/usr/lib/python3/dist-packages/blockhost/broker/wizard_hook.py"
find "build/${PKG_NAME}/usr/lib/python3/dist-packages/blockhost" -type d -exec chmod 755 {} \;

# ── Conffiles (dpkg won't overwrite user edits on upgrade) ───────

cat > "build/${PKG_NAME}/DEBIAN/conffiles" << EOF
/etc/blockhost/broker-chains.json
EOF

# ── Build ────────────────────────────────────────────────────────────

# Clean up lockfile changes from npm ci (prevents dirty submodule on git pull)
git -C "$REPO_ROOT" checkout -- '*/package-lock.json' 2>/dev/null || true

dpkg-deb --build "build/${PKG_NAME}"

echo ""
echo "Package built: build/${PKG_NAME}.deb"
echo ""
echo "To install:"
echo "  sudo dpkg -i build/${PKG_NAME}.deb"
