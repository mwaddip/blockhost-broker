"""
Blockhost broker wizard hook.

Provides fetch_registry() for the installer wizard's connectivity options page.
Importable as: blockhost.broker.wizard_hook
"""

import json
import re
import urllib.request
from typing import Optional

_REPO_RAW = "https://raw.githubusercontent.com/mwaddip/blockhost-broker/main"

_EVM_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")
_OPNET_PATTERN = re.compile(r"^(bc1p|opt1p)[a-z0-9]{58}$")
_CARDANO_PATTERN = re.compile(r"^addr(_test)?1[a-z0-9]{50,120}$")
_ERGO_PATTERN = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{40,60}$")


def fetch_registry(wallet_address: str, testing: bool = False) -> Optional[str]:
    """Return the registry contract address for the given wallet's chain.

    Derives the chain from wallet_address format:
    - EVM:     0x + 40 hex chars                → registry.json / registry-testnet.json
    - OPNet:   bc1p (mainnet) / opt1p (testnet)  → registry-opnet-testnet.json
    - Cardano: addr1... / addr_test1...          → registry-cardano-preprod.json
    - Ergo:    Base58 (40-60 chars)              → registry-ergo-testnet.json

    Returns the registry_contract string (or registry_nft_id for Ergo),
    or None on any error.
    """
    registry_key = "registry_contract"

    if _CARDANO_PATTERN.match(wallet_address):
        filename = "registry-cardano-preprod.json"
    elif _OPNET_PATTERN.match(wallet_address):
        filename = "registry-opnet-testnet.json"
    elif _EVM_PATTERN.match(wallet_address):
        filename = "registry-testnet.json" if testing else "registry.json"
    elif _ERGO_PATTERN.match(wallet_address):
        filename = "registry-ergo-testnet.json"
        registry_key = "registry_nft_id"
    else:
        return None

    url = f"{_REPO_RAW}/{filename}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        return data.get(registry_key) or None
    except Exception:
        return None
