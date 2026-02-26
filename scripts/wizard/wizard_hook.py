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


def fetch_registry(wallet_address: str, testing: bool = False) -> Optional[str]:
    """Return the registry contract address for the given wallet's chain.

    Derives the chain from wallet_address format:
    - EVM:   0x + 40 hex chars              → registry.json / registry-testnet.json
    - OPNet: bc1p (mainnet) / opt1p (testnet) + 58 alphanum → registry-opnet-testnet.json

    Returns the registry_contract string, or None on any error.
    """
    if _OPNET_PATTERN.match(wallet_address):
        filename = "registry-opnet-testnet.json"
    elif _EVM_PATTERN.match(wallet_address):
        filename = "registry-testnet.json" if testing else "registry.json"
    else:
        return None

    url = f"{_REPO_RAW}/{filename}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        return data.get("registry_contract") or None
    except Exception:
        return None
