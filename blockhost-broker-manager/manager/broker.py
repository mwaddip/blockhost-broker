"""Broker interaction - read leases and release allocations.

Release is local-only in V3: remove WireGuard peer and delete DB row.
The broker detects lost peers via handshake timeout; a new on-chain request
on the same NFT will overwrite the old one automatically.
"""

import json
import logging
import sqlite3
import subprocess
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from eth_account import Account
from eth_account.signers.local import LocalAccount
from web3 import Web3

logger = logging.getLogger(__name__)


@dataclass
class Lease:
    """A broker lease/allocation."""

    id: int
    prefix: str
    prefix_index: int
    pubkey: str
    nft_contract: str
    allocated_at: str
    endpoint: Optional[str] = None
    is_test: bool = False
    expires_at: Optional[str] = None
    source: str = "evm"


@dataclass
class WalletInfo:
    """Broker operator wallet information."""

    address: str
    balance_wei: int
    balance_eth: float
    chain_id: int
    network_name: str
    low_balance: bool  # True if below threshold


@dataclass
class BtcWalletInfo:
    """OPNet operator wallet information."""

    address: str
    balance_sat: int
    balance_btc: float
    network: str
    low_balance: bool


@dataclass
class CardanoWalletInfo:
    """Cardano operator wallet information."""

    address: str
    balance_lovelace: int
    balance_ada: float
    network: str
    low_balance: bool


@dataclass
class ErgoWalletInfo:
    """Ergo operator wallet information."""

    address: str
    balance_erg: float
    explorer_url: str


# Chain ID to network name mapping
CHAIN_NAMES = {
    1: "Ethereum Mainnet",
    11155111: "Sepolia Testnet",
    5: "Goerli Testnet",
    137: "Polygon",
    80001: "Mumbai Testnet",
    42161: "Arbitrum One",
    10: "Optimism",
}

LOW_BALANCE_THRESHOLD_WEI = 50000000000000000  # 0.05 ETH
LOW_BTC_BALANCE_SAT = 10000  # 0.0001 BTC
LOW_ADA_BALANCE_LOVELACE = 10_000_000  # 10 ADA


class BrokerManager:
    """Manages broker leases and releases."""

    def __init__(
        self,
        db_path: Path,
        operator_key_path: Path,
        rpc_url: str,
        chain_id: int,
        wg_interface: str = "wg-broker",
        opnet_rpc_url: Optional[str] = None,
        opnet_operator_address: Optional[str] = None,
        opnet_network: str = "OPNet Testnet",
        cardano_operator_address: Optional[str] = None,
        cardano_blockfrost_key: Optional[str] = None,
        cardano_network: str = "Cardano Preprod",
        ergo_operator_address: Optional[str] = None,
        ergo_explorer_url: str = "https://api-testnet.ergoplatform.com",
    ):
        self.db_path = db_path
        self.operator_key_path = operator_key_path
        self.rpc_url = rpc_url
        self.chain_id = chain_id
        self.wg_interface = wg_interface
        self.opnet_rpc_url = opnet_rpc_url
        self.opnet_operator_address = opnet_operator_address
        self.opnet_network = opnet_network
        self.cardano_operator_address = cardano_operator_address
        self.cardano_blockfrost_key = cardano_blockfrost_key
        self.cardano_network = cardano_network
        self.ergo_operator_address = ergo_operator_address
        self.ergo_explorer_url = ergo_explorer_url

        self.w3 = Web3(Web3.HTTPProvider(rpc_url))

    def _get_operator_account(self) -> LocalAccount:
        """Load operator wallet from key file."""
        key = self.operator_key_path.read_text().strip()
        return Account.from_key(key)

    def get_wallet_info(self) -> WalletInfo:
        """Get operator wallet address and balance."""
        account = self._get_operator_account()
        balance_wei = self.w3.eth.get_balance(account.address)
        balance_eth = balance_wei / 10**18
        network_name = CHAIN_NAMES.get(self.chain_id, f"Chain {self.chain_id}")

        return WalletInfo(
            address=account.address,
            balance_wei=balance_wei,
            balance_eth=balance_eth,
            chain_id=self.chain_id,
            network_name=network_name,
            low_balance=balance_wei < LOW_BALANCE_THRESHOLD_WEI,
        )

    def get_btc_wallet_info(self) -> Optional[BtcWalletInfo]:
        """Get OPNet operator BTC wallet address and balance."""
        if not self.opnet_rpc_url or not self.opnet_operator_address:
            return None

        try:
            rpc_url = self.opnet_rpc_url.rstrip("/") + "/api/v1/json-rpc"
            payload = json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "btc_getBalance",
                "params": [self.opnet_operator_address],
            }).encode()
            req = urllib.request.Request(
                rpc_url,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())

            raw = data.get("result", "0")
            balance_sat = int(raw, 16) if isinstance(raw, str) and raw.startswith("0x") else int(raw)
            return BtcWalletInfo(
                address=self.opnet_operator_address,
                balance_sat=balance_sat,
                balance_btc=balance_sat / 10**8,
                network=self.opnet_network,
                low_balance=balance_sat < LOW_BTC_BALANCE_SAT,
            )
        except Exception as e:
            logger.warning("Failed to fetch OPNet balance: %s", e)
            return None

    def get_cardano_wallet_info(self) -> Optional[CardanoWalletInfo]:
        """Get Cardano operator wallet address and ADA balance."""
        if not self.cardano_operator_address or not self.cardano_blockfrost_key:
            return None

        try:
            key = self.cardano_blockfrost_key
            if "preview" in key:
                base = "https://cardano-preview.blockfrost.io/api/v0"
            elif "preprod" in key:
                base = "https://cardano-preprod.blockfrost.io/api/v0"
            else:
                base = "https://cardano-mainnet.blockfrost.io/api/v0"

            url = f"{base}/addresses/{self.cardano_operator_address}"
            req = urllib.request.Request(url, headers={"project_id": key})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())

            amounts = data.get("amount", [])
            lovelace = 0
            for a in amounts:
                if a["unit"] == "lovelace":
                    lovelace = int(a["quantity"])
                    break

            return CardanoWalletInfo(
                address=self.cardano_operator_address,
                balance_lovelace=lovelace,
                balance_ada=lovelace / 10**6,
                network=self.cardano_network,
                low_balance=lovelace < LOW_ADA_BALANCE_LOVELACE,
            )
        except Exception as e:
            logger.warning("Failed to fetch Cardano balance: %s", e)
            return None

    def get_ergo_wallet_info(self) -> Optional[ErgoWalletInfo]:
        """Get Ergo operator wallet address and ERG balance."""
        if not self.ergo_operator_address:
            return None

        try:
            url = f"{self.ergo_explorer_url}/api/v1/addresses/{self.ergo_operator_address}/balance/total"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())

            nano_erg = int(data.get("confirmed", {}).get("nanoErgs", 0))
            return ErgoWalletInfo(
                address=self.ergo_operator_address,
                balance_erg=nano_erg / 10**9,
                explorer_url=self.ergo_explorer_url,
            )
        except Exception as e:
            logger.warning("Failed to fetch Ergo balance: %s", e)
            return ErgoWalletInfo(
                address=self.ergo_operator_address,
                balance_erg=0.0,
                explorer_url=self.ergo_explorer_url,
            )

    def get_leases(self) -> list[Lease]:
        """Get all current leases from the broker database."""
        if not self.db_path.exists():
            return []

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                SELECT id, prefix, prefix_index, pubkey, nft_contract, allocated_at, endpoint,
                       is_test, expires_at, source
                FROM allocations
                ORDER BY id DESC
                """
            )
            rows = cursor.fetchall()

            leases = []
            for row in rows:
                leases.append(
                    Lease(
                        id=row[0],
                        prefix=row[1],
                        prefix_index=row[2],
                        pubkey=row[3],
                        nft_contract=row[4],
                        allocated_at=row[5],
                        endpoint=row[6],
                        is_test=bool(row[7]) if row[7] is not None else False,
                        expires_at=row[8],
                        source=row[9] if row[9] else "evm",
                    )
                )
            return leases
        finally:
            conn.close()

    def release_lease(self, lease_id: int) -> dict:
        """Release a lease by ID (local-only: WireGuard peer removal + DB delete).

        Returns dict with success status and message.
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute(
                "SELECT prefix, pubkey, nft_contract FROM allocations WHERE id = ?",
                (lease_id,),
            )
            row = cursor.fetchone()

            if not row:
                return {"success": False, "message": "Lease not found"}

            prefix, pubkey, nft_contract = row

            # 1. Remove WireGuard peer
            try:
                self._remove_wg_peer(pubkey)
            except Exception as e:
                logger.warning("Failed to remove WireGuard peer %s: %s", pubkey[:20], e)

            # 2. Delete from database
            cursor.execute("DELETE FROM allocations WHERE id = ?", (lease_id,))
            conn.commit()

            logger.info("Released lease %d (prefix=%s, nft=%s)", lease_id, prefix, nft_contract)
            return {
                "success": True,
                "message": f"Lease {lease_id} released ({prefix})",
            }

        finally:
            conn.close()

    def _remove_wg_peer(self, pubkey: str) -> None:
        """Remove a WireGuard peer."""
        subprocess.run(
            ["wg", "set", self.wg_interface, "peer", pubkey, "remove"],
            check=True,
            capture_output=True,
        )
