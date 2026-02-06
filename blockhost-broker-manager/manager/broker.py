"""Broker interaction - read leases and release allocations."""

import sqlite3
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from eth_account import Account
from eth_account.signers.local import LocalAccount
from web3 import Web3


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


@dataclass
class WalletInfo:
    """Broker operator wallet information."""

    address: str
    balance_wei: int
    balance_eth: float
    chain_id: int
    network_name: str
    low_balance: bool  # True if below threshold


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


BROKER_REQUESTS_ABI = [
    {
        "inputs": [{"internalType": "address", "name": "nftContract", "type": "address"}],
        "name": "releaseAllocation",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "address", "name": "", "type": "address"}],
        "name": "nftContractToRequestId",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
]


class BrokerManager:
    """Manages broker leases and releases."""

    def __init__(
        self,
        db_path: Path,
        operator_key_path: Path,
        requests_contract: str,
        rpc_url: str,
        chain_id: int,
        wg_interface: str = "wg-broker",
    ):
        self.db_path = db_path
        self.operator_key_path = operator_key_path
        self.requests_contract = requests_contract
        self.rpc_url = rpc_url
        self.chain_id = chain_id
        self.wg_interface = wg_interface

        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(requests_contract),
            abi=BROKER_REQUESTS_ABI,
        )

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

    def get_leases(self) -> list[Lease]:
        """Get all current leases from the broker database."""
        if not self.db_path.exists():
            return []

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                SELECT id, prefix, prefix_index, pubkey, nft_contract, allocated_at, endpoint
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
                    )
                )
            return leases
        finally:
            conn.close()

    def release_lease(self, lease_id: int) -> dict:
        """
        Release a lease by ID.
        Returns dict with success status and message.
        """
        # Get the lease details
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

            # 1. Release on-chain
            try:
                tx_hash = self._release_onchain(nft_contract)
            except Exception as e:
                return {"success": False, "message": f"On-chain release failed: {e}"}

            # 2. Remove WireGuard peer
            try:
                self._remove_wg_peer(pubkey)
            except Exception as e:
                # Log but continue - on-chain release succeeded
                pass

            # 3. Delete from database
            cursor.execute("DELETE FROM allocations WHERE id = ?", (lease_id,))
            conn.commit()

            return {
                "success": True,
                "message": f"Lease released. TX: {tx_hash}",
                "tx_hash": tx_hash,
            }

        finally:
            conn.close()

    def _release_onchain(self, nft_contract: str) -> str:
        """Release allocation on-chain. Returns tx hash."""
        account = self._get_operator_account()

        # Check if there's actually an allocation
        request_id = self.contract.functions.nftContractToRequestId(
            Web3.to_checksum_address(nft_contract)
        ).call()

        if request_id == 0:
            raise ValueError("No on-chain allocation found")

        # Estimate gas
        gas_estimate = self.contract.functions.releaseAllocation(
            Web3.to_checksum_address(nft_contract)
        ).estimate_gas({"from": account.address})

        tx = self.contract.functions.releaseAllocation(
            Web3.to_checksum_address(nft_contract)
        ).build_transaction(
            {
                "from": account.address,
                "nonce": self.w3.eth.get_transaction_count(account.address),
                "gas": gas_estimate + 50000,
                "maxFeePerGas": self.w3.eth.gas_price * 2,
                "maxPriorityFeePerGas": self.w3.eth.gas_price,
                "chainId": self.chain_id,
            }
        )

        signed = account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        if receipt["status"] != 1:
            raise RuntimeError(f"Transaction failed: {tx_hash.hex()}")

        return tx_hash.hex()

    def _remove_wg_peer(self, pubkey: str) -> None:
        """Remove a WireGuard peer."""
        subprocess.run(
            ["wg", "set", self.wg_interface, "peer", pubkey, "remove"],
            check=True,
            capture_output=True,
        )
