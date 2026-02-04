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
    wg_pubkey: str
    nft_contract: str
    allocated_at: str
    token_id: Optional[str] = None


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

    def get_leases(self) -> list[Lease]:
        """Get all current leases from the broker database."""
        if not self.db_path.exists():
            return []

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                SELECT id, prefix, prefix_index, wg_pubkey, token_id, nft_contract, allocated_at
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
                        wg_pubkey=row[3],
                        token_id=row[4],
                        nft_contract=row[5],
                        allocated_at=row[6],
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
                "SELECT prefix, wg_pubkey, nft_contract FROM allocations WHERE id = ?",
                (lease_id,),
            )
            row = cursor.fetchone()

            if not row:
                return {"success": False, "message": "Lease not found"}

            prefix, wg_pubkey, nft_contract = row

            # 1. Release on-chain
            try:
                tx_hash = self._release_onchain(nft_contract)
            except Exception as e:
                return {"success": False, "message": f"On-chain release failed: {e}"}

            # 2. Remove WireGuard peer
            try:
                self._remove_wg_peer(wg_pubkey)
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
