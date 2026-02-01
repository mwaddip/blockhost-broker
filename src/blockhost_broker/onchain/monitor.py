"""On-chain event monitor for broker requests.

Polls the BrokerRequests contract for new allocation requests and processes them.
"""

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from web3 import Web3
from web3.exceptions import ContractLogicError
from eth_account import Account
from eth_account.signers.local import LocalAccount

from .encryption import ECIESEncryption, ResponsePayload
from .verifier import NFTVerifier

if TYPE_CHECKING:
    from ..config import OnchainConfig, BrokerConfig, WireGuardConfig
    from ..ipam import IPAM
    from ..wireguard import WireGuardManager

logger = logging.getLogger(__name__)

# ABI for BrokerRequests contract (minimal subset for monitoring)
BROKER_REQUESTS_ABI = [
    {
        "inputs": [],
        "name": "getRequestCount",
        "outputs": [{"internalType": "uint256", "name": "count", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "getPendingRequests",
        "outputs": [
            {"internalType": "uint256[]", "name": "pendingIds", "type": "uint256[]"},
            {
                "components": [
                    {"internalType": "uint256", "name": "id", "type": "uint256"},
                    {"internalType": "address", "name": "requester", "type": "address"},
                    {"internalType": "address", "name": "nftContract", "type": "address"},
                    {"internalType": "bytes", "name": "encryptedPayload", "type": "bytes"},
                    {"internalType": "uint8", "name": "status", "type": "uint8"},
                    {"internalType": "bytes", "name": "responsePayload", "type": "bytes"},
                    {"internalType": "string", "name": "rejectionReason", "type": "string"},
                    {"internalType": "uint256", "name": "submittedAt", "type": "uint256"},
                    {"internalType": "uint256", "name": "respondedAt", "type": "uint256"},
                ],
                "internalType": "struct BrokerRequests.Request[]",
                "name": "pendingRequests",
                "type": "tuple[]",
            },
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "uint256", "name": "requestId", "type": "uint256"}],
        "name": "getRequest",
        "outputs": [
            {
                "components": [
                    {"internalType": "uint256", "name": "id", "type": "uint256"},
                    {"internalType": "address", "name": "requester", "type": "address"},
                    {"internalType": "address", "name": "nftContract", "type": "address"},
                    {"internalType": "bytes", "name": "encryptedPayload", "type": "bytes"},
                    {"internalType": "uint8", "name": "status", "type": "uint8"},
                    {"internalType": "bytes", "name": "responsePayload", "type": "bytes"},
                    {"internalType": "string", "name": "rejectionReason", "type": "string"},
                    {"internalType": "uint256", "name": "submittedAt", "type": "uint256"},
                    {"internalType": "uint256", "name": "respondedAt", "type": "uint256"},
                ],
                "internalType": "struct BrokerRequests.Request",
                "name": "request",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "requestId", "type": "uint256"},
            {"internalType": "bool", "name": "approved", "type": "bool"},
            {"internalType": "bytes", "name": "encryptedPayload", "type": "bytes"},
            {"internalType": "string", "name": "rejectionReason", "type": "string"},
        ],
        "name": "submitResponse",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "address", "name": "nftContract", "type": "address"}],
        "name": "releaseAllocation",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "uint256", "name": "requestId", "type": "uint256"},
            {"indexed": True, "internalType": "address", "name": "requester", "type": "address"},
            {"indexed": True, "internalType": "address", "name": "nftContract", "type": "address"},
            {"indexed": False, "internalType": "bytes", "name": "encryptedPayload", "type": "bytes"},
        ],
        "name": "RequestSubmitted",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "uint256", "name": "requestId", "type": "uint256"},
            {"indexed": False, "internalType": "uint8", "name": "status", "type": "uint8"},
            {"indexed": False, "internalType": "bytes", "name": "encryptedPayload", "type": "bytes"},
        ],
        "name": "ResponseSubmitted",
        "type": "event",
    },
]

# Request status enum values
REQUEST_STATUS_PENDING = 0
REQUEST_STATUS_APPROVED = 1
REQUEST_STATUS_REJECTED = 2
REQUEST_STATUS_EXPIRED = 3


@dataclass
class PendingRequest:
    """A pending allocation request from the blockchain."""

    id: int
    requester: str
    nft_contract: str
    encrypted_payload: bytes
    submitted_at: datetime


class OnchainMonitor:
    """Monitors BrokerRequests contract for new allocation requests."""

    def __init__(
        self,
        onchain_config: "OnchainConfig",
        broker_config: "BrokerConfig",
        wg_config: "WireGuardConfig",
        ipam: "IPAM",
        wg: "WireGuardManager",
    ):
        """Initialize the on-chain monitor.

        Args:
            onchain_config: On-chain configuration.
            broker_config: Broker configuration.
            wg_config: WireGuard configuration.
            ipam: IPAM instance for allocation management.
            wg: WireGuard manager for peer configuration.
        """
        self.onchain_config = onchain_config
        self.broker_config = broker_config
        self.wg_config = wg_config
        self.ipam = ipam
        self.wg = wg

        # Initialize Web3
        self.w3 = Web3(Web3.HTTPProvider(onchain_config.rpc_url))

        # Load operator account
        private_key = Path(onchain_config.private_key_file).read_text().strip()
        self.account: LocalAccount = Account.from_key(private_key)

        # Load ECIES encryption key
        self.encryption = ECIESEncryption.from_file(onchain_config.ecies_private_key_file)

        # Initialize NFT verifier with requests contract for on-chain allocation checks
        self.verifier = NFTVerifier(self.w3, onchain_config.requests_contract)

        # Initialize contract
        self.requests_contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(onchain_config.requests_contract),
            abi=BROKER_REQUESTS_ABI,
        )

        # Track processed requests to avoid duplicates
        self._processed_requests: set[int] = set()

        # Running flag
        self._running = False

    async def start(self) -> None:
        """Start the on-chain monitor loop."""
        self._running = True
        logger.info(
            f"Starting on-chain monitor for {self.onchain_config.requests_contract} "
            f"(poll interval: {self.onchain_config.poll_interval_ms}ms)"
        )

        # Load existing allocations to prevent duplicates
        await self._load_existing_allocations()

        while self._running:
            try:
                await self._poll_pending_requests()
            except Exception as e:
                logger.error(f"Error polling pending requests: {e}")

            await asyncio.sleep(self.onchain_config.poll_interval_ms / 1000.0)

    def stop(self) -> None:
        """Stop the on-chain monitor loop."""
        self._running = False
        logger.info("Stopping on-chain monitor")

    async def _load_existing_allocations(self) -> None:
        """Load existing allocations to track which NFT contracts are allocated."""
        allocations = self.ipam.list_allocations()
        # Extract NFT contracts from allocation metadata if stored
        # For now, we rely on the contract-side nftContractToRequestId mapping
        logger.info(f"Loaded {len(allocations)} existing allocations")

    async def _poll_pending_requests(self) -> None:
        """Poll for pending requests and process them."""
        try:
            pending_ids, pending_requests = self.requests_contract.functions.getPendingRequests().call()
        except ContractLogicError as e:
            logger.warning(f"Contract error getting pending requests: {e}")
            return

        if not pending_ids:
            return

        logger.debug(f"Found {len(pending_ids)} pending requests")

        for request_id, request_data in zip(pending_ids, pending_requests):
            if request_id in self._processed_requests:
                continue

            pending = PendingRequest(
                id=request_id,
                requester=request_data[1],  # requester address
                nft_contract=request_data[2],  # nftContract address
                encrypted_payload=request_data[3],  # encryptedPayload
                submitted_at=datetime.fromtimestamp(request_data[7], tz=timezone.utc),
            )

            await self._process_request(pending)
            self._processed_requests.add(request_id)

    async def _process_request(self, request: PendingRequest) -> None:
        """Process a single pending allocation request.

        Args:
            request: The pending request to process.
        """
        logger.info(
            f"Processing request #{request.id} from {request.requester} "
            f"(NFT: {request.nft_contract})"
        )

        # Verify NFT ownership
        verification = self.verifier.verify_request(
            request.nft_contract, request.requester
        )

        if not verification.valid:
            logger.warning(f"Request #{request.id} verification failed: {verification.error}")
            await self._submit_rejection(request.id, verification.error or "Verification failed")
            return

        # Decrypt request payload
        try:
            payload = self.encryption.decrypt_request_payload(request.encrypted_payload)
        except Exception as e:
            logger.error(f"Failed to decrypt request #{request.id}: {e}")
            await self._submit_rejection(request.id, "Failed to decrypt payload")
            return

        # Allocate prefix using IPAM
        # Use NFT contract as the "token" identifier for on-chain allocations
        nft_contract_hash = request.nft_contract.lower()
        allocation = self.ipam.allocate(
            pubkey=payload.wg_pubkey,
            token_hash=nft_contract_hash,
            endpoint=None,  # Blockhost servers don't expose endpoints
        )

        if allocation is None:
            # Check if pubkey already has allocation
            existing = self.ipam.get_allocation_by_pubkey(payload.wg_pubkey)
            if existing:
                logger.warning(f"Request #{request.id}: pubkey already has allocation")
                await self._submit_rejection(request.id, "WireGuard pubkey already allocated")
            else:
                logger.error(f"Request #{request.id}: no prefixes available")
                await self._submit_rejection(request.id, "No prefixes available")
            return

        # Add WireGuard peer
        try:
            self.wg.add_peer(
                pubkey=payload.wg_pubkey,
                allowed_ips=allocation.prefix,
                endpoint=None,
            )
        except Exception as e:
            logger.error(f"Failed to add WireGuard peer for request #{request.id}: {e}")
            # Rollback allocation
            self.ipam.release(str(allocation.prefix), nft_contract_hash)
            await self._submit_rejection(request.id, "Failed to configure WireGuard")
            return

        # Mark NFT contract as allocated in verifier
        self.verifier.mark_allocated(request.nft_contract)

        # Build response
        wg_pubkey = self.wg.get_public_key()
        if not wg_pubkey:
            logger.error("Could not get broker WireGuard public key")
            # Rollback
            self.wg.remove_peer(payload.wg_pubkey)
            self.ipam.release(str(allocation.prefix), nft_contract_hash)
            await self._submit_rejection(request.id, "Broker configuration error")
            return

        response = ResponsePayload(
            prefix=str(allocation.prefix),
            gateway=str(self.broker_config.broker_ipv6),
            broker_pubkey=wg_pubkey,
            broker_endpoint=self.wg_config.public_endpoint,
        )

        # Encrypt response for the server
        try:
            encrypted_response = self.encryption.encrypt_response_payload(
                response, payload.server_pubkey
            )
        except Exception as e:
            logger.error(f"Failed to encrypt response for request #{request.id}: {e}")
            # Rollback
            self.wg.remove_peer(payload.wg_pubkey)
            self.ipam.release(str(allocation.prefix), nft_contract_hash)
            self.verifier.mark_released(request.nft_contract)
            await self._submit_rejection(request.id, "Failed to encrypt response")
            return

        # Submit approval on-chain
        await self._submit_approval(request.id, encrypted_response)

        logger.info(
            f"Approved request #{request.id}: allocated {allocation.prefix} "
            f"to {payload.wg_pubkey[:16]}..."
        )

    async def _submit_approval(self, request_id: int, encrypted_payload: bytes) -> None:
        """Submit an approval response on-chain.

        Args:
            request_id: Request ID to approve.
            encrypted_payload: ECIES encrypted response data.
        """
        await self._submit_response(request_id, approved=True, encrypted_payload=encrypted_payload)

    async def _submit_rejection(self, request_id: int, reason: str) -> None:
        """Submit a rejection response on-chain.

        Args:
            request_id: Request ID to reject.
            reason: Rejection reason.
        """
        await self._submit_response(request_id, approved=False, rejection_reason=reason)

    async def _submit_response(
        self,
        request_id: int,
        approved: bool,
        encrypted_payload: bytes = b"",
        rejection_reason: str = "",
    ) -> None:
        """Submit a response transaction on-chain.

        Args:
            request_id: Request ID.
            approved: Whether approved or rejected.
            encrypted_payload: Encrypted response (for approvals).
            rejection_reason: Reason for rejection.
        """
        try:
            # Estimate gas first
            gas_estimate = self.requests_contract.functions.submitResponse(
                request_id, approved, encrypted_payload, rejection_reason
            ).estimate_gas({"from": self.account.address})

            # Build transaction with buffer
            tx = self.requests_contract.functions.submitResponse(
                request_id, approved, encrypted_payload, rejection_reason
            ).build_transaction(
                {
                    "from": self.account.address,
                    "nonce": self.w3.eth.get_transaction_count(self.account.address),
                    "gas": gas_estimate + 50000,
                    "maxFeePerGas": self.w3.eth.gas_price * 2,
                    "maxPriorityFeePerGas": self.w3.eth.gas_price,
                    "chainId": self.onchain_config.chain_id,
                }
            )

            # Sign and send
            signed = self.account.sign_transaction(tx)
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)

            # Wait for receipt
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

            if receipt["status"] == 1:
                status = "approved" if approved else "rejected"
                logger.info(f"Response for request #{request_id} ({status}) confirmed: {tx_hash.hex()}")
            else:
                logger.error(f"Response transaction for request #{request_id} failed: {tx_hash.hex()}")

        except Exception as e:
            logger.error(f"Failed to submit response for request #{request_id}: {e}")

    async def release_allocation(self, nft_contract: str, prefix: str, pubkey: str) -> bool:
        """Release an allocation (remove WireGuard peer and on-chain mapping).

        Args:
            nft_contract: NFT contract address.
            prefix: Allocated prefix to release.
            pubkey: WireGuard public key.

        Returns:
            True if successful.
        """
        try:
            # Remove WireGuard peer
            self.wg.remove_peer(pubkey)

            # Release from IPAM
            nft_contract_hash = nft_contract.lower()
            self.ipam.release(prefix, nft_contract_hash)

            # Mark released in verifier
            self.verifier.mark_released(nft_contract)

            # Release on-chain
            tx = self.requests_contract.functions.releaseAllocation(
                Web3.to_checksum_address(nft_contract)
            ).build_transaction(
                {
                    "from": self.account.address,
                    "nonce": self.w3.eth.get_transaction_count(self.account.address),
                    "gas": 100000,
                    "maxFeePerGas": self.w3.eth.gas_price * 2,
                    "maxPriorityFeePerGas": self.w3.eth.gas_price,
                    "chainId": self.onchain_config.chain_id,
                }
            )

            signed = self.account.sign_transaction(tx)
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

            if receipt["status"] == 1:
                logger.info(f"Released allocation for {nft_contract}: {tx_hash.hex()}")
                return True
            else:
                logger.error(f"Release transaction failed: {tx_hash.hex()}")
                return False

        except Exception as e:
            logger.error(f"Failed to release allocation for {nft_contract}: {e}")
            return False
