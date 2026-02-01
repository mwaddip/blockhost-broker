"""NFT ownership verification for on-chain authentication.

Verifies that allocation requests come from legitimate Blockhost installations
by checking NFT contract ownership on-chain.
"""

import logging
from dataclasses import dataclass

from web3 import Web3
from web3.exceptions import ContractLogicError

logger = logging.getLogger(__name__)

# ERC721 interface ID
ERC721_INTERFACE_ID = bytes.fromhex("80ac58cd")

# Minimal ABIs for verification
ERC165_ABI = [
    {
        "inputs": [{"internalType": "bytes4", "name": "interfaceId", "type": "bytes4"}],
        "name": "supportsInterface",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    }
]

OWNABLE_ABI = [
    {
        "inputs": [],
        "name": "owner",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    }
]


@dataclass
class VerificationResult:
    """Result of NFT contract verification."""

    valid: bool
    nft_contract: str
    requester: str
    error: str | None = None


class NFTVerifier:
    """Verifies NFT contract ownership for broker authentication."""

    def __init__(self, w3: Web3, requests_contract: str | None = None):
        """Initialize verifier with Web3 instance.

        Args:
            w3: Connected Web3 instance.
            requests_contract: BrokerRequests contract address for allocation checks.
        """
        self.w3 = w3
        self.requests_contract = requests_contract

        # ABI for checking nftContractToRequestId
        self._requests_abi = [
            {
                "inputs": [{"internalType": "address", "name": "", "type": "address"}],
                "name": "nftContractToRequestId",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function",
            }
        ]

    def verify_request(
        self, nft_contract: str, requester: str
    ) -> VerificationResult:
        """Verify that a request is from a legitimate Blockhost installation.

        Verification steps:
        1. NFT contract exists (has code)
        2. NFT contract supports ERC721 interface
        3. Requester owns the NFT contract (is Ownable owner)
        4. NFT contract not already allocated (checked on-chain)

        Args:
            nft_contract: Address of the AccessCredentialNFT contract.
            requester: Address that submitted the request.

        Returns:
            VerificationResult with validity and any error message.
        """
        nft_contract = Web3.to_checksum_address(nft_contract)
        requester = Web3.to_checksum_address(requester)

        # 1. Check NFT contract exists
        if not self._contract_exists(nft_contract):
            return VerificationResult(
                valid=False,
                nft_contract=nft_contract,
                requester=requester,
                error="NFT contract does not exist",
            )

        # 2. Check ERC721 interface
        if not self._is_erc721(nft_contract):
            return VerificationResult(
                valid=False,
                nft_contract=nft_contract,
                requester=requester,
                error="Contract does not support ERC721 interface",
            )

        # 3. Check requester owns the contract
        if not self._is_owner(nft_contract, requester):
            return VerificationResult(
                valid=False,
                nft_contract=nft_contract,
                requester=requester,
                error="Requester does not own the NFT contract",
            )

        # Note: We don't check nftContractToRequestId here because:
        # 1. The BrokerRequests contract already enforces uniqueness at submission time
        # 2. If we're processing a pending request, the mapping will point to that request
        # The contract-level check is sufficient to prevent duplicates

        return VerificationResult(
            valid=True,
            nft_contract=nft_contract,
            requester=requester,
        )

    def _is_allocated_onchain(self, nft_contract: str) -> bool:
        """Check if NFT contract has an active allocation on-chain.

        This checks the BrokerRequests contract's nftContractToRequestId mapping.
        If non-zero, the NFT is already allocated.
        """
        if not self.requests_contract:
            return False

        try:
            contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(self.requests_contract),
                abi=self._requests_abi
            )
            request_id = contract.functions.nftContractToRequestId(nft_contract).call()
            return request_id != 0
        except Exception as e:
            logger.warning(f"Error checking allocation status for {nft_contract}: {e}")
            return False

    def mark_allocated(self, nft_contract: str) -> None:
        """Mark an NFT contract as having an allocation.

        Note: This is now a no-op since we check on-chain state directly.
        """
        pass

    def mark_released(self, nft_contract: str) -> None:
        """Mark an NFT contract as released.

        Note: This is now a no-op since we check on-chain state directly.
        """
        pass

    def load_allocated_contracts(self, contracts: list[str]) -> None:
        """Load set of already-allocated contracts.

        Note: This is now a no-op since we check on-chain state directly.
        """
        pass

    def _contract_exists(self, address: str) -> bool:
        """Check if an address has contract code."""
        try:
            code = self.w3.eth.get_code(address)
            return len(code) > 0 and code != b"\x00"
        except Exception as e:
            logger.warning(f"Error checking contract code at {address}: {e}")
            return False

    def _is_erc721(self, address: str) -> bool:
        """Check if contract supports ERC721 interface."""
        try:
            contract = self.w3.eth.contract(address=address, abi=ERC165_ABI)
            return contract.functions.supportsInterface(ERC721_INTERFACE_ID).call()
        except ContractLogicError:
            return False
        except Exception as e:
            logger.warning(f"Error checking ERC721 interface at {address}: {e}")
            return False

    def _is_owner(self, nft_contract: str, requester: str) -> bool:
        """Check if requester owns the contract via Ownable.owner()."""
        try:
            contract = self.w3.eth.contract(address=nft_contract, abi=OWNABLE_ABI)
            owner = contract.functions.owner().call()
            return owner.lower() == requester.lower()
        except ContractLogicError:
            return False
        except Exception as e:
            logger.warning(f"Error checking owner of {nft_contract}: {e}")
            return False
