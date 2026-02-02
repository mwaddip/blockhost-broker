//! NFT ownership verification for on-chain authentication.

use ethers::prelude::*;
use thiserror::Error;
use tracing::warn;

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("Contract call failed: {0}")]
    ContractError(#[from] ContractError<Provider<Http>>),

    #[error("Provider error: {0}")]
    ProviderError(#[from] ProviderError),
}

/// Result of NFT contract verification.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub valid: bool,
    pub nft_contract: Address,
    pub requester: Address,
    pub error: Option<String>,
}

/// ERC165 interface ID for ERC721.
const ERC721_INTERFACE_ID: [u8; 4] = [0x80, 0xac, 0x58, 0xcd];

abigen!(
    IERC165,
    r#"[
        function supportsInterface(bytes4 interfaceId) external view returns (bool)
    ]"#
);

abigen!(
    IOwnable,
    r#"[
        function owner() external view returns (address)
    ]"#
);

/// Verifies NFT contract ownership for broker authentication.
pub struct NftVerifier {
    provider: Provider<Http>,
}

impl NftVerifier {
    /// Create a new NFT verifier.
    pub fn new(provider: Provider<Http>) -> Self {
        Self { provider }
    }

    /// Verify that a request is from a legitimate Blockhost installation.
    ///
    /// Verification steps:
    /// 1. NFT contract exists (has code)
    /// 2. NFT contract supports ERC721 interface
    /// 3. Requester owns the NFT contract (is Ownable owner)
    pub async fn verify_request(
        &self,
        nft_contract: Address,
        requester: Address,
    ) -> VerificationResult {
        // 1. Check NFT contract exists
        if !self.contract_exists(nft_contract).await {
            return VerificationResult {
                valid: false,
                nft_contract,
                requester,
                error: Some("NFT contract does not exist".to_string()),
            };
        }

        // 2. Check ERC721 interface
        if !self.is_erc721(nft_contract).await {
            return VerificationResult {
                valid: false,
                nft_contract,
                requester,
                error: Some("Contract does not support ERC721 interface".to_string()),
            };
        }

        // 3. Check requester owns the contract
        if !self.is_owner(nft_contract, requester).await {
            return VerificationResult {
                valid: false,
                nft_contract,
                requester,
                error: Some("Requester does not own the NFT contract".to_string()),
            };
        }

        VerificationResult {
            valid: true,
            nft_contract,
            requester,
            error: None,
        }
    }

    /// Check if an address has contract code.
    async fn contract_exists(&self, address: Address) -> bool {
        match self.provider.get_code(address, None).await {
            Ok(code) => !code.is_empty() && code.0 != vec![0u8],
            Err(e) => {
                warn!("Error checking contract code at {}: {}", address, e);
                false
            }
        }
    }

    /// Check if contract supports ERC721 interface.
    async fn is_erc721(&self, address: Address) -> bool {
        let contract = IERC165::new(address, self.provider.clone().into());

        match contract
            .supports_interface(ERC721_INTERFACE_ID)
            .call()
            .await
        {
            Ok(supported) => supported,
            Err(e) => {
                warn!("Error checking ERC721 interface at {}: {}", address, e);
                false
            }
        }
    }

    /// Check if requester owns the contract via Ownable.owner().
    async fn is_owner(&self, nft_contract: Address, requester: Address) -> bool {
        let contract = IOwnable::new(nft_contract, self.provider.clone().into());

        match contract.owner().call().await {
            Ok(owner) => owner == requester,
            Err(e) => {
                warn!("Error checking owner of {}: {}", nft_contract, e);
                false
            }
        }
    }
}
