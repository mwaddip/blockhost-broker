//! Contract bindings for BrokerRequests.

use ethers::prelude::*;

// Manually define the contract bindings since abigen requires build.rs compilation
abigen!(
    BrokerRequestsContract,
    r#"[
        function getRequest(uint256 requestId) external view returns (uint256 id, address requester, address nftContract, bytes encryptedPayload, uint8 status, bytes responsePayload, uint256 submittedAt, uint256 respondedAt)
        function getRequestCount() external view returns (uint256 count)
        function submitResponse(uint256 requestId, bytes calldata encryptedPayload) external
        function releaseAllocation(address nftContract) external
        function requestExpirationTime() external view returns (uint256)
        function nftContractToRequestId(address) external view returns (uint256)
        event RequestSubmitted(uint256 indexed requestId, address indexed requester, address indexed nftContract, bytes encryptedPayload)
        event ResponseSubmitted(uint256 indexed requestId, uint8 status, bytes encryptedPayload)
    ]"#
);

/// Parsed request data from contract call.
#[derive(Debug, Clone)]
pub struct RequestData {
    pub id: U256,
    pub requester: Address,
    pub nft_contract: Address,
    pub encrypted_payload: Bytes,
    pub status: u8,
    pub response_payload: Bytes,
    pub submitted_at: U256,
    pub responded_at: U256,
}

impl From<(U256, Address, Address, Bytes, u8, Bytes, U256, U256)> for RequestData {
    fn from(tuple: (U256, Address, Address, Bytes, u8, Bytes, U256, U256)) -> Self {
        Self {
            id: tuple.0,
            requester: tuple.1,
            nft_contract: tuple.2,
            encrypted_payload: tuple.3,
            status: tuple.4,
            response_payload: tuple.5,
            submitted_at: tuple.6,
            responded_at: tuple.7,
        }
    }
}

/// Request status enum values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RequestStatus {
    Pending = 0,
    Approved = 1,
    Rejected = 2,
    Expired = 3,
}

impl From<u8> for RequestStatus {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Pending,
            1 => Self::Approved,
            2 => Self::Rejected,
            3 => Self::Expired,
            _ => Self::Pending, // Default to pending for unknown values
        }
    }
}

impl RequestStatus {
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }
}
