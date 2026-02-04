//! Contract bindings for BrokerRequests.

use ethers::prelude::*;

// Use JSON ABI for proper struct handling
abigen!(
    BrokerRequestsContract,
    "contracts/abi/BrokerRequests.json"
);

// Re-export the generated Request struct
pub use broker_requests_contract::Request as RequestData;

// Note: The abigen! macro generates a Request struct with fields:
// - id: U256
// - requester: Address
// - nft_contract: Address
// - encrypted_payload: Bytes
// - status: u8
// - response_payload: Bytes
// - submitted_at: U256
// - responded_at: U256

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
