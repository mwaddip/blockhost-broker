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
// - submitted_at: U256
