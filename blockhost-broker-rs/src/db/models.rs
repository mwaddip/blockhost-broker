//! Database model definitions.

use chrono::{DateTime, Utc};
use ipnet::Ipv6Net;
use serde::{Deserialize, Serialize};

/// An IPv6 prefix allocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Allocation {
    pub id: i64,
    pub prefix: Ipv6Net,
    pub prefix_index: i64,
    pub pubkey: String,
    pub endpoint: Option<String>,
    pub nft_contract: String,
    pub allocated_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub is_test: bool,
    pub expires_at: Option<DateTime<Utc>>,
}

/// An API token (for REST API authentication).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub id: i64,
    pub token_hash: String,
    pub name: Option<String>,
    pub max_allocations: i64,
    pub is_admin: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

impl Token {
    /// Check if the token is valid (not revoked and not expired).
    pub fn is_valid(&self) -> bool {
        if self.revoked {
            return false;
        }
        if let Some(expires_at) = self.expires_at {
            if expires_at < Utc::now() {
                return false;
            }
        }
        true
    }
}
