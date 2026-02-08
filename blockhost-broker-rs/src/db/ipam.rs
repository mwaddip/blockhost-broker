//! IP Address Management (IPAM) database operations.

use std::net::Ipv6Addr;
use std::path::Path;

use chrono::{DateTime, Utc};
use ipnet::Ipv6Net;
use sha2::{Digest, Sha256};
use sqlx::{sqlite::SqlitePoolOptions, Pool, Row, Sqlite};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::config::BrokerConfig;

use super::models::{Allocation, Token};

#[derive(Debug, Error)]
pub enum IpamError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("No prefixes available")]
    NoPrefixesAvailable,

    #[error("Public key already has an allocation")]
    PubkeyAlreadyAllocated,

    #[error("Allocation not found")]
    AllocationNotFound,

    #[error("Invalid prefix")]
    InvalidPrefix,
}

/// Hash a token using SHA-256.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate a new random token.
pub fn generate_token() -> String {
    use base64::Engine;
    use rand::Rng;
    let bytes: [u8; 32] = rand::thread_rng().gen();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// IP Address Management database.
pub struct Ipam {
    pool: Pool<Sqlite>,
    config: BrokerConfig,
}

impl Ipam {
    /// Create a new IPAM instance.
    pub async fn new(db_path: &Path, config: BrokerConfig) -> Result<Self, IpamError> {
        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                IpamError::Database(sqlx::Error::Configuration(
                    format!("Failed to create database directory {}: {}", parent.display(), e).into(),
                ))
            })?;
        }

        let db_url = format!("sqlite:{}?mode=rwc", db_path.display());
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await?;

        let ipam = Self { pool, config };
        ipam.init_schema().await?;

        Ok(ipam)
    }

    /// Initialize the database schema.
    async fn init_schema(&self) -> Result<(), IpamError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS allocations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                prefix TEXT UNIQUE NOT NULL,
                prefix_index INTEGER UNIQUE NOT NULL,
                pubkey TEXT NOT NULL,
                endpoint TEXT,
                nft_contract TEXT NOT NULL,
                allocated_at TEXT NOT NULL,
                last_seen_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_allocations_nft_contract ON allocations(nft_contract);
            CREATE INDEX IF NOT EXISTS idx_allocations_pubkey ON allocations(pubkey);
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT UNIQUE NOT NULL,
                name TEXT,
                max_allocations INTEGER DEFAULT 1,
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                revoked BOOLEAN DEFAULT FALSE
            );

            CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(token_hash);
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                nft_contract TEXT,
                prefix TEXT,
                details TEXT
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Initialize last_processed_id if not exists
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO state (key, value, updated_at)
            VALUES ('last_processed_id', '0', datetime('now'))
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Calculate subnet from index.
    pub fn get_subnet(&self, index: i64) -> Ipv6Net {
        let network = self.config.upstream_prefix;
        let prefix_len = self.config.allocation_size;
        let subnet_size: u128 = 1 << (128 - prefix_len);
        let subnet_start = u128::from(network.network()) + (index as u128 * subnet_size);
        let addr = Ipv6Addr::from(subnet_start);
        Ipv6Net::new(addr, prefix_len).expect("Valid prefix")
    }

    /// Get the next available prefix index.
    pub async fn get_next_available_index(&self) -> Result<Option<i64>, IpamError> {
        // Calculate max index based on upstream prefix and allocation size
        let upstream_bits = 128 - self.config.upstream_prefix.prefix_len();
        let alloc_bits = 128 - self.config.allocation_size;
        let max_index: i64 = if upstream_bits > alloc_bits {
            ((1u64 << (upstream_bits - alloc_bits)) - 1) as i64
        } else {
            return Ok(None);
        };

        // Get all used indices
        let used_indices: Vec<i64> = sqlx::query_scalar(
            "SELECT prefix_index FROM allocations ORDER BY prefix_index",
        )
        .fetch_all(&self.pool)
        .await?;

        let used_set: std::collections::HashSet<i64> = used_indices.into_iter().collect();

        // Find first available (start at 1, reserve 0 for broker)
        for i in 1..=max_index {
            if !used_set.contains(&i) {
                return Ok(Some(i));
            }
        }

        Ok(None)
    }

    /// Allocate a new prefix.
    pub async fn allocate(
        &self,
        pubkey: &str,
        nft_contract: &str,
        endpoint: Option<&str>,
    ) -> Result<Allocation, IpamError> {
        // Check if pubkey already has an allocation
        if self.get_allocation_by_pubkey(pubkey).await?.is_some() {
            return Err(IpamError::PubkeyAlreadyAllocated);
        }

        // Get next available index
        let index = self
            .get_next_available_index()
            .await?
            .ok_or(IpamError::NoPrefixesAvailable)?;

        let prefix = self.get_subnet(index);
        let now = Utc::now();
        let nft_contract_lower = nft_contract.to_lowercase();

        let id = sqlx::query(
            r#"
            INSERT INTO allocations (prefix, prefix_index, pubkey, endpoint, nft_contract, allocated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(prefix.to_string())
        .bind(index)
        .bind(pubkey)
        .bind(endpoint)
        .bind(&nft_contract_lower)
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?
        .last_insert_rowid();

        self.audit("allocate", Some(&nft_contract_lower), Some(&prefix.to_string()),
                   &serde_json::json!({"pubkey": pubkey}).to_string()).await?;

        info!(prefix = %prefix, pubkey = %pubkey, "Allocated prefix");

        Ok(Allocation {
            id,
            prefix,
            prefix_index: index,
            pubkey: pubkey.to_string(),
            endpoint: endpoint.map(String::from),
            nft_contract: nft_contract_lower,
            allocated_at: now,
            last_seen_at: None,
        })
    }

    /// Get allocation by ID.
    pub async fn get_allocation(&self, id: i64) -> Result<Option<Allocation>, IpamError> {
        let row = sqlx::query(
            "SELECT id, prefix, prefix_index, pubkey, endpoint, nft_contract, allocated_at, last_seen_at FROM allocations WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| self.row_to_allocation(&r)).transpose()
    }

    /// Get allocation by prefix.
    pub async fn get_allocation_by_prefix(
        &self,
        prefix: &str,
    ) -> Result<Option<Allocation>, IpamError> {
        let row = sqlx::query(
            "SELECT id, prefix, prefix_index, pubkey, endpoint, nft_contract, allocated_at, last_seen_at FROM allocations WHERE prefix = ?",
        )
        .bind(prefix)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| self.row_to_allocation(&r)).transpose()
    }

    /// Get allocation by WireGuard public key.
    pub async fn get_allocation_by_pubkey(
        &self,
        pubkey: &str,
    ) -> Result<Option<Allocation>, IpamError> {
        let row = sqlx::query(
            "SELECT id, prefix, prefix_index, pubkey, endpoint, nft_contract, allocated_at, last_seen_at FROM allocations WHERE pubkey = ?",
        )
        .bind(pubkey)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| self.row_to_allocation(&r)).transpose()
    }

    /// Get allocation by NFT contract address.
    pub async fn get_allocation_by_nft_contract(
        &self,
        nft_contract: &str,
    ) -> Result<Option<Allocation>, IpamError> {
        let row = sqlx::query(
            "SELECT id, prefix, prefix_index, pubkey, endpoint, nft_contract, allocated_at, last_seen_at FROM allocations WHERE nft_contract = ?",
        )
        .bind(nft_contract.to_lowercase())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| self.row_to_allocation(&r)).transpose()
    }

    /// List all allocations.
    pub async fn list_allocations(&self) -> Result<Vec<Allocation>, IpamError> {
        let rows = sqlx::query(
            "SELECT id, prefix, prefix_index, pubkey, endpoint, nft_contract, allocated_at, last_seen_at FROM allocations ORDER BY prefix_index",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(|r| self.row_to_allocation(r)).collect()
    }

    /// Release an allocation.
    pub async fn release(&self, prefix: &str, nft_contract: &str) -> Result<bool, IpamError> {
        let result = sqlx::query("DELETE FROM allocations WHERE prefix = ? AND nft_contract = ?")
            .bind(prefix)
            .bind(nft_contract.to_lowercase())
            .execute(&self.pool)
            .await?;

        if result.rows_affected() > 0 {
            self.audit("release", Some(nft_contract), Some(prefix), "{}").await?;
            info!(prefix = %prefix, "Released allocation");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Update last seen timestamp for an allocation.
    pub async fn update_last_seen(&self, prefix: &str, timestamp: DateTime<Utc>) -> Result<(), IpamError> {
        sqlx::query("UPDATE allocations SET last_seen_at = ? WHERE prefix = ?")
            .bind(timestamp.to_rfc3339())
            .bind(prefix)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Update the WireGuard public key for an existing allocation.
    /// Returns the updated allocation.
    pub async fn update_allocation_pubkey(
        &self,
        nft_contract: &str,
        new_pubkey: &str,
        endpoint: Option<&str>,
    ) -> Result<Allocation, IpamError> {
        let nft_contract_lower = nft_contract.to_lowercase();

        // Get existing allocation
        let allocation = self
            .get_allocation_by_nft_contract(&nft_contract_lower)
            .await?
            .ok_or(IpamError::AllocationNotFound)?;

        // Update the pubkey
        sqlx::query(
            "UPDATE allocations SET pubkey = ?, endpoint = ? WHERE nft_contract = ?",
        )
        .bind(new_pubkey)
        .bind(endpoint)
        .bind(&nft_contract_lower)
        .execute(&self.pool)
        .await?;

        self.audit(
            "update_pubkey",
            Some(&nft_contract_lower),
            Some(&allocation.prefix.to_string()),
            &serde_json::json!({"old_pubkey": allocation.pubkey, "new_pubkey": new_pubkey}).to_string(),
        )
        .await?;

        info!(
            prefix = %allocation.prefix,
            old_pubkey = %allocation.pubkey,
            new_pubkey = %new_pubkey,
            "Updated allocation pubkey"
        );

        // Return updated allocation
        Ok(Allocation {
            pubkey: new_pubkey.to_string(),
            endpoint: endpoint.map(String::from),
            ..allocation
        })
    }

    /// Get allocation statistics.
    pub async fn get_stats(&self) -> Result<AllocationStats, IpamError> {
        let upstream_bits = 128 - self.config.upstream_prefix.prefix_len();
        let alloc_bits = 128 - self.config.allocation_size;
        let total: i64 = if upstream_bits > alloc_bits {
            ((1u64 << (upstream_bits - alloc_bits)) - 1) as i64
        } else {
            0
        };

        let used: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM allocations")
            .fetch_one(&self.pool)
            .await?;

        Ok(AllocationStats {
            upstream_prefix: self.config.upstream_prefix.to_string(),
            allocation_size: self.config.allocation_size,
            total_allocations: total,
            used_allocations: used,
            available_allocations: total - used,
        })
    }

    // State management

    /// Get the last processed request ID (legacy — uses default key).
    pub async fn get_last_processed_id(&self) -> Result<u64, IpamError> {
        let value: String = sqlx::query_scalar("SELECT value FROM state WHERE key = 'last_processed_id'")
            .fetch_one(&self.pool)
            .await?;

        Ok(value.parse().unwrap_or(0))
    }

    /// Set the last processed request ID (legacy — uses default key).
    pub async fn set_last_processed_id(&self, id: u64) -> Result<(), IpamError> {
        sqlx::query(
            "UPDATE state SET value = ?, updated_at = datetime('now') WHERE key = 'last_processed_id'",
        )
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;

        debug!(last_processed_id = id, "Updated last processed ID");
        Ok(())
    }

    /// Get the last processed request ID for a specific contract address.
    pub async fn get_last_processed_id_for_contract(&self, contract: &str) -> Result<u64, IpamError> {
        let key = format!("last_processed_id:{}", contract.to_lowercase());
        let value: Option<String> = sqlx::query_scalar("SELECT value FROM state WHERE key = ?")
            .bind(&key)
            .fetch_optional(&self.pool)
            .await?;

        Ok(value.and_then(|v| v.parse().ok()).unwrap_or(0))
    }

    /// Set the last processed request ID for a specific contract address.
    pub async fn set_last_processed_id_for_contract(&self, contract: &str, id: u64) -> Result<(), IpamError> {
        let key = format!("last_processed_id:{}", contract.to_lowercase());
        sqlx::query(
            "INSERT INTO state (key, value, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        )
        .bind(&key)
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;

        debug!(contract = contract, last_processed_id = id, "Updated last processed ID for contract");
        Ok(())
    }

    /// Migrate legacy last_processed_id to per-contract key.
    /// Call this during startup if a legacy contract is configured.
    pub async fn migrate_last_processed_id(&self, legacy_contract: &str) -> Result<(), IpamError> {
        let key = format!("last_processed_id:{}", legacy_contract.to_lowercase());

        // Check if per-contract key already exists
        let existing: Option<String> = sqlx::query_scalar("SELECT value FROM state WHERE key = ?")
            .bind(&key)
            .fetch_optional(&self.pool)
            .await?;

        if existing.is_some() {
            return Ok(()); // Already migrated
        }

        // Read legacy key
        let legacy_value: Option<String> = sqlx::query_scalar("SELECT value FROM state WHERE key = 'last_processed_id'")
            .fetch_optional(&self.pool)
            .await?;

        if let Some(value) = legacy_value {
            let id: u64 = value.parse().unwrap_or(0);
            if id > 0 {
                info!(
                    legacy_contract = legacy_contract,
                    last_processed_id = id,
                    "Migrating last_processed_id to per-contract key"
                );
                self.set_last_processed_id_for_contract(legacy_contract, id).await?;

                // Reset legacy key to 0 so it doesn't confuse future reads
                sqlx::query("UPDATE state SET value = '0', updated_at = datetime('now') WHERE key = 'last_processed_id'")
                    .execute(&self.pool)
                    .await?;
            }
        }

        Ok(())
    }

    // Token management (for REST API compatibility)

    /// Create a new API token.
    pub async fn create_token(
        &self,
        name: Option<&str>,
        max_allocations: i64,
        is_admin: bool,
    ) -> Result<(String, Token), IpamError> {
        let token = generate_token();
        let token_hash = hash_token(&token);
        let now = Utc::now();

        let id = sqlx::query(
            r#"
            INSERT INTO tokens (token_hash, name, max_allocations, is_admin, created_at)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(&token_hash)
        .bind(name)
        .bind(max_allocations)
        .bind(is_admin)
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await?
        .last_insert_rowid();

        Ok((
            token,
            Token {
                id,
                token_hash,
                name: name.map(String::from),
                max_allocations,
                is_admin,
                created_at: now,
                expires_at: None,
                revoked: false,
            },
        ))
    }

    /// Get token by hash.
    pub async fn get_token(&self, token_hash: &str) -> Result<Option<Token>, IpamError> {
        let row = sqlx::query(
            "SELECT id, token_hash, name, max_allocations, is_admin, created_at, expires_at, revoked FROM tokens WHERE token_hash = ?",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| self.row_to_token(&r)).transpose()
    }

    /// List all tokens.
    pub async fn list_tokens(&self) -> Result<Vec<Token>, IpamError> {
        let rows = sqlx::query(
            "SELECT id, token_hash, name, max_allocations, is_admin, created_at, expires_at, revoked FROM tokens ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(|r| self.row_to_token(r)).collect()
    }

    /// Validate a plaintext token and return Token if valid.
    pub async fn validate_token(&self, token: &str) -> Result<Option<Token>, IpamError> {
        let token_hash = hash_token(token);
        let token_opt = self.get_token(&token_hash).await?;

        Ok(token_opt.filter(|t| t.is_valid()))
    }

    // Audit logging

    async fn audit(
        &self,
        action: &str,
        nft_contract: Option<&str>,
        prefix: Option<&str>,
        details: &str,
    ) -> Result<(), IpamError> {
        sqlx::query(
            "INSERT INTO audit_log (timestamp, action, nft_contract, prefix, details) VALUES (datetime('now'), ?, ?, ?, ?)",
        )
        .bind(action)
        .bind(nft_contract)
        .bind(prefix)
        .bind(details)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Helper functions

    fn row_to_allocation(&self, row: &sqlx::sqlite::SqliteRow) -> Result<Allocation, IpamError> {
        let prefix_str: String = row.get("prefix");
        let allocated_at_str: String = row.get("allocated_at");
        let last_seen_at_str: Option<String> = row.get("last_seen_at");

        Ok(Allocation {
            id: row.get("id"),
            prefix: prefix_str.parse().map_err(|_| IpamError::InvalidPrefix)?,
            prefix_index: row.get("prefix_index"),
            pubkey: row.get("pubkey"),
            endpoint: row.get("endpoint"),
            nft_contract: row.get("nft_contract"),
            allocated_at: DateTime::parse_from_rfc3339(&allocated_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            last_seen_at: last_seen_at_str.and_then(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .map(|dt| dt.with_timezone(&Utc))
                    .ok()
            }),
        })
    }

    fn row_to_token(&self, row: &sqlx::sqlite::SqliteRow) -> Result<Token, IpamError> {
        let created_at_str: String = row.get("created_at");
        let expires_at_str: Option<String> = row.get("expires_at");

        Ok(Token {
            id: row.get("id"),
            token_hash: row.get("token_hash"),
            name: row.get("name"),
            max_allocations: row.get("max_allocations"),
            is_admin: row.get("is_admin"),
            created_at: DateTime::parse_from_rfc3339(&created_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            expires_at: expires_at_str.and_then(|s| {
                DateTime::parse_from_rfc3339(&s)
                    .map(|dt| dt.with_timezone(&Utc))
                    .ok()
            }),
            revoked: row.get("revoked"),
        })
    }
}

/// Allocation statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationStats {
    pub upstream_prefix: String,
    pub allocation_size: u8,
    pub total_allocations: i64,
    pub used_allocations: i64,
    pub available_allocations: i64,
}

use serde::{Deserialize, Serialize};
