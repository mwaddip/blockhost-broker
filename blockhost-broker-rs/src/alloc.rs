//! Shared allocate-or-update flow.
//!
//! Both the on-chain monitor and the HTTP API arrive at the same IPAM/WireGuard
//! dance: check whether the NFT contract already has an allocation, then either
//! rotate the WireGuard pubkey on the existing prefix or carve out a new one.
//!
//! Keeping this in one place prevents the two paths from drifting on subtle
//! details like lock release ordering or rollback semantics.

use std::sync::Arc;

use thiserror::Error;
use tokio::sync::Mutex;
use tracing::warn;

use crate::db::{Allocation, Ipam};
use crate::wg::WireGuardManager;

#[derive(Debug, Error)]
pub enum AllocateOrUpdateError {
    #[error("WireGuard pubkey already has an allocation")]
    PubkeyAlreadyAllocated,

    #[error("No prefixes available")]
    NoPrefixesAvailable,

    #[error("Database error: {0}")]
    Database(#[from] crate::db::ipam::IpamError),

    #[error("WireGuard error: {0}")]
    WireGuard(#[from] crate::wg::WireGuardError),
}

pub struct AllocateOrUpdateResult {
    pub allocation: Allocation,
    /// `Some(old_pubkey)` if this was a re-request that rotated an existing peer.
    /// `None` for a fresh allocation.
    pub previous_pubkey: Option<String>,
}

/// Allocate a new prefix for `nft_contract`, or rotate the WireGuard pubkey on
/// the existing one if it's already in the IPAM.
///
/// The IPAM mutex is held only across DB operations and dropped before any
/// WireGuard syscall. On WG-add failure for a fresh allocation, the IPAM
/// reservation is released so the prefix doesn't leak.
pub async fn allocate_or_update(
    ipam: &Arc<Mutex<Ipam>>,
    wg: &WireGuardManager,
    pubkey: &str,
    nft_contract: &str,
    is_test: bool,
    source: &str,
    lease_duration: Option<u64>,
) -> Result<AllocateOrUpdateResult, AllocateOrUpdateError> {
    let ipam_guard = ipam.lock().await;
    let existing = ipam_guard.get_allocation_by_nft_contract(nft_contract).await?;

    if let Some(existing) = existing {
        let updated = ipam_guard
            .update_allocation_pubkey(nft_contract, pubkey, None)
            .await?;
        drop(ipam_guard);

        // Rotate the WireGuard peer. The remove may legitimately fail if the
        // old peer was already gone (e.g., manually cleaned up); log but proceed.
        if let Err(e) = wg.remove_peer(&existing.pubkey) {
            warn!(
                old_pubkey = %existing.pubkey,
                error = %e,
                "Re-request: failed to remove old WireGuard peer (continuing)"
            );
        }
        wg.add_peer(pubkey, &updated.prefix, None)?;

        Ok(AllocateOrUpdateResult {
            allocation: updated,
            previous_pubkey: Some(existing.pubkey),
        })
    } else {
        let allocation = match ipam_guard
            .allocate(pubkey, nft_contract, None, is_test, source, lease_duration)
            .await
        {
            Ok(a) => a,
            Err(crate::db::ipam::IpamError::PubkeyAlreadyAllocated) => {
                return Err(AllocateOrUpdateError::PubkeyAlreadyAllocated);
            }
            Err(crate::db::ipam::IpamError::NoPrefixesAvailable) => {
                return Err(AllocateOrUpdateError::NoPrefixesAvailable);
            }
            Err(e) => return Err(e.into()),
        };
        drop(ipam_guard);

        if let Err(e) = wg.add_peer(pubkey, &allocation.prefix, None) {
            // Rollback the IPAM reservation so the prefix doesn't leak.
            warn!(
                prefix = %allocation.prefix,
                nft_contract = nft_contract,
                error = %e,
                "Failed to add WG peer; rolling back IPAM reservation"
            );
            let ipam_guard = ipam.lock().await;
            if let Err(release_err) = ipam_guard.release(&allocation.prefix.to_string(), nft_contract).await {
                warn!(
                    prefix = %allocation.prefix,
                    nft_contract = nft_contract,
                    error = %release_err,
                    "Rollback: failed to release IPAM prefix (allocation may leak)"
                );
            }
            return Err(e.into());
        }

        Ok(AllocateOrUpdateResult {
            allocation,
            previous_pubkey: None,
        })
    }
}
