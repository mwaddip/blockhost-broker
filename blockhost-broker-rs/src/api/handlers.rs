//! REST API handlers for internal management.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::config::Config;
use crate::db::Ipam;
use crate::wg::WireGuardManager;

/// Application state shared across handlers.
pub struct AppState {
    pub config: Config,
    pub ipam: Arc<Mutex<Ipam>>,
    pub wg: Arc<WireGuardManager>,
}

/// Health check response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

/// Status response.
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub upstream_prefix: String,
    pub allocation_size: u8,
    pub total_allocations: i64,
    pub used_allocations: i64,
    pub available_allocations: i64,
    pub active_peers: usize,
    pub idle_peers: usize,
}

/// Allocation info response.
#[derive(Debug, Serialize)]
pub struct AllocationInfo {
    pub prefix: String,
    pub pubkey: String,
    pub endpoint: Option<String>,
    pub nft_contract: String,
    pub source: String,
    pub allocated_at: String,
    pub last_seen_at: Option<String>,
    pub expires_at: Option<String>,
    pub status: String,
}

/// Client configuration response (static broker info fetched through tunnel).
#[derive(Debug, Serialize)]
pub struct ClientConfigResponse {
    pub dns_zone: String,
}

/// Create allocation request body.
#[derive(Debug, Deserialize)]
pub struct CreateAllocationRequest {
    pub wg_pubkey: String,
    pub nft_contract: String,
    /// Identifies the adapter instance (e.g. "opnet-regtest", "evm-sepolia").
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub is_test: bool,
    /// Lease duration in seconds. If set, the allocation expires after this time.
    pub lease_duration: Option<u64>,
}

/// Create allocation response body.
#[derive(Debug, Serialize)]
pub struct CreateAllocationResponse {
    pub prefix: String,
    pub gateway: String,
    pub broker_pubkey: String,
    pub broker_endpoint: String,
}

/// Error response.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(self)).into_response()
    }
}

/// Create the API router.
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/status", get(status))
        .route("/v1/allocations", get(list_allocations).post(create_allocation))
        .route("/v1/allocations/{prefix}", get(get_allocation).delete(delete_allocation))
        .route("/v1/config", get(client_config))
        .with_state(Arc::new(state))
}

/// Health check endpoint (no auth required).
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Client configuration — static broker info fetched through the tunnel.
async fn client_config(State(state): State<Arc<AppState>>) -> Json<ClientConfigResponse> {
    Json(ClientConfigResponse {
        dns_zone: state.config.dns.domain.clone(),
    })
}

/// Get broker status.
async fn status(State(state): State<Arc<AppState>>) -> Result<Json<StatusResponse>, ErrorResponse> {
    let ipam = state.ipam.lock().await;
    let stats = ipam.get_stats().await.map_err(|e| ErrorResponse {
        error: e.to_string(),
    })?;
    drop(ipam);

    let peers = state.wg.list_peers().unwrap_or_default();
    let active = peers.iter().filter(|p| p.is_active()).count();
    let idle = peers.len() - active;

    Ok(Json(StatusResponse {
        upstream_prefix: stats.upstream_prefix,
        allocation_size: stats.allocation_size,
        total_allocations: stats.total_allocations,
        used_allocations: stats.used_allocations,
        available_allocations: stats.available_allocations,
        active_peers: active,
        idle_peers: idle,
    }))
}

/// Create a new allocation (used by external chain adapters).
///
/// If the NFT contract already has an allocation, the WG pubkey is updated
/// and the same prefix is returned (re-request).
async fn create_allocation(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateAllocationRequest>,
) -> Result<(StatusCode, Json<CreateAllocationResponse>), (StatusCode, Json<ErrorResponse>)> {
    let nft_contract = body.nft_contract.to_lowercase();

    let ipam = state.ipam.lock().await;
    let existing = ipam
        .get_allocation_by_nft_contract(&nft_contract)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e.to_string() }),
            )
        })?;

    let allocation = if let Some(existing) = existing {
        // Re-request: update pubkey, swap WG peer
        info!(
            nft_contract = %nft_contract,
            prefix = %existing.prefix,
            old_pubkey = %existing.pubkey,
            new_pubkey = %body.wg_pubkey,
            "Re-request from existing allocation, updating pubkey"
        );

        let updated = ipam
            .update_allocation_pubkey(&nft_contract, &body.wg_pubkey, None)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse { error: e.to_string() }),
                )
            })?;
        drop(ipam);

        let _ = state.wg.remove_peer(&existing.pubkey);
        state
            .wg
            .add_peer(&body.wg_pubkey, &updated.prefix, None)
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("Failed to add WireGuard peer: {}", e),
                    }),
                )
            })?;

        updated
    } else {
        // New allocation
        let allocation = ipam
            .allocate(&body.wg_pubkey, &nft_contract, None, body.is_test, &body.source, body.lease_duration)
            .await
            .map_err(|e| {
                let (status, msg) = match &e {
                    crate::db::ipam::IpamError::PubkeyAlreadyAllocated => {
                        (StatusCode::CONFLICT, "WireGuard pubkey already has an allocation")
                    }
                    crate::db::ipam::IpamError::NoPrefixesAvailable => {
                        (StatusCode::SERVICE_UNAVAILABLE, "No prefixes available")
                    }
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, "Allocation failed"),
                };
                warn!(nft_contract = %nft_contract, error = %e, "Allocation failed");
                (status, Json(ErrorResponse { error: msg.to_string() }))
            })?;
        drop(ipam);

        // Add WireGuard peer
        if let Err(e) = state.wg.add_peer(&body.wg_pubkey, &allocation.prefix, None) {
            // Rollback
            warn!(error = %e, "Failed to add WG peer, rolling back allocation");
            let ipam = state.ipam.lock().await;
            let _ = ipam.release(&allocation.prefix.to_string(), &nft_contract).await;
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to add WireGuard peer: {}", e),
                }),
            ));
        }

        allocation
    };

    // Build response from broker config
    let broker_pubkey = state.wg.get_public_key().unwrap_or_default();

    info!(
        prefix = %allocation.prefix,
        nft_contract = %nft_contract,
        "Allocation created via API"
    );

    Ok((
        StatusCode::CREATED,
        Json(CreateAllocationResponse {
            prefix: allocation.prefix.to_string(),
            gateway: state.config.broker.broker_ipv6.to_string(),
            broker_pubkey,
            broker_endpoint: state.config.wireguard.public_endpoint.clone(),
        }),
    ))
}

/// List all allocations.
async fn list_allocations(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<AllocationInfo>>, ErrorResponse> {
    let ipam = state.ipam.lock().await;
    let allocations = ipam.list_allocations().await.map_err(|e| ErrorResponse {
        error: e.to_string(),
    })?;

    let infos: Vec<AllocationInfo> = allocations
        .into_iter()
        .map(|a| {
            let peer_status = state.wg.get_peer_status(&a.pubkey).ok().flatten();
            let status = match peer_status {
                Some(p) if p.is_active() => "active",
                Some(p) if p.latest_handshake.is_some() => "idle",
                _ => "never_connected",
            };

            AllocationInfo {
                prefix: a.prefix.to_string(),
                pubkey: a.pubkey,
                endpoint: a.endpoint,
                nft_contract: a.nft_contract,
                source: a.source,
                allocated_at: a.allocated_at.to_rfc3339(),
                last_seen_at: a.last_seen_at.map(|dt| dt.to_rfc3339()),
                expires_at: a.expires_at.map(|dt| dt.to_rfc3339()),
                status: status.to_string(),
            }
        })
        .collect();

    Ok(Json(infos))
}

/// Validate that a string is a valid IPv6 CIDR prefix.
fn validate_prefix(prefix: &str) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    prefix.parse::<ipnet::Ipv6Net>().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid IPv6 prefix format".to_string(),
            }),
        )
    })?;
    Ok(())
}

/// Get a specific allocation.
async fn get_allocation(
    State(state): State<Arc<AppState>>,
    Path(prefix): Path<String>,
) -> Result<Json<AllocationInfo>, (StatusCode, Json<ErrorResponse>)> {
    validate_prefix(&prefix)?;
    let ipam = state.ipam.lock().await;
    let allocation = ipam.get_allocation_by_prefix(&prefix).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    match allocation {
        Some(a) => {
            let peer_status = state.wg.get_peer_status(&a.pubkey).ok().flatten();
            let status = match peer_status {
                Some(p) if p.is_active() => "active",
                Some(p) if p.latest_handshake.is_some() => "idle",
                _ => "never_connected",
            };

            Ok(Json(AllocationInfo {
                prefix: a.prefix.to_string(),
                pubkey: a.pubkey,
                endpoint: a.endpoint,
                nft_contract: a.nft_contract,
                source: a.source,
                allocated_at: a.allocated_at.to_rfc3339(),
                last_seen_at: a.last_seen_at.map(|dt| dt.to_rfc3339()),
                expires_at: a.expires_at.map(|dt| dt.to_rfc3339()),
                status: status.to_string(),
            }))
        }
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Allocation not found".to_string(),
            }),
        )),
    }
}

/// Delete/release an allocation.
async fn delete_allocation(
    State(state): State<Arc<AppState>>,
    Path(prefix): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    validate_prefix(&prefix)?;
    let ipam = state.ipam.lock().await;

    // Get allocation first to get pubkey for WireGuard cleanup
    let allocation = ipam.get_allocation_by_prefix(&prefix).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    match allocation {
        Some(a) => {
            // Remove WireGuard peer
            let _ = state.wg.remove_peer(&a.pubkey);

            // Release from IPAM
            let released = ipam.release(&prefix, &a.nft_contract).await.map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: e.to_string(),
                    }),
                )
            })?;

            if released {
                info!(prefix = %prefix, "Released allocation via API");
                Ok(StatusCode::NO_CONTENT)
            } else {
                Err((
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Allocation not found".to_string(),
                    }),
                ))
            }
        }
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Allocation not found".to_string(),
            }),
        )),
    }
}
