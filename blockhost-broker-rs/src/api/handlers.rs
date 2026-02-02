//! REST API handlers for internal management.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, delete},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::info;

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
    pub allocated_at: String,
    pub last_seen_at: Option<String>,
    pub status: String,
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
        .route("/v1/allocations", get(list_allocations))
        .route("/v1/allocations/{prefix}", get(get_allocation).delete(delete_allocation))
        .with_state(Arc::new(state))
}

/// Health check endpoint (no auth required).
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
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
                allocated_at: a.allocated_at.to_rfc3339(),
                last_seen_at: a.last_seen_at.map(|dt| dt.to_rfc3339()),
                status: status.to_string(),
            }
        })
        .collect();

    Ok(Json(infos))
}

/// Get a specific allocation.
async fn get_allocation(
    State(state): State<Arc<AppState>>,
    Path(prefix): Path<String>,
) -> Result<Json<AllocationInfo>, (StatusCode, Json<ErrorResponse>)> {
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
                allocated_at: a.allocated_at.to_rfc3339(),
                last_seen_at: a.last_seen_at.map(|dt| dt.to_rfc3339()),
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
