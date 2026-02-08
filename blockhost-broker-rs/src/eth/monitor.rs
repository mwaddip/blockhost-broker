//! On-chain event monitor for broker requests.
//!
//! Uses lazy polling to check for new requests instead of unbounded loops.
//! Supports a primary contract and optional legacy contracts.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use chrono::{DateTime, TimeZone, Utc};
use ethers::prelude::*;
use thiserror::Error;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::config::{BrokerConfig, OnchainConfig, WireGuardConfig};
use crate::crypto::{EciesEncryption, RequestPayload, ResponsePayload};
use crate::db::Ipam;
use crate::wg::WireGuardManager;

use super::contracts::{BrokerRequestsContract, RequestData, RequestStatus};
use super::verifier::NftVerifier;

#[derive(Debug, Error)]
pub enum MonitorError {
    #[error("Provider error: {0}")]
    Provider(#[from] ProviderError),

    #[error("Contract error: {0}")]
    Contract(String),

    #[error("Database error: {0}")]
    Database(#[from] crate::db::ipam::IpamError),

    #[error("Encryption error: {0}")]
    Encryption(#[from] crate::crypto::ecies::EciesError),

    #[error("WireGuard error: {0}")]
    WireGuard(#[from] crate::wg::WireGuardError),

    #[error("Wallet error: {0}")]
    Wallet(#[from] WalletError),

    #[error("Configuration error: {0}")]
    Config(String),
}

/// A pending allocation request from the blockchain.
#[derive(Debug, Clone)]
pub struct PendingRequest {
    pub id: u64,
    pub requester: Address,
    pub nft_contract: Address,
    pub encrypted_payload: Bytes,
    pub submitted_at: DateTime<Utc>,
}

type SignerMiddleware = ethers::middleware::SignerMiddleware<Provider<Http>, LocalWallet>;

/// How long to wait for a WireGuard handshake after approval before releasing.
const TUNNEL_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(120);

/// An approved allocation awaiting WireGuard tunnel establishment.
struct PendingVerification {
    nft_contract: Address,
    pubkey: String,
    prefix: String,
    approved_at: Instant,
    /// Which contract this allocation was approved on.
    contract_address: String,
}

/// Monitors BrokerRequests contract for new allocation requests.
pub struct OnchainMonitor {
    onchain_config: OnchainConfig,
    broker_config: BrokerConfig,
    wg_config: WireGuardConfig,
    ipam: Arc<tokio::sync::Mutex<Ipam>>,
    wg: Arc<WireGuardManager>,
    provider: Provider<Http>,
    wallet: LocalWallet,
    encryption: EciesEncryption,
    verifier: NftVerifier,
    primary_contract: BrokerRequestsContract<SignerMiddleware>,
    primary_address: String,
    legacy_contracts: Vec<(String, BrokerRequestsContract<SignerMiddleware>)>,
    shutdown_rx: watch::Receiver<bool>,
    shutdown_tx: watch::Sender<bool>,
    pending_verifications: Vec<PendingVerification>,
}

impl OnchainMonitor {
    /// Create a new on-chain monitor.
    pub async fn new(
        onchain_config: OnchainConfig,
        broker_config: BrokerConfig,
        wg_config: WireGuardConfig,
        ipam: Arc<tokio::sync::Mutex<Ipam>>,
        wg: Arc<WireGuardManager>,
    ) -> Result<Self, MonitorError> {
        // Validate config
        let requests_contract_addr = onchain_config
            .requests_contract
            .as_ref()
            .ok_or_else(|| MonitorError::Config("requests_contract must be set".to_string()))?
            .clone();

        // Initialize provider
        let provider = Provider::<Http>::try_from(&onchain_config.rpc_url)
            .map_err(|e| MonitorError::Config(format!("Invalid RPC URL: {}", e)))?;

        // Load operator wallet (with size limit to catch misconfigured paths)
        let key_metadata = std::fs::metadata(&onchain_config.private_key_file)
            .map_err(|e| MonitorError::Config(format!("Failed to read private key: {}", e)))?;
        if key_metadata.len() > 1024 {
            return Err(MonitorError::Config("Private key file too large (>1KB)".to_string()));
        }
        let private_key = std::fs::read_to_string(&onchain_config.private_key_file)
            .map_err(|e| MonitorError::Config(format!("Failed to read private key: {}", e)))?;
        let wallet: LocalWallet = private_key
            .trim()
            .parse::<LocalWallet>()?
            .with_chain_id(onchain_config.chain_id);

        // Load ECIES encryption key
        let encryption = EciesEncryption::from_file(&onchain_config.ecies_private_key_file)?;

        // Initialize verifier
        let verifier = NftVerifier::new(provider.clone());

        // Initialize signing middleware
        let client = Arc::new(SignerMiddleware::new(provider.clone(), wallet.clone()));

        // Initialize primary contract
        let primary_address: Address = requests_contract_addr
            .parse()
            .map_err(|_| MonitorError::Config("Invalid requests contract address".to_string()))?;
        let primary_contract = BrokerRequestsContract::new(primary_address, client.clone());

        // Initialize legacy contracts
        let mut legacy_contracts = Vec::new();
        for legacy_addr_str in &onchain_config.legacy_requests_contracts {
            let legacy_addr: Address = legacy_addr_str
                .parse()
                .map_err(|_| MonitorError::Config(format!("Invalid legacy contract address: {}", legacy_addr_str)))?;
            let legacy_contract = BrokerRequestsContract::new(legacy_addr, client.clone());
            legacy_contracts.push((legacy_addr_str.to_lowercase(), legacy_contract));
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Migrate legacy last_processed_id if needed
        if !onchain_config.legacy_requests_contracts.is_empty() {
            let ipam_lock = ipam.lock().await;
            for legacy_addr_str in &onchain_config.legacy_requests_contracts {
                if let Err(e) = ipam_lock.migrate_last_processed_id(legacy_addr_str).await {
                    warn!(
                        contract = legacy_addr_str.as_str(),
                        error = %e,
                        "Failed to migrate last_processed_id for legacy contract"
                    );
                }
            }
        }

        Ok(Self {
            onchain_config,
            broker_config,
            wg_config,
            ipam,
            wg,
            provider,
            wallet,
            encryption,
            verifier,
            primary_contract,
            primary_address: requests_contract_addr.to_lowercase(),
            legacy_contracts,
            shutdown_rx,
            shutdown_tx,
            pending_verifications: Vec::new(),
        })
    }

    /// Start the on-chain monitor loop.
    pub async fn start(&mut self) -> Result<(), MonitorError> {
        info!(
            contract = %self.primary_address,
            legacy_count = self.legacy_contracts.len(),
            poll_interval_ms = %self.onchain_config.poll_interval_ms,
            "Starting on-chain monitor"
        );

        // Sync on-chain capacity with config
        self.sync_capacity().await;

        let poll_interval = Duration::from_millis(self.onchain_config.poll_interval_ms);

        loop {
            tokio::select! {
                _ = tokio::time::sleep(poll_interval) => {
                    // Poll primary contract
                    if let Err(e) = self.poll_requests_for_contract(&self.primary_contract.clone(), &self.primary_address.clone()).await {
                        error!(contract = %self.primary_address, error = %e, "Error polling primary contract");
                    }

                    // Poll legacy contracts
                    for (addr, contract) in self.legacy_contracts.clone() {
                        if let Err(e) = self.poll_requests_for_contract(&contract, &addr).await {
                            error!(contract = %addr, error = %e, "Error polling legacy contract");
                        }
                    }

                    self.check_pending_verifications().await;
                }
                _ = self.shutdown_rx.changed() => {
                    if *self.shutdown_rx.borrow() {
                        info!("Shutdown signal received, stopping monitor");
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Stop the on-chain monitor.
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Sync on-chain totalCapacity with config max_allocations (if explicitly set).
    /// If max_allocations is not configured, sets totalCapacity to 0 (unlimited).
    async fn sync_capacity(&self) {
        let desired = self.broker_config.max_allocations.unwrap_or(0);
        let on_chain = match self.primary_contract.total_capacity().call().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "Failed to read on-chain totalCapacity");
                return;
            }
        };

        let on_chain_u64 = on_chain.as_u64();
        if on_chain_u64 == desired {
            return;
        }

        info!(
            on_chain = on_chain_u64,
            desired = desired,
            "Syncing on-chain totalCapacity with config"
        );

        let call = self.primary_contract.set_total_capacity(U256::from(desired));
        let pending_tx = match call.send().await {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "Failed to send setTotalCapacity transaction");
                return;
            }
        };

        match pending_tx.await {
            Ok(Some(receipt)) if receipt.status == Some(1.into()) => {
                info!("On-chain totalCapacity updated to {}", desired);
            }
            Ok(_) => {
                warn!("setTotalCapacity transaction failed or no receipt");
            }
            Err(e) => {
                warn!(error = %e, "Failed to confirm setTotalCapacity");
            }
        }
    }

    /// Poll for new requests on a specific contract.
    async fn poll_requests_for_contract(
        &mut self,
        contract: &BrokerRequestsContract<SignerMiddleware>,
        contract_address: &str,
    ) -> Result<(), MonitorError> {
        // Get total request count
        let count: U256 = contract
            .get_request_count()
            .call()
            .await
            .map_err(|e| MonitorError::Contract(e.to_string()))?;

        let count = count.as_u64();

        // Get last processed ID from database (per-contract)
        let ipam = self.ipam.lock().await;
        let last_processed = ipam.get_last_processed_id_for_contract(contract_address).await?;
        drop(ipam);

        if count == 0 || last_processed >= count {
            return Ok(());
        }

        debug!(
            contract = contract_address,
            last_processed = last_processed,
            total_count = count,
            "Checking for new requests"
        );

        // Process new requests
        for id in (last_processed + 1)..=count {
            let request = contract
                .get_request(U256::from(id))
                .call()
                .await
                .map_err(|e| MonitorError::Contract(e.to_string()))?;

            let status = RequestStatus::from(request.status);

            if status.is_pending() {
                let pending = PendingRequest {
                    id,
                    requester: request.requester,
                    nft_contract: request.nft_contract,
                    encrypted_payload: request.encrypted_payload,
                    submitted_at: Utc.timestamp_opt(request.submitted_at.as_u64() as i64, 0)
                        .single()
                        .unwrap_or_else(Utc::now),
                };

                if let Err(e) = self.process_request(pending, contract, contract_address).await {
                    // Silent rejection - just log and continue
                    warn!(request_id = id, contract = contract_address, error = %e, "Request processing failed (silent rejection)");
                }
            }

            // Update last processed ID (per-contract)
            let ipam = self.ipam.lock().await;
            ipam.set_last_processed_id_for_contract(contract_address, id).await?;
        }

        Ok(())
    }

    /// Process a single pending allocation request.
    async fn process_request(
        &mut self,
        request: PendingRequest,
        contract: &BrokerRequestsContract<SignerMiddleware>,
        contract_address: &str,
    ) -> Result<(), MonitorError> {
        info!(
            request_id = request.id,
            requester = %request.requester,
            nft_contract = %request.nft_contract,
            contract = contract_address,
            "Processing request"
        );

        // Verify NFT ownership
        let verification = self
            .verifier
            .verify_request(request.nft_contract, request.requester)
            .await;

        if !verification.valid {
            warn!(
                request_id = request.id,
                error = ?verification.error,
                "Request verification failed"
            );
            // Silent rejection - don't submit response, let it expire
            return Ok(());
        }

        // Decrypt request payload
        let payload: RequestPayload = self
            .encryption
            .decrypt_request_payload(&request.encrypted_payload)?;

        let nft_contract_str = format!("{:?}", request.nft_contract).to_lowercase();

        // Check if this NFT contract already has an allocation
        let ipam = self.ipam.lock().await;
        let existing_allocation = ipam
            .get_allocation_by_nft_contract(&nft_contract_str)
            .await?;

        let allocation = if let Some(existing) = existing_allocation {
            // Re-request from the same NFT contract - update pubkey and re-send same allocation
            info!(
                request_id = request.id,
                prefix = %existing.prefix,
                old_pubkey = %existing.pubkey,
                new_pubkey = %payload.wg_pubkey,
                "Re-request from existing allocation, updating pubkey"
            );

            // Update the pubkey in the database
            let updated = ipam
                .update_allocation_pubkey(&nft_contract_str, &payload.wg_pubkey, None)
                .await?;
            drop(ipam);

            // Remove old WireGuard peer and add new one
            let _ = self.wg.remove_peer(&existing.pubkey);
            if let Err(e) = self.wg.add_peer(&payload.wg_pubkey, &updated.prefix, None) {
                error!(
                    request_id = request.id,
                    error = %e,
                    "Failed to add WireGuard peer for re-request"
                );
                return Err(e.into());
            }

            // Remove stale pending_verification for the old pubkey (fix 5e)
            self.pending_verifications.retain(|pv| {
                let same_nft = pv.nft_contract == request.nft_contract;
                if same_nft {
                    info!(
                        pubkey = %pv.pubkey,
                        prefix = %pv.prefix,
                        "Removing stale pending verification for re-request"
                    );
                }
                !same_nft
            });

            updated
        } else {
            // New allocation
            let allocation = match ipam
                .allocate(
                    &payload.wg_pubkey,
                    &nft_contract_str,
                    None,
                )
                .await
            {
                Ok(alloc) => alloc,
                Err(crate::db::ipam::IpamError::PubkeyAlreadyAllocated) => {
                    warn!(
                        request_id = request.id,
                        "WireGuard pubkey already has allocation"
                    );
                    return Ok(()); // Silent rejection
                }
                Err(crate::db::ipam::IpamError::NoPrefixesAvailable) => {
                    error!(request_id = request.id, "No prefixes available");
                    return Ok(()); // Silent rejection
                }
                Err(e) => return Err(e.into()),
            };
            drop(ipam);

            // Add WireGuard peer
            if let Err(e) = self.wg.add_peer(&payload.wg_pubkey, &allocation.prefix, None) {
                error!(
                    request_id = request.id,
                    error = %e,
                    "Failed to add WireGuard peer"
                );
                // Rollback allocation
                self.rollback_allocation(&payload.wg_pubkey, &allocation.prefix.to_string(), &nft_contract_str).await;
                return Err(e.into());
            }

            allocation
        };

        // Get broker WireGuard public key
        let wg_pubkey = match self.wg.get_public_key() {
            Some(key) => key,
            None => {
                error!(request_id = request.id, "Could not get broker WireGuard public key");
                self.rollback_allocation(&payload.wg_pubkey, &allocation.prefix.to_string(), &nft_contract_str).await;
                return Ok(()); // Silent rejection
            }
        };

        // Build response
        let response = ResponsePayload {
            prefix: allocation.prefix.to_string(),
            gateway: self.broker_config.broker_ipv6.to_string(),
            broker_pubkey: wg_pubkey,
            broker_endpoint: self.wg_config.public_endpoint.clone(),
        };

        // Encrypt response for the server's new key
        let encrypted_response = match self
            .encryption
            .encrypt_response_payload(&response, &payload.server_pubkey)
        {
            Ok(r) => r,
            Err(e) => {
                error!(
                    request_id = request.id,
                    error = %e,
                    "Failed to encrypt response"
                );
                self.rollback_allocation(&payload.wg_pubkey, &allocation.prefix.to_string(), &nft_contract_str).await;
                return Err(e.into());
            }
        };

        // Submit approval on-chain
        if let Err(e) = self.submit_approval(request.id, encrypted_response, contract).await {
            // Rollback IPAM + WG on failed on-chain submission
            error!(
                request_id = request.id,
                error = %e,
                "Failed to submit approval on-chain, rolling back allocation"
            );
            self.rollback_allocation(&payload.wg_pubkey, &allocation.prefix.to_string(), &nft_contract_str).await;
            return Err(e);
        }

        // Track for tunnel verification — if no WG handshake within timeout,
        // release the allocation so the client can re-request with a new key.
        self.pending_verifications.push(PendingVerification {
            nft_contract: request.nft_contract,
            pubkey: payload.wg_pubkey.clone(),
            prefix: allocation.prefix.to_string(),
            approved_at: Instant::now(),
            contract_address: contract_address.to_string(),
        });

        info!(
            request_id = request.id,
            prefix = %allocation.prefix,
            contract = contract_address,
            "Request approved"
        );

        Ok(())
    }

    /// Rollback a failed allocation: remove WireGuard peer and release IPAM prefix.
    async fn rollback_allocation(&self, pubkey: &str, prefix: &str, nft_contract: &str) {
        let _ = self.wg.remove_peer(pubkey);
        let ipam = self.ipam.lock().await;
        let _ = ipam.release(prefix, nft_contract).await;
    }

    /// Submit an approval response on-chain.
    ///
    /// Prepends the request ID as an 8-byte big-endian prefix before the encrypted
    /// payload so the client can identify stale responses without attempting decryption.
    async fn submit_approval(
        &self,
        request_id: u64,
        encrypted_payload: Vec<u8>,
        contract: &BrokerRequestsContract<SignerMiddleware>,
    ) -> Result<(), MonitorError> {
        let mut prefixed_payload = Vec::with_capacity(8 + encrypted_payload.len());
        prefixed_payload.extend_from_slice(&request_id.to_be_bytes());
        prefixed_payload.extend(encrypted_payload);

        let tx = contract.submit_response(
            U256::from(request_id),
            Bytes::from(prefixed_payload),
        );

        let pending_tx = tx.send().await.map_err(|e| MonitorError::Contract(e.to_string()))?;

        info!(
            request_id = request_id,
            tx_hash = %pending_tx.tx_hash(),
            "Submitted approval transaction"
        );

        // Wait for confirmation
        let receipt = pending_tx
            .await
            .map_err(|e| MonitorError::Contract(e.to_string()))?;

        match receipt {
            Some(r) if r.status == Some(1.into()) => {
                info!(
                    request_id = request_id,
                    tx_hash = %r.transaction_hash,
                    "Approval confirmed"
                );
                Ok(())
            }
            Some(r) => {
                error!(
                    request_id = request_id,
                    tx_hash = %r.transaction_hash,
                    "Approval transaction failed"
                );
                Err(MonitorError::Contract("Transaction failed".to_string()))
            }
            None => {
                error!(request_id = request_id, "No receipt received");
                Err(MonitorError::Contract("No receipt".to_string()))
            }
        }
    }

    /// Check pending verifications — release allocations where no WG handshake
    /// has occurred within the verification timeout.
    async fn check_pending_verifications(&mut self) {
        if self.pending_verifications.is_empty() {
            return;
        }

        let mut to_release = Vec::new();
        let mut to_keep = Vec::new();

        for pv in self.pending_verifications.drain(..) {
            if pv.approved_at.elapsed() < TUNNEL_VERIFICATION_TIMEOUT {
                to_keep.push(pv);
                continue;
            }

            // Timeout reached — check if a handshake ever happened
            match self.wg.get_peer_status(&pv.pubkey) {
                Ok(Some(status)) if status.latest_handshake.is_some() => {
                    info!(
                        pubkey = %pv.pubkey,
                        prefix = %pv.prefix,
                        "Tunnel verification passed — handshake detected"
                    );
                    // Verified, drop from list
                }
                Ok(_) => {
                    // No handshake (peer not found or never connected)
                    warn!(
                        pubkey = %pv.pubkey,
                        prefix = %pv.prefix,
                        nft_contract = %pv.nft_contract,
                        "No WG handshake within verification timeout — releasing allocation"
                    );
                    to_release.push(pv);
                }
                Err(e) => {
                    warn!(
                        pubkey = %pv.pubkey,
                        error = %e,
                        "Failed to check peer status — keeping verification pending"
                    );
                    to_keep.push(pv);
                }
            }
        }

        self.pending_verifications = to_keep;

        for pv in to_release {
            // Resolve which contract to release on
            let contract = self.resolve_contract(&pv.contract_address);
            if let Err(e) = self
                .release_allocation(pv.nft_contract, &pv.prefix, &pv.pubkey, contract)
                .await
            {
                error!(
                    nft_contract = %pv.nft_contract,
                    prefix = %pv.prefix,
                    error = %e,
                    "Failed to release unverified allocation"
                );
            }
        }
    }

    /// Resolve a contract reference by address string.
    fn resolve_contract(&self, contract_address: &str) -> &BrokerRequestsContract<SignerMiddleware> {
        if contract_address == self.primary_address {
            return &self.primary_contract;
        }
        for (addr, contract) in &self.legacy_contracts {
            if addr == contract_address {
                return contract;
            }
        }
        // Fallback to primary (shouldn't happen)
        &self.primary_contract
    }

    /// Release an allocation.
    pub async fn release_allocation(
        &self,
        nft_contract: Address,
        prefix: &str,
        pubkey: &str,
        contract: &BrokerRequestsContract<SignerMiddleware>,
    ) -> Result<(), MonitorError> {
        // Remove WireGuard peer
        let _ = self.wg.remove_peer(pubkey);

        // Release from IPAM
        let ipam = self.ipam.lock().await;
        let _ = ipam.release(prefix, &format!("{:?}", nft_contract).to_lowercase()).await;
        drop(ipam);

        // Release on-chain
        let tx = contract.release_allocation(nft_contract);
        let pending_tx = tx.send().await.map_err(|e| MonitorError::Contract(e.to_string()))?;

        info!(
            nft_contract = %nft_contract,
            tx_hash = %pending_tx.tx_hash(),
            "Submitted release transaction"
        );

        let receipt = pending_tx
            .await
            .map_err(|e| MonitorError::Contract(e.to_string()))?;

        match receipt {
            Some(r) if r.status == Some(1.into()) => {
                info!(
                    nft_contract = %nft_contract,
                    tx_hash = %r.transaction_hash,
                    "Release confirmed"
                );
                Ok(())
            }
            _ => Err(MonitorError::Contract("Release transaction failed".to_string())),
        }
    }
}
