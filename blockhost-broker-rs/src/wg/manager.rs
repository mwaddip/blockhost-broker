//! WireGuard interface management.

use std::process::Command;

use chrono::{DateTime, TimeZone, Utc};
use ipnet::Ipv6Net;
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::config::WireGuardConfig;

#[derive(Debug, Error)]
pub enum WireGuardError {
    #[error("Command execution failed: {0}")]
    CommandFailed(String),

    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Status of a WireGuard peer.
#[derive(Debug, Clone)]
pub struct PeerStatus {
    pub pubkey: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub latest_handshake: Option<DateTime<Utc>>,
    pub transfer_rx: u64,
    pub transfer_tx: u64,
}

impl PeerStatus {
    /// Check if peer has had a recent handshake (within 5 minutes).
    pub fn is_active(&self) -> bool {
        self.latest_handshake
            .map(|hs| (Utc::now() - hs).num_seconds() < 300)
            .unwrap_or(false)
    }
}

/// Manage WireGuard interface and peers.
pub struct WireGuardManager {
    config: WireGuardConfig,
}

impl WireGuardManager {
    /// Create a new WireGuard manager.
    pub fn new(config: WireGuardConfig) -> Self {
        Self { config }
    }

    /// Run a command and return the output.
    fn run_command(&self, args: &[&str]) -> Result<String, WireGuardError> {
        debug!(command = ?args, "Running command");

        let output = Command::new(args[0])
            .args(&args[1..])
            .output()
            .map_err(|e| WireGuardError::CommandFailed(e.to_string()))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(WireGuardError::CommandFailed(stderr.to_string()))
        }
    }

    /// Run a command that may fail (best effort, logs failures).
    fn run_command_best_effort(&self, args: &[&str]) -> Option<String> {
        match self.run_command(args) {
            Ok(output) => Some(output),
            Err(e) => {
                warn!(command = ?args, error = %e, "Best-effort command failed");
                None
            }
        }
    }

    /// Add a WireGuard peer.
    pub fn add_peer(
        &self,
        pubkey: &str,
        allowed_ips: &Ipv6Net,
        endpoint: Option<&str>,
    ) -> Result<(), WireGuardError> {
        let allowed_ips_str = allowed_ips.to_string();

        let mut args = vec![
            "wg",
            "set",
            &self.config.interface,
            "peer",
            pubkey,
            "allowed-ips",
            &allowed_ips_str,
        ];

        if let Some(ep) = endpoint {
            args.push("endpoint");
            args.push(ep);
        }

        self.run_command(&args)?;

        // Add route for the peer's prefix (best effort)
        let _ = self.run_command_best_effort(&[
            "ip",
            "-6",
            "route",
            "add",
            &allowed_ips_str,
            "dev",
            &self.config.interface,
        ]);

        // Add NDP proxy entries for all addresses in the prefix
        if let Some(ref upstream_if) = self.config.upstream_interface {
            self.add_ndp_proxy_for_prefix(allowed_ips, upstream_if);
        }

        info!(
            pubkey = %pubkey,
            allowed_ips = %allowed_ips,
            "Added WireGuard peer"
        );

        Ok(())
    }

    /// Remove a WireGuard peer.
    pub fn remove_peer(&self, pubkey: &str) -> Result<(), WireGuardError> {
        // Get peer's allowed IPs first for route and NDP proxy cleanup
        if let Some(status) = self.get_peer_status(pubkey)? {
            for allowed_ip in &status.allowed_ips {
                // Remove route
                let _ = self.run_command_best_effort(&[
                    "ip",
                    "-6",
                    "route",
                    "del",
                    allowed_ip,
                    "dev",
                    &self.config.interface,
                ]);

                // Remove NDP proxy entries for the prefix
                if let Some(ref upstream_if) = self.config.upstream_interface {
                    if let Ok(prefix) = allowed_ip.parse::<Ipv6Net>() {
                        self.remove_ndp_proxy_for_prefix(&prefix, upstream_if);
                    }
                }
            }
        }

        self.run_command(&[
            "wg",
            "set",
            &self.config.interface,
            "peer",
            pubkey,
            "remove",
        ])?;

        info!(pubkey = %pubkey, "Removed WireGuard peer");

        Ok(())
    }

    /// Get status of a specific peer.
    pub fn get_peer_status(&self, pubkey: &str) -> Result<Option<PeerStatus>, WireGuardError> {
        let peers = self.list_peers()?;
        Ok(peers.into_iter().find(|p| p.pubkey == pubkey))
    }

    /// List all WireGuard peers with their status.
    pub fn list_peers(&self) -> Result<Vec<PeerStatus>, WireGuardError> {
        let output = match self.run_command(&["wg", "show", &self.config.interface, "dump"]) {
            Ok(o) => o,
            Err(_) => return Ok(vec![]), // Interface might not exist yet
        };

        let mut peers = Vec::new();

        for line in output.lines().skip(1) {
            // Skip interface line
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() < 8 {
                continue;
            }

            let pubkey = parts[0].to_string();
            let endpoint = if parts[2] != "(none)" {
                Some(parts[2].to_string())
            } else {
                None
            };
            let allowed_ips: Vec<String> = if parts[3].is_empty() {
                vec![]
            } else {
                parts[3].split(',').map(|s| s.to_string()).collect()
            };
            let handshake_ts: Option<i64> = parts[4].parse().ok().filter(|&ts| ts != 0);
            let rx_bytes: u64 = parts[5].parse().unwrap_or(0);
            let tx_bytes: u64 = parts[6].parse().unwrap_or(0);

            let latest_handshake =
                handshake_ts.and_then(|ts| Utc.timestamp_opt(ts, 0).single());

            peers.push(PeerStatus {
                pubkey,
                endpoint,
                allowed_ips,
                latest_handshake,
                transfer_rx: rx_bytes,
                transfer_tx: tx_bytes,
            });
        }

        Ok(peers)
    }

    /// Get the interface's public key.
    pub fn get_public_key(&self) -> Option<String> {
        self.run_command(&["wg", "show", &self.config.interface, "public-key"])
            .ok()
            .map(|s| s.trim().to_string())
            .or_else(|| {
                // Fall back to reading from public key file
                let pub_file = self
                    .config
                    .private_key_file
                    .parent()?
                    .join("wg-public.key");
                std::fs::read_to_string(pub_file)
                    .ok()
                    .map(|s| s.trim().to_string())
            })
    }

    /// Check if the WireGuard interface exists.
    pub fn interface_exists(&self) -> bool {
        self.run_command(&["ip", "link", "show", &self.config.interface])
            .is_ok()
    }

    /// Save current WireGuard config to file.
    pub fn save_config(&self) -> Result<(), WireGuardError> {
        let config_path = format!("/etc/wireguard/{}.conf", self.config.interface);
        let output = self.run_command(&["wg", "showconf", &self.config.interface])?;

        std::fs::write(&config_path, output)
            .map_err(|e| WireGuardError::CommandFailed(format!("Failed to write config: {}", e)))?;

        info!(path = %config_path, "Saved WireGuard config");

        Ok(())
    }

    /// Maximum number of NDP proxy entries to add per allocation.
    /// For /120 (256 addresses) or smaller, we add entries for all.
    /// For larger prefixes, we limit to avoid overwhelming the neighbor table.
    const MAX_NDP_PROXY_ENTRIES: u32 = 256;

    /// Calculate all usable addresses in a prefix (up to MAX_NDP_PROXY_ENTRIES).
    /// Skips the network address (e.g., ::700) and returns ::701, ::702, etc.
    fn prefix_addresses(prefix: &Ipv6Net) -> Vec<std::net::Ipv6Addr> {
        use std::net::Ipv6Addr;

        let prefix_len = prefix.prefix_len();
        let host_bits = 128 - prefix_len;

        // Calculate number of addresses in the prefix
        let num_addresses: u128 = if host_bits >= 128 {
            u128::MAX
        } else {
            1u128 << host_bits
        };

        // Limit to MAX_NDP_PROXY_ENTRIES
        let count = std::cmp::min(num_addresses, Self::MAX_NDP_PROXY_ENTRIES as u128) as u32;

        let network_addr: u128 = prefix.network().into();
        let mut addresses = Vec::with_capacity(count as usize);

        // Start from 1 (skip network address) up to count
        for i in 1..=count {
            addresses.push(Ipv6Addr::from(network_addr + i as u128));
        }

        addresses
    }

    /// Add NDP proxy entries for all addresses in a prefix.
    fn add_ndp_proxy_for_prefix(&self, prefix: &Ipv6Net, upstream_interface: &str) {
        let addresses = Self::prefix_addresses(prefix);
        let count = addresses.len();

        for addr in addresses {
            let addr_str = addr.to_string();
            let _ = self.run_command_best_effort(&[
                "ip",
                "-6",
                "neigh",
                "add",
                "proxy",
                &addr_str,
                "dev",
                upstream_interface,
            ]);
        }

        info!(
            prefix = %prefix,
            count = count,
            interface = %upstream_interface,
            "Added NDP proxy entries for prefix"
        );
    }

    /// Remove NDP proxy entries for all addresses in a prefix.
    fn remove_ndp_proxy_for_prefix(&self, prefix: &Ipv6Net, upstream_interface: &str) {
        let addresses = Self::prefix_addresses(prefix);
        let count = addresses.len();

        for addr in addresses {
            let addr_str = addr.to_string();
            let _ = self.run_command_best_effort(&[
                "ip",
                "-6",
                "neigh",
                "del",
                "proxy",
                &addr_str,
                "dev",
                upstream_interface,
            ]);
        }

        debug!(
            prefix = %prefix,
            count = count,
            interface = %upstream_interface,
            "Removed NDP proxy entries for prefix"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_status_is_active() {
        let active_peer = PeerStatus {
            pubkey: "test".to_string(),
            endpoint: None,
            allowed_ips: vec![],
            latest_handshake: Some(Utc::now()),
            transfer_rx: 0,
            transfer_tx: 0,
        };
        assert!(active_peer.is_active());

        let inactive_peer = PeerStatus {
            pubkey: "test".to_string(),
            endpoint: None,
            allowed_ips: vec![],
            latest_handshake: Some(Utc::now() - chrono::Duration::minutes(10)),
            transfer_rx: 0,
            transfer_tx: 0,
        };
        assert!(!inactive_peer.is_active());

        let never_connected = PeerStatus {
            pubkey: "test".to_string(),
            endpoint: None,
            allowed_ips: vec![],
            latest_handshake: None,
            transfer_rx: 0,
            transfer_tx: 0,
        };
        assert!(!never_connected.is_active());
    }
}
