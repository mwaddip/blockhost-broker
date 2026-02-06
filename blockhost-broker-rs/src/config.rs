//! Configuration management for blockhost-broker.

use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use ipnet::Ipv6Net;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default configuration file path.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/blockhost-broker/config.toml";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    ReadError(#[from] std::io::Error),

    #[error("Failed to parse config: {0}")]
    ParseError(#[from] toml::de::Error),

    #[error("Invalid configuration: {0}")]
    ValidationError(String),
}

/// On-chain broker authentication configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct OnchainConfig {
    /// Enable on-chain authentication (disables REST API allocation).
    pub enabled: bool,

    /// Ethereum RPC URL.
    pub rpc_url: String,

    /// Chain ID (11155111 = Sepolia).
    pub chain_id: u64,

    /// Path to file containing operator private key (hex).
    pub private_key_file: PathBuf,

    /// Path to file containing ECIES private key (hex, secp256k1).
    pub ecies_private_key_file: PathBuf,

    /// BrokerRegistry contract address.
    pub registry_contract: Option<String>,

    /// BrokerRequests contract address (this broker's instance).
    pub requests_contract: Option<String>,

    /// Poll interval for pending requests (milliseconds).
    pub poll_interval_ms: u64,
}

impl Default for OnchainConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rpc_url: "https://ethereum-sepolia-rpc.publicnode.com".to_string(),
            chain_id: 11155111,
            private_key_file: PathBuf::from("/etc/blockhost-broker/deployer.key"),
            ecies_private_key_file: PathBuf::from("/etc/blockhost-broker/ecies.key"),
            registry_contract: None,
            requests_contract: None,
            poll_interval_ms: 5000,
        }
    }
}

impl OnchainConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.poll_interval_ms < 1000 {
            return Err(ConfigError::ValidationError(
                "poll_interval_ms must be at least 1000ms".to_string(),
            ));
        }
        if self.poll_interval_ms > 60000 {
            return Err(ConfigError::ValidationError(
                "poll_interval_ms must be at most 60000ms".to_string(),
            ));
        }
        Ok(())
    }
}

/// Broker configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BrokerConfig {
    /// Upstream prefix from tunnel provider.
    #[serde(with = "ipv6net_serde")]
    pub upstream_prefix: Ipv6Net,

    /// Size of allocations to hand out (prefix length).
    pub allocation_size: u8,

    /// Broker's own IPv6 address.
    pub broker_ipv6: Ipv6Addr,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            upstream_prefix: "2a11:6c7:f04:276::/64".parse().unwrap(),
            allocation_size: 120,
            broker_ipv6: "2a11:6c7:f04:276::2".parse().unwrap(),
        }
    }
}

impl BrokerConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.allocation_size < 64 || self.allocation_size > 128 {
            return Err(ConfigError::ValidationError(
                "allocation_size must be between 64 and 128".to_string(),
            ));
        }
        Ok(())
    }

    /// Calculate the maximum number of allocations possible.
    pub fn max_allocations(&self) -> u64 {
        let upstream_bits = 128 - self.upstream_prefix.prefix_len();
        let alloc_bits = 128 - self.allocation_size;
        if upstream_bits <= alloc_bits {
            0
        } else {
            (1u64 << (upstream_bits - alloc_bits)) - 1 // -1 for reserved index 0
        }
    }
}

/// WireGuard configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct WireGuardConfig {
    /// WireGuard interface name.
    pub interface: String,

    /// WireGuard listen port.
    pub listen_port: u16,

    /// Path to WireGuard private key file.
    pub private_key_file: PathBuf,

    /// Public endpoint for clients to connect to.
    pub public_endpoint: String,

    /// Upstream interface for NDP proxy (e.g., tunnel interface to provider).
    /// If set, NDP proxy entries will be added/removed when peers are added/removed.
    pub upstream_interface: Option<String>,
}

impl Default for WireGuardConfig {
    fn default() -> Self {
        Self {
            interface: "wg-broker".to_string(),
            listen_port: 51820,
            private_key_file: PathBuf::from("/etc/blockhost-broker/wg-private.key"),
            public_endpoint: "127.0.0.1:51820".to_string(),
            upstream_interface: None,
        }
    }
}

/// API server configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ApiConfig {
    /// Listen address.
    pub listen_host: String,

    /// Listen port.
    pub listen_port: u16,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen_host: "0.0.0.0".to_string(),
            listen_port: 8080,
        }
    }
}

impl ApiConfig {
    pub fn socket_addr(&self) -> Result<SocketAddr, ConfigError> {
        format!("{}:{}", self.listen_host, self.listen_port)
            .parse()
            .map_err(|_| ConfigError::ValidationError("Invalid listen address".to_string()))
    }
}

/// Database configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DatabaseConfig {
    /// Path to SQLite database.
    pub path: PathBuf,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/var/lib/blockhost-broker/ipam.db"),
        }
    }
}

/// Main configuration container.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct Config {
    pub broker: BrokerConfig,
    pub wireguard: WireGuardConfig,
    pub api: ApiConfig,
    pub database: DatabaseConfig,
    pub onchain: OnchainConfig,
}

impl Config {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.broker.validate()?;
        self.onchain.validate()?;
        Ok(())
    }
}

/// Load configuration from the default or specified path.
pub fn load_config(path: Option<&std::path::Path>) -> Result<Config, ConfigError> {
    let config_path = path.unwrap_or(std::path::Path::new(DEFAULT_CONFIG_PATH));
    Config::from_file(config_path)
}

/// Custom serde for Ipv6Net.
mod ipv6net_serde {
    use ipnet::Ipv6Net;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(net: &Ipv6Net, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&net.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Ipv6Net, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(!config.onchain.enabled);
        assert_eq!(config.broker.allocation_size, 120);
    }

    #[test]
    fn test_max_allocations() {
        let config = BrokerConfig {
            upstream_prefix: "2001:db8::/48".parse().unwrap(),
            allocation_size: 64,
            broker_ipv6: "2001:db8::1".parse().unwrap(),
        };
        // /48 to /64 = 16 bits = 65535 allocations (minus 1 reserved)
        assert_eq!(config.max_allocations(), 65535);
    }

    #[test]
    fn test_parse_config() {
        let toml = r#"
[broker]
upstream_prefix = "2001:db8::/48"
allocation_size = 64
broker_ipv6 = "2001:db8::1"

[wireguard]
interface = "wg0"
listen_port = 51821
public_endpoint = "example.com:51821"

[onchain]
enabled = true
requests_contract = "0x1234567890123456789012345678901234567890"
poll_interval_ms = 3000
"#;

        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.onchain.enabled);
        assert_eq!(config.broker.allocation_size, 64);
        assert_eq!(config.wireguard.interface, "wg0");
        assert_eq!(config.onchain.poll_interval_ms, 3000);
    }
}
