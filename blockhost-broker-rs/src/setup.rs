//! Setup and deployment utilities for blockhost-broker.

use std::net::Ipv6Addr;
use std::path::Path;
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use ethers::prelude::*;
use ipnet::Ipv6Net;

/// Detected IPv6 interface information.
#[derive(Debug, Clone)]
pub struct Ipv6Interface {
    pub name: String,
    pub addresses: Vec<Ipv6Net>,
}

/// Detect IPv6 interfaces with global addresses.
pub fn detect_ipv6_interfaces() -> Result<Vec<Ipv6Interface>> {
    let output = Command::new("ip")
        .args(["-6", "addr", "show", "scope", "global"])
        .output()
        .context("Failed to run 'ip -6 addr show'")?;

    if !output.status.success() {
        return Err(anyhow!("ip command failed"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut interfaces: Vec<Ipv6Interface> = Vec::new();
    let mut current_iface: Option<String> = None;
    let mut current_addrs: Vec<Ipv6Net> = Vec::new();

    for line in stdout.lines() {
        // Interface line: "2: eth0: <BROADCAST,..."
        if let Some(idx) = line.find(':') {
            if !line.starts_with(' ') {
                // Save previous interface
                if let Some(name) = current_iface.take() {
                    if !current_addrs.is_empty() {
                        interfaces.push(Ipv6Interface {
                            name,
                            addresses: std::mem::take(&mut current_addrs),
                        });
                    }
                }
                // Parse new interface name
                let rest = &line[idx + 1..];
                if let Some(name_end) = rest.find(':') {
                    current_iface = Some(rest[1..name_end].to_string());
                }
            }
        }
        // Address line: "    inet6 2001:db8::1/64 scope global"
        if line.trim_start().starts_with("inet6 ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(net) = parts[1].parse::<Ipv6Net>() {
                    // Filter out link-local and temporary addresses
                    if !net.addr().is_loopback()
                        && !is_link_local(&net.addr())
                        && !line.contains("temporary")
                        && !line.contains("deprecated")
                    {
                        current_addrs.push(net);
                    }
                }
            }
        }
    }

    // Save last interface
    if let Some(name) = current_iface {
        if !current_addrs.is_empty() {
            interfaces.push(Ipv6Interface {
                name,
                addresses: current_addrs,
            });
        }
    }

    Ok(interfaces)
}

fn is_link_local(addr: &Ipv6Addr) -> bool {
    let segments = addr.segments();
    segments[0] == 0xfe80
}

/// Suggest allocation sizes for a given prefix.
pub fn suggest_allocation_sizes(prefix: &Ipv6Net) -> Vec<AllocationOption> {
    let prefix_len = prefix.prefix_len();
    let mut options = Vec::new();

    // Common allocation sizes
    let sizes = [
        (64, "Standard /64 (18 quintillion addresses per host)"),
        (112, "/112 (65,536 addresses per host)"),
        (120, "/120 (256 addresses per host)"),
        (124, "/124 (16 addresses per host)"),
        (128, "/128 (Single address per host)"),
    ];

    for (size, description) in sizes {
        if size > prefix_len {
            let num_allocations = 1u128 << (size - prefix_len);
            if num_allocations > 1 {
                options.push(AllocationOption {
                    size,
                    description: description.to_string(),
                    num_allocations,
                });
            }
        }
    }

    options
}

#[derive(Debug, Clone)]
pub struct AllocationOption {
    pub size: u8,
    pub description: String,
    pub num_allocations: u128,
}

/// Get wallet address from private key.
pub fn get_wallet_address(private_key: &str) -> Result<Address> {
    let key = private_key.trim();
    let key = key.strip_prefix("0x").unwrap_or(key);
    let wallet: LocalWallet = key.parse().context("Invalid private key")?;
    Ok(wallet.address())
}

/// Check wallet balance.
pub async fn get_wallet_balance(rpc_url: &str, address: Address) -> Result<U256> {
    let provider = Provider::<Http>::try_from(rpc_url)
        .context("Invalid RPC URL")?;
    let balance = provider.get_balance(address, None).await
        .context("Failed to get balance")?;
    Ok(balance)
}

/// Format ETH balance for display.
pub fn format_eth(wei: U256) -> String {
    let eth = wei.as_u128() as f64 / 1e18;
    format!("{:.6} ETH", eth)
}

/// Minimum required balance for deployment (0.01 ETH).
pub const MIN_DEPLOYMENT_BALANCE: u128 = 10_000_000_000_000_000; // 0.01 ETH

/// BrokerRequests contract bytecode (compiled).
/// This is embedded at compile time from the JSON artifact.
pub const BROKER_REQUESTS_BYTECODE: &str = include_str!("../contracts/BrokerRequests.bin");

/// Deploy BrokerRequests contract.
pub async fn deploy_broker_requests(
    rpc_url: &str,
    chain_id: u64,
    private_key: &str,
) -> Result<Address> {
    let key = private_key.trim();
    let key = key.strip_prefix("0x").unwrap_or(key);

    let provider = Provider::<Http>::try_from(rpc_url)
        .context("Invalid RPC URL")?;

    let wallet: LocalWallet = key.parse::<LocalWallet>()
        .context("Invalid private key")?
        .with_chain_id(chain_id);

    let client = SignerMiddleware::new(provider.clone(), wallet);
    let client = std::sync::Arc::new(client);

    // Parse bytecode
    let bytecode = hex::decode(BROKER_REQUESTS_BYTECODE.trim())
        .context("Invalid contract bytecode")?;

    // Create deployment transaction
    let tx = TransactionRequest::new()
        .data(bytecode);

    // Send transaction
    let pending_tx = client.send_transaction(tx, None).await
        .context("Failed to send deployment transaction")?;

    println!("Deployment transaction sent: {:?}", pending_tx.tx_hash());
    println!("Waiting for confirmation...");

    // Wait for receipt
    let receipt = pending_tx.await
        .context("Failed to get transaction receipt")?
        .ok_or_else(|| anyhow!("No receipt returned"))?;

    let contract_address = receipt.contract_address
        .ok_or_else(|| anyhow!("No contract address in receipt"))?;

    Ok(contract_address)
}

/// Read ECIES private key file and derive the uncompressed public key (65 bytes, hex).
pub fn read_ecies_pubkey(path: &Path) -> Result<String> {
    use crate::crypto::EciesEncryption;

    if !path.exists() {
        return Err(anyhow!("ECIES key file not found: {}", path.display()));
    }

    let metadata = std::fs::metadata(path)
        .context("Failed to read ECIES key file metadata")?;
    if metadata.len() == 0 {
        return Err(anyhow!("ECIES key file is empty: {}", path.display()));
    }
    if metadata.len() > 256 {
        return Err(anyhow!("ECIES key file is too large (expected ~64 hex chars): {}", path.display()));
    }

    let enc = EciesEncryption::from_file(path)
        .map_err(|e| anyhow!("Failed to load ECIES key: {}", e))?;
    Ok(enc.public_key_hex())
}

/// Generate a new Ethereum private key.
pub fn generate_private_key() -> String {
    use rand::Rng;
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// Read private key from file.
pub fn read_private_key(path: &Path) -> Result<String> {
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .context("Failed to read private key file")
}

/// Write private key to file with secure permissions.
pub fn write_private_key(path: &Path, key: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, key)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

    Ok(())
}
