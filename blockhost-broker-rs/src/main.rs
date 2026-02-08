//! Blockhost IPv6 Tunnel Broker
//!
//! A broker daemon that manages IPv6 prefix allocations for Blockhost servers
//! with on-chain authentication via NFT contract ownership.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::signal;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod api;
mod config;
mod crypto;
mod db;
mod eth;
mod setup;
mod wg;

use config::{load_config, Config, DEFAULT_CONFIG_PATH};
use crypto::{generate_ecies_keypair, EciesEncryption};
use db::Ipam;
use eth::OnchainMonitor;
use setup::{
    detect_ipv6_interfaces, format_eth, generate_private_key, get_wallet_address,
    get_wallet_balance, read_private_key, suggest_allocation_sizes, write_private_key,
    deploy_broker_requests, MIN_DEPLOYMENT_BALANCE,
};
use wg::WireGuardManager;

/// Blockhost IPv6 Tunnel Broker
#[derive(Parser)]
#[command(name = "blockhost-broker")]
#[command(about = "IPv6 tunnel broker for Blockhost network with on-chain authentication")]
#[command(version)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the broker daemon
    Run {
        /// Override API listen host
        #[arg(long)]
        host: Option<String>,

        /// Override API listen port
        #[arg(long)]
        port: Option<u16>,
    },

    /// Validate configuration and exit
    CheckConfig,

    /// Generate a new ECIES keypair
    GenerateKey {
        /// Path to save the private key
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Token management commands
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },

    /// Show broker status
    Status,

    /// List allocations
    Allocations {
        #[command(subcommand)]
        action: Option<AllocationAction>,
    },

    /// Interactive setup wizard
    Setup,

    /// Detect IPv6 interfaces
    DetectIpv6,

    /// Wallet management
    Wallet {
        #[command(subcommand)]
        action: WalletAction,
    },

    /// Deploy BrokerRequests contract
    DeployRequests {
        /// RPC URL
        #[arg(long)]
        rpc_url: String,

        /// Chain ID
        #[arg(long)]
        chain_id: u64,

        /// Path to private key file
        #[arg(long)]
        private_key: PathBuf,
    },
}

#[derive(Subcommand)]
enum TokenAction {
    /// Create a new API token
    Create {
        /// Token name
        #[arg(short, long)]
        name: Option<String>,

        /// Maximum allocations
        #[arg(short, long, default_value = "1")]
        max_allocations: i64,

        /// Create admin token
        #[arg(short, long)]
        admin: bool,
    },

    /// List all tokens
    List,
}

#[derive(Subcommand)]
enum AllocationAction {
    /// List all allocations
    List,

    /// Show allocation details
    Show {
        /// Prefix to show
        prefix: String,
    },
}

#[derive(Subcommand)]
enum WalletAction {
    /// Generate a new private key
    Generate {
        /// Path to save the private key
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Show wallet address from private key
    Address {
        /// Path to private key file
        #[arg(short, long)]
        key: PathBuf,
    },

    /// Check wallet balance
    Balance {
        /// Path to private key file
        #[arg(short, long)]
        key: PathBuf,

        /// RPC URL
        #[arg(long, default_value = "https://ethereum-sepolia-rpc.publicnode.com")]
        rpc_url: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    // Load configuration
    let config = load_config(Some(&cli.config)).context("Failed to load configuration")?;

    match cli.command {
        Some(Commands::CheckConfig) => cmd_check_config(&config),
        Some(Commands::GenerateKey { output }) => cmd_generate_key(&output),
        Some(Commands::Token { action }) => cmd_token(&config, action).await,
        Some(Commands::Status) => cmd_status(&config).await,
        Some(Commands::Allocations { action }) => cmd_allocations(&config, action).await,
        Some(Commands::Setup) => cmd_setup().await,
        Some(Commands::DetectIpv6) => cmd_detect_ipv6(),
        Some(Commands::Wallet { action }) => cmd_wallet(action).await,
        Some(Commands::DeployRequests { rpc_url, chain_id, private_key }) => {
            cmd_deploy_requests(&rpc_url, chain_id, &private_key).await
        }
        Some(Commands::Run { host, port }) => {
            cmd_run(&config, host, port).await
        }
        None => {
            cmd_run(&config, None, None).await
        }
    }
}

fn cmd_check_config(config: &Config) -> Result<()> {
    println!("Configuration is valid");

    if config.onchain.enabled {
        println!("On-chain mode: ENABLED");
        println!("  RPC URL: {}", config.onchain.rpc_url);
        println!("  Chain ID: {}", config.onchain.chain_id);
        if let Some(ref contract) = config.onchain.requests_contract {
            println!("  Requests contract: {}", contract);
        }
        println!("  Poll interval: {}ms", config.onchain.poll_interval_ms);
    } else {
        println!("On-chain mode: DISABLED");
    }

    println!("\nBroker:");
    println!("  Upstream prefix: {}", config.broker.upstream_prefix);
    println!("  Allocation size: /{}", config.broker.allocation_size);
    println!("  Broker IPv6: {}", config.broker.broker_ipv6);

    println!("\nWireGuard:");
    println!("  Interface: {}", config.wireguard.interface);
    println!("  Public endpoint: {}", config.wireguard.public_endpoint);

    println!("\nAPI:");
    println!("  Listen: {}:{}", config.api.listen_host, config.api.listen_port);

    println!("\nDatabase:");
    println!("  Path: {}", config.database.path.display());

    Ok(())
}

fn cmd_generate_key(output: &PathBuf) -> Result<()> {
    let encryption = generate_ecies_keypair(output)
        .context("Failed to generate keypair")?;

    println!("Generated ECIES keypair");
    println!("Private key saved to: {}", output.display());
    println!("Public key (hex, 65 bytes): {}", encryption.public_key_hex());
    println!("\nUse this public key when registering your broker in BrokerRegistry");

    Ok(())
}

async fn cmd_token(config: &Config, action: TokenAction) -> Result<()> {
    let ipam = Ipam::new(&config.database.path, config.broker.clone())
        .await
        .context("Failed to initialize IPAM")?;

    match action {
        TokenAction::Create { name, max_allocations, admin } => {
            let (token, token_obj) = ipam
                .create_token(name.as_deref(), max_allocations, admin)
                .await
                .context("Failed to create token")?;

            println!("Token created successfully!");
            println!("  ID:          {}", token_obj.id);
            println!("  Name:        {}", token_obj.name.as_deref().unwrap_or("(none)"));
            println!("  Max allocs:  {}", token_obj.max_allocations);
            println!("  Admin:       {}", token_obj.is_admin);
            println!();
            println!("  Token: {}", token);
            println!();
            println!("Save this token securely - it cannot be retrieved later!");
        }
        TokenAction::List => {
            let tokens = ipam.list_tokens().await.context("Failed to list tokens")?;
            if tokens.is_empty() {
                println!("No tokens found");
            } else {
                println!("{:<5} {:<20} {:<12} {:<6} {:<8}", "ID", "Name", "Max Allocs", "Admin", "Revoked");
                println!("{}", "-".repeat(55));
                for t in &tokens {
                    println!(
                        "{:<5} {:<20} {:<12} {:<6} {:<8}",
                        t.id,
                        t.name.as_deref().unwrap_or("(none)"),
                        t.max_allocations,
                        t.is_admin,
                        t.revoked,
                    );
                }
            }
        }
    }

    Ok(())
}

async fn cmd_status(config: &Config) -> Result<()> {
    let ipam = Ipam::new(&config.database.path, config.broker.clone())
        .await
        .context("Failed to initialize IPAM")?;

    let stats = ipam.get_stats().await.context("Failed to get stats")?;

    println!("Blockhost Broker Status");
    println!("{}", "=".repeat(40));
    println!("Upstream Prefix:    {}", stats.upstream_prefix);
    println!("Allocation Size:    /{}", stats.allocation_size);
    println!("Total Allocations:  {}", stats.total_allocations);
    println!("Used Allocations:   {}", stats.used_allocations);
    println!("Available:          {}", stats.available_allocations);

    Ok(())
}

async fn cmd_allocations(config: &Config, action: Option<AllocationAction>) -> Result<()> {
    let ipam = Ipam::new(&config.database.path, config.broker.clone())
        .await
        .context("Failed to initialize IPAM")?;

    match action {
        Some(AllocationAction::Show { prefix }) => {
            let allocation = ipam
                .get_allocation_by_prefix(&prefix)
                .await
                .context("Failed to get allocation")?;

            match allocation {
                Some(a) => {
                    println!("Prefix:       {}", a.prefix);
                    println!("Index:        {}", a.prefix_index);
                    println!("Public Key:   {}", a.pubkey);
                    println!("Endpoint:     {}", a.endpoint.as_deref().unwrap_or("(none)"));
                    println!("NFT Contract: {}", a.nft_contract);
                    println!("Allocated:    {}", a.allocated_at);
                    println!("Last Seen:    {}", a.last_seen_at.map(|dt| dt.to_string()).unwrap_or_else(|| "Never".to_string()));
                }
                None => {
                    eprintln!("Allocation not found: {}", prefix);
                    std::process::exit(1);
                }
            }
        }
        Some(AllocationAction::List) | None => {
            let allocations = ipam.list_allocations().await.context("Failed to list allocations")?;

            if allocations.is_empty() {
                println!("No allocations found");
                return Ok(());
            }

            println!("{:<35} {:<20} {:<25} {}", "Prefix", "Pubkey", "NFT Contract", "Allocated");
            println!("{}", "-".repeat(100));

            for a in allocations {
                let pubkey_short = if a.pubkey.len() > 16 {
                    format!("{}...", &a.pubkey[..16])
                } else {
                    a.pubkey.clone()
                };
                let nft_short = if a.nft_contract.len() > 20 {
                    format!("{}...", &a.nft_contract[..20])
                } else {
                    a.nft_contract.clone()
                };
                let allocated = a.allocated_at.format("%Y-%m-%d %H:%M");
                println!("{:<35} {:<20} {:<25} {}", a.prefix, pubkey_short, nft_short, allocated);
            }
        }
    }

    Ok(())
}

async fn cmd_run(config: &Config, host: Option<String>, port: Option<u16>) -> Result<()> {
    // Initialize components
    let ipam = Ipam::new(&config.database.path, config.broker.clone())
        .await
        .context("Failed to initialize IPAM")?;
    let ipam = Arc::new(Mutex::new(ipam));

    let wg = WireGuardManager::new(config.wireguard.clone());
    let wg = Arc::new(wg);

    // Check WireGuard interface
    if !wg.interface_exists() {
        warn!(
            interface = %config.wireguard.interface,
            "WireGuard interface does not exist. Peers will not be added until the interface is created."
        );
    }

    // Determine listen address
    let listen_host = host.unwrap_or_else(|| config.api.listen_host.clone());
    let listen_port = port.unwrap_or(config.api.listen_port);
    let listen_addr = format!("{}:{}", listen_host, listen_port);

    if config.onchain.enabled {
        // Validate on-chain config
        if config.onchain.requests_contract.is_none() {
            error!("onchain.requests_contract must be set when on-chain mode is enabled");
            std::process::exit(1);
        }
        if !config.onchain.private_key_file.exists() {
            error!(
                path = %config.onchain.private_key_file.display(),
                "Private key file not found"
            );
            std::process::exit(1);
        }
        if !config.onchain.ecies_private_key_file.exists() {
            error!(
                path = %config.onchain.ecies_private_key_file.display(),
                "ECIES key file not found. Generate one with: blockhost-broker generate-key -o /path/to/key"
            );
            std::process::exit(1);
        }

        info!(
            listen_addr = %listen_addr,
            contract = %config.onchain.requests_contract.as_ref().unwrap(),
            "Starting blockhost-broker (on-chain mode)"
        );

        run_with_onchain_monitor(config.clone(), ipam, wg, &listen_addr).await?;
    } else {
        info!(listen_addr = %listen_addr, "Starting blockhost-broker");
        run_api_only(config.clone(), ipam, wg, &listen_addr).await?;
    }

    Ok(())
}

async fn run_with_onchain_monitor(
    config: Config,
    ipam: Arc<Mutex<Ipam>>,
    wg: Arc<WireGuardManager>,
    listen_addr: &str,
) -> Result<()> {
    // Create on-chain monitor
    let mut monitor = OnchainMonitor::new(
        config.onchain.clone(),
        config.broker.clone(),
        config.wireguard.clone(),
        ipam.clone(),
        wg.clone(),
    )
    .await
    .context("Failed to create on-chain monitor")?;

    // Create API router
    let app_state = api::handlers::AppState {
        config: config.clone(),
        ipam,
        wg,
    };
    let app = api::create_router(app_state);

    // Create listener
    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .context("Failed to bind to address")?;

    info!(listen_addr = %listen_addr, "API server listening");

    // Run both concurrently
    tokio::select! {
        result = monitor.start() => {
            if let Err(e) = result {
                error!(error = %e, "Monitor error");
            }
        }
        result = axum::serve(listener, app) => {
            if let Err(e) = result {
                error!(error = %e, "Server error");
            }
        }
        _ = shutdown_signal() => {
            info!("Shutdown signal received");
            monitor.stop();
        }
    }

    Ok(())
}

async fn run_api_only(
    config: Config,
    ipam: Arc<Mutex<Ipam>>,
    wg: Arc<WireGuardManager>,
    listen_addr: &str,
) -> Result<()> {
    // Create API router
    let app_state = api::handlers::AppState {
        config,
        ipam,
        wg,
    };
    let app = api::create_router(app_state);

    // Create listener
    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .context("Failed to bind to address")?;

    info!(listen_addr = %listen_addr, "API server listening");

    // Run server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("Server error")?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received");
}

fn cmd_detect_ipv6() -> Result<()> {
    println!("Detecting IPv6 interfaces with global addresses...\n");

    let interfaces = detect_ipv6_interfaces()?;

    if interfaces.is_empty() {
        println!("No IPv6 interfaces with global addresses found.");
        println!("\nYou will need to configure an IPv6 tunnel (e.g., Hurricane Electric)");
        println!("before running the broker.");
        return Ok(());
    }

    for iface in &interfaces {
        println!("Interface: {}", iface.name);
        for addr in &iface.addresses {
            println!("  Address: {}", addr);

            // Show allocation options
            let options = suggest_allocation_sizes(addr);
            if !options.is_empty() {
                println!("  Allocation options:");
                for opt in options {
                    println!("    /{}: {} ({} allocations possible)",
                        opt.size, opt.description, opt.num_allocations);
                }
            }
        }
        println!();
    }

    Ok(())
}

async fn cmd_wallet(action: WalletAction) -> Result<()> {
    match action {
        WalletAction::Generate { output } => {
            let key = generate_private_key();
            write_private_key(&output, &key)?;
            let address = get_wallet_address(&key)?;

            println!("Generated new Ethereum private key");
            println!("Saved to: {}", output.display());
            println!("Address:  0x{:x}", address);
            println!("\nKeep this key secure! Anyone with access can control your funds.");
        }
        WalletAction::Address { key } => {
            let private_key = read_private_key(&key)?;
            let address = get_wallet_address(&private_key)?;
            println!("0x{:x}", address);
        }
        WalletAction::Balance { key, rpc_url } => {
            let private_key = read_private_key(&key)?;
            let address = get_wallet_address(&private_key)?;
            let balance = get_wallet_balance(&rpc_url, address).await?;

            println!("Address: 0x{:x}", address);
            println!("Balance: {}", format_eth(balance));

            if balance.as_u128() < MIN_DEPLOYMENT_BALANCE {
                println!("\nWarning: Balance is below minimum required for deployment ({}).",
                    format_eth(MIN_DEPLOYMENT_BALANCE.into()));
            }
        }
    }
    Ok(())
}

async fn cmd_deploy_requests(rpc_url: &str, chain_id: u64, key_path: &PathBuf) -> Result<()> {
    let private_key = read_private_key(key_path)?;
    let address = get_wallet_address(&private_key)?;

    println!("Deploying BrokerRequests contract...");
    println!("  RPC URL:  {}", rpc_url);
    println!("  Chain ID: {}", chain_id);
    println!("  Deployer: 0x{:x}", address);
    println!();

    // Check balance first
    let balance = get_wallet_balance(rpc_url, address).await?;
    println!("  Balance:  {}", format_eth(balance));

    if balance.as_u128() < MIN_DEPLOYMENT_BALANCE {
        anyhow::bail!(
            "Insufficient balance. Need at least {} to deploy.",
            format_eth(MIN_DEPLOYMENT_BALANCE.into())
        );
    }

    println!("\nSending deployment transaction...");

    let contract_address = deploy_broker_requests(rpc_url, chain_id, &private_key).await?;

    println!("\nContract deployed successfully!");
    println!("Address: 0x{:x}", contract_address);
    println!("\nAdd this to your config.toml:");
    println!("  requests_contract = \"0x{:x}\"", contract_address);

    Ok(())
}

async fn cmd_setup() -> Result<()> {
    use std::io::{self, Write};

    println!("===========================================");
    println!("  Blockhost Broker Interactive Setup");
    println!("===========================================\n");

    let config_dir = PathBuf::from("/etc/blockhost-broker");
    let deployer_key_path = config_dir.join("deployer.key");
    let ecies_key_path = config_dir.join("ecies.key");
    let config_path = config_dir.join("config.toml");

    // Step 1: Create directories
    std::fs::create_dir_all(&config_dir).context("Failed to create config directory")?;

    // Step 2: Check/generate deployer key
    println!("Step 1: Ethereum Deployer Key");
    println!("-----------------------------");

    let private_key = if deployer_key_path.exists() {
        println!("Found existing deployer key at {}", deployer_key_path.display());
        read_private_key(&deployer_key_path)?
    } else {
        print!("No deployer key found. Generate new key? [Y/n]: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();

        if input.is_empty() || input == "y" || input == "yes" {
            let key = generate_private_key();
            write_private_key(&deployer_key_path, &key)?;
            println!("Generated new key at {}", deployer_key_path.display());
            key
        } else {
            print!("Enter private key (hex, with or without 0x prefix): ");
            io::stdout().flush()?;
            let mut key = String::new();
            io::stdin().read_line(&mut key)?;
            let key = key.trim().to_string();
            write_private_key(&deployer_key_path, &key)?;
            key
        }
    };

    let address = get_wallet_address(&private_key)?;
    println!("Wallet address: 0x{:x}\n", address);

    // Step 3: Check wallet balance
    println!("Step 2: Wallet Balance");
    println!("----------------------");

    let rpc_url = "https://ethereum-sepolia-rpc.publicnode.com";
    let chain_id = 11155111u64; // Sepolia

    let balance = get_wallet_balance(rpc_url, address).await?;
    println!("Current balance: {}", format_eth(balance));

    if balance.as_u128() < MIN_DEPLOYMENT_BALANCE {
        println!("\nInsufficient balance for contract deployment.");
        println!("Please send at least {} to 0x{:x}", format_eth(MIN_DEPLOYMENT_BALANCE.into()), address);
        println!("\nPress Enter when funds have been sent...");
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        // Re-check balance
        let balance = get_wallet_balance(rpc_url, address).await?;
        println!("New balance: {}", format_eth(balance));

        if balance.as_u128() < MIN_DEPLOYMENT_BALANCE {
            anyhow::bail!("Still insufficient balance. Aborting setup.");
        }
    }
    println!();

    // Step 4: Deploy BrokerRequests contract
    println!("Step 3: Deploy BrokerRequests Contract");
    println!("--------------------------------------");

    print!("Deploy BrokerRequests contract now? [Y/n]: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();

    let requests_contract = if input.is_empty() || input == "y" || input == "yes" {
        println!("Deploying contract...");
        let addr = deploy_broker_requests(rpc_url, chain_id, &private_key).await?;
        println!("Deployed at: 0x{:x}\n", addr);
        Some(format!("0x{:x}", addr))
    } else {
        print!("Enter existing BrokerRequests contract address (or press Enter to skip): ");
        io::stdout().flush()?;
        let mut addr = String::new();
        io::stdin().read_line(&mut addr)?;
        let addr = addr.trim();
        if addr.is_empty() {
            None
        } else {
            Some(addr.to_string())
        }
    };

    // Step 5: Generate ECIES key
    println!("Step 4: ECIES Encryption Key");
    println!("----------------------------");

    let ecies_pubkey = if ecies_key_path.exists() {
        println!("Found existing ECIES key at {}", ecies_key_path.display());
        let enc = EciesEncryption::from_file(&ecies_key_path)?;
        enc.public_key_hex()
    } else {
        let enc = generate_ecies_keypair(&ecies_key_path)?;
        println!("Generated new ECIES key at {}", ecies_key_path.display());
        enc.public_key_hex()
    };
    println!("Public key: {}\n", ecies_pubkey);

    // Step 6: Detect IPv6 interfaces
    println!("Step 5: IPv6 Configuration");
    println!("--------------------------");

    let interfaces = detect_ipv6_interfaces()?;

    let (upstream_prefix, allocation_size, broker_ipv6) = if interfaces.is_empty() {
        println!("No IPv6 interfaces detected.");
        print!("Enter upstream IPv6 prefix (e.g., 2001:db8::/48): ");
        io::stdout().flush()?;
        let mut prefix = String::new();
        io::stdin().read_line(&mut prefix)?;
        let prefix = prefix.trim().to_string();

        print!("Enter allocation size (e.g., 64 for /64): ");
        io::stdout().flush()?;
        let mut size = String::new();
        io::stdin().read_line(&mut size)?;
        let size: u8 = size.trim().parse().unwrap_or(64);

        print!("Enter broker's own IPv6 address (e.g., 2001:db8::1): ");
        io::stdout().flush()?;
        let mut addr = String::new();
        io::stdin().read_line(&mut addr)?;
        let addr = addr.trim().to_string();

        (prefix, size, addr)
    } else {
        println!("Found IPv6 interfaces:");
        for (i, iface) in interfaces.iter().enumerate() {
            for addr in &iface.addresses {
                println!("  {}: {} on {}", i + 1, addr, iface.name);
            }
        }
        println!();

        // Use first interface by default
        let first = &interfaces[0];
        let prefix = &first.addresses[0];

        println!("Using prefix: {}", prefix);
        let options = suggest_allocation_sizes(prefix);

        println!("\nAllocation size options:");
        for (i, opt) in options.iter().enumerate() {
            println!("  {}: /{} - {} ({} allocations)",
                i + 1, opt.size, opt.description, opt.num_allocations);
        }

        print!("\nSelect allocation size [1]: ");
        io::stdout().flush()?;
        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        let choice: usize = choice.trim().parse().unwrap_or(1);
        let size = if choice > 0 && choice <= options.len() {
            options[choice - 1].size
        } else {
            64
        };

        // Derive broker address (first address in prefix + ::1)
        let broker_addr = format!("{}1", prefix.network().to_string().strip_suffix("::").unwrap_or(&prefix.network().to_string()));

        (prefix.to_string(), size, broker_addr)
    };

    // Step 7: WireGuard configuration
    println!("\nStep 6: WireGuard Configuration");
    println!("--------------------------------");

    print!("WireGuard interface name [wg-broker]: ");
    io::stdout().flush()?;
    let mut wg_iface = String::new();
    io::stdin().read_line(&mut wg_iface)?;
    let wg_iface = if wg_iface.trim().is_empty() { "wg-broker".to_string() } else { wg_iface.trim().to_string() };

    print!("WireGuard listen port [51820]: ");
    io::stdout().flush()?;
    let mut wg_port = String::new();
    io::stdin().read_line(&mut wg_port)?;
    let wg_port: u16 = wg_port.trim().parse().unwrap_or(51820);

    print!("Public endpoint (hostname:port): ");
    io::stdout().flush()?;
    let mut wg_endpoint = String::new();
    io::stdin().read_line(&mut wg_endpoint)?;
    let wg_endpoint = wg_endpoint.trim().to_string();

    // Step 8: Write configuration file
    println!("\nStep 7: Writing Configuration");
    println!("------------------------------");

    let config_content = format!(r#"# Blockhost Broker Configuration
# Generated by setup wizard

[broker]
upstream_prefix = "{upstream_prefix}"
allocation_size = {allocation_size}
broker_ipv6 = "{broker_ipv6}"

[wireguard]
interface = "{wg_iface}"
listen_port = {wg_port}
private_key_file = "/etc/blockhost-broker/wg-private.key"
public_endpoint = "{wg_endpoint}"

[api]
listen_host = "127.0.0.1"
listen_port = 8080

[database]
path = "/var/lib/blockhost-broker/ipam.db"

[onchain]
enabled = true
rpc_url = "{rpc_url}"
chain_id = {chain_id}
private_key_file = "{}"
ecies_private_key_file = "{}"
{}poll_interval_ms = 5000
"#,
        deployer_key_path.display(),
        ecies_key_path.display(),
        if let Some(ref addr) = requests_contract {
            format!("requests_contract = \"{}\"\n", addr)
        } else {
            "# requests_contract = \"0x...\"\n".to_string()
        }
    );

    std::fs::write(&config_path, &config_content)?;
    println!("Configuration written to {}", config_path.display());

    // Summary
    println!("\n===========================================");
    println!("  Setup Complete!");
    println!("===========================================");
    println!("\nNext steps:");
    println!("1. Register your broker in BrokerRegistry with:");
    println!("   - Operator address: 0x{:x}", address);
    if let Some(ref addr) = requests_contract {
        println!("   - Requests contract: {}", addr);
    }
    println!("   - ECIES public key: {}", ecies_pubkey);
    println!("\n2. Set up WireGuard interface:");
    println!("   wg genkey > /etc/blockhost-broker/wg-private.key");
    println!("   ip link add {} type wireguard", wg_iface);
    println!("   wg set {} listen-port {} private-key /etc/blockhost-broker/wg-private.key", wg_iface, wg_port);
    println!("   ip -6 addr add {}/128 dev {}", broker_ipv6, wg_iface);
    println!("   ip link set {} up", wg_iface);
    println!("\n3. Start the broker:");
    println!("   systemctl enable --now blockhost-broker");

    Ok(())
}
