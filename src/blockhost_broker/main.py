"""Main entry point for blockhost-broker."""

from __future__ import annotations

import argparse
import asyncio
import sys
import signal
import logging
from pathlib import Path
from typing import Optional

import uvicorn

from .config import load_config, DEFAULT_CONFIG_PATH
from .ipam import IPAM
from .wireguard import WireGuardManager
from .api import app, init_deps

logger = logging.getLogger(__name__)


async def run_with_onchain_monitor(
    config,
    ipam: IPAM,
    wg: WireGuardManager,
    host: str,
    port: int,
) -> None:
    """Run the API server alongside the on-chain monitor.

    Args:
        config: Application configuration.
        ipam: IPAM instance.
        wg: WireGuard manager.
        host: API host.
        port: API port.
    """
    from .onchain import OnchainMonitor

    # Create on-chain monitor
    monitor = OnchainMonitor(
        onchain_config=config.onchain,
        broker_config=config.broker,
        wg_config=config.wireguard,
        ipam=ipam,
        wg=wg,
    )

    # Create uvicorn server
    uvicorn_config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="info",
    )
    server = uvicorn.Server(uvicorn_config)

    # Handle shutdown signals
    loop = asyncio.get_event_loop()
    shutdown_event = asyncio.Event()

    def signal_handler():
        logger.info("Received shutdown signal")
        monitor.stop()
        shutdown_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)

    # Run both concurrently
    try:
        await asyncio.gather(
            monitor.start(),
            server.serve(),
        )
    except asyncio.CancelledError:
        pass
    finally:
        monitor.stop()


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Blockhost IPv6 Tunnel Broker")
    parser.add_argument(
        "-c", "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help=f"Configuration file path (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Validate configuration and exit",
    )
    parser.add_argument(
        "--host",
        type=str,
        help="Override API listen host",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Override API listen port",
    )
    parser.add_argument(
        "--generate-ecies-key",
        type=Path,
        metavar="PATH",
        help="Generate a new ECIES keypair and save to PATH, then exit",
    )

    args = parser.parse_args()

    # Handle key generation
    if args.generate_ecies_key:
        from .onchain.encryption import generate_ecies_keypair
        try:
            encryption = generate_ecies_keypair(args.generate_ecies_key)
            print(f"Generated ECIES keypair")
            print(f"Private key saved to: {args.generate_ecies_key}")
            print(f"Public key (hex, 65 bytes): {encryption.public_key_hex}")
            print(f"\nUse this public key when registering your broker in BrokerRegistry")
            return 0
        except Exception as e:
            print(f"Error generating keypair: {e}", file=sys.stderr)
            return 1

    # Load configuration
    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"Error loading configuration: {e}", file=sys.stderr)
        return 1

    if args.check_config:
        print("Configuration is valid")
        if config.onchain.enabled:
            print("On-chain mode: ENABLED")
            print(f"  RPC URL: {config.onchain.rpc_url}")
            print(f"  Chain ID: {config.onchain.chain_id}")
            print(f"  Requests contract: {config.onchain.requests_contract}")
            print(f"  Poll interval: {config.onchain.poll_interval_ms}ms")
        else:
            print("On-chain mode: DISABLED (using REST API authentication)")
        return 0

    # Initialize components
    ipam = IPAM(config.database.path, config.broker)
    wg = WireGuardManager(config.wireguard)

    # Check WireGuard interface
    if not wg.interface_exists():
        print(f"Warning: WireGuard interface '{config.wireguard.interface}' does not exist", file=sys.stderr)
        print("Peers will not be added until the interface is created", file=sys.stderr)

    # Initialize API dependencies
    init_deps(config, ipam, wg)

    # Run server
    host = args.host or config.api.listen_host
    port = args.port or config.api.listen_port

    if config.onchain.enabled:
        # Validate on-chain config
        if not config.onchain.requests_contract:
            print("Error: onchain.requests_contract must be set when on-chain mode is enabled", file=sys.stderr)
            return 1
        if not config.onchain.private_key_file.exists():
            print(f"Error: Private key file not found: {config.onchain.private_key_file}", file=sys.stderr)
            return 1
        if not config.onchain.ecies_private_key_file.exists():
            print(f"Error: ECIES key file not found: {config.onchain.ecies_private_key_file}", file=sys.stderr)
            print("Generate one with: blockhost-broker --generate-ecies-key /path/to/key", file=sys.stderr)
            return 1

        print(f"Starting blockhost-broker on {host}:{port} (on-chain mode)")
        print(f"Monitoring {config.onchain.requests_contract} for allocation requests")
        asyncio.run(run_with_onchain_monitor(config, ipam, wg, host, port))
    else:
        print(f"Starting blockhost-broker on {host}:{port}")
        uvicorn.run(
            app,
            host=host,
            port=port,
            log_level="info",
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
