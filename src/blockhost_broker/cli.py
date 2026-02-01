"""CLI tool for blockhost-broker administration."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from datetime import datetime

from .config import load_config, DEFAULT_CONFIG_PATH
from .ipam import IPAM


def cmd_token_create(ipam: IPAM, args: argparse.Namespace) -> int:
    """Create a new token."""
    token, token_obj = ipam.create_token(
        name=args.name,
        max_allocations=args.max_allocations,
        is_admin=args.admin,
    )

    print(f"Token created successfully!")
    print(f"  ID:          {token_obj.id}")
    print(f"  Name:        {token_obj.name or '(none)'}")
    print(f"  Max allocs:  {token_obj.max_allocations}")
    print(f"  Admin:       {token_obj.is_admin}")
    print()
    print(f"  Token: {token}")
    print()
    print("Save this token securely - it cannot be retrieved later!")
    return 0


def cmd_token_list(ipam: IPAM, args: argparse.Namespace) -> int:
    """List all tokens."""
    tokens = ipam.list_tokens()

    if not tokens:
        print("No tokens found")
        return 0

    print(f"{'ID':<4} {'Name':<20} {'Max':<5} {'Admin':<6} {'Revoked':<8} {'Allocations'}")
    print("-" * 70)

    for t in tokens:
        allocs = len(ipam.get_allocations_by_token(t.token_hash))
        revoked = "Yes" if t.revoked else "No"
        admin = "Yes" if t.is_admin else "No"
        name = t.name or "(none)"
        print(f"{t.id:<4} {name:<20} {t.max_allocations:<5} {admin:<6} {revoked:<8} {allocs}")

    return 0


def cmd_token_revoke(ipam: IPAM, args: argparse.Namespace) -> int:
    """Revoke a token."""
    if ipam.revoke_token(args.token_id):
        print(f"Token {args.token_id} revoked")
        return 0
    else:
        print(f"Token {args.token_id} not found", file=sys.stderr)
        return 1


def cmd_allocations_list(ipam: IPAM, args: argparse.Namespace) -> int:
    """List all allocations."""
    allocations = ipam.list_allocations()

    if not allocations:
        print("No allocations found")
        return 0

    print(f"{'Prefix':<35} {'Pubkey':<20} {'Endpoint':<25} {'Allocated'}")
    print("-" * 100)

    for a in allocations:
        pubkey_short = a.pubkey[:16] + "..."
        endpoint = a.endpoint or "(none)"
        allocated = a.allocated_at.strftime("%Y-%m-%d %H:%M")
        print(f"{str(a.prefix):<35} {pubkey_short:<20} {endpoint:<25} {allocated}")

    return 0


def cmd_allocations_show(ipam: IPAM, args: argparse.Namespace) -> int:
    """Show details of an allocation."""
    allocation = ipam.get_allocation_by_prefix(args.prefix)

    if not allocation:
        print(f"Allocation not found: {args.prefix}", file=sys.stderr)
        return 1

    print(f"Prefix:       {allocation.prefix}")
    print(f"Index:        {allocation.prefix_index}")
    print(f"Public Key:   {allocation.pubkey}")
    print(f"Endpoint:     {allocation.endpoint or '(none)'}")
    print(f"Allocated:    {allocation.allocated_at}")
    print(f"Last Seen:    {allocation.last_seen_at or 'Never'}")

    return 0


def cmd_allocations_revoke(ipam: IPAM, args: argparse.Namespace) -> int:
    """Revoke an allocation (admin operation)."""
    allocation = ipam.get_allocation_by_prefix(args.prefix)
    if not allocation:
        print(f"Allocation not found: {args.prefix}", file=sys.stderr)
        return 1

    # Use a fake admin token hash for CLI operations
    from .ipam import hash_token

    # Create temporary admin token for this operation
    tokens = ipam.list_tokens()
    admin_token = next((t for t in tokens if t.is_admin and not t.revoked), None)

    if not admin_token:
        print("No admin token available. Create one first.", file=sys.stderr)
        return 1

    if ipam.release(args.prefix, admin_token.token_hash):
        print(f"Allocation {args.prefix} revoked")
        return 0
    else:
        print(f"Failed to revoke allocation", file=sys.stderr)
        return 1


def cmd_status(ipam: IPAM, args: argparse.Namespace) -> int:
    """Show broker status."""
    stats = ipam.get_stats()

    print("Blockhost Broker Status")
    print("=" * 40)
    print(f"Upstream Prefix:    {stats['upstream_prefix']}")
    print(f"Allocation Size:    /{stats['allocation_size']}")
    print(f"Total Allocations:  {stats['total_allocations']}")
    print(f"Used Allocations:   {stats['used_allocations']}")
    print(f"Available:          {stats['available_allocations']}")

    return 0


def cmd_peers(ipam: IPAM, args: argparse.Namespace) -> int:
    """Show WireGuard peer status."""
    from .config import load_config
    from .wireguard import WireGuardManager

    config = load_config(args.config if hasattr(args, 'config') else None)
    wg = WireGuardManager(config.wireguard)

    peers = wg.list_peers()

    if not peers:
        print("No WireGuard peers configured")
        return 0

    print(f"{'Pubkey':<20} {'Endpoint':<25} {'Handshake':<20} {'RX':<12} {'TX':<12}")
    print("-" * 90)

    for p in peers:
        pubkey_short = p.pubkey[:16] + "..."
        endpoint = p.endpoint or "(none)"
        handshake = p.latest_handshake.strftime("%Y-%m-%d %H:%M:%S") if p.latest_handshake else "Never"
        rx = f"{p.transfer_rx / 1024:.1f} KiB"
        tx = f"{p.transfer_tx / 1024:.1f} KiB"
        print(f"{pubkey_short:<20} {endpoint:<25} {handshake:<20} {rx:<12} {tx:<12}")

    return 0


def main() -> int:
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description="Blockhost Broker Administration",
        prog="blockhost-broker-ctl",
    )
    parser.add_argument(
        "-c", "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help=f"Configuration file path (default: {DEFAULT_CONFIG_PATH})",
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Token commands
    token_parser = subparsers.add_parser("token", help="Token management")
    token_sub = token_parser.add_subparsers(dest="token_command")

    token_create = token_sub.add_parser("create", help="Create a new token")
    token_create.add_argument("--name", "-n", help="Token name")
    token_create.add_argument("--max-allocations", "-m", type=int, default=1, help="Maximum allocations")
    token_create.add_argument("--admin", "-a", action="store_true", help="Create admin token")

    token_sub.add_parser("list", help="List all tokens")

    token_revoke = token_sub.add_parser("revoke", help="Revoke a token")
    token_revoke.add_argument("token_id", type=int, help="Token ID to revoke")

    # Allocation commands
    alloc_parser = subparsers.add_parser("allocations", help="Allocation management")
    alloc_sub = alloc_parser.add_subparsers(dest="alloc_command")

    alloc_sub.add_parser("list", help="List all allocations")

    alloc_show = alloc_sub.add_parser("show", help="Show allocation details")
    alloc_show.add_argument("prefix", help="Prefix to show")

    alloc_revoke = alloc_sub.add_parser("revoke", help="Revoke an allocation")
    alloc_revoke.add_argument("prefix", help="Prefix to revoke")

    # Status command
    subparsers.add_parser("status", help="Show broker status")

    # Peers command
    subparsers.add_parser("peers", help="Show WireGuard peer status")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Load config and initialize IPAM
    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"Error loading configuration: {e}", file=sys.stderr)
        return 1

    ipam = IPAM(config.database.path, config.broker)

    # Dispatch commands
    if args.command == "token":
        if args.token_command == "create":
            return cmd_token_create(ipam, args)
        elif args.token_command == "list":
            return cmd_token_list(ipam, args)
        elif args.token_command == "revoke":
            return cmd_token_revoke(ipam, args)
        else:
            token_parser.print_help()
            return 1

    elif args.command == "allocations":
        if args.alloc_command == "list":
            return cmd_allocations_list(ipam, args)
        elif args.alloc_command == "show":
            return cmd_allocations_show(ipam, args)
        elif args.alloc_command == "revoke":
            return cmd_allocations_revoke(ipam, args)
        else:
            alloc_parser.print_help()
            return 1

    elif args.command == "status":
        return cmd_status(ipam, args)

    elif args.command == "peers":
        return cmd_peers(ipam, args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
