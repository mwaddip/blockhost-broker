"""WireGuard interface management."""

from __future__ import annotations

import subprocess
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import IPv6Network

from .config import WireGuardConfig


@dataclass
class PeerStatus:
    """Status of a WireGuard peer."""

    pubkey: str
    endpoint: str | None
    allowed_ips: list[str]
    latest_handshake: datetime | None
    transfer_rx: int
    transfer_tx: int

    @property
    def is_active(self) -> bool:
        """Check if peer has had a recent handshake (within 5 minutes)."""
        if not self.latest_handshake:
            return False
        age = (datetime.now(timezone.utc) - self.latest_handshake).total_seconds()
        return age < 300


class WireGuardError(Exception):
    """WireGuard operation failed."""

    pass


class WireGuardManager:
    """Manage WireGuard interface and peers."""

    def __init__(self, config: WireGuardConfig):
        self.config = config

    def _run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        """Run a command."""
        try:
            return subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=check,
            )
        except subprocess.CalledProcessError as e:
            raise WireGuardError(f"Command failed: {e.stderr}") from e

    def add_peer(
        self,
        pubkey: str,
        allowed_ips: IPv6Network | str,
        endpoint: str | None = None,
    ) -> None:
        """Add a WireGuard peer."""
        allowed_ips_str = str(allowed_ips)

        cmd = [
            "wg",
            "set",
            self.config.interface,
            "peer",
            pubkey,
            "allowed-ips",
            allowed_ips_str,
        ]

        if endpoint:
            cmd.extend(["endpoint", endpoint])

        self._run(*cmd)

        # Add route for the peer's prefix
        self._run(
            "ip", "-6", "route", "add", allowed_ips_str, "dev", self.config.interface,
            check=False,  # May already exist
        )

    def remove_peer(self, pubkey: str) -> None:
        """Remove a WireGuard peer."""
        # Get peer's allowed IPs first for route cleanup
        status = self.get_peer_status(pubkey)
        if status:
            for allowed_ip in status.allowed_ips:
                self._run(
                    "ip", "-6", "route", "del", allowed_ip, "dev", self.config.interface,
                    check=False,
                )

        self._run("wg", "set", self.config.interface, "peer", pubkey, "remove")

    def get_peer_status(self, pubkey: str) -> PeerStatus | None:
        """Get status of a specific peer."""
        for peer in self.list_peers():
            if peer.pubkey == pubkey:
                return peer
        return None

    def list_peers(self) -> list[PeerStatus]:
        """List all WireGuard peers with their status."""
        result = self._run("wg", "show", self.config.interface, "dump", check=False)
        if result.returncode != 0:
            return []

        peers = []
        lines = result.stdout.strip().split("\n")

        for line in lines[1:]:  # Skip interface line
            parts = line.split("\t")
            if len(parts) < 8:
                continue

            pubkey = parts[0]
            endpoint = parts[2] if parts[2] != "(none)" else None
            allowed_ips = parts[3].split(",") if parts[3] else []
            handshake_ts = int(parts[4]) if parts[4] != "0" else None
            rx_bytes = int(parts[5])
            tx_bytes = int(parts[6])

            latest_handshake = None
            if handshake_ts:
                latest_handshake = datetime.fromtimestamp(handshake_ts, tz=timezone.utc)

            peers.append(
                PeerStatus(
                    pubkey=pubkey,
                    endpoint=endpoint,
                    allowed_ips=allowed_ips,
                    latest_handshake=latest_handshake,
                    transfer_rx=rx_bytes,
                    transfer_tx=tx_bytes,
                )
            )

        return peers

    def get_public_key(self) -> str | None:
        """Get the interface's public key."""
        result = self._run("wg", "show", self.config.interface, "public-key", check=False)
        if result.returncode != 0:
            return self.config.public_key
        return result.stdout.strip()

    def interface_exists(self) -> bool:
        """Check if the WireGuard interface exists."""
        result = self._run("ip", "link", "show", self.config.interface, check=False)
        return result.returncode == 0

    def save_config(self) -> None:
        """Save current WireGuard config to file."""
        config_path = f"/etc/wireguard/{self.config.interface}.conf"
        result = self._run("wg", "showconf", self.config.interface)
        with open(config_path, "w") as f:
            f.write(result.stdout)
