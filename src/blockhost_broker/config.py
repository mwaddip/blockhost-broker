"""Configuration management for blockhost-broker."""

from __future__ import annotations

import sys
from pathlib import Path
from ipaddress import IPv6Network, IPv6Address
from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


class OnchainConfig(BaseSettings):
    """On-chain broker authentication configuration."""

    model_config = SettingsConfigDict(env_prefix="ONCHAIN_")

    # Enable on-chain authentication (disables REST API allocation)
    enabled: bool = False

    # Ethereum RPC URL
    rpc_url: str = "https://ethereum-sepolia-rpc.publicnode.com"

    # Chain ID (11155111 = Sepolia)
    chain_id: int = 11155111

    # Path to file containing operator private key (hex)
    private_key_file: Path = Path("/etc/blockhost-broker/deployer.key")

    # Path to file containing ECIES private key (hex, secp256k1)
    ecies_private_key_file: Path = Path("/etc/blockhost-broker/ecies.key")

    # BrokerRegistry contract address
    registry_contract: Optional[str] = None

    # BrokerRequests contract address (this broker's instance)
    requests_contract: Optional[str] = None

    # Poll interval for pending requests (milliseconds)
    poll_interval_ms: int = 5000

    @field_validator("poll_interval_ms")
    @classmethod
    def validate_poll_interval(cls, v: int) -> int:
        if v < 1000:
            raise ValueError("poll_interval_ms must be at least 1000ms")
        if v > 60000:
            raise ValueError("poll_interval_ms must be at most 60000ms")
        return v


class BrokerConfig(BaseSettings):
    """Broker configuration."""

    model_config = SettingsConfigDict(env_prefix="BROKER_")

    # Upstream prefix from tunnel provider
    upstream_prefix: IPv6Network = IPv6Network("2a11:6c7:f04:276::/64")

    # Size of allocations to hand out
    allocation_size: int = 120

    # Broker's own IPv6 address
    broker_ipv6: IPv6Address = IPv6Address("2a11:6c7:f04:276::2")

    @field_validator("allocation_size")
    @classmethod
    def validate_allocation_size(cls, v: int, info) -> int:
        if v < 64 or v > 128:
            raise ValueError("allocation_size must be between 64 and 128")
        return v


class WireGuardConfig(BaseSettings):
    """WireGuard configuration."""

    model_config = SettingsConfigDict(env_prefix="WG_")

    interface: str = "wg-broker"
    listen_port: int = 51820
    private_key_file: Path = Path("/etc/blockhost-broker/wg-private.key")
    public_endpoint: str = "127.0.0.1:51820"  # Override in config.toml

    @property
    def public_key(self) -> str | None:
        """Read public key from file."""
        pub_file = self.private_key_file.with_suffix(".key").parent / "wg-public.key"
        if pub_file.exists():
            return pub_file.read_text().strip()
        return None


class APIConfig(BaseSettings):
    """API server configuration."""

    model_config = SettingsConfigDict(env_prefix="API_")

    listen_host: str = "0.0.0.0"
    listen_port: int = 8080


class DatabaseConfig(BaseSettings):
    """Database configuration."""

    model_config = SettingsConfigDict(env_prefix="DB_")

    path: Path = Path("/var/lib/blockhost-broker/ipam.db")


class Config(BaseSettings):
    """Main configuration container."""

    broker: BrokerConfig = BrokerConfig()
    wireguard: WireGuardConfig = WireGuardConfig()
    api: APIConfig = APIConfig()
    database: DatabaseConfig = DatabaseConfig()
    onchain: OnchainConfig = OnchainConfig()

    @classmethod
    def from_toml(cls, path: Path) -> "Config":
        """Load configuration from TOML file."""
        if not path.exists():
            return cls()

        with open(path, "rb") as f:
            data = tomllib.load(f)

        return cls(
            broker=BrokerConfig(**data.get("broker", {})),
            wireguard=WireGuardConfig(**data.get("wireguard", {})),
            api=APIConfig(**data.get("api", {})),
            database=DatabaseConfig(**data.get("database", {})),
            onchain=OnchainConfig(**data.get("onchain", {})),
        )


# Default config path
DEFAULT_CONFIG_PATH = Path("/etc/blockhost-broker/config.toml")


def load_config(path: Path | None = None) -> Config:
    """Load configuration from file or defaults."""
    config_path = path or DEFAULT_CONFIG_PATH
    return Config.from_toml(config_path)
