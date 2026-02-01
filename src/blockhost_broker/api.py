"""REST API for blockhost-broker."""

from __future__ import annotations

import base64
import re
from typing import Annotated
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Depends, Header, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

from .config import Config
from .ipam import IPAM, Token, hash_token
from .wireguard import WireGuardManager, WireGuardError


# Pydantic models for API

class AllocateRequest(BaseModel):
    """Request to allocate a new prefix."""

    pubkey: str
    endpoint: str | None = None

    @field_validator("pubkey")
    @classmethod
    def validate_pubkey(cls, v: str) -> str:
        """Validate WireGuard public key format."""
        try:
            decoded = base64.b64decode(v)
            if len(decoded) != 32:
                raise ValueError("Invalid key length")
        except Exception:
            raise ValueError("Invalid WireGuard public key (must be base64-encoded 32 bytes)")
        return v

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, v: str | None) -> str | None:
        """Validate endpoint format (host:port)."""
        if v is None:
            return None
        pattern = r"^[\w\.\-]+:\d+$"
        if not re.match(pattern, v):
            raise ValueError("Invalid endpoint format (expected host:port)")
        return v


class AllocateResponse(BaseModel):
    """Response from allocation request."""

    prefix: str
    gateway: str
    broker_pubkey: str
    broker_endpoint: str
    allocated_at: str


class AllocationInfo(BaseModel):
    """Information about an allocation."""

    prefix: str
    pubkey: str
    endpoint: str | None
    allocated_at: str
    last_seen_at: str | None
    status: str  # "active", "idle", "never_connected"


class StatusResponse(BaseModel):
    """Broker status response."""

    upstream_prefix: str
    allocation_size: int
    total_allocations: int
    used_allocations: int
    available_allocations: int
    active_peers: int
    idle_peers: int


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    version: str


# Dependency injection

class BrokerDeps:
    """Dependency container for the broker."""

    def __init__(self, config: Config, ipam: IPAM, wg: WireGuardManager):
        self.config = config
        self.ipam = ipam
        self.wg = wg


_deps: BrokerDeps | None = None


def get_deps() -> BrokerDeps:
    if _deps is None:
        raise RuntimeError("Dependencies not initialized")
    return _deps


def init_deps(config: Config, ipam: IPAM, wg: WireGuardManager) -> None:
    global _deps
    _deps = BrokerDeps(config, ipam, wg)


async def get_token(
    authorization: Annotated[str | None, Header()] = None,
    deps: BrokerDeps = Depends(get_deps),
) -> Token:
    """Validate authorization header and return token."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format",
        )

    token_str = authorization[7:]
    token = deps.ipam.validate_token(token_str)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    return token


async def get_admin_token(token: Token = Depends(get_token)) -> Token:
    """Require admin token."""
    if not token.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return token


# FastAPI app

app = FastAPI(
    title="Blockhost Broker",
    description="IPv6 tunnel broker for Blockhost installations",
    version="0.1.0",
)


@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint (no auth required)."""
    from . import __version__
    return HealthResponse(status="healthy", version=__version__)


@app.post("/v1/allocate", response_model=AllocateResponse, status_code=status.HTTP_201_CREATED)
async def allocate(
    request: AllocateRequest,
    token: Token = Depends(get_token),
    deps: BrokerDeps = Depends(get_deps),
):
    """Allocate a new IPv6 prefix.

    Note: When on-chain mode is enabled, allocations are managed through
    the blockchain and this endpoint is disabled.
    """
    # Check if on-chain mode is enabled
    if deps.config.onchain.enabled:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="REST API allocations disabled. Use on-chain allocation via BrokerRequests contract.",
        )

    # Check if token can allocate more
    if not deps.ipam.can_allocate(token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token allocation limit reached",
        )

    # Check for existing allocation with same pubkey
    existing = deps.ipam.get_allocation_by_pubkey(request.pubkey)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Public key already has an allocation",
        )

    # Allocate prefix
    allocation = deps.ipam.allocate(
        pubkey=request.pubkey,
        token_hash=token.token_hash,
        endpoint=request.endpoint,
    )

    if not allocation:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No prefixes available",
        )

    # Add WireGuard peer
    try:
        deps.wg.add_peer(
            pubkey=request.pubkey,
            allowed_ips=allocation.prefix,
            endpoint=request.endpoint,
        )
    except WireGuardError as e:
        # Rollback allocation
        deps.ipam.release(str(allocation.prefix), token.token_hash)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to configure WireGuard: {e}",
        )

    broker_pubkey = deps.wg.get_public_key() or ""

    return AllocateResponse(
        prefix=str(allocation.prefix),
        gateway=str(deps.config.broker.broker_ipv6),
        broker_pubkey=broker_pubkey,
        broker_endpoint=deps.config.wireguard.public_endpoint,
        allocated_at=allocation.allocated_at.isoformat(),
    )


@app.get("/v1/allocate/{prefix:path}", response_model=AllocationInfo)
async def get_allocation(
    prefix: str,
    token: Token = Depends(get_token),
    deps: BrokerDeps = Depends(get_deps),
):
    """Get information about an allocation."""
    allocation = deps.ipam.get_allocation_by_prefix(prefix)
    if not allocation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Allocation not found",
        )

    # Check ownership (unless admin)
    if not token.is_admin and allocation.token_hash != token.token_hash:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this allocation",
        )

    # Determine status from WireGuard
    peer_status = deps.wg.get_peer_status(allocation.pubkey)
    if peer_status and peer_status.is_active:
        alloc_status = "active"
    elif peer_status and peer_status.latest_handshake:
        alloc_status = "idle"
    else:
        alloc_status = "never_connected"

    return AllocationInfo(
        prefix=str(allocation.prefix),
        pubkey=allocation.pubkey,
        endpoint=allocation.endpoint,
        allocated_at=allocation.allocated_at.isoformat(),
        last_seen_at=allocation.last_seen_at.isoformat() if allocation.last_seen_at else None,
        status=alloc_status,
    )


@app.delete("/v1/allocate/{prefix:path}", status_code=status.HTTP_204_NO_CONTENT)
async def release_allocation(
    prefix: str,
    token: Token = Depends(get_token),
    deps: BrokerDeps = Depends(get_deps),
):
    """Release an allocation.

    Note: When on-chain mode is enabled, releases are managed through
    the blockchain and this endpoint is disabled.
    """
    # Check if on-chain mode is enabled
    if deps.config.onchain.enabled:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="REST API releases disabled. Use on-chain release via BrokerRequests contract.",
        )

    allocation = deps.ipam.get_allocation_by_prefix(prefix)
    if not allocation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Allocation not found",
        )

    # Check ownership (unless admin)
    if not token.is_admin and allocation.token_hash != token.token_hash:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to release this allocation",
        )

    # Remove WireGuard peer
    try:
        deps.wg.remove_peer(allocation.pubkey)
    except WireGuardError:
        pass  # Best effort

    # Release from IPAM
    deps.ipam.release(prefix, token.token_hash)

    return None


@app.get("/v1/status", response_model=StatusResponse)
async def get_status(
    token: Token = Depends(get_admin_token),
    deps: BrokerDeps = Depends(get_deps),
):
    """Get broker status (admin only)."""
    stats = deps.ipam.get_stats()
    peers = deps.wg.list_peers()

    active = sum(1 for p in peers if p.is_active)
    idle = len(peers) - active

    return StatusResponse(
        upstream_prefix=stats["upstream_prefix"],
        allocation_size=stats["allocation_size"],
        total_allocations=stats["total_allocations"],
        used_allocations=stats["used_allocations"],
        available_allocations=stats["available_allocations"],
        active_peers=active,
        idle_peers=idle,
    )
