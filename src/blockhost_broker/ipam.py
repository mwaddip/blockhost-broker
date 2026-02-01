"""IP Address Management (IPAM) module."""

from __future__ import annotations

import sqlite3
import hashlib
import secrets
from datetime import datetime, timezone
from ipaddress import IPv6Network
from pathlib import Path
from dataclasses import dataclass
from typing import Iterator

from .config import BrokerConfig


@dataclass
class Allocation:
    """An IPv6 prefix allocation."""

    id: int
    prefix: IPv6Network
    prefix_index: int
    pubkey: str
    endpoint: str | None
    token_hash: str
    allocated_at: datetime
    last_seen_at: datetime | None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Allocation":
        return cls(
            id=row["id"],
            prefix=IPv6Network(row["prefix"]),
            prefix_index=row["prefix_index"],
            pubkey=row["pubkey"],
            endpoint=row["endpoint"],
            token_hash=row["token_hash"],
            allocated_at=datetime.fromisoformat(row["allocated_at"]),
            last_seen_at=datetime.fromisoformat(row["last_seen_at"]) if row["last_seen_at"] else None,
        )


@dataclass
class Token:
    """An API token."""

    id: int
    token_hash: str
    name: str | None
    max_allocations: int
    is_admin: bool
    created_at: datetime
    expires_at: datetime | None
    revoked: bool

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Token":
        return cls(
            id=row["id"],
            token_hash=row["token_hash"],
            name=row["name"],
            max_allocations=row["max_allocations"],
            is_admin=row["is_admin"],
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            revoked=bool(row["revoked"]),
        )


def hash_token(token: str) -> str:
    """Hash a token using SHA-256."""
    return hashlib.sha256(token.encode()).hexdigest()


def generate_token() -> str:
    """Generate a new random token."""
    return secrets.token_urlsafe(32)


class IPAM:
    """IP Address Management database."""

    def __init__(self, db_path: Path, config: BrokerConfig):
        self.db_path = db_path
        self.config = config
        self._conn: sqlite3.Connection | None = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._init_schema()
        return self._conn

    def _init_schema(self) -> None:
        """Initialize database schema."""
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS allocations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                prefix TEXT UNIQUE NOT NULL,
                prefix_index INTEGER UNIQUE NOT NULL,
                pubkey TEXT NOT NULL,
                endpoint TEXT,
                token_hash TEXT NOT NULL,
                allocated_at TEXT NOT NULL,
                last_seen_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_allocations_token ON allocations(token_hash);
            CREATE INDEX IF NOT EXISTS idx_allocations_pubkey ON allocations(pubkey);

            CREATE TABLE IF NOT EXISTS tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT UNIQUE NOT NULL,
                name TEXT,
                max_allocations INTEGER DEFAULT 1,
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                revoked BOOLEAN DEFAULT FALSE
            );

            CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(token_hash);

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                token_hash TEXT,
                prefix TEXT,
                details TEXT
            );
        """)
        self.conn.commit()

    def close(self) -> None:
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def get_subnet(self, index: int) -> IPv6Network:
        """Calculate subnet from index."""
        network = self.config.upstream_prefix
        prefix_len = self.config.allocation_size
        subnet_size = 1 << (128 - prefix_len)
        subnet_start = int(network.network_address) + (index * subnet_size)
        return IPv6Network((subnet_start, prefix_len))

    def get_next_available_index(self) -> int | None:
        """Get the next available prefix index."""
        # Calculate max index based on upstream prefix and allocation size
        upstream_size = 128 - self.config.upstream_prefix.prefixlen
        alloc_size = 128 - self.config.allocation_size
        max_index = (1 << (upstream_size - alloc_size)) - 1

        # Get all used indices
        cursor = self.conn.execute(
            "SELECT prefix_index FROM allocations ORDER BY prefix_index"
        )
        used = {row["prefix_index"] for row in cursor}

        # Find first available (start at 1, reserve 0 for broker)
        for i in range(1, max_index + 1):
            if i not in used:
                return i
        return None

    def allocate(
        self,
        pubkey: str,
        token_hash: str,
        endpoint: str | None = None,
    ) -> Allocation | None:
        """Allocate a new prefix."""
        # Check if pubkey already has an allocation
        existing = self.get_allocation_by_pubkey(pubkey)
        if existing:
            return None

        # Get next available index
        index = self.get_next_available_index()
        if index is None:
            return None

        prefix = self.get_subnet(index)
        now = datetime.now(timezone.utc).isoformat()

        cursor = self.conn.execute(
            """
            INSERT INTO allocations (prefix, prefix_index, pubkey, endpoint, token_hash, allocated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (str(prefix), index, pubkey, endpoint, token_hash, now),
        )
        self.conn.commit()

        self._audit("allocate", token_hash, str(prefix), {"pubkey": pubkey, "endpoint": endpoint})

        return self.get_allocation(cursor.lastrowid)

    def get_allocation(self, alloc_id: int) -> Allocation | None:
        """Get allocation by ID."""
        cursor = self.conn.execute(
            "SELECT * FROM allocations WHERE id = ?", (alloc_id,)
        )
        row = cursor.fetchone()
        return Allocation.from_row(row) if row else None

    def get_allocation_by_prefix(self, prefix: str) -> Allocation | None:
        """Get allocation by prefix."""
        cursor = self.conn.execute(
            "SELECT * FROM allocations WHERE prefix = ?", (prefix,)
        )
        row = cursor.fetchone()
        return Allocation.from_row(row) if row else None

    def get_allocation_by_pubkey(self, pubkey: str) -> Allocation | None:
        """Get allocation by WireGuard public key."""
        cursor = self.conn.execute(
            "SELECT * FROM allocations WHERE pubkey = ?", (pubkey,)
        )
        row = cursor.fetchone()
        return Allocation.from_row(row) if row else None

    def get_allocations_by_token(self, token_hash: str) -> list[Allocation]:
        """Get all allocations for a token."""
        cursor = self.conn.execute(
            "SELECT * FROM allocations WHERE token_hash = ?", (token_hash,)
        )
        return [Allocation.from_row(row) for row in cursor]

    def list_allocations(self) -> list[Allocation]:
        """List all allocations."""
        cursor = self.conn.execute("SELECT * FROM allocations ORDER BY prefix_index")
        return [Allocation.from_row(row) for row in cursor]

    def release(self, prefix: str, token_hash: str) -> bool:
        """Release an allocation."""
        # Verify ownership
        alloc = self.get_allocation_by_prefix(prefix)
        if not alloc:
            return False

        # Check if token owns this allocation (or is admin)
        token = self.get_token(token_hash)
        if not token:
            return False
        if not token.is_admin and alloc.token_hash != token_hash:
            return False

        self.conn.execute("DELETE FROM allocations WHERE prefix = ?", (prefix,))
        self.conn.commit()

        self._audit("release", token_hash, prefix, {})
        return True

    def update_last_seen(self, prefix: str, timestamp: datetime) -> None:
        """Update last seen timestamp for an allocation."""
        self.conn.execute(
            "UPDATE allocations SET last_seen_at = ? WHERE prefix = ?",
            (timestamp.isoformat(), prefix),
        )
        self.conn.commit()

    # Token management

    def create_token(
        self,
        name: str | None = None,
        max_allocations: int = 1,
        is_admin: bool = False,
    ) -> tuple[str, Token]:
        """Create a new API token. Returns (plaintext_token, Token)."""
        token = generate_token()
        token_h = hash_token(token)
        now = datetime.now(timezone.utc).isoformat()

        cursor = self.conn.execute(
            """
            INSERT INTO tokens (token_hash, name, max_allocations, is_admin, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (token_h, name, max_allocations, is_admin, now),
        )
        self.conn.commit()

        self._audit("token_create", token_h, None, {"name": name, "is_admin": is_admin})

        return token, self.get_token(token_h)

    def get_token(self, token_hash: str) -> Token | None:
        """Get token by hash."""
        cursor = self.conn.execute(
            "SELECT * FROM tokens WHERE token_hash = ?", (token_hash,)
        )
        row = cursor.fetchone()
        return Token.from_row(row) if row else None

    def validate_token(self, token: str) -> Token | None:
        """Validate a plaintext token and return Token if valid."""
        token_h = hash_token(token)
        t = self.get_token(token_h)
        if not t:
            return None
        if t.revoked:
            return None
        if t.expires_at and t.expires_at < datetime.now(timezone.utc):
            return None
        return t

    def can_allocate(self, token: Token) -> bool:
        """Check if token can make another allocation."""
        if token.is_admin:
            return True
        current = len(self.get_allocations_by_token(token.token_hash))
        return current < token.max_allocations

    def list_tokens(self) -> list[Token]:
        """List all tokens."""
        cursor = self.conn.execute("SELECT * FROM tokens ORDER BY created_at")
        return [Token.from_row(row) for row in cursor]

    def revoke_token(self, token_id: int) -> bool:
        """Revoke a token."""
        cursor = self.conn.execute(
            "UPDATE tokens SET revoked = TRUE WHERE id = ?", (token_id,)
        )
        self.conn.commit()
        return cursor.rowcount > 0

    # Stats

    def get_stats(self) -> dict:
        """Get allocation statistics."""
        upstream_size = 128 - self.config.upstream_prefix.prefixlen
        alloc_size = 128 - self.config.allocation_size
        total = (1 << (upstream_size - alloc_size)) - 1  # -1 for reserved index 0

        cursor = self.conn.execute("SELECT COUNT(*) as count FROM allocations")
        used = cursor.fetchone()["count"]

        return {
            "upstream_prefix": str(self.config.upstream_prefix),
            "allocation_size": self.config.allocation_size,
            "total_allocations": total,
            "used_allocations": used,
            "available_allocations": total - used,
        }

    def _audit(self, action: str, token_hash: str | None, prefix: str | None, details: dict) -> None:
        """Log an audit event."""
        import json
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT INTO audit_log (timestamp, action, token_hash, prefix, details) VALUES (?, ?, ?, ?, ?)",
            (now, action, token_hash, prefix, json.dumps(details)),
        )
        self.conn.commit()
