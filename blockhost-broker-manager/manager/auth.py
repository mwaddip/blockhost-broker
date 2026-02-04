"""Wallet-based authentication with replay protection."""

import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path
from typing import Optional

from eth_account.messages import encode_defunct
from web3 import Web3


class AuthManager:
    """Manages wallet-based authentication with nonce-based replay protection."""

    NONCE_EXPIRY = 300  # 5 minutes
    SESSION_EXPIRY = 86400  # 24 hours

    def __init__(self, config_path: Path, secret_key: str):
        self.config_path = config_path
        self.secret_key = secret_key.encode()
        self._nonces: dict[str, float] = {}  # nonce -> expiry timestamp
        self._sessions: dict[str, tuple[str, float]] = {}  # token -> (address, expiry)
        self._load_config()

    def _load_config(self) -> None:
        """Load authorized wallets from config."""
        if self.config_path.exists():
            data = json.loads(self.config_path.read_text())
            # Normalize addresses to checksum format
            self.authorized_wallets = {
                Web3.to_checksum_address(addr)
                for addr in data.get("authorized_wallets", [])
            }
        else:
            self.authorized_wallets = set()

    def save_config(self) -> None:
        """Save config to file."""
        data = {"authorized_wallets": list(self.authorized_wallets)}
        self.config_path.write_text(json.dumps(data, indent=2))

    def add_wallet(self, address: str) -> None:
        """Add an authorized wallet."""
        self.authorized_wallets.add(Web3.to_checksum_address(address))
        self.save_config()

    def remove_wallet(self, address: str) -> None:
        """Remove an authorized wallet."""
        self.authorized_wallets.discard(Web3.to_checksum_address(address))
        self.save_config()

    def is_authorized(self, address: str) -> bool:
        """Check if wallet is authorized."""
        try:
            return Web3.to_checksum_address(address) in self.authorized_wallets
        except Exception:
            return False

    def generate_nonce(self) -> str:
        """Generate a unique nonce for signing."""
        # Clean expired nonces
        now = time.time()
        self._nonces = {k: v for k, v in self._nonces.items() if v > now}

        nonce = secrets.token_hex(32)
        self._nonces[nonce] = now + self.NONCE_EXPIRY
        return nonce

    def verify_signature(self, nonce: str, signature: str) -> Optional[str]:
        """
        Verify a signed nonce and return the signer's address.
        Returns None if invalid or nonce already used/expired.
        """
        # Check nonce exists and not expired
        now = time.time()
        if nonce not in self._nonces or self._nonces[nonce] < now:
            return None

        # Consume the nonce (one-time use)
        del self._nonces[nonce]

        # Create the message that was signed
        message = f"Sign this message to authenticate with Blockhost Broker Manager.\n\nNonce: {nonce}"

        try:
            # Recover the signer's address
            message_hash = encode_defunct(text=message)
            w3 = Web3()
            recovered = w3.eth.account.recover_message(message_hash, signature=signature)
            return Web3.to_checksum_address(recovered)
        except Exception:
            return None

    def create_session(self, address: str) -> str:
        """Create a session token for an authenticated address."""
        token = secrets.token_hex(32)
        expiry = time.time() + self.SESSION_EXPIRY
        self._sessions[token] = (Web3.to_checksum_address(address), expiry)
        return token

    def validate_session(self, token: str) -> Optional[str]:
        """Validate a session token and return the address if valid."""
        if token not in self._sessions:
            return None

        address, expiry = self._sessions[token]
        if time.time() > expiry:
            del self._sessions[token]
            return None

        return address

    def invalidate_session(self, token: str) -> None:
        """Invalidate a session token (logout)."""
        self._sessions.pop(token, None)

    def cleanup_expired(self) -> None:
        """Remove expired nonces and sessions."""
        now = time.time()
        self._nonces = {k: v for k, v in self._nonces.items() if v > now}
        self._sessions = {k: v for k, v in self._sessions.items() if v[1] > now}
