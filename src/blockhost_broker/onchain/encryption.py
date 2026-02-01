"""ECIES encryption/decryption for on-chain communication.

Uses secp256k1 curve for encryption of request/response payloads.
WireGuard uses Curve25519 separately (inside the encrypted payload).
"""

import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import ecies
from eth_account import Account


@dataclass
class RequestPayload:
    """Decrypted request payload from Blockhost server."""

    wg_pubkey: str  # Base64 WireGuard public key
    nft_contract: str  # Checksummed NFT contract address
    server_pubkey: str  # Hex secp256k1 pubkey for response encryption


@dataclass
class ResponsePayload:
    """Response payload to encrypt for Blockhost server."""

    prefix: str  # e.g., "2a11:6c7:f04:276::100/120"
    gateway: str  # e.g., "2a11:6c7:f04:276::2"
    broker_pubkey: str  # Base64 WireGuard public key
    broker_endpoint: str  # e.g., "95.179.128.177:51820"


class ECIESEncryption:
    """ECIES encryption handler using secp256k1."""

    def __init__(self, private_key_hex: str | None = None):
        """Initialize with optional private key.

        Args:
            private_key_hex: Hex-encoded secp256k1 private key (32 bytes).
                           If None, a new key will be generated.
        """
        if private_key_hex:
            # Remove 0x prefix if present
            if private_key_hex.startswith("0x"):
                private_key_hex = private_key_hex[2:]
            self._private_key = bytes.fromhex(private_key_hex)
        else:
            self._private_key = secrets.token_bytes(32)

        # Derive public key using eth_account
        account = Account.from_key(self._private_key)
        # Get uncompressed public key (65 bytes: 04 || x || y)
        self._public_key = self._get_uncompressed_pubkey(account)

    def _get_uncompressed_pubkey(self, account: Account) -> bytes:
        """Get uncompressed secp256k1 public key (65 bytes)."""
        from eth_keys import keys

        pk = keys.PrivateKey(self._private_key)
        # eth_keys returns 64 bytes (x || y), we need to add 0x04 prefix
        # for uncompressed format that eciespy expects
        pubkey_bytes = pk.public_key.to_bytes()
        if len(pubkey_bytes) == 64:
            return b"\x04" + pubkey_bytes
        return pubkey_bytes

    @property
    def private_key_hex(self) -> str:
        """Get private key as hex string."""
        return self._private_key.hex()

    @property
    def public_key_bytes(self) -> bytes:
        """Get uncompressed public key (65 bytes)."""
        return self._public_key

    @property
    def public_key_hex(self) -> str:
        """Get public key as hex string."""
        return self._public_key.hex()

    @classmethod
    def from_file(cls, key_path: Path | str) -> "ECIESEncryption":
        """Load private key from file.

        Args:
            key_path: Path to file containing hex-encoded private key.

        Returns:
            ECIESEncryption instance.
        """
        key_path = Path(key_path)
        private_key_hex = key_path.read_text().strip()
        return cls(private_key_hex)

    def save_to_file(self, key_path: Path | str) -> None:
        """Save private key to file.

        Args:
            key_path: Path to save hex-encoded private key.
        """
        key_path = Path(key_path)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_text(self.private_key_hex)
        # Set restrictive permissions
        key_path.chmod(0o600)

    def encrypt(self, plaintext: bytes, recipient_pubkey: bytes) -> bytes:
        """Encrypt data for a recipient.

        Args:
            plaintext: Data to encrypt.
            recipient_pubkey: Recipient's uncompressed secp256k1 public key (65 bytes).

        Returns:
            Encrypted ciphertext.
        """
        return ecies.encrypt(recipient_pubkey, plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt data encrypted for this key.

        Args:
            ciphertext: Encrypted data.

        Returns:
            Decrypted plaintext.
        """
        return ecies.decrypt(self._private_key, ciphertext)

    def encrypt_json(self, data: dict[str, Any], recipient_pubkey: bytes) -> bytes:
        """Encrypt JSON data for a recipient.

        Args:
            data: Dictionary to encrypt.
            recipient_pubkey: Recipient's uncompressed secp256k1 public key.

        Returns:
            Encrypted ciphertext.
        """
        plaintext = json.dumps(data).encode("utf-8")
        return self.encrypt(plaintext, recipient_pubkey)

    def decrypt_json(self, ciphertext: bytes) -> dict[str, Any]:
        """Decrypt JSON data.

        Args:
            ciphertext: Encrypted data.

        Returns:
            Decrypted dictionary.
        """
        plaintext = self.decrypt(ciphertext)
        return json.loads(plaintext.decode("utf-8"))

    def decrypt_request_payload(self, encrypted_payload: bytes) -> RequestPayload:
        """Decrypt and parse a request payload from Blockhost server.

        Args:
            encrypted_payload: ECIES encrypted request data.

        Returns:
            RequestPayload with WireGuard pubkey, NFT contract, and server pubkey.
        """
        data = self.decrypt_json(encrypted_payload)
        return RequestPayload(
            wg_pubkey=data["wgPubkey"],
            nft_contract=data["nftContract"],
            server_pubkey=data["serverPubkey"],
        )

    def encrypt_response_payload(
        self, response: ResponsePayload, server_pubkey_hex: str
    ) -> bytes:
        """Encrypt a response payload for Blockhost server.

        Args:
            response: Response data to encrypt.
            server_pubkey_hex: Server's secp256k1 public key (hex, 65 bytes).

        Returns:
            ECIES encrypted response.
        """
        server_pubkey = bytes.fromhex(server_pubkey_hex)
        data = {
            "prefix": response.prefix,
            "gateway": response.gateway,
            "brokerPubkey": response.broker_pubkey,
            "brokerEndpoint": response.broker_endpoint,
        }
        return self.encrypt_json(data, server_pubkey)


def generate_ecies_keypair(key_path: Path | str) -> ECIESEncryption:
    """Generate a new ECIES keypair and save to file.

    Args:
        key_path: Path to save the private key.

    Returns:
        ECIESEncryption instance with new keypair.
    """
    encryption = ECIESEncryption()
    encryption.save_to_file(key_path)
    return encryption
