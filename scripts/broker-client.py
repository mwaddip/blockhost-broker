#!/usr/bin/env python3
"""
Blockhost Broker Client

Runs on Blockhost servers (Proxmox) to request IPv6 prefix allocations
from brokers via on-chain authentication.

This script is standalone and does not depend on the blockhost-broker package.
It can be deployed independently to Proxmox servers.

Usage:
    broker-client.py request --nft-contract 0x... --wallet-key /path/to/key
    broker-client.py status --nft-contract 0x...
    broker-client.py release --nft-contract 0x... --wallet-key /path/to/key

Requirements:
    pip install web3 eciespy eth-account
"""

from __future__ import annotations

CLIENT_VERSION = "0.3.0"  # V2 contracts: overwrite, capacity-aware broker selection

import argparse
import ipaddress
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import ecies
    from eth_account import Account
    from eth_account.signers.local import LocalAccount
    from eth_keys import keys
    from web3 import Web3
    import urllib.request
except ImportError as e:
    print(f"Missing dependency: {e}", file=sys.stderr)
    print("Install with: pip install web3 eciespy eth-account", file=sys.stderr)
    sys.exit(1)


# Default configuration
DEFAULT_CONFIG_DIR = Path("/etc/blockhost")
DEFAULT_RPC_URL = "https://ethereum-sepolia-rpc.publicnode.com"
DEFAULT_CHAIN_ID = 11155111
DEFAULT_POLL_INTERVAL = 5  # seconds
MIN_POLL_INTERVAL = 2  # minimum seconds between RPC polls
DEFAULT_TIMEOUT = 300  # 5 minutes
GAS_BUFFER = 50000  # extra gas added to estimates
TX_RECEIPT_TIMEOUT = 120  # seconds to wait for transaction receipt
EVENT_BLOCK_LOOKBACK = 10000  # blocks to search back for events

# Remote configuration URL - contains the current BrokerRegistry contract address
# This allows updating the registry address without releasing a new client version
REGISTRY_CONFIG_URL = "https://raw.githubusercontent.com/mwaddip/blockhost-broker/main/registry.json"


WG_INTERFACE_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,15}$")


def validate_wg_interface(name: str) -> str:
    """Validate WireGuard interface name."""
    if not WG_INTERFACE_PATTERN.match(name):
        raise ValueError(
            f"Invalid WireGuard interface name: {name!r} "
            "(must be 1-15 alphanumeric/dash/underscore characters)"
        )
    return name


def validate_hex_pubkey(hex_str: str, label: str = "public key") -> bytes:
    """Validate a hex-encoded public key and return bytes."""
    try:
        key_bytes = bytes.fromhex(hex_str)
    except ValueError:
        raise ValueError(f"Invalid hex encoding for {label}: {hex_str[:20]}...")
    if len(key_bytes) < 32:
        raise ValueError(f"{label} too short ({len(key_bytes)} bytes, expected >= 32)")
    return key_bytes


def fetch_registry_address() -> Optional[str]:
    """Fetch the current BrokerRegistry contract address from remote config."""
    try:
        with urllib.request.urlopen(REGISTRY_CONFIG_URL, timeout=10) as response:
            raw = response.read(4096)  # Limit read size
            data = json.loads(raw.decode('utf-8'))
            addr = data.get("registry_contract")
            if addr and isinstance(addr, str) and len(addr) == 42 and addr.startswith("0x"):
                return addr
            print("Warning: Invalid registry address format in remote config", file=sys.stderr)
            return None
    except (urllib.error.URLError, json.JSONDecodeError, ValueError) as e:
        print(f"Warning: Could not fetch registry address: {e}", file=sys.stderr)
        return None


# Contract ABIs (minimal subsets needed for client operations)

BROKER_REGISTRY_ABI = [
    {
        "inputs": [],
        "name": "getBrokerCount",
        "outputs": [{"internalType": "uint256", "name": "count", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "uint256", "name": "brokerId", "type": "uint256"}],
        "name": "getBroker",
        "outputs": [
            {
                "components": [
                    {"internalType": "address", "name": "operator", "type": "address"},
                    {"internalType": "address", "name": "requestsContract", "type": "address"},
                    {"internalType": "bytes", "name": "encryptionPubkey", "type": "bytes"},
                    {"internalType": "string", "name": "region", "type": "string"},
                    {"internalType": "bool", "name": "active", "type": "bool"},
                    {"internalType": "uint256", "name": "capacity", "type": "uint256"},
                    {"internalType": "uint256", "name": "currentLoad", "type": "uint256"},
                    {"internalType": "uint256", "name": "registeredAt", "type": "uint256"},
                ],
                "internalType": "struct BrokerRegistry.Broker",
                "name": "broker",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
]

BROKER_REQUESTS_ABI = [
    {
        "inputs": [
            {"internalType": "address", "name": "nftContract", "type": "address"},
            {"internalType": "bytes", "name": "encryptedPayload", "type": "bytes"},
        ],
        "name": "submitRequest",
        "outputs": [{"internalType": "uint256", "name": "requestId", "type": "uint256"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "address", "name": "nftContract", "type": "address"},
        ],
        "name": "releaseAllocation",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "uint256", "name": "requestId", "type": "uint256"}],
        "name": "getRequest",
        "outputs": [
            {
                "components": [
                    {"internalType": "uint256", "name": "id", "type": "uint256"},
                    {"internalType": "address", "name": "requester", "type": "address"},
                    {"internalType": "address", "name": "nftContract", "type": "address"},
                    {"internalType": "bytes", "name": "encryptedPayload", "type": "bytes"},
                    {"internalType": "uint8", "name": "status", "type": "uint8"},
                    {"internalType": "bytes", "name": "responsePayload", "type": "bytes"},
                    {"internalType": "uint256", "name": "submittedAt", "type": "uint256"},
                    {"internalType": "uint256", "name": "respondedAt", "type": "uint256"},
                ],
                "internalType": "struct BrokerRequests.Request",
                "name": "request",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "address", "name": "", "type": "address"}],
        "name": "nftContractToRequestId",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "getAvailableCapacity",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "uint256", "name": "requestId", "type": "uint256"},
            {"indexed": True, "internalType": "address", "name": "requester", "type": "address"},
            {"indexed": True, "internalType": "address", "name": "nftContract", "type": "address"},
            {"indexed": False, "internalType": "bytes", "name": "encryptedPayload", "type": "bytes"},
        ],
        "name": "RequestSubmitted",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "uint256", "name": "requestId", "type": "uint256"},
            {"indexed": False, "internalType": "uint8", "name": "status", "type": "uint8"},
            {"indexed": False, "internalType": "bytes", "name": "encryptedPayload", "type": "bytes"},
        ],
        "name": "ResponseSubmitted",
        "type": "event",
    },
]

# Request status enum (v2 contracts use silent rejections - no REJECTED status)
REQUEST_STATUS_PENDING = 0
REQUEST_STATUS_APPROVED = 1
REQUEST_STATUS_EXPIRED = 3

REQUEST_STATUS_NAMES = {
    REQUEST_STATUS_PENDING: "Pending",
    REQUEST_STATUS_APPROVED: "Approved",
    REQUEST_STATUS_EXPIRED: "Expired",
}


@dataclass
class BrokerInfo:
    """Information about an available broker."""

    id: int
    operator: str
    requests_contract: str
    encryption_pubkey: bytes
    region: str
    capacity: int
    current_load: int


def _validate_allocation_response(data: dict) -> "AllocationResponse":
    """Validate and construct an AllocationResponse from decrypted broker data."""
    required_fields = ["prefix", "gateway", "brokerPubkey", "brokerEndpoint"]
    for field in required_fields:
        if field not in data or not isinstance(data[field], str) or not data[field]:
            raise ValueError(f"Missing or invalid field in broker response: {field}")

    # Validate prefix is a valid IPv6 CIDR
    try:
        ipaddress.IPv6Network(data["prefix"], strict=False)
    except (ValueError, ipaddress.AddressValueError) as e:
        raise ValueError(f"Invalid IPv6 prefix in broker response: {e}")

    # Validate gateway is a valid IPv6 address
    try:
        ipaddress.IPv6Address(data["gateway"])
    except (ValueError, ipaddress.AddressValueError) as e:
        raise ValueError(f"Invalid gateway address in broker response: {e}")

    return AllocationResponse(
        prefix=data["prefix"],
        gateway=data["gateway"],
        broker_pubkey=data["brokerPubkey"],
        broker_endpoint=data["brokerEndpoint"],
    )


REQUEST_ID_PREFIX_LEN = 8


def _extract_request_id_prefix(payload: bytes) -> tuple[int, bytes]:
    """Extract the 8-byte big-endian request ID prefix from a response payload.

    Returns (request_id, remaining_payload).  If the payload is too short
    to contain a prefix, returns (0, original_payload).
    """
    if len(payload) <= REQUEST_ID_PREFIX_LEN:
        return (0, payload)
    prefix_bytes = payload[:REQUEST_ID_PREFIX_LEN]
    request_id = int.from_bytes(prefix_bytes, byteorder="big")
    return (request_id, payload[REQUEST_ID_PREFIX_LEN:])


@dataclass
class AllocationResponse:
    """Decrypted allocation response from broker."""

    prefix: str
    gateway: str
    broker_pubkey: str
    broker_endpoint: str


@dataclass
class AllocationConfig:
    """Stored allocation configuration."""

    prefix: str
    gateway: str
    broker_pubkey: str
    broker_endpoint: str
    nft_contract: str
    request_id: int
    wg_private_key: str
    wg_public_key: str
    allocated_at: str
    broker_wallet: str = ""  # Wallet address that submitted the response


class ECIESClient:
    """ECIES encryption for client-side operations."""

    def __init__(self, private_key_hex: Optional[str] = None):
        """Initialize with optional private key."""
        if private_key_hex:
            if private_key_hex.startswith("0x"):
                private_key_hex = private_key_hex[2:]
            self._private_key = bytes.fromhex(private_key_hex)
        else:
            self._private_key = secrets.token_bytes(32)

        pk = keys.PrivateKey(self._private_key)
        # eth_keys returns 64 bytes (x || y), add 0x04 prefix for uncompressed format
        pubkey_bytes = pk.public_key.to_bytes()
        if len(pubkey_bytes) == 64:
            self._public_key = b"\x04" + pubkey_bytes
        else:
            self._public_key = pubkey_bytes

    @property
    def private_key_hex(self) -> str:
        return self._private_key.hex()

    @property
    def public_key_hex(self) -> str:
        return self._public_key.hex()

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key

    def encrypt_json(self, data: dict, recipient_pubkey: bytes) -> bytes:
        """Encrypt JSON data for recipient."""
        plaintext = json.dumps(data).encode("utf-8")
        return ecies.encrypt(recipient_pubkey, plaintext)

    def decrypt_json(self, ciphertext: bytes) -> dict:
        """Decrypt JSON data."""
        plaintext = ecies.decrypt(self._private_key, ciphertext)
        return json.loads(plaintext.decode("utf-8"))


class BrokerClient:
    """Client for interacting with broker contracts."""

    def __init__(
        self,
        rpc_url: str = DEFAULT_RPC_URL,
        chain_id: int = DEFAULT_CHAIN_ID,
        registry_contract: Optional[str] = None,
    ):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.chain_id = chain_id
        self.registry_contract = registry_contract

        if registry_contract:
            self.registry = self.w3.eth.contract(
                address=Web3.to_checksum_address(registry_contract),
                abi=BROKER_REGISTRY_ABI,
            )
        else:
            self.registry = None

    def get_active_brokers(self) -> list[BrokerInfo]:
        """Get list of active brokers from registry using lazy iteration."""
        if not self.registry:
            raise ValueError("Registry contract not configured")

        # Get total broker count
        count = self.registry.functions.getBrokerCount().call()

        result = []
        # Iterate through all brokers (IDs start at 1)
        for broker_id in range(1, count + 1):
            try:
                broker = self.registry.functions.getBroker(broker_id).call()
                # broker[4] is the 'active' field
                if broker[4]:  # Only include active brokers
                    result.append(
                        BrokerInfo(
                            id=broker_id,
                            operator=broker[0],
                            requests_contract=broker[1],
                            encryption_pubkey=broker[2],
                            region=broker[3],
                            capacity=broker[5],
                            current_load=broker[6],
                        )
                    )
            except Exception as e:
                # Skip brokers that fail to load
                print(f"Warning: Could not load broker #{broker_id}: {e}", file=sys.stderr)
                continue

        return result

    def get_broker(self, broker_id: int) -> BrokerInfo:
        """Get broker by ID from registry."""
        if not self.registry:
            raise ValueError("Registry contract not configured")

        broker = self.registry.functions.getBroker(broker_id).call()
        return BrokerInfo(
            id=broker_id,
            operator=broker[0],
            requests_contract=broker[1],
            encryption_pubkey=broker[2],
            region=broker[3],
            capacity=broker[5],
            current_load=broker[6],
        )

    def get_available_capacity(self, requests_contract: str) -> int:
        """Get available capacity for a broker's requests contract.

        Returns type(uint256).max if unlimited (0 capacity configured).
        """
        contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(requests_contract),
            abi=BROKER_REQUESTS_ABI,
        )
        return contract.functions.getAvailableCapacity().call()

    def submit_request(
        self,
        account: LocalAccount,
        requests_contract: str,
        nft_contract: str,
        encrypted_payload: bytes,
    ) -> int:
        """Submit allocation request to broker's contract."""
        contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(requests_contract),
            abi=BROKER_REQUESTS_ABI,
        )

        # Estimate gas first
        gas_estimate = contract.functions.submitRequest(
            Web3.to_checksum_address(nft_contract),
            encrypted_payload,
        ).estimate_gas({"from": account.address})

        tx = contract.functions.submitRequest(
            Web3.to_checksum_address(nft_contract),
            encrypted_payload,
        ).build_transaction(
            {
                "from": account.address,
                "nonce": self.w3.eth.get_transaction_count(account.address),
                "gas": gas_estimate + GAS_BUFFER,
                "maxFeePerGas": self.w3.eth.gas_price * 2,
                "maxPriorityFeePerGas": self.w3.eth.gas_price,
                "chainId": self.chain_id,
            }
        )

        signed = account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=TX_RECEIPT_TIMEOUT)

        if receipt["status"] != 1:
            raise RuntimeError(f"Transaction failed: {tx_hash.hex()}")

        # Parse request ID from logs — event must exist if tx succeeded
        logs = contract.events.RequestSubmitted().process_receipt(receipt)
        if not logs:
            raise RuntimeError(
                f"Transaction succeeded but no RequestSubmitted event found (tx: {tx_hash.hex()}). "
                "This should not happen — the RPC node may have returned an incomplete receipt."
            )
        return logs[0]["args"]["requestId"]

    def get_request_status(
        self, requests_contract: str, request_id: int
    ) -> tuple[int, bytes]:
        """Get request status and response payload."""
        contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(requests_contract),
            abi=BROKER_REQUESTS_ABI,
        )

        request = contract.functions.getRequest(request_id).call()
        # Returns: (id, requester, nftContract, encryptedPayload, status, responsePayload, submittedAt, respondedAt)
        status = request[4]
        response_payload = request[5]
        return status, response_payload

    def get_request_id_for_nft(
        self, requests_contract: str, nft_contract: str
    ) -> int:
        """Get request ID for an NFT contract."""
        contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(requests_contract),
            abi=BROKER_REQUESTS_ABI,
        )
        return contract.functions.nftContractToRequestId(
            Web3.to_checksum_address(nft_contract)
        ).call()

    def get_response_sender(
        self, requests_contract: str, request_id: int
    ) -> Optional[str]:
        """Get the wallet address that submitted the response for a request.

        Queries the ResponseSubmitted event logs to find the transaction,
        then extracts the sender (from) address.
        """
        contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(requests_contract),
            abi=BROKER_REQUESTS_ABI,
        )

        try:
            # Get ResponseSubmitted events for this request ID
            latest_block = self.w3.eth.block_number
            from_block = max(0, latest_block - EVENT_BLOCK_LOOKBACK)

            logs = contract.events.ResponseSubmitted().get_logs(
                from_block=from_block,
                argument_filters={"requestId": request_id},
            )

            if logs:
                # Get the transaction that emitted the event
                tx_hash = logs[0]["transactionHash"]
                tx = self.w3.eth.get_transaction(tx_hash)
                return tx["from"]
        except Exception as e:
            print(f"Warning: Could not get response sender: {e}", file=sys.stderr)

        return None

    def release_allocation(
        self,
        account: LocalAccount,
        requests_contract: str,
        nft_contract: str,
    ) -> str:
        """Release an allocation on-chain. Returns transaction hash."""
        contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(requests_contract),
            abi=BROKER_REQUESTS_ABI,
        )

        # Estimate gas
        gas_estimate = contract.functions.releaseAllocation(
            Web3.to_checksum_address(nft_contract),
        ).estimate_gas({"from": account.address})

        tx = contract.functions.releaseAllocation(
            Web3.to_checksum_address(nft_contract),
        ).build_transaction(
            {
                "from": account.address,
                "nonce": self.w3.eth.get_transaction_count(account.address),
                "gas": gas_estimate + GAS_BUFFER,
                "maxFeePerGas": self.w3.eth.gas_price * 2,
                "maxPriorityFeePerGas": self.w3.eth.gas_price,
                "chainId": self.chain_id,
            }
        )

        signed = account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=TX_RECEIPT_TIMEOUT)

        if receipt["status"] != 1:
            raise RuntimeError(f"Transaction failed: {tx_hash.hex()}")

        return tx_hash.hex()


def generate_wireguard_keypair() -> tuple[str, str]:
    """Generate WireGuard keypair using wg command."""
    # Generate private key
    result = subprocess.run(
        ["wg", "genkey"],
        capture_output=True,
        text=True,
        check=True,
    )
    private_key = result.stdout.strip()

    # Derive public key
    result = subprocess.run(
        ["wg", "pubkey"],
        input=private_key,
        capture_output=True,
        text=True,
        check=True,
    )
    public_key = result.stdout.strip()

    return private_key, public_key


def configure_wireguard(
    interface: str,
    private_key: str,
    prefix: str,
    gateway: str,
    broker_pubkey: str,
    broker_endpoint: str,
) -> None:
    """Configure WireGuard interface for broker tunnel."""
    validate_wg_interface(interface)

    # Write private key to temp file (secure creation to avoid TOCTOU race)
    fd = os.open(
        f"/tmp/wg-{interface}-private.key",
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    key_file = Path(f"/tmp/wg-{interface}-private.key")
    with os.fdopen(fd, "w") as f:
        f.write(private_key)

    try:
        # Create interface if not exists
        subprocess.run(
            ["ip", "link", "show", interface],
            capture_output=True,
            check=False,
        )
        result = subprocess.run(
            ["ip", "link", "show", interface],
            capture_output=True,
        )
        if result.returncode != 0:
            subprocess.run(
                ["ip", "link", "add", interface, "type", "wireguard"],
                check=True,
            )

        # Configure WireGuard
        subprocess.run(
            ["wg", "set", interface, "private-key", str(key_file)],
            check=True,
        )

        # Add broker as peer
        subprocess.run(
            [
                "wg", "set", interface,
                "peer", broker_pubkey,
                "endpoint", broker_endpoint,
                "allowed-ips", "::/0",
                "persistent-keepalive", "25",
            ],
            check=True,
        )

        # Configure IP address - use first address in allocated prefix
        network = ipaddress.IPv6Network(prefix, strict=False)
        # Use network address + 1 as interface address (e.g., ::400/120 -> ::401)
        interface_ip = network.network_address + 1
        interface_addr = f"{interface_ip}/{network.prefixlen}"

        subprocess.run(
            ["ip", "-6", "addr", "add", interface_addr, "dev", interface],
            check=False,  # May already exist
        )

        # Bring up interface
        subprocess.run(
            ["ip", "link", "set", interface, "up"],
            check=True,
        )

        # Add default route through the WireGuard interface
        # Use 'dev' instead of 'via gateway' since it's a point-to-point tunnel
        subprocess.run(
            ["ip", "-6", "route", "add", "default", "dev", interface],
            check=False,  # May already exist
        )

        print(f"WireGuard interface {interface} configured")

    finally:
        key_file.unlink(missing_ok=True)


def save_allocation_config(config_dir: Path, config: AllocationConfig) -> None:
    """Save allocation configuration to file."""
    config_dir.mkdir(parents=True, exist_ok=True)

    config_file = config_dir / "broker-allocation.json"
    config_file.write_text(
        json.dumps(
            {
                "prefix": config.prefix,
                "gateway": config.gateway,
                "broker_pubkey": config.broker_pubkey,
                "broker_endpoint": config.broker_endpoint,
                "nft_contract": config.nft_contract,
                "request_id": config.request_id,
                "wg_private_key": config.wg_private_key,
                "wg_public_key": config.wg_public_key,
                "allocated_at": config.allocated_at,
                "broker_wallet": config.broker_wallet,
            },
            indent=2,
        )
    )
    config_file.chmod(0o600)

    print(f"Allocation config saved to {config_file}")


def load_allocation_config(config_dir: Path) -> Optional[AllocationConfig]:
    """Load allocation configuration from file."""
    config_file = config_dir / "broker-allocation.json"
    if not config_file.exists():
        return None

    data = json.loads(config_file.read_text())
    return AllocationConfig(
        prefix=data["prefix"],
        gateway=data["gateway"],
        broker_pubkey=data["broker_pubkey"],
        broker_endpoint=data["broker_endpoint"],
        nft_contract=data["nft_contract"],
        request_id=data["request_id"],
        wg_private_key=data["wg_private_key"],
        wg_public_key=data["wg_public_key"],
        allocated_at=data["allocated_at"],
        broker_wallet=data.get("broker_wallet", ""),
    )


def delete_allocation_config(config_dir: Path) -> bool:
    """Delete allocation configuration file. Returns True if deleted."""
    config_file = config_dir / "broker-allocation.json"
    if config_file.exists():
        config_file.unlink()
        return True
    return False


def teardown_wireguard(interface: str) -> None:
    """Tear down WireGuard interface and remove persistent config."""
    # Stop wg-quick interface
    subprocess.run(
        ["wg-quick", "down", interface],
        capture_output=True,
    )

    # Also try to remove raw interface (in case not using wg-quick)
    subprocess.run(
        ["ip", "link", "del", interface],
        capture_output=True,
    )

    # Disable systemd service
    subprocess.run(
        ["systemctl", "disable", f"wg-quick@{interface}"],
        capture_output=True,
    )

    # Remove wg-quick config file
    wg_conf = Path(f"/etc/wireguard/{interface}.conf")
    if wg_conf.exists():
        try:
            wg_conf.unlink()
            print(f"Removed {wg_conf}")
        except PermissionError:
            print(f"Warning: Could not remove {wg_conf} (permission denied)", file=sys.stderr)


def cmd_request(args: argparse.Namespace) -> int:
    """Handle allocation request command."""
    # Load server key for ECIES operations
    server_key_file = Path(args.config_dir) / "server.key"
    if not server_key_file.exists():
        print(f"Server key not found at {server_key_file}", file=sys.stderr)
        print("Run the setup wizard first to generate the server keypair", file=sys.stderr)
        return 1

    server_key = server_key_file.read_text().strip()
    ecies_client = ECIESClient(private_key_hex=server_key)
    print(f"Using server key: {ecies_client.public_key_hex[:16]}...")

    # Load wallet
    wallet_key = Path(args.wallet_key).read_text().strip()
    account = Account.from_key(wallet_key)
    print(f"Using wallet: {account.address}")

    # Initialize client
    client = BrokerClient(
        rpc_url=args.rpc_url,
        chain_id=args.chain_id,
        registry_contract=args.registry_contract,
    )

    # Get broker info
    if args.broker_id:
        broker = client.get_broker(args.broker_id)
        print(f"Using broker #{broker.id} in {broker.region}")
    elif args.requests_contract and args.broker_pubkey:
        # Direct broker specification
        broker = BrokerInfo(
            id=0,
            operator="",
            requests_contract=args.requests_contract,
            encryption_pubkey=validate_hex_pubkey(args.broker_pubkey, "broker ECIES public key"),
            region="",
            capacity=0,
            current_load=0,
        )
        print(f"Using broker at {broker.requests_contract}")
    else:
        # Get from registry
        brokers = client.get_active_brokers()
        if not brokers:
            print("No active brokers found", file=sys.stderr)
            return 1

        # Filter by region if specified
        if args.region:
            brokers = [b for b in brokers if b.region == args.region]
            if not brokers:
                print(f"No brokers found in region {args.region}", file=sys.stderr)
                return 1

        # Filter by on-chain capacity
        available_brokers = []
        for b in brokers:
            try:
                capacity = client.get_available_capacity(b.requests_contract)
                if capacity > 0:
                    available_brokers.append(b)
                else:
                    print(f"  Broker #{b.id} ({b.region}): no capacity", file=sys.stderr)
            except Exception as e:
                # If capacity check fails (legacy contract), include the broker anyway
                print(f"  Broker #{b.id}: capacity check failed ({e}), including", file=sys.stderr)
                available_brokers.append(b)

        if not available_brokers:
            print("No brokers with available capacity", file=sys.stderr)
            return 1

        # Select broker with lowest load from those with capacity
        broker = min(available_brokers, key=lambda b: b.current_load)
        print(f"Selected broker #{broker.id} in {broker.region} (load: {broker.current_load})")

    # Check for existing request
    existing_request_id = client.get_request_id_for_nft(
        broker.requests_contract, args.nft_contract
    )
    if existing_request_id != 0:
        print(f"NFT contract already has request #{existing_request_id}")
        status, response_payload = client.get_request_status(
            broker.requests_contract, existing_request_id
        )
        if status == REQUEST_STATUS_APPROVED:
            print("Request already approved - recovering allocation...")
            # Check request ID prefix to detect stale responses before decryption
            embedded_id, encrypted_part = _extract_request_id_prefix(response_payload)
            stale = False
            if embedded_id != existing_request_id:
                print(
                    f"Response request ID ({embedded_id}) does not match "
                    f"current request ({existing_request_id}) — stale response",
                    file=sys.stderr,
                )
                stale = True
            else:
                # IDs match (or legacy response) — try decryption
                try:
                    response_data = ecies_client.decrypt_json(encrypted_part)
                    allocation = _validate_allocation_response(response_data)
                    # Get broker wallet from the response transaction
                    recovered_broker_wallet = client.get_response_sender(
                        broker.requests_contract, existing_request_id
                    ) or ""
                    print(f"Recovered allocation:")
                    print(f"  Prefix: {allocation.prefix}")
                    print(f"  Gateway: {allocation.gateway}")
                    print(f"  Broker endpoint: {allocation.broker_endpoint}")
                    if recovered_broker_wallet:
                        print(f"  Broker wallet: {recovered_broker_wallet}")

                    # Load existing config to get WG keys, or generate new ones
                    existing_config = load_allocation_config(Path(args.config_dir))
                    if existing_config and existing_config.nft_contract == args.nft_contract:
                        wg_private_key = existing_config.wg_private_key
                        wg_public_key = existing_config.wg_public_key
                        print("Using existing WireGuard keys from saved config")
                    else:
                        print("Generating new WireGuard keypair...")
                        wg_private_key, wg_public_key = generate_wireguard_keypair()

                    # Save configuration
                    config = AllocationConfig(
                        prefix=allocation.prefix,
                        gateway=allocation.gateway,
                        broker_pubkey=allocation.broker_pubkey,
                        broker_endpoint=allocation.broker_endpoint,
                        nft_contract=args.nft_contract,
                        request_id=existing_request_id,
                        wg_private_key=wg_private_key,
                        wg_public_key=wg_public_key,
                        allocated_at=datetime.now(timezone.utc).isoformat(),
                        broker_wallet=recovered_broker_wallet,
                    )
                    save_allocation_config(Path(args.config_dir), config)

                    # Configure WireGuard if requested
                    if args.configure_wg:
                        print("Configuring WireGuard tunnel...")
                        configure_wireguard(
                            interface=args.wg_interface,
                            private_key=wg_private_key,
                            prefix=allocation.prefix,
                            gateway=allocation.gateway,
                            broker_pubkey=allocation.broker_pubkey,
                            broker_endpoint=allocation.broker_endpoint,
                        )

                    print("Allocation recovered!")
                    return 0
                except Exception as e:
                    print(f"Failed to decrypt existing response: {e}", file=sys.stderr)
                    stale = True

            if stale:
                # Stale or undecryptable response — V2 contracts support overwrite,
                # so we can submit a new request immediately without waiting.
                print(
                    "Stale allocation detected — submitting new request (overwrite)",
                    file=sys.stderr,
                )
                existing_request_id = 0
        elif status == REQUEST_STATUS_PENDING:
            print("Request pending - waiting for response...")
            # Fall through to polling
        elif status == REQUEST_STATUS_EXPIRED:
            print("Previous request expired - submitting new request", file=sys.stderr)
            existing_request_id = 0  # Allow new request
        else:
            print(f"Previous request not approved (status: {status})", file=sys.stderr)
            return 1

    # Generate WireGuard keypair
    print("Generating WireGuard keypair...")
    wg_private_key, wg_public_key = generate_wireguard_keypair()

    if existing_request_id == 0:
        # Build request payload
        payload = {
            "wgPubkey": wg_public_key,
            "nftContract": Web3.to_checksum_address(args.nft_contract),
            "serverPubkey": ecies_client.public_key_hex,
        }

        # Encrypt payload
        print("Encrypting request payload...")
        encrypted_payload = ecies_client.encrypt_json(payload, broker.encryption_pubkey)

        # Submit request
        print("Submitting allocation request on-chain...")
        request_id = client.submit_request(
            account=account,
            requests_contract=broker.requests_contract,
            nft_contract=args.nft_contract,
            encrypted_payload=encrypted_payload,
        )
        print(f"Request submitted: #{request_id}")
    else:
        request_id = existing_request_id

    # Poll for response (enforce minimum interval to avoid RPC spam)
    poll_interval = max(args.poll_interval, MIN_POLL_INTERVAL)
    print(f"Waiting for broker response (request_id={request_id})...")
    start_time = time.time()
    broker_wallet = ""
    while True:
        status, response_payload = client.get_request_status(
            broker.requests_contract, request_id
        )

        if status == REQUEST_STATUS_APPROVED:
            print("Request approved!")
            # Get the broker's wallet address from the response transaction
            broker_wallet = client.get_response_sender(broker.requests_contract, request_id) or ""
            if broker_wallet:
                print(f"Broker wallet: {broker_wallet}")
            break
        elif status == REQUEST_STATUS_EXPIRED:
            print("Request expired (silent rejection or timeout)", file=sys.stderr)
            return 1

        elapsed = time.time() - start_time
        if elapsed > args.timeout:
            print(f"Timeout waiting for response after {args.timeout}s", file=sys.stderr)
            return 1

        print(f"  Pending... ({int(elapsed)}s)")
        time.sleep(poll_interval)

    # Strip request ID prefix and decrypt response
    print("Decrypting response...")
    _, encrypted_part = _extract_request_id_prefix(response_payload)
    try:
        response_data = ecies_client.decrypt_json(encrypted_part)
    except Exception as e:
        print(f"Failed to decrypt response: {e}", file=sys.stderr)
        return 1

    allocation = _validate_allocation_response(response_data)

    print(f"Allocated prefix: {allocation.prefix}")
    print(f"Gateway: {allocation.gateway}")
    print(f"Broker endpoint: {allocation.broker_endpoint}")

    # Save configuration
    config = AllocationConfig(
        prefix=allocation.prefix,
        gateway=allocation.gateway,
        broker_pubkey=allocation.broker_pubkey,
        broker_endpoint=allocation.broker_endpoint,
        nft_contract=args.nft_contract,
        request_id=request_id,
        wg_private_key=wg_private_key,
        wg_public_key=wg_public_key,
        allocated_at=datetime.now(timezone.utc).isoformat(),
        broker_wallet=broker_wallet,
    )
    save_allocation_config(Path(args.config_dir), config)

    # Configure WireGuard if requested
    if args.configure_wg:
        print("Configuring WireGuard tunnel...")
        configure_wireguard(
            interface=args.wg_interface,
            private_key=wg_private_key,
            prefix=allocation.prefix,
            gateway=allocation.gateway,
            broker_pubkey=allocation.broker_pubkey,
            broker_endpoint=allocation.broker_endpoint,
        )

    print("Allocation complete!")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Handle status command."""
    # Load saved config
    config = load_allocation_config(Path(args.config_dir))
    if config:
        print("Saved allocation:")
        print(f"  Prefix: {config.prefix}")
        print(f"  Gateway: {config.gateway}")
        print(f"  Broker: {config.broker_endpoint}")
        if config.broker_wallet:
            print(f"  Broker Wallet: {config.broker_wallet}")
        print(f"  NFT Contract: {config.nft_contract}")
        print(f"  Request ID: {config.request_id}")
        print(f"  Allocated: {config.allocated_at}")
    else:
        print("No saved allocation found")

    # Check on-chain status if contract provided
    if args.nft_contract and args.requests_contract:
        client = BrokerClient(
            rpc_url=args.rpc_url,
            chain_id=args.chain_id,
        )

        request_id = client.get_request_id_for_nft(
            args.requests_contract, args.nft_contract
        )

        if request_id == 0:
            print("\nNo on-chain request found for this NFT contract")
        else:
            status, _ = client.get_request_status(
                args.requests_contract, request_id
            )
            print(f"\nOn-chain request #{request_id}: {REQUEST_STATUS_NAMES.get(status, 'Unknown')}")

    return 0


def cmd_list_brokers(args: argparse.Namespace) -> int:
    """Handle list-brokers command."""
    if not args.registry_contract:
        print("Registry contract address required", file=sys.stderr)
        return 1

    client = BrokerClient(
        rpc_url=args.rpc_url,
        chain_id=args.chain_id,
        registry_contract=args.registry_contract,
    )

    brokers = client.get_active_brokers()
    if not brokers:
        print("No active brokers found")
        return 0

    print(f"Active brokers ({len(brokers)}):")
    for broker in brokers:
        # Query on-chain capacity if available
        try:
            on_chain_capacity = client.get_available_capacity(broker.requests_contract)
            if on_chain_capacity == 2**256 - 1:
                capacity_str = "unlimited"
            else:
                capacity_str = str(on_chain_capacity)
        except Exception:
            capacity_str = "unknown"

        print(f"  #{broker.id}: {broker.region}")
        print(f"    Requests contract: {broker.requests_contract}")
        print(f"    Available capacity: {capacity_str}")
        print(f"    Pubkey: {broker.encryption_pubkey.hex()[:32]}...")
        print()

    return 0


def cmd_configure(args: argparse.Namespace) -> int:
    """Handle configure command - set up WireGuard from saved allocation."""
    config = load_allocation_config(Path(args.config_dir))
    if not config:
        print("No saved allocation found", file=sys.stderr)
        print(f"Run 'broker-client.py request' first, or check --config-dir", file=sys.stderr)
        return 1

    print(f"Configuring WireGuard from saved allocation:")
    print(f"  Prefix: {config.prefix}")
    print(f"  Gateway: {config.gateway}")
    print(f"  Broker: {config.broker_endpoint}")
    print(f"  Interface: {args.wg_interface}")

    try:
        configure_wireguard(
            interface=args.wg_interface,
            private_key=config.wg_private_key,
            prefix=config.prefix,
            gateway=config.gateway,
            broker_pubkey=config.broker_pubkey,
            broker_endpoint=config.broker_endpoint,
        )
    except subprocess.CalledProcessError as e:
        print(f"Failed to configure WireGuard: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Verify the interface is up
    result = subprocess.run(
        ["wg", "show", args.wg_interface],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        print(f"\nWireGuard interface {args.wg_interface} is up:")
        print(result.stdout)
    else:
        print(f"Warning: Could not verify interface status", file=sys.stderr)

    return 0


def cmd_install(args: argparse.Namespace) -> int:
    """Handle install command - create persistent wg-quick config and enable service."""
    config = load_allocation_config(Path(args.config_dir))
    if not config:
        print("No saved allocation found", file=sys.stderr)
        print(f"Run 'broker-client.py request' first", file=sys.stderr)
        return 1

    interface = args.wg_interface
    wg_conf_path = Path(f"/etc/wireguard/{interface}.conf")

    # Calculate interface address from prefix
    network = ipaddress.IPv6Network(config.prefix, strict=False)
    interface_ip = network.network_address + 1

    # Generate wg-quick config
    wg_config = f"""[Interface]
PrivateKey = {config.wg_private_key}
Address = {interface_ip}/{network.prefixlen}

# Default route for IPv6 through the tunnel
PostUp = ip -6 route add default dev %i
PostDown = ip -6 route del default dev %i

[Peer]
PublicKey = {config.broker_pubkey}
Endpoint = {config.broker_endpoint}
AllowedIPs = ::/0
PersistentKeepalive = 25
"""

    print(f"Installing WireGuard configuration:")
    print(f"  Config file: {wg_conf_path}")
    print(f"  Interface: {interface}")
    print(f"  Address: {interface_ip}/{network.prefixlen}")

    # Write config file
    try:
        wg_conf_path.parent.mkdir(parents=True, exist_ok=True)
        wg_conf_path.write_text(wg_config)
        wg_conf_path.chmod(0o600)
        print(f"  Config written to {wg_conf_path}")
    except PermissionError:
        print(f"Error: Permission denied writing to {wg_conf_path}", file=sys.stderr)
        print("Run with sudo", file=sys.stderr)
        return 1

    # Stop existing interface if running
    subprocess.run(
        ["wg-quick", "down", interface],
        capture_output=True,
    )

    # Start the interface
    result = subprocess.run(
        ["wg-quick", "up", interface],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"Error starting interface: {result.stderr}", file=sys.stderr)
        return 1
    print(f"  Interface {interface} started")

    # Enable service for boot persistence
    result = subprocess.run(
        ["systemctl", "enable", f"wg-quick@{interface}"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        print(f"  Service wg-quick@{interface} enabled for boot")
    else:
        print(f"  Warning: Could not enable service: {result.stderr}", file=sys.stderr)

    # Verify connectivity
    print("\nVerifying connectivity...")
    result = subprocess.run(
        ["ping", "-6", "-c", "1", "-W", "5", config.gateway],
        capture_output=True,
    )
    if result.returncode == 0:
        print(f"  Gateway {config.gateway} reachable")
    else:
        print(f"  Warning: Gateway {config.gateway} not reachable", file=sys.stderr)

    print(f"\nInstallation complete. WireGuard tunnel will persist across reboots.")
    return 0


def cmd_release(args: argparse.Namespace) -> int:
    """Handle release command - release allocation on-chain and clean up locally."""
    # Load saved config to get NFT contract if not provided
    config = load_allocation_config(Path(args.config_dir))

    nft_contract = args.nft_contract
    if not nft_contract and config:
        nft_contract = config.nft_contract
        print(f"Using NFT contract from saved config: {nft_contract}")

    if not nft_contract:
        print("Error: No NFT contract specified and no saved allocation found", file=sys.stderr)
        print("Use --nft-contract to specify the NFT contract address", file=sys.stderr)
        return 1

    # Load wallet
    wallet_key = Path(args.wallet_key).read_text().strip()
    account = Account.from_key(wallet_key)
    print(f"Using wallet: {account.address}")

    # Get broker's requests contract
    requests_contract = args.requests_contract
    if not requests_contract:
        # Try to find it from registry
        if not args.registry_contract:
            print("Error: No requests contract specified", file=sys.stderr)
            print("Use --requests-contract or ensure --registry-contract is set", file=sys.stderr)
            return 1

        client = BrokerClient(
            rpc_url=args.rpc_url,
            chain_id=args.chain_id,
            registry_contract=args.registry_contract,
        )

        # Find the broker that has this NFT's request
        brokers = client.get_active_brokers()
        for broker in brokers:
            try:
                request_id = client.get_request_id_for_nft(broker.requests_contract, nft_contract)
                if request_id != 0:
                    requests_contract = broker.requests_contract
                    print(f"Found allocation on broker's contract: {requests_contract}")
                    break
            except Exception:
                continue

        if not requests_contract:
            print("Error: Could not find which broker has this NFT's allocation", file=sys.stderr)
            print("Use --requests-contract to specify directly", file=sys.stderr)
            return 1
    else:
        client = BrokerClient(
            rpc_url=args.rpc_url,
            chain_id=args.chain_id,
        )

    # Check if there's an allocation to release
    request_id = client.get_request_id_for_nft(requests_contract, nft_contract)
    if request_id == 0:
        print("No on-chain allocation found for this NFT contract")
    else:
        status, _ = client.get_request_status(requests_contract, request_id)
        print(f"Found request #{request_id} (status: {REQUEST_STATUS_NAMES.get(status, 'Unknown')})")

        # Release on-chain
        print("Releasing allocation on-chain...")
        try:
            tx_hash = client.release_allocation(
                account=account,
                requests_contract=requests_contract,
                nft_contract=nft_contract,
            )
            print(f"Release transaction confirmed: {tx_hash}")
        except Exception as e:
            print(f"Error releasing on-chain: {e}", file=sys.stderr)
            if not args.force:
                print("Use --force to continue with local cleanup anyway", file=sys.stderr)
                return 1

    # Tear down WireGuard
    if args.cleanup_wg:
        print(f"Tearing down WireGuard interface {args.wg_interface}...")
        teardown_wireguard(args.wg_interface)

    # Delete local config
    if delete_allocation_config(Path(args.config_dir)):
        print(f"Deleted local allocation config")
    else:
        print("No local allocation config to delete")

    print("Release complete!")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Blockhost Broker Client - Request IPv6 prefix allocations via on-chain authentication"
    )
    parser.add_argument(
        "--version", action="version", version=f"broker-client {CLIENT_VERSION}",
    )
    parser.add_argument(
        "--rpc-url",
        default=os.environ.get("ETH_RPC_URL", DEFAULT_RPC_URL),
        help=f"Ethereum RPC URL (default: {DEFAULT_RPC_URL})",
    )
    parser.add_argument(
        "--chain-id",
        type=int,
        default=int(os.environ.get("ETH_CHAIN_ID", DEFAULT_CHAIN_ID)),
        help=f"Chain ID (default: {DEFAULT_CHAIN_ID})",
    )
    parser.add_argument(
        "--registry-contract",
        default=os.environ.get("BROKER_REGISTRY_CONTRACT"),
        help="BrokerRegistry contract address",
    )
    parser.add_argument(
        "--config-dir",
        default=str(DEFAULT_CONFIG_DIR),
        help=f"Configuration directory (default: {DEFAULT_CONFIG_DIR})",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Request command
    request_parser = subparsers.add_parser("request", help="Request a new prefix allocation")
    request_parser.add_argument(
        "--nft-contract",
        required=True,
        help="AccessCredentialNFT contract address",
    )
    request_parser.add_argument(
        "--wallet-key",
        required=True,
        help="Path to wallet private key file",
    )
    request_parser.add_argument(
        "--broker-id",
        type=int,
        help="Specific broker ID to use (from registry)",
    )
    request_parser.add_argument(
        "--requests-contract",
        help="Broker's requests contract (if not using registry)",
    )
    request_parser.add_argument(
        "--broker-pubkey",
        help="Broker's ECIES public key hex (if not using registry)",
    )
    request_parser.add_argument(
        "--region",
        help="Preferred broker region",
    )
    request_parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Timeout for waiting for response (default: {DEFAULT_TIMEOUT}s)",
    )
    request_parser.add_argument(
        "--poll-interval",
        type=int,
        default=DEFAULT_POLL_INTERVAL,
        help=f"Poll interval (default: {DEFAULT_POLL_INTERVAL}s)",
    )
    request_parser.add_argument(
        "--configure-wg",
        action="store_true",
        help="Configure WireGuard tunnel after allocation",
    )
    request_parser.add_argument(
        "--wg-interface",
        default="wg-broker",
        help="WireGuard interface name (default: wg-broker)",
    )

    # Status command
    status_parser = subparsers.add_parser("status", help="Check allocation status")
    status_parser.add_argument(
        "--nft-contract",
        help="AccessCredentialNFT contract address",
    )
    status_parser.add_argument(
        "--requests-contract",
        help="Broker's requests contract",
    )

    # List brokers command
    list_parser = subparsers.add_parser("list-brokers", help="List available brokers")

    # Configure command
    configure_parser = subparsers.add_parser(
        "configure", help="Configure WireGuard tunnel from saved allocation (non-persistent)"
    )
    configure_parser.add_argument(
        "--wg-interface",
        default="wg-broker",
        help="WireGuard interface name (default: wg-broker)",
    )

    # Install command
    install_parser = subparsers.add_parser(
        "install", help="Install persistent WireGuard config (survives reboot)"
    )
    install_parser.add_argument(
        "--wg-interface",
        default="wg-broker",
        help="WireGuard interface name (default: wg-broker)",
    )

    # Release command
    release_parser = subparsers.add_parser(
        "release", help="Release allocation on-chain and clean up locally"
    )
    release_parser.add_argument(
        "--nft-contract",
        help="AccessCredentialNFT contract address (uses saved config if not specified)",
    )
    release_parser.add_argument(
        "--wallet-key",
        required=True,
        help="Path to wallet private key file",
    )
    release_parser.add_argument(
        "--requests-contract",
        help="Broker's requests contract (auto-detected from registry if not specified)",
    )
    release_parser.add_argument(
        "--cleanup-wg",
        action="store_true",
        help="Also tear down WireGuard interface and remove config",
    )
    release_parser.add_argument(
        "--wg-interface",
        default="wg-broker",
        help="WireGuard interface name (default: wg-broker)",
    )
    release_parser.add_argument(
        "--force",
        action="store_true",
        help="Continue with local cleanup even if on-chain release fails",
    )

    args = parser.parse_args()

    # Fetch registry address from remote if not provided
    if not args.registry_contract:
        print("Fetching registry address from remote config...")
        args.registry_contract = fetch_registry_address()
        if args.registry_contract:
            print(f"Using registry: {args.registry_contract}")
        elif args.command in ("request", "list-brokers"):
            print("Error: Could not fetch registry address and none provided", file=sys.stderr)
            print("Use --registry-contract to specify manually", file=sys.stderr)
            return 1

    if args.command == "request":
        return cmd_request(args)
    elif args.command == "status":
        return cmd_status(args)
    elif args.command == "list-brokers":
        return cmd_list_brokers(args)
    elif args.command == "configure":
        return cmd_configure(args)
    elif args.command == "install":
        return cmd_install(args)
    elif args.command == "release":
        return cmd_release(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
