#!/usr/bin/env python3
"""
Blockhost Broker Client

Runs on Blockhost servers (Proxmox) to request IPv6 prefix allocations
from brokers via on-chain authentication.

This script is standalone and does not depend on the blockhost-broker package.
It can be deployed independently to Proxmox servers.

Usage:
    broker-client.py request --nft-contract 0x... --wallet-key /path/to/key
    broker-client.py renew --nft-contract 0x... --wallet-key /path/to/key
    broker-client.py status --nft-contract 0x...
    broker-client.py release --nft-contract 0x... --wallet-key /path/to/key

Requirements:
    pip install web3 eciespy eth-account
"""

from __future__ import annotations

CLIENT_VERSION = "0.5.0"  # V3 contracts: direct tx responses, no on-chain release

import argparse
import grp
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
DEFAULT_CHAINS_CONFIG = Path("/etc/blockhost/broker-chains.json")
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
        "inputs": [{"internalType": "address", "name": "", "type": "address"}],
        "name": "nftContractToRequestId",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "capacityStatus",
        "outputs": [{"internalType": "uint8", "name": "", "type": "uint8"}],
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
]

# Capacity status values (from BrokerRequests.capacityStatus)
CAPACITY_AVAILABLE = 0
CAPACITY_LIMITED = 1
CAPACITY_CLOSED = 2


@dataclass
class BrokerInfo:
    """Information about an available broker."""

    id: int
    operator: str
    requests_contract: str
    encryption_pubkey: bytes
    region: str


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
        dns_zone=data.get("dnsZone", ""),
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
    dns_zone: str = ""


# ── Chain adapter dispatch ───────────────────────────────────────────

@dataclass
class ChainAdapter:
    """Configuration for a blockchain adapter."""

    name: str
    pattern: re.Pattern
    adapter: str  # "builtin" for EVM, or command path
    adapter_args: list  # extra args prepended to the command
    settings: dict  # chain-specific settings (rpc_url, registry, etc.)


def load_chains_config(config_path: Path) -> list[ChainAdapter]:
    """Load chain adapter configuration from JSON file.

    Format:
      [
        {
          "name": "evm",
          "match": "^0x[0-9a-fA-F]{40}$",
          "adapter": "builtin"
        },
        {
          "name": "opnet",
          "match": "^(0x[0-9a-fA-F]{64}|opr1.+)$",
          "adapter": "npx",
          "adapter_args": ["tsx", "/opt/blockhost/client-opnet/src/main.ts", "request"],
          "rpc_url": "https://regtest.opnet.org",
          "registry_pubkey": "0x..."
        }
      ]
    """
    if not config_path.exists():
        return []

    try:
        data = json.loads(config_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"Warning: Could not load chains config {config_path}: {e}", file=sys.stderr)
        return []

    adapters = []
    for entry in data:
        name = entry.get("name", "unknown")
        match_str = entry.get("match")
        if not match_str:
            print(f"Warning: Chain '{name}' has no 'match' pattern, skipping", file=sys.stderr)
            continue
        try:
            pattern = re.compile(match_str)
        except re.error as e:
            print(f"Warning: Chain '{name}' has invalid pattern: {e}", file=sys.stderr)
            continue

        adapter = entry.get("adapter", "builtin")
        adapter_args = entry.get("adapter_args", [])

        # Everything else is chain-specific settings
        settings = {k: v for k, v in entry.items()
                    if k not in ("name", "match", "adapter", "adapter_args")}

        adapters.append(ChainAdapter(
            name=name,
            pattern=pattern,
            adapter=adapter,
            adapter_args=adapter_args,
            settings=settings,
        ))

    return adapters


def resolve_chain(nft_contract: str, adapters: list[ChainAdapter]) -> Optional[ChainAdapter]:
    """Match an NFT contract address to a chain adapter."""
    for adapter in adapters:
        if adapter.pattern.match(nft_contract):
            return adapter
    return None


def load_or_generate_server_key(config_dir: Path) -> "ECIESClient":
    """Load persistent ECIES server key, generating and saving it on first use."""
    server_key_file = config_dir / "server.key"
    if server_key_file.exists():
        key = server_key_file.read_text().strip()
        client = ECIESClient(private_key_hex=key)
        print(f"Using server key: {client.public_key_hex[:16]}...")
    else:
        client = ECIESClient()
        config_dir.mkdir(parents=True, exist_ok=True)
        server_key_file.write_text(client.private_key_hex + "\n")
        server_key_file.chmod(0o600)
        print(f"Generated new server key: {client.public_key_hex[:16]}...")
    return client


def request_via_external_adapter(
    adapter: ChainAdapter,
    nft_contract: str,
    wallet_key_path: str,
    broker_id: Optional[int],
    timeout: int,
    server_key_hex: Optional[str] = None,
    registry_contract: Optional[str] = None,
) -> dict:
    """Run an external chain adapter as a subprocess and return the allocation JSON.

    The adapter must output a single JSON line to stdout on success.
    All progress logging goes to stderr (passed through to the user).
    """
    cmd = [adapter.adapter] + adapter.adapter_args

    # Map settings to CLI args
    if "rpc_url" in adapter.settings:
        cmd += ["--rpc-url", adapter.settings["rpc_url"]]

    # Registry pubkey: prefer explicit arg, fall back to chain config
    effective_registry = registry_contract or adapter.settings.get("registry_pubkey")
    if effective_registry:
        cmd += ["--registry-pubkey", effective_registry]

    cmd += ["--nft-pubkey", nft_contract]
    cmd += ["--timeout", str(timeout)]

    if broker_id is not None:
        cmd += ["--broker-id", str(broker_id)]

    # Read wallet key — for OPNet this is a mnemonic file
    wallet_key = Path(wallet_key_path).read_text().strip()
    cmd += ["--mnemonic", wallet_key]

    if server_key_hex is not None:
        cmd += ["--server-key", server_key_hex]

    print(f"Running {adapter.name} adapter: {cmd[0]} ...")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout + 30,  # give the subprocess a bit more time than its internal timeout
    )

    # Pass stderr through (adapter's progress logging)
    if result.stderr:
        for line in result.stderr.rstrip().split("\n"):
            print(f"  {line}", file=sys.stderr)

    if result.returncode != 0:
        raise RuntimeError(
            f"{adapter.name} adapter exited with code {result.returncode}"
        )

    stdout = result.stdout.strip()
    if not stdout:
        raise RuntimeError(f"{adapter.name} adapter produced no output")

    try:
        return json.loads(stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"{adapter.name} adapter returned invalid JSON: {e}")


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
    dns_zone: str = ""  # DNS zone for this broker (optional)


@dataclass
class BrokerContract:
    """Saved broker identity for renewals."""

    requests_contract: str
    broker_pubkey: str  # hex-encoded ECIES public key
    broker_id: int = 0


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
        )

    def get_capacity_status(self, requests_contract: str) -> int:
        """Get capacity status for a broker's requests contract.

        Returns 0 (available), 1 (limited), or 2 (closed).
        """
        contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(requests_contract),
            abi=BROKER_REQUESTS_ABI,
        )
        return contract.functions.capacityStatus().call()

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

    def wait_for_response_tx(
        self,
        client_address: str,
        broker_operator: str,
        after_block: int,
        request_id: int,
        timeout: int = DEFAULT_TIMEOUT,
        poll_interval: int = DEFAULT_POLL_INTERVAL,
    ) -> tuple[bytes, str]:
        """Wait for a direct response transaction from the broker.

        Scans for transactions from broker_operator to client_address
        in blocks after after_block. Returns (payload_bytes, broker_wallet)
        when a matching transaction is found.
        """
        poll_interval = max(poll_interval, MIN_POLL_INTERVAL)
        start_time = time.time()
        last_scanned_block = after_block

        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                raise TimeoutError(f"Timeout waiting for response after {timeout}s")

            latest_block = self.w3.eth.block_number
            if latest_block <= last_scanned_block:
                print(f"  Waiting for new blocks... ({int(elapsed)}s)")
                time.sleep(poll_interval)
                continue

            # Scan new blocks for transactions from broker to us
            for block_num in range(last_scanned_block + 1, latest_block + 1):
                block = self.w3.eth.get_block(block_num, full_transactions=True)
                for tx in block["transactions"]:
                    tx_from = tx.get("from", "").lower()
                    tx_to = (tx.get("to") or "").lower()
                    if broker_operator and tx_from != broker_operator.lower():
                        continue
                    if tx_to != client_address.lower():
                        continue

                    # Found a tx from broker to us — check request ID prefix
                    tx_input = tx.get("input", b"")
                    if isinstance(tx_input, str):
                        tx_input = bytes.fromhex(tx_input[2:]) if tx_input.startswith("0x") else bytes.fromhex(tx_input)

                    if len(tx_input) <= REQUEST_ID_PREFIX_LEN:
                        continue

                    embedded_id, _ = _extract_request_id_prefix(tx_input)
                    if embedded_id == request_id:
                        return tx_input, tx_from

            last_scanned_block = latest_block
            print(f"  Scanning blocks... ({int(elapsed)}s)")
            time.sleep(poll_interval)


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
                "dns_zone": config.dns_zone,
            },
            indent=2,
        )
    )
    gid = grp.getgrnam("blockhost").gr_gid
    os.chown(config_file, 0, gid)
    config_file.chmod(0o640)

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
        dns_zone=data.get("dns_zone", ""),
    )


def delete_allocation_config(config_dir: Path) -> bool:
    """Delete allocation configuration file. Returns True if deleted."""
    config_file = config_dir / "broker-allocation.json"
    if config_file.exists():
        config_file.unlink()
        return True
    return False


def fetch_broker_config(gateway: str, port: int = 8080, timeout: int = 5) -> Optional[dict]:
    """Fetch static broker config through the WireGuard tunnel."""
    url = f"http://[{gateway}]:{port}/v1/config"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        print(f"  Warning: Could not fetch broker config: {e}", file=sys.stderr)
        return None


def save_broker_contract(config_dir: Path, contract: BrokerContract) -> None:
    """Save broker contract info for future renewals."""
    config_dir.mkdir(parents=True, exist_ok=True)
    config_file = config_dir / "broker-contract.json"
    config_file.write_text(
        json.dumps(
            {
                "requests_contract": contract.requests_contract,
                "broker_pubkey": contract.broker_pubkey,
                "broker_id": contract.broker_id,
            },
            indent=2,
        )
    )
    gid = grp.getgrnam("blockhost").gr_gid
    os.chown(config_file, 0, gid)
    config_file.chmod(0o640)
    print(f"Broker contract saved to {config_file}")


def load_broker_contract(config_dir: Path) -> Optional[BrokerContract]:
    """Load saved broker contract info."""
    config_file = config_dir / "broker-contract.json"
    if not config_file.exists():
        return None

    try:
        data = json.loads(config_file.read_text())
    except (json.JSONDecodeError, OSError) as e:
        raise ValueError(f"Corrupt broker contract file {config_file}: {e}")

    addr = data.get("requests_contract", "")
    if not isinstance(addr, str) or len(addr) != 42 or not addr.startswith("0x"):
        raise ValueError(f"Invalid requests_contract in {config_file}: {addr!r}")

    pubkey = data.get("broker_pubkey", "")
    if not isinstance(pubkey, str) or len(pubkey) < 64:
        raise ValueError(f"Invalid broker_pubkey in {config_file}")

    # Validate pubkey is valid hex
    try:
        bytes.fromhex(pubkey)
    except ValueError:
        raise ValueError(f"broker_pubkey is not valid hex in {config_file}")

    return BrokerContract(
        requests_contract=addr,
        broker_pubkey=pubkey,
        broker_id=data.get("broker_id", 0),
    )


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


def _submit_poll_save(
    client: BrokerClient,
    ecies_client: "ECIESClient",
    account: "LocalAccount",
    broker: BrokerInfo,
    nft_contract: str,
    config_dir: Path,
    timeout: int,
    poll_interval: int,
    configure_wg: bool,
    wg_interface: str,
) -> int:
    """Submit request to broker, poll for direct tx response, decrypt, and save config.

    Returns 0 on success, 1 on failure.
    """
    # Generate WireGuard keypair
    print("Generating WireGuard keypair...")
    wg_private_key, wg_public_key = generate_wireguard_keypair()

    # Build request payload
    payload = {
        "wgPubkey": wg_public_key,
        "nftContract": Web3.to_checksum_address(nft_contract),
        "serverPubkey": ecies_client.public_key_hex,
    }

    # Encrypt payload
    print("Encrypting request payload...")
    encrypted_payload = ecies_client.encrypt_json(payload, broker.encryption_pubkey)

    # Note block before submission — response can only come after this
    after_block = client.w3.eth.block_number

    # Submit request
    print("Submitting allocation request on-chain...")
    request_id = client.submit_request(
        account=account,
        requests_contract=broker.requests_contract,
        nft_contract=nft_contract,
        encrypted_payload=encrypted_payload,
    )
    print(f"Request submitted: #{request_id}")

    # Wait for direct response transaction from broker
    print(f"Waiting for broker response (request_id={request_id})...")
    print(f"  Scanning for txs from {broker.operator} after block {after_block}")
    try:
        response_payload, broker_wallet = client.wait_for_response_tx(
            client_address=account.address,
            broker_operator=broker.operator,
            after_block=after_block,
            request_id=request_id,
            timeout=timeout,
            poll_interval=poll_interval,
        )
        print("Response received!")
        if broker_wallet:
            print(f"Broker wallet: {broker_wallet}")
    except TimeoutError as e:
        print(str(e), file=sys.stderr)
        return 1

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
        nft_contract=nft_contract,
        request_id=request_id,
        wg_private_key=wg_private_key,
        wg_public_key=wg_public_key,
        allocated_at=datetime.now(timezone.utc).isoformat(),
        broker_wallet=broker_wallet,
        dns_zone=allocation.dns_zone,
    )
    save_allocation_config(config_dir, config)
    save_broker_contract(
        config_dir,
        BrokerContract(
            requests_contract=broker.requests_contract,
            broker_pubkey=broker.encryption_pubkey.hex(),
            broker_id=broker.id,
        ),
    )

    # Configure WireGuard if requested
    if configure_wg:
        print("Configuring WireGuard tunnel...")
        configure_wireguard(
            interface=wg_interface,
            private_key=wg_private_key,
            prefix=allocation.prefix,
            gateway=allocation.gateway,
            broker_pubkey=allocation.broker_pubkey,
            broker_endpoint=allocation.broker_endpoint,
        )

    return 0


def cmd_request(args: argparse.Namespace) -> int:
    """Handle allocation request command."""
    config_dir = Path(args.config_dir)

    # Resolve chain adapter from NFT contract address format
    chains_config = getattr(args, "chains_config", str(DEFAULT_CHAINS_CONFIG))
    adapters = load_chains_config(Path(chains_config))
    chain = resolve_chain(args.nft_contract, adapters)

    # Apply chain-level defaults for timeout/poll_interval when the user
    # didn't explicitly override them on the command line.
    if chain:
        if "timeout" in chain.settings and args.timeout == DEFAULT_TIMEOUT:
            args.timeout = int(chain.settings["timeout"])
        if "poll_interval" in chain.settings and args.poll_interval == DEFAULT_POLL_INTERVAL:
            args.poll_interval = int(chain.settings["poll_interval"])

    if chain and chain.adapter != "builtin":
        return _cmd_request_external(args, chain, config_dir)

    if chain:
        print(f"Chain: {chain.name} (builtin)")

    return _cmd_request_evm(args, config_dir)


def _cmd_request_external(
    args: argparse.Namespace,
    chain: ChainAdapter,
    config_dir: Path,
) -> int:
    """Handle request via an external chain adapter subprocess."""
    print(f"Chain: {chain.name}")

    ecies_client = load_or_generate_server_key(config_dir)

    try:
        result = request_via_external_adapter(
            adapter=chain,
            nft_contract=args.nft_contract,
            wallet_key_path=args.wallet_key,
            broker_id=getattr(args, "broker_id", None),
            timeout=args.timeout,
            server_key_hex=ecies_client.private_key_hex,
            registry_contract=getattr(args, "registry_contract", None),
        )
    except (RuntimeError, subprocess.TimeoutExpired, OSError) as e:
        print(f"Adapter error: {e}", file=sys.stderr)
        return 1

    # Validate required fields
    required = ["prefix", "gateway", "broker_pubkey", "broker_endpoint",
                "wg_private_key", "wg_public_key"]
    for field in required:
        if field not in result or not result[field]:
            print(f"Adapter response missing field: {field}", file=sys.stderr)
            return 1

    # Validate prefix is valid IPv6 CIDR
    try:
        ipaddress.IPv6Network(result["prefix"], strict=False)
    except (ValueError, ipaddress.AddressValueError) as e:
        print(f"Invalid prefix from adapter: {e}", file=sys.stderr)
        return 1

    print(f"Allocated prefix: {result['prefix']}")
    print(f"Gateway: {result['gateway']}")
    print(f"Broker endpoint: {result['broker_endpoint']}")

    # Save configuration
    config = AllocationConfig(
        prefix=result["prefix"],
        gateway=result["gateway"],
        broker_pubkey=result["broker_pubkey"],
        broker_endpoint=result["broker_endpoint"],
        nft_contract=args.nft_contract,
        request_id=result.get("request_id", 0),
        wg_private_key=result["wg_private_key"],
        wg_public_key=result["wg_public_key"],
        allocated_at=datetime.now(timezone.utc).isoformat(),
        dns_zone=result.get("dns_zone", ""),
    )
    save_allocation_config(config_dir, config)

    # Configure WireGuard if requested
    if args.configure_wg:
        print("Configuring WireGuard tunnel...")
        configure_wireguard(
            interface=args.wg_interface,
            private_key=result["wg_private_key"],
            prefix=result["prefix"],
            gateway=result["gateway"],
            broker_pubkey=result["broker_pubkey"],
            broker_endpoint=result["broker_endpoint"],
        )

        # Wait for tunnel to come up, then fetch broker config (dns_zone etc.)
        print("Waiting for tunnel...")
        gateway = result["gateway"]
        tunnel_up = False
        for attempt in range(6):
            ping = subprocess.run(
                ["ping", "-6", "-c", "1", "-W", "3", gateway],
                capture_output=True,
            )
            if ping.returncode == 0:
                print(f"  Gateway {gateway} reachable")
                tunnel_up = True
                break
            if attempt < 5:
                time.sleep(2)
        if not tunnel_up:
            print(f"Error: Gateway {gateway} not reachable — tunnel failed to come up", file=sys.stderr)
            return 1

        broker_config = fetch_broker_config(gateway)
        if broker_config:
            if broker_config.get("dns_zone") and not config.dns_zone:
                config.dns_zone = broker_config["dns_zone"]
                save_allocation_config(config_dir, config)
                print(f"  DNS zone: {config.dns_zone}")

    print("Allocation complete!")
    return 0


def _cmd_request_evm(args: argparse.Namespace, config_dir: Path) -> int:
    """Handle request via the builtin EVM path."""
    ecies_client = load_or_generate_server_key(config_dir)

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
        broker = BrokerInfo(
            id=0,
            operator="",
            requests_contract=args.requests_contract,
            encryption_pubkey=validate_hex_pubkey(args.broker_pubkey, "broker ECIES public key"),
            region="",
        )
        print(f"Using broker at {broker.requests_contract}")
    else:
        # Get from registry
        brokers = client.get_active_brokers()
        if not brokers:
            print("No active brokers found", file=sys.stderr)
            return 1

        if args.region:
            brokers = [b for b in brokers if b.region == args.region]
            if not brokers:
                print(f"No brokers found in region {args.region}", file=sys.stderr)
                return 1

        available_brokers = []
        for b in brokers:
            try:
                cap_status = client.get_capacity_status(b.requests_contract)
                if cap_status == CAPACITY_CLOSED:
                    print(f"  Broker #{b.id} ({b.region}): closed", file=sys.stderr)
                    continue
                available_brokers.append((b, cap_status))
            except Exception as e:
                print(f"  Broker #{b.id}: capacity check failed ({e}), including", file=sys.stderr)
                available_brokers.append((b, CAPACITY_AVAILABLE))

        if not available_brokers:
            print("No brokers with available capacity", file=sys.stderr)
            return 1

        available_brokers.sort(key=lambda x: x[1])
        broker = available_brokers[0][0]
        cap_label = {CAPACITY_AVAILABLE: "available", CAPACITY_LIMITED: "limited"}.get(
            available_brokers[0][1], "unknown"
        )
        print(f"Selected broker #{broker.id} in {broker.region} ({cap_label})")

    existing_request_id = client.get_request_id_for_nft(
        broker.requests_contract, args.nft_contract
    )
    if existing_request_id != 0:
        print(f"NFT contract already has request #{existing_request_id} — will overwrite")

    result = _submit_poll_save(
        client=client,
        ecies_client=ecies_client,
        account=account,
        broker=broker,
        nft_contract=args.nft_contract,
        config_dir=config_dir,
        timeout=args.timeout,
        poll_interval=args.poll_interval,
        configure_wg=args.configure_wg,
        wg_interface=args.wg_interface,
    )
    if result != 0:
        return result

    print("Allocation complete!")
    return 0


def cmd_renew(args: argparse.Namespace) -> int:
    """Handle renew command - re-request from the same broker."""
    # Load saved broker contract
    try:
        broker_contract = load_broker_contract(Path(args.config_dir))
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if not broker_contract:
        print(
            "No previous broker allocation found — use `request` for initial allocation",
            file=sys.stderr,
        )
        return 1

    print(f"Renewing from broker contract: {broker_contract.requests_contract}")
    if broker_contract.broker_id:
        print(f"  Broker ID: #{broker_contract.broker_id}")

    ecies_client = load_or_generate_server_key(Path(args.config_dir))

    # Load wallet
    wallet_key = Path(args.wallet_key).read_text().strip()
    account = Account.from_key(wallet_key)
    print(f"Using wallet: {account.address}")

    # Initialize client (no registry needed)
    client = BrokerClient(
        rpc_url=args.rpc_url,
        chain_id=args.chain_id,
    )

    # Build broker info from saved contract
    broker_pubkey_bytes = validate_hex_pubkey(
        broker_contract.broker_pubkey, "saved broker ECIES public key"
    )
    broker = BrokerInfo(
        id=broker_contract.broker_id,
        operator="",
        requests_contract=broker_contract.requests_contract,
        encryption_pubkey=broker_pubkey_bytes,
        region="",
    )

    result = _submit_poll_save(
        client=client,
        ecies_client=ecies_client,
        account=account,
        broker=broker,
        nft_contract=args.nft_contract,
        config_dir=Path(args.config_dir),
        timeout=args.timeout,
        poll_interval=args.poll_interval,
        configure_wg=args.configure_wg,
        wg_interface=args.wg_interface,
    )
    if result != 0:
        return result

    print("Renewal complete!")
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

    # Check on-chain request if contract provided
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
            print(f"\nOn-chain request #{request_id} exists")

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
        # Query capacity status
        try:
            cap_status = client.get_capacity_status(broker.requests_contract)
            status_str = {
                CAPACITY_AVAILABLE: "available",
                CAPACITY_LIMITED: "limited",
                CAPACITY_CLOSED: "closed",
            }.get(cap_status, f"unknown ({cap_status})")
        except Exception:
            status_str = "unknown"

        print(f"  #{broker.id}: {broker.region}")
        print(f"    Requests contract: {broker.requests_contract}")
        print(f"    Capacity: {status_str}")
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

    # Wait for tunnel connectivity
    print("\nWaiting for tunnel...")
    tunnel_up = False
    for attempt in range(6):
        result = subprocess.run(
            ["ping", "-6", "-c", "1", "-W", "3", config.gateway],
            capture_output=True,
        )
        if result.returncode == 0:
            print(f"  Gateway {config.gateway} reachable")
            tunnel_up = True
            break
        if attempt < 5:
            time.sleep(2)
    if not tunnel_up:
        print(f"Error: Gateway {config.gateway} not reachable — tunnel failed to come up", file=sys.stderr)
        return 1

    # Fetch broker config through the tunnel (dns_zone etc.)
    broker_config = fetch_broker_config(config.gateway)
    if broker_config:
        updated = False
        if broker_config.get("dns_zone") and not config.dns_zone:
            config.dns_zone = broker_config["dns_zone"]
            updated = True
            print(f"  DNS zone: {config.dns_zone}")
        if updated:
            save_allocation_config(Path(args.config_dir), config)

    print(f"\nInstallation complete. WireGuard tunnel will persist across reboots.")
    return 0


def cmd_release(args: argparse.Namespace) -> int:
    """Handle release command - clean up local allocation and WireGuard config.

    Release is local-only in V3: the broker detects lost peers via WireGuard
    handshake timeout and reclaims resources automatically. A new request on the
    same NFT will overwrite the old one on-chain.
    """
    # Load saved config
    config = load_allocation_config(Path(args.config_dir))
    if not config:
        print("No saved allocation found", file=sys.stderr)
        return 1

    print(f"Releasing allocation:")
    print(f"  Prefix: {config.prefix}")
    print(f"  NFT Contract: {config.nft_contract}")

    # Tear down WireGuard
    if args.cleanup_wg:
        print(f"Tearing down WireGuard interface {args.wg_interface}...")
        teardown_wireguard(args.wg_interface)

    # Delete local config
    if delete_allocation_config(Path(args.config_dir)):
        print("Deleted local allocation config")
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
    parser.add_argument(
        "--chains-config",
        default=str(DEFAULT_CHAINS_CONFIG),
        help=f"Chain adapters config file (default: {DEFAULT_CHAINS_CONFIG})",
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

    # Renew command
    renew_parser = subparsers.add_parser(
        "renew", help="Re-request allocation from the same broker"
    )
    renew_parser.add_argument(
        "--nft-contract",
        required=True,
        help="AccessCredentialNFT contract address",
    )
    renew_parser.add_argument(
        "--wallet-key",
        required=True,
        help="Path to wallet private key file",
    )
    renew_parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Timeout for waiting for response (default: {DEFAULT_TIMEOUT}s)",
    )
    renew_parser.add_argument(
        "--poll-interval",
        type=int,
        default=DEFAULT_POLL_INTERVAL,
        help=f"Poll interval (default: {DEFAULT_POLL_INTERVAL}s)",
    )
    renew_parser.add_argument(
        "--configure-wg",
        action="store_true",
        help="Configure WireGuard tunnel after allocation",
    )
    renew_parser.add_argument(
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
        "release", help="Clean up local allocation and WireGuard config"
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
    elif args.command == "renew":
        return cmd_renew(args)
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
