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

import argparse
import ipaddress
import json
import os
import secrets
import subprocess
import sys
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
    from web3.exceptions import ContractLogicError
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
DEFAULT_TIMEOUT = 300  # 5 minutes

# Remote configuration URL - contains the current BrokerRegistry contract address
# This allows updating the registry address without releasing a new client version
REGISTRY_CONFIG_URL = "https://raw.githubusercontent.com/mwaddip/blockhost-broker/main/registry.json"


def fetch_registry_address() -> Optional[str]:
    """Fetch the current BrokerRegistry contract address from remote config."""
    try:
        with urllib.request.urlopen(REGISTRY_CONFIG_URL, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
            return data.get("registry_contract")
    except Exception as e:
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
        "inputs": [],
        "name": "getActiveBrokers",
        "outputs": [
            {"internalType": "uint256[]", "name": "", "type": "uint256[]"},
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
                "internalType": "struct BrokerRegistry.Broker[]",
                "name": "",
                "type": "tuple[]",
            },
        ],
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
                    {"internalType": "string", "name": "rejectionReason", "type": "string"},
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

# Request status enum
REQUEST_STATUS_PENDING = 0
REQUEST_STATUS_APPROVED = 1
REQUEST_STATUS_REJECTED = 2
REQUEST_STATUS_EXPIRED = 3


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
        """Get list of active brokers from registry."""
        if not self.registry:
            raise ValueError("Registry contract not configured")

        ids, brokers = self.registry.functions.getActiveBrokers().call()
        result = []
        for broker_id, broker in zip(ids, brokers):
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
                "gas": gas_estimate + 50000,  # Add buffer
                "maxFeePerGas": self.w3.eth.gas_price * 2,
                "maxPriorityFeePerGas": self.w3.eth.gas_price,
                "chainId": self.chain_id,
            }
        )

        signed = account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        if receipt["status"] != 1:
            raise RuntimeError(f"Transaction failed: {tx_hash.hex()}")

        # Parse request ID from logs
        logs = contract.events.RequestSubmitted().process_receipt(receipt)
        if logs:
            return logs[0]["args"]["requestId"]

        # Fallback: query by NFT contract
        request_id = contract.functions.nftContractToRequestId(
            Web3.to_checksum_address(nft_contract)
        ).call()
        return request_id

    def get_request_status(
        self, requests_contract: str, request_id: int
    ) -> tuple[int, bytes, str]:
        """Get request status, response payload, and rejection reason."""
        contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(requests_contract),
            abi=BROKER_REQUESTS_ABI,
        )

        request = contract.functions.getRequest(request_id).call()
        status = request[4]
        response_payload = request[5]
        rejection_reason = request[6]
        return status, response_payload, rejection_reason

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
    # Write private key to temp file
    key_file = Path(f"/tmp/wg-{interface}-private.key")
    key_file.write_text(private_key)
    key_file.chmod(0o600)

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
    )


def cmd_request(args: argparse.Namespace) -> int:
    """Handle allocation request command."""
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
            encryption_pubkey=bytes.fromhex(args.broker_pubkey),
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

        # Select broker with lowest load
        broker = min(brokers, key=lambda b: b.current_load)
        print(f"Selected broker #{broker.id} in {broker.region} (load: {broker.current_load})")

    # Check for existing request
    existing_request_id = client.get_request_id_for_nft(
        broker.requests_contract, args.nft_contract
    )
    if existing_request_id != 0:
        print(f"NFT contract already has request #{existing_request_id}")
        status, response_payload, rejection_reason = client.get_request_status(
            broker.requests_contract, existing_request_id
        )
        if status == REQUEST_STATUS_APPROVED:
            print("Request already approved - use existing allocation")
            return 0
        elif status == REQUEST_STATUS_PENDING:
            print("Request pending - waiting for response...")
            # Fall through to polling
        else:
            print(f"Previous request rejected: {rejection_reason}", file=sys.stderr)
            return 1

    # Generate WireGuard keypair
    print("Generating WireGuard keypair...")
    wg_private_key, wg_public_key = generate_wireguard_keypair()

    # Generate ECIES keypair for response encryption
    ecies_client = ECIESClient()

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

    # Poll for response
    print("Waiting for broker response...")
    start_time = time.time()
    while True:
        status, response_payload, rejection_reason = client.get_request_status(
            broker.requests_contract, request_id
        )

        if status == REQUEST_STATUS_APPROVED:
            print("Request approved!")
            break
        elif status == REQUEST_STATUS_REJECTED:
            print(f"Request rejected: {rejection_reason}", file=sys.stderr)
            return 1
        elif status == REQUEST_STATUS_EXPIRED:
            print("Request expired", file=sys.stderr)
            return 1

        elapsed = time.time() - start_time
        if elapsed > args.timeout:
            print(f"Timeout waiting for response after {args.timeout}s", file=sys.stderr)
            return 1

        print(f"  Pending... ({int(elapsed)}s)")
        time.sleep(args.poll_interval)

    # Decrypt response
    print("Decrypting response...")
    try:
        response_data = ecies_client.decrypt_json(response_payload)
    except Exception as e:
        print(f"Failed to decrypt response: {e}", file=sys.stderr)
        return 1

    allocation = AllocationResponse(
        prefix=response_data["prefix"],
        gateway=response_data["gateway"],
        broker_pubkey=response_data["brokerPubkey"],
        broker_endpoint=response_data["brokerEndpoint"],
    )

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
            status, _, rejection_reason = client.get_request_status(
                args.requests_contract, request_id
            )
            status_names = {
                REQUEST_STATUS_PENDING: "Pending",
                REQUEST_STATUS_APPROVED: "Approved",
                REQUEST_STATUS_REJECTED: "Rejected",
                REQUEST_STATUS_EXPIRED: "Expired",
            }
            print(f"\nOn-chain request #{request_id}: {status_names.get(status, 'Unknown')}")
            if rejection_reason:
                print(f"  Rejection reason: {rejection_reason}")

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
        available = broker.capacity - broker.current_load if broker.capacity > 0 else "unlimited"
        print(f"  #{broker.id}: {broker.region}")
        print(f"    Requests contract: {broker.requests_contract}")
        print(f"    Load: {broker.current_load}/{broker.capacity or 'unlimited'} (available: {available})")
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Blockhost Broker Client - Request IPv6 prefix allocations via on-chain authentication"
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
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
