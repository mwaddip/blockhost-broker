// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title BrokerRegistry
 * @notice Global registry of IPv6 tunnel brokers for the Blockhost network
 * @dev Deployed once, brokers self-register with their request contract and encryption pubkey
 */
contract BrokerRegistry is Ownable {
    struct Broker {
        address operator;           // Broker owner wallet
        address requestsContract;   // Address of broker's BrokerRequests contract
        bytes encryptionPubkey;     // secp256k1 pubkey for ECIES encryption (65 bytes uncompressed)
        string region;              // Geographic hint (e.g., "eu-west", "us-east")
        bool active;                // Accepting new requests
        uint256 capacity;           // Maximum allocations (0 = unlimited)
        uint256 currentLoad;        // Current number of allocations
        uint256 registeredAt;       // Registration timestamp
    }

    /// @notice All registered brokers
    Broker[] public brokers;

    /// @notice Mapping from operator address to broker ID (1-indexed, 0 = not registered)
    mapping(address => uint256) public operatorToBrokerId;

    /// @notice Mapping from requests contract to broker ID
    mapping(address => uint256) public requestsContractToBrokerId;

    // Events
    event BrokerRegistered(
        uint256 indexed brokerId,
        address indexed operator,
        address requestsContract,
        string region
    );
    event BrokerUpdated(uint256 indexed brokerId, address indexed operator);
    event BrokerDeactivated(uint256 indexed brokerId, address indexed operator);
    event BrokerActivated(uint256 indexed brokerId, address indexed operator);
    event BrokerLoadUpdated(uint256 indexed brokerId, uint256 currentLoad);

    constructor() Ownable(msg.sender) {}

    /**
     * @dev Get caller's broker ID; reverts if not a registered operator.
     */
    function _requireOperator() internal view returns (uint256 brokerId) {
        brokerId = operatorToBrokerId[msg.sender];
        require(brokerId != 0, "Not a registered operator");
    }

    /**
     * @notice Register a new broker (owner only)
     * @param operator Address of the broker operator wallet
     * @param requestsContract Address of the broker's BrokerRequests contract
     * @param encryptionPubkey secp256k1 public key for ECIES encryption (65 bytes)
     * @param region Geographic region hint
     * @param capacity Maximum allocations (0 = unlimited)
     * @return brokerId The ID of the newly registered broker
     */
    function registerBroker(
        address operator,
        address requestsContract,
        bytes calldata encryptionPubkey,
        string calldata region,
        uint256 capacity
    ) external onlyOwner returns (uint256 brokerId) {
        require(operator != address(0), "Invalid operator address");
        require(requestsContract != address(0), "Invalid requests contract");
        require(encryptionPubkey.length == 65, "Pubkey must be 65 bytes (uncompressed secp256k1)");
        require(operatorToBrokerId[operator] == 0, "Operator already registered");
        require(requestsContractToBrokerId[requestsContract] == 0, "Requests contract already registered");

        brokers.push(Broker({
            operator: operator,
            requestsContract: requestsContract,
            encryptionPubkey: encryptionPubkey,
            region: region,
            active: true,
            capacity: capacity,
            currentLoad: 0,
            registeredAt: block.timestamp
        }));

        brokerId = brokers.length; // 1-indexed
        operatorToBrokerId[operator] = brokerId;
        requestsContractToBrokerId[requestsContract] = brokerId;

        emit BrokerRegistered(brokerId, operator, requestsContract, region);
    }

    /**
     * @notice Update broker encryption pubkey
     * @param encryptionPubkey New secp256k1 public key (65 bytes)
     */
    function updateEncryptionPubkey(bytes calldata encryptionPubkey) external {
        uint256 brokerId = _requireOperator();
        require(encryptionPubkey.length == 65, "Pubkey must be 65 bytes");

        brokers[brokerId - 1].encryptionPubkey = encryptionPubkey;
        emit BrokerUpdated(brokerId, msg.sender);
    }

    /**
     * @notice Update broker region
     * @param region New region string
     */
    function updateRegion(string calldata region) external {
        uint256 brokerId = _requireOperator();
        require(bytes(region).length > 0, "Region cannot be empty");

        brokers[brokerId - 1].region = region;
        emit BrokerUpdated(brokerId, msg.sender);
    }

    /**
     * @notice Update broker capacity
     * @param capacity New capacity (0 = unlimited)
     */
    function updateCapacity(uint256 capacity) external {
        uint256 brokerId = _requireOperator();

        brokers[brokerId - 1].capacity = capacity;
        emit BrokerUpdated(brokerId, msg.sender);
    }

    /**
     * @notice Update current load (called by broker when allocations change)
     * @param currentLoad New current load value
     */
    function updateLoad(uint256 currentLoad) external {
        uint256 brokerId = _requireOperator();
        uint256 cap = brokers[brokerId - 1].capacity;
        require(cap == 0 || currentLoad <= cap, "Load exceeds capacity");

        brokers[brokerId - 1].currentLoad = currentLoad;
        emit BrokerLoadUpdated(brokerId, currentLoad);
    }

    /**
     * @notice Deactivate broker (stop accepting new requests)
     */
    function deactivate() external {
        uint256 brokerId = _requireOperator();

        brokers[brokerId - 1].active = false;
        emit BrokerDeactivated(brokerId, msg.sender);
    }

    /**
     * @notice Activate broker (start accepting new requests)
     */
    function activate() external {
        uint256 brokerId = _requireOperator();

        brokers[brokerId - 1].active = true;
        emit BrokerActivated(brokerId, msg.sender);
    }

    /**
     * @notice Get broker by ID
     * @param brokerId Broker ID (1-indexed)
     * @return broker The broker details
     */
    function getBroker(uint256 brokerId) external view returns (Broker memory broker) {
        require(brokerId > 0 && brokerId <= brokers.length, "Invalid broker ID");
        return brokers[brokerId - 1];
    }

    /**
     * @notice Get total number of registered brokers
     * @return count Total broker count
     */
    function getBrokerCount() external view returns (uint256 count) {
        return brokers.length;
    }

    /**
     * @notice Check if an address is a registered operator
     * @param operator Address to check
     * @return isRegistered True if registered
     */
    function isOperator(address operator) external view returns (bool isRegistered) {
        return operatorToBrokerId[operator] != 0;
    }

    /**
     * @notice Admin function to remove a malicious broker
     * @param brokerId Broker ID to remove
     */
    function removeBroker(uint256 brokerId) external onlyOwner {
        require(brokerId > 0 && brokerId <= brokers.length, "Invalid broker ID");

        Broker storage broker = brokers[brokerId - 1];
        delete operatorToBrokerId[broker.operator];
        delete requestsContractToBrokerId[broker.requestsContract];

        // Mark as inactive and clear operator (don't delete to preserve IDs)
        broker.active = false;
        broker.operator = address(0);

        emit BrokerDeactivated(brokerId, msg.sender);
    }
}
