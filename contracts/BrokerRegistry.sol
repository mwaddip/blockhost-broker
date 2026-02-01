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
     * @notice Register a new broker
     * @param requestsContract Address of the broker's BrokerRequests contract
     * @param encryptionPubkey secp256k1 public key for ECIES encryption (65 bytes)
     * @param region Geographic region hint
     * @param capacity Maximum allocations (0 = unlimited)
     * @return brokerId The ID of the newly registered broker
     */
    function registerBroker(
        address requestsContract,
        bytes calldata encryptionPubkey,
        string calldata region,
        uint256 capacity
    ) external returns (uint256 brokerId) {
        require(requestsContract != address(0), "Invalid requests contract");
        require(encryptionPubkey.length == 65, "Pubkey must be 65 bytes (uncompressed secp256k1)");
        require(operatorToBrokerId[msg.sender] == 0, "Operator already registered");
        require(requestsContractToBrokerId[requestsContract] == 0, "Requests contract already registered");

        brokers.push(Broker({
            operator: msg.sender,
            requestsContract: requestsContract,
            encryptionPubkey: encryptionPubkey,
            region: region,
            active: true,
            capacity: capacity,
            currentLoad: 0,
            registeredAt: block.timestamp
        }));

        brokerId = brokers.length; // 1-indexed
        operatorToBrokerId[msg.sender] = brokerId;
        requestsContractToBrokerId[requestsContract] = brokerId;

        emit BrokerRegistered(brokerId, msg.sender, requestsContract, region);
    }

    /**
     * @notice Update broker encryption pubkey
     * @param encryptionPubkey New secp256k1 public key (65 bytes)
     */
    function updateEncryptionPubkey(bytes calldata encryptionPubkey) external {
        uint256 brokerId = operatorToBrokerId[msg.sender];
        require(brokerId != 0, "Not a registered operator");
        require(encryptionPubkey.length == 65, "Pubkey must be 65 bytes");

        brokers[brokerId - 1].encryptionPubkey = encryptionPubkey;
        emit BrokerUpdated(brokerId, msg.sender);
    }

    /**
     * @notice Update broker region
     * @param region New region string
     */
    function updateRegion(string calldata region) external {
        uint256 brokerId = operatorToBrokerId[msg.sender];
        require(brokerId != 0, "Not a registered operator");

        brokers[brokerId - 1].region = region;
        emit BrokerUpdated(brokerId, msg.sender);
    }

    /**
     * @notice Update broker capacity
     * @param capacity New capacity (0 = unlimited)
     */
    function updateCapacity(uint256 capacity) external {
        uint256 brokerId = operatorToBrokerId[msg.sender];
        require(brokerId != 0, "Not a registered operator");

        brokers[brokerId - 1].capacity = capacity;
        emit BrokerUpdated(brokerId, msg.sender);
    }

    /**
     * @notice Update current load (called by broker when allocations change)
     * @param currentLoad New current load value
     */
    function updateLoad(uint256 currentLoad) external {
        uint256 brokerId = operatorToBrokerId[msg.sender];
        require(brokerId != 0, "Not a registered operator");

        brokers[brokerId - 1].currentLoad = currentLoad;
        emit BrokerLoadUpdated(brokerId, currentLoad);
    }

    /**
     * @notice Deactivate broker (stop accepting new requests)
     */
    function deactivate() external {
        uint256 brokerId = operatorToBrokerId[msg.sender];
        require(brokerId != 0, "Not a registered operator");

        brokers[brokerId - 1].active = false;
        emit BrokerDeactivated(brokerId, msg.sender);
    }

    /**
     * @notice Activate broker (start accepting new requests)
     */
    function activate() external {
        uint256 brokerId = operatorToBrokerId[msg.sender];
        require(brokerId != 0, "Not a registered operator");

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
     * @notice Get all active brokers
     * @return activeBrokers Array of active broker details with their IDs
     */
    function getActiveBrokers() external view returns (uint256[] memory, Broker[] memory) {
        // First count active brokers
        uint256 activeCount = 0;
        for (uint256 i = 0; i < brokers.length; i++) {
            if (brokers[i].active) {
                activeCount++;
            }
        }

        // Allocate arrays
        uint256[] memory ids = new uint256[](activeCount);
        Broker[] memory activeBrokers = new Broker[](activeCount);

        // Fill arrays
        uint256 j = 0;
        for (uint256 i = 0; i < brokers.length; i++) {
            if (brokers[i].active) {
                ids[j] = i + 1; // 1-indexed
                activeBrokers[j] = brokers[i];
                j++;
            }
        }

        return (ids, activeBrokers);
    }

    /**
     * @notice Get active brokers in a specific region
     * @param region Region to filter by
     * @return ids Broker IDs
     * @return regionBrokers Broker details
     */
    function getActiveBrokersByRegion(string calldata region)
        external
        view
        returns (uint256[] memory ids, Broker[] memory regionBrokers)
    {
        // First count matching brokers
        uint256 count = 0;
        bytes32 regionHash = keccak256(bytes(region));
        for (uint256 i = 0; i < brokers.length; i++) {
            if (brokers[i].active && keccak256(bytes(brokers[i].region)) == regionHash) {
                count++;
            }
        }

        // Allocate arrays
        ids = new uint256[](count);
        regionBrokers = new Broker[](count);

        // Fill arrays
        uint256 j = 0;
        for (uint256 i = 0; i < brokers.length; i++) {
            if (brokers[i].active && keccak256(bytes(brokers[i].region)) == regionHash) {
                ids[j] = i + 1;
                regionBrokers[j] = brokers[i];
                j++;
            }
        }
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
