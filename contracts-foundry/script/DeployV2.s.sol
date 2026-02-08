// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/BrokerRegistry.sol";
import "../src/BrokerRequests.sol";

/**
 * @title DeployV2
 * @notice Deploys V2 contracts and registers the broker in a single script.
 *
 * Three broadcast phases using two keys:
 *   1. DEPLOYER_PRIVATE_KEY → deploy BrokerRegistry
 *   2. OPERATOR_PRIVATE_KEY → deploy BrokerRequests (operator = contract owner)
 *   3. DEPLOYER_PRIVATE_KEY → registerBroker() on the registry
 *
 * Environment variables:
 *   DEPLOYER_PRIVATE_KEY  - Registry owner / deployer wallet
 *   OPERATOR_PRIVATE_KEY  - Broker operator wallet (also owns BrokerRequests)
 *   ECIES_PUBKEY          - Hex-encoded 65-byte uncompressed secp256k1 pubkey
 *   BROKER_REGION         - Region string (default: "eu-west")
 *   BROKER_CAPACITY       - Max allocations, 0 = unlimited (default: 0)
 */
contract DeployV2 is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        uint256 operatorKey = vm.envUint("OPERATOR_PRIVATE_KEY");
        bytes memory eciesPubkey = vm.envBytes("ECIES_PUBKEY");
        string memory region = vm.envOr("BROKER_REGION", string("eu-west"));
        uint256 capacity = vm.envOr("BROKER_CAPACITY", uint256(0));

        address operatorAddr = vm.addr(operatorKey);

        // Phase 1: Deploy BrokerRegistry (deployer = registry owner)
        vm.startBroadcast(deployerKey);
        BrokerRegistry registry = new BrokerRegistry();
        console.log("BrokerRegistry deployed at:", address(registry));
        vm.stopBroadcast();

        // Phase 2: Deploy BrokerRequests (operator = contract owner)
        vm.startBroadcast(operatorKey);
        BrokerRequests requests = new BrokerRequests();
        console.log("BrokerRequests deployed at:", address(requests));
        vm.stopBroadcast();

        // Phase 3: Register broker in registry (deployer = registry owner)
        vm.startBroadcast(deployerKey);
        uint256 brokerId = registry.registerBroker(
            operatorAddr,
            address(requests),
            eciesPubkey,
            region,
            capacity
        );
        console.log("Broker registered with ID:", brokerId);
        vm.stopBroadcast();

        // Output summary
        console.log("");
        console.log("=== Contract Addresses ===");
        console.log("BROKER_REGISTRY_CONTRACT=%s", address(registry));
        console.log("BROKER_REQUESTS_CONTRACT=%s", address(requests));
        console.log("OPERATOR_ADDRESS=%s", operatorAddr);
        console.log("BROKER_ID=%d", brokerId);
    }
}
