// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/BrokerRegistry.sol";
import "../src/BrokerRequests.sol";

contract DeployScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        // Deploy BrokerRegistry (global)
        BrokerRegistry registry = new BrokerRegistry();
        console.log("BrokerRegistry deployed at:", address(registry));

        // Deploy BrokerRequests (this broker's instance)
        BrokerRequests requests = new BrokerRequests();
        console.log("BrokerRequests deployed at:", address(requests));

        vm.stopBroadcast();

        // Output for easy copying
        console.log("");
        console.log("=== Contract Addresses ===");
        console.log("BROKER_REGISTRY_CONTRACT=%s", address(registry));
        console.log("BROKER_REQUESTS_CONTRACT=%s", address(requests));
    }
}
