// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {BrokerRegistry} from "../src/BrokerRegistry.sol";

contract BrokerRegistryTest is Test {
    BrokerRegistry public registry;
    address public owner;
    address public operator;
    address public requestsContract;

    // 65-byte uncompressed secp256k1 pubkey (04 prefix + 32-byte X + 32-byte Y)
    bytes constant VALID_PUBKEY = hex"04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    function setUp() public {
        owner = address(this);
        operator = makeAddr("operator");
        requestsContract = makeAddr("requests");
        registry = new BrokerRegistry();
    }

    // ========== Registration ==========

    function test_registerBroker() public {
        uint256 id = registry.registerBroker(operator, requestsContract, VALID_PUBKEY, "eu-west", 100);
        assertEq(id, 1);
        assertEq(registry.operatorToBrokerId(operator), 1);
        assertEq(registry.requestsContractToBrokerId(requestsContract), 1);
        assertEq(registry.getBrokerCount(), 1);
    }

    function test_registerBroker_revertZeroOperator() public {
        vm.expectRevert("Invalid operator address");
        registry.registerBroker(address(0), requestsContract, VALID_PUBKEY, "eu-west", 100);
    }

    function test_registerBroker_revertZeroContract() public {
        vm.expectRevert("Invalid requests contract");
        registry.registerBroker(operator, address(0), VALID_PUBKEY, "eu-west", 100);
    }

    function test_registerBroker_revertBadPubkey() public {
        vm.expectRevert("Pubkey must be 65 bytes (uncompressed secp256k1)");
        registry.registerBroker(operator, requestsContract, hex"aabb", "eu-west", 100);
    }

    function test_registerBroker_reRegistration() public {
        // First registration
        uint256 id1 = registry.registerBroker(operator, requestsContract, VALID_PUBKEY, "eu-west", 100);
        assertEq(id1, 1);
        assertTrue(registry.getBroker(1).active);

        // Re-register same operator with new requests contract
        address newRequestsContract = makeAddr("requests2");
        uint256 id2 = registry.registerBroker(operator, newRequestsContract, VALID_PUBKEY, "us-east", 200);
        assertEq(id2, 2);

        // Old entry should be deactivated
        assertFalse(registry.getBroker(1).active);

        // New entry should be active
        assertTrue(registry.getBroker(2).active);
        assertEq(registry.getBroker(2).region, "us-east");
        assertEq(registry.getBroker(2).capacity, 200);

        // Operator mapping should point to new entry
        assertEq(registry.operatorToBrokerId(operator), 2);

        // Old requests contract mapping should be cleared
        assertEq(registry.requestsContractToBrokerId(requestsContract), 0);

        // New requests contract mapping should be set
        assertEq(registry.requestsContractToBrokerId(newRequestsContract), 2);

        // Total count should be 2 (old entry preserved)
        assertEq(registry.getBrokerCount(), 2);
    }

    function test_registerBroker_revertNonOwner() public {
        vm.prank(operator);
        vm.expectRevert();
        registry.registerBroker(operator, requestsContract, VALID_PUBKEY, "eu-west", 100);
    }

    // ========== Updates ==========

    function test_updateEncryptionPubkey() public {
        registry.registerBroker(operator, requestsContract, VALID_PUBKEY, "eu-west", 100);

        bytes memory newPubkey = hex"04ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        vm.prank(operator);
        registry.updateEncryptionPubkey(newPubkey);

        BrokerRegistry.Broker memory broker = registry.getBroker(1);
        assertEq(broker.encryptionPubkey, newPubkey);
    }

    function test_updateRegion() public {
        registry.registerBroker(operator, requestsContract, VALID_PUBKEY, "eu-west", 100);

        vm.prank(operator);
        registry.updateRegion("us-east");

        BrokerRegistry.Broker memory broker = registry.getBroker(1);
        assertEq(broker.region, "us-east");
    }

    function test_updateRegion_revertEmpty() public {
        registry.registerBroker(operator, requestsContract, VALID_PUBKEY, "eu-west", 100);

        vm.prank(operator);
        vm.expectRevert("Region cannot be empty");
        registry.updateRegion("");
    }

    function test_updateLoad() public {
        registry.registerBroker(operator, requestsContract, VALID_PUBKEY, "eu-west", 100);

        vm.prank(operator);
        registry.updateLoad(50);

        BrokerRegistry.Broker memory broker = registry.getBroker(1);
        assertEq(broker.currentLoad, 50);
    }

    function test_updateLoad_revertExceedsCapacity() public {
        registry.registerBroker(operator, requestsContract, VALID_PUBKEY, "eu-west", 100);

        vm.prank(operator);
        vm.expectRevert("Load exceeds capacity");
        registry.updateLoad(101);
    }

    function test_updateLoad_unlimitedCapacity() public {
        // capacity = 0 means unlimited
        registry.registerBroker(operator, requestsContract, VALID_PUBKEY, "eu-west", 0);

        vm.prank(operator);
        registry.updateLoad(999999);

        BrokerRegistry.Broker memory broker = registry.getBroker(1);
        assertEq(broker.currentLoad, 999999);
    }

    // ========== Activation ==========

    function test_deactivateAndActivate() public {
        registry.registerBroker(operator, requestsContract, VALID_PUBKEY, "eu-west", 100);

        vm.prank(operator);
        registry.deactivate();
        assertFalse(registry.getBroker(1).active);

        vm.prank(operator);
        registry.activate();
        assertTrue(registry.getBroker(1).active);
    }

    // ========== Removal ==========

    function test_removeBroker() public {
        registry.registerBroker(operator, requestsContract, VALID_PUBKEY, "eu-west", 100);
        registry.removeBroker(1);

        assertFalse(registry.getBroker(1).active);
        assertEq(registry.getBroker(1).operator, address(0));
        assertEq(registry.operatorToBrokerId(operator), 0);
    }

    function test_removeBroker_revertInvalidId() public {
        vm.expectRevert("Invalid broker ID");
        registry.removeBroker(0);
    }

    // ========== View functions ==========

    function test_isOperator() public {
        assertFalse(registry.isOperator(operator));
        registry.registerBroker(operator, requestsContract, VALID_PUBKEY, "eu-west", 100);
        assertTrue(registry.isOperator(operator));
    }
}
