// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {BrokerRequests} from "../src/BrokerRequests.sol";

/// @dev Minimal ERC721 mock that supports ERC165 and has an owner.
contract MockNFT {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        // ERC721 interface ID = 0x80ac58cd
        return interfaceId == 0x80ac58cd || interfaceId == 0x01ffc9a7;
    }
}

contract BrokerRequestsTest is Test {
    BrokerRequests public requests;
    address public owner;
    address public user;
    MockNFT public nft;
    MockNFT public nft2;

    bytes constant ENCRYPTED_PAYLOAD = hex"deadbeef01020304";
    bytes constant ENCRYPTED_PAYLOAD_2 = hex"aabbccdd11223344";

    function setUp() public {
        owner = address(this);
        user = makeAddr("user");
        requests = new BrokerRequests();
        nft = new MockNFT(user);
        nft2 = new MockNFT(user);
    }

    // ========== Submit Request ==========

    function test_submitRequest() public {
        vm.prank(user);
        uint256 id = requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);
        assertEq(id, 1);
        assertEq(requests.getRequestCount(), 1);
        assertEq(requests.nftContractToRequestId(address(nft)), 1);
    }

    function test_submitRequest_revertZeroAddress() public {
        vm.prank(user);
        vm.expectRevert("Invalid NFT contract address");
        requests.submitRequest(address(0), ENCRYPTED_PAYLOAD);
    }

    function test_submitRequest_revertEmptyPayload() public {
        vm.prank(user);
        vm.expectRevert("Empty payload");
        requests.submitRequest(address(nft), "");
    }

    function test_submitRequest_overwrite() public {
        // First request
        vm.prank(user);
        uint256 id1 = requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);
        assertEq(id1, 1);

        // Overwrite with second request (same NFT)
        vm.prank(user);
        uint256 id2 = requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD_2);
        assertEq(id2, 2);

        // Mapping should point to new request
        assertEq(requests.nftContractToRequestId(address(nft)), id2);

        // Both requests stored (old one still readable, just superseded)
        BrokerRequests.Request memory oldReq = requests.getRequest(id1);
        assertEq(oldReq.requester, user);
        BrokerRequests.Request memory newReq = requests.getRequest(id2);
        assertEq(newReq.requester, user);
    }

    function test_submitRequest_multipleNfts() public {
        vm.prank(user);
        uint256 id1 = requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);
        vm.prank(user);
        uint256 id2 = requests.submitRequest(address(nft2), ENCRYPTED_PAYLOAD_2);

        assertEq(id1, 1);
        assertEq(id2, 2);
        assertEq(requests.nftContractToRequestId(address(nft)), 1);
        assertEq(requests.nftContractToRequestId(address(nft2)), 2);
    }

    function test_submitRequest_revertNotOwner() public {
        address stranger = makeAddr("stranger");
        vm.prank(stranger);
        vm.expectRevert("Sender does not own NFT contract");
        requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);
    }

    // ========== Capacity Status ==========

    function test_capacityStatus_default() public view {
        assertEq(requests.capacityStatus(), 0);
    }

    function test_setCapacityStatus() public {
        requests.setCapacityStatus(1);
        assertEq(requests.capacityStatus(), 1);

        requests.setCapacityStatus(2);
        assertEq(requests.capacityStatus(), 2);

        requests.setCapacityStatus(0);
        assertEq(requests.capacityStatus(), 0);
    }

    function test_setCapacityStatus_revertInvalid() public {
        vm.expectRevert("Invalid status");
        requests.setCapacityStatus(3);
    }

    function test_setCapacityStatus_revertNotOwner() public {
        vm.prank(user);
        vm.expectRevert();
        requests.setCapacityStatus(1);
    }

    // ========== View Functions ==========

    function test_getRequest() public {
        vm.prank(user);
        uint256 id = requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);

        BrokerRequests.Request memory req = requests.getRequest(id);
        assertEq(req.id, 1);
        assertEq(req.requester, user);
        assertEq(req.nftContract, address(nft));
        assertEq(req.encryptedPayload, ENCRYPTED_PAYLOAD);
        assertTrue(req.submittedAt > 0);
    }

    function test_getRequest_revertInvalidId() public {
        vm.expectRevert("Invalid request ID");
        requests.getRequest(0);

        vm.expectRevert("Invalid request ID");
        requests.getRequest(999);
    }

    function test_getRequestCount() public {
        assertEq(requests.getRequestCount(), 0);

        vm.prank(user);
        requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);
        assertEq(requests.getRequestCount(), 1);

        vm.prank(user);
        requests.submitRequest(address(nft2), ENCRYPTED_PAYLOAD_2);
        assertEq(requests.getRequestCount(), 2);
    }
}
