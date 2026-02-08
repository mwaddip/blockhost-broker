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

    bytes constant ENCRYPTED_PAYLOAD = hex"deadbeef01020304";
    bytes constant RESPONSE_PAYLOAD = hex"cafebabe05060708";

    function setUp() public {
        owner = address(this);
        user = makeAddr("user");
        requests = new BrokerRequests();
        nft = new MockNFT(user);
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

    function test_submitRequest_revertDuplicate() public {
        vm.prank(user);
        requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);

        vm.prank(user);
        vm.expectRevert("NFT contract already has a request");
        requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);
    }

    function test_submitRequest_revertNotOwner() public {
        address stranger = makeAddr("stranger");
        vm.prank(stranger);
        vm.expectRevert("Sender does not own NFT contract");
        requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);
    }

    // ========== Submit Response ==========

    function test_submitResponse() public {
        vm.prank(user);
        uint256 id = requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);

        requests.submitResponse(id, RESPONSE_PAYLOAD);

        BrokerRequests.Request memory req = requests.getRequest(id);
        assertEq(uint8(req.status), uint8(BrokerRequests.RequestStatus.Approved));
        assertEq(req.responsePayload, RESPONSE_PAYLOAD);
    }

    function test_submitResponse_revertNotOwner() public {
        vm.prank(user);
        uint256 id = requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);

        vm.prank(user);
        vm.expectRevert();
        requests.submitResponse(id, RESPONSE_PAYLOAD);
    }

    function test_submitResponse_revertInvalidId() public {
        vm.expectRevert("Invalid request ID");
        requests.submitResponse(0, RESPONSE_PAYLOAD);
    }

    function test_submitResponse_revertExpired() public {
        vm.prank(user);
        uint256 id = requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);

        // Warp past expiration
        vm.warp(block.timestamp + 25 hours);

        vm.expectRevert("Request expired");
        requests.submitResponse(id, RESPONSE_PAYLOAD);
    }

    function test_submitResponse_revertEmptyPayload() public {
        vm.prank(user);
        uint256 id = requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);

        vm.expectRevert("Response requires payload");
        requests.submitResponse(id, "");
    }

    // ========== Mark Expired ==========

    function test_markExpired() public {
        vm.prank(user);
        uint256 id = requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);

        // Can't expire before time
        uint256[] memory ids = new uint256[](1);
        ids[0] = id;
        requests.markExpired(ids);
        assertEq(uint8(requests.getRequest(id).status), uint8(BrokerRequests.RequestStatus.Pending));

        // Warp past expiration
        vm.warp(block.timestamp + 25 hours);
        requests.markExpired(ids);
        assertEq(uint8(requests.getRequest(id).status), uint8(BrokerRequests.RequestStatus.Expired));

        // NFT contract mapping cleared — can resubmit
        assertEq(requests.nftContractToRequestId(address(nft)), 0);
    }

    // ========== Release Allocation ==========

    function test_releaseAllocation() public {
        vm.prank(user);
        requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);

        requests.releaseAllocation(address(nft));
        assertEq(requests.nftContractToRequestId(address(nft)), 0);
    }

    function test_releaseAllocation_revertNoAllocation() public {
        vm.expectRevert("No allocation for this NFT contract");
        requests.releaseAllocation(address(nft));
    }

    function test_releaseAllocation_revertNotOwner() public {
        vm.prank(user);
        requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);

        vm.prank(user);
        vm.expectRevert();
        requests.releaseAllocation(address(nft));
    }

    // ========== Expiration Config ==========

    function test_setRequestExpirationTime() public {
        requests.setRequestExpirationTime(2 hours);
        assertEq(requests.requestExpirationTime(), 2 hours);
    }

    function test_setRequestExpirationTime_revertTooShort() public {
        vm.expectRevert("Expiration time too short");
        requests.setRequestExpirationTime(30 minutes);
    }

    function test_setRequestExpirationTime_revertTooLong() public {
        vm.expectRevert("Expiration time too long");
        requests.setRequestExpirationTime(8 days);
    }

    // ========== View Functions ==========

    function test_getRequest_revertInvalidId() public {
        vm.expectRevert("Invalid request ID");
        requests.getRequest(0);

        vm.expectRevert("Invalid request ID");
        requests.getRequest(999);
    }
}
