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
    bytes constant RESPONSE_PAYLOAD = hex"cafebabe05060708";

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
        assertEq(requests._pendingCount(), 1);
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
        assertEq(requests._pendingCount(), 1);

        // Overwrite with second request (same NFT)
        vm.prank(user);
        uint256 id2 = requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD_2);
        assertEq(id2, 2);

        // Old request should be expired
        BrokerRequests.Request memory oldReq = requests.getRequest(id1);
        assertEq(uint8(oldReq.status), uint8(BrokerRequests.RequestStatus.Expired));
        assertTrue(oldReq.respondedAt > 0);

        // New request should be pending
        BrokerRequests.Request memory newReq = requests.getRequest(id2);
        assertEq(uint8(newReq.status), uint8(BrokerRequests.RequestStatus.Pending));

        // Mapping should point to new request
        assertEq(requests.nftContractToRequestId(address(nft)), id2);

        // Pending count should still be 1 (decremented for old, incremented for new)
        assertEq(requests._pendingCount(), 1);
    }

    function test_submitRequest_overwriteApproved() public {
        // Submit and approve first request
        vm.prank(user);
        uint256 id1 = requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);
        requests.submitResponse(id1, RESPONSE_PAYLOAD);
        assertEq(requests._activeCount(), 1);
        assertEq(requests._pendingCount(), 0);

        // Overwrite with new request
        vm.prank(user);
        uint256 id2 = requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD_2);

        // Old request should be expired, counters updated
        BrokerRequests.Request memory oldReq = requests.getRequest(id1);
        assertEq(uint8(oldReq.status), uint8(BrokerRequests.RequestStatus.Expired));

        assertEq(requests._activeCount(), 0);  // Decremented from overwrite
        assertEq(requests._pendingCount(), 1);  // New pending request

        // New request is pending
        BrokerRequests.Request memory newReq = requests.getRequest(id2);
        assertEq(uint8(newReq.status), uint8(BrokerRequests.RequestStatus.Pending));
        assertEq(requests.nftContractToRequestId(address(nft)), id2);
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
        assertEq(requests._activeCount(), 1);
        assertEq(requests._pendingCount(), 0);
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

    function test_submitResponse_revertSuperseded() public {
        // Submit first request
        vm.prank(user);
        uint256 id1 = requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);

        // Overwrite with second request
        vm.prank(user);
        requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD_2);

        // Try to approve the old request — should revert
        vm.expectRevert("Request not pending");
        requests.submitResponse(id1, RESPONSE_PAYLOAD);
    }

    function test_submitResponse_revertSupersededStillPending() public {
        // This tests the case where the old request is somehow still pending
        // but the mapping has moved on. We need two different NFT contracts.
        vm.prank(user);
        uint256 id1 = requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);

        // Overwrite — old request is now Expired, mapping points to id2
        vm.prank(user);
        uint256 id2 = requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD_2);

        // id1 is Expired, so submitResponse reverts with "Request not pending"
        vm.expectRevert("Request not pending");
        requests.submitResponse(id1, RESPONSE_PAYLOAD);

        // id2 should still work
        requests.submitResponse(id2, RESPONSE_PAYLOAD);
        assertEq(requests._activeCount(), 1);
    }

    // ========== Mark Expired ==========

    function test_markExpired() public {
        vm.prank(user);
        uint256 id = requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);
        assertEq(requests._pendingCount(), 1);

        // Can't expire before time
        uint256[] memory ids = new uint256[](1);
        ids[0] = id;
        requests.markExpired(ids);
        assertEq(uint8(requests.getRequest(id).status), uint8(BrokerRequests.RequestStatus.Pending));

        // Warp past expiration
        vm.warp(block.timestamp + 25 hours);
        requests.markExpired(ids);
        assertEq(uint8(requests.getRequest(id).status), uint8(BrokerRequests.RequestStatus.Expired));
        assertEq(requests._pendingCount(), 0);

        // NFT contract mapping cleared — can resubmit
        assertEq(requests.nftContractToRequestId(address(nft)), 0);
    }

    // ========== Release Allocation ==========

    function test_releaseAllocation() public {
        vm.prank(user);
        uint256 id = requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);
        requests.submitResponse(id, RESPONSE_PAYLOAD);
        assertEq(requests._activeCount(), 1);

        requests.releaseAllocation(address(nft));
        assertEq(requests.nftContractToRequestId(address(nft)), 0);
        assertEq(requests._activeCount(), 0);
    }

    function test_releaseAllocation_pending() public {
        vm.prank(user);
        requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);
        assertEq(requests._pendingCount(), 1);

        requests.releaseAllocation(address(nft));
        assertEq(requests.nftContractToRequestId(address(nft)), 0);
        assertEq(requests._pendingCount(), 0);
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

    // ========== Capacity ==========

    function test_setTotalCapacity() public {
        requests.setTotalCapacity(10);
        assertEq(requests.totalCapacity(), 10);
    }

    function test_setTotalCapacity_revertNotOwner() public {
        vm.prank(user);
        vm.expectRevert();
        requests.setTotalCapacity(10);
    }

    function test_getAvailableCapacity_unlimited() public view {
        // Default capacity = 0 = unlimited
        assertEq(requests.getAvailableCapacity(), type(uint256).max);
    }

    function test_getAvailableCapacity() public {
        requests.setTotalCapacity(3);
        assertEq(requests.getAvailableCapacity(), 3);

        // Submit a request (pending)
        vm.prank(user);
        requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);
        assertEq(requests.getAvailableCapacity(), 2);

        // Approve it
        requests.submitResponse(1, RESPONSE_PAYLOAD);
        assertEq(requests.getAvailableCapacity(), 2); // still 1 used (active now, not pending)

        // Submit another request
        vm.prank(user);
        requests.submitRequest(address(nft2), ENCRYPTED_PAYLOAD);
        assertEq(requests.getAvailableCapacity(), 1); // 1 active + 1 pending = 2 used

        // Release the approved one
        requests.releaseAllocation(address(nft));
        assertEq(requests.getAvailableCapacity(), 2); // 0 active + 1 pending = 1 used
    }

    function test_capacityTracking() public {
        requests.setTotalCapacity(2);

        // Submit two requests
        vm.prank(user);
        uint256 id1 = requests.submitRequest(address(nft), ENCRYPTED_PAYLOAD);
        vm.prank(user);
        uint256 id2 = requests.submitRequest(address(nft2), ENCRYPTED_PAYLOAD);
        assertEq(requests._pendingCount(), 2);
        assertEq(requests._activeCount(), 0);
        assertEq(requests.getAvailableCapacity(), 0);

        // Approve first
        requests.submitResponse(id1, RESPONSE_PAYLOAD);
        assertEq(requests._pendingCount(), 1);
        assertEq(requests._activeCount(), 1);
        assertEq(requests.getAvailableCapacity(), 0);

        // Approve second
        requests.submitResponse(id2, RESPONSE_PAYLOAD);
        assertEq(requests._pendingCount(), 0);
        assertEq(requests._activeCount(), 2);
        assertEq(requests.getAvailableCapacity(), 0);

        // Release first
        requests.releaseAllocation(address(nft));
        assertEq(requests._activeCount(), 1);
        assertEq(requests.getAvailableCapacity(), 1);

        // Release second
        requests.releaseAllocation(address(nft2));
        assertEq(requests._activeCount(), 0);
        assertEq(requests.getAvailableCapacity(), 2);
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
