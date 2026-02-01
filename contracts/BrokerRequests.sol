// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title BrokerRequests
 * @notice Handles IPv6 allocation requests for a specific broker
 * @dev Each broker deploys their own instance of this contract
 */
contract BrokerRequests is Ownable {
    /// @notice ERC721 interface ID for verification
    bytes4 private constant ERC721_INTERFACE_ID = 0x80ac58cd;

    /// @notice Request status enum
    enum RequestStatus {
        Pending,
        Approved,
        Rejected,
        Expired
    }

    /// @notice Allocation request structure
    struct Request {
        uint256 id;
        address requester;          // Wallet that submitted the request
        address nftContract;        // Blockhost AccessCredentialNFT contract
        bytes encryptedPayload;     // ECIES encrypted request data
        RequestStatus status;
        bytes responsePayload;      // ECIES encrypted response data (if approved)
        string rejectionReason;     // Reason for rejection (if rejected)
        uint256 submittedAt;
        uint256 respondedAt;
    }

    /// @notice All requests
    Request[] public requests;

    /// @notice Mapping from NFT contract to request ID (1-indexed, 0 = no request)
    mapping(address => uint256) public nftContractToRequestId;

    /// @notice Mapping from requester address to their request IDs
    mapping(address => uint256[]) public requesterToRequestIds;

    /// @notice Request expiration time (default: 24 hours)
    uint256 public requestExpirationTime = 24 hours;

    // Events
    event RequestSubmitted(
        uint256 indexed requestId,
        address indexed requester,
        address indexed nftContract,
        bytes encryptedPayload
    );

    event ResponseSubmitted(
        uint256 indexed requestId,
        RequestStatus status,
        bytes encryptedPayload
    );

    event RequestExpired(uint256 indexed requestId);

    constructor() Ownable(msg.sender) {}

    /**
     * @notice Submit an allocation request
     * @param nftContract Address of the Blockhost AccessCredentialNFT contract
     * @param encryptedPayload ECIES encrypted request data (contains WireGuard pubkey, server pubkey)
     * @return requestId The ID of the submitted request
     */
    function submitRequest(
        address nftContract,
        bytes calldata encryptedPayload
    ) external returns (uint256 requestId) {
        require(nftContract != address(0), "Invalid NFT contract address");
        require(encryptedPayload.length > 0, "Empty payload");
        require(nftContractToRequestId[nftContract] == 0, "NFT contract already has a request");

        // Verify NFT contract exists and is ERC721
        require(_isContract(nftContract), "NFT contract does not exist");
        require(_isERC721(nftContract), "Not an ERC721 contract");

        // Verify sender owns the NFT contract
        require(_isOwner(nftContract, msg.sender), "Sender does not own NFT contract");

        requests.push(Request({
            id: requests.length + 1, // 1-indexed
            requester: msg.sender,
            nftContract: nftContract,
            encryptedPayload: encryptedPayload,
            status: RequestStatus.Pending,
            responsePayload: "",
            rejectionReason: "",
            submittedAt: block.timestamp,
            respondedAt: 0
        }));

        requestId = requests.length; // 1-indexed
        nftContractToRequestId[nftContract] = requestId;
        requesterToRequestIds[msg.sender].push(requestId);

        emit RequestSubmitted(requestId, msg.sender, nftContract, encryptedPayload);
    }

    /**
     * @notice Submit a response to an allocation request (broker only)
     * @param requestId Request ID to respond to
     * @param approved Whether to approve or reject the request
     * @param encryptedPayload ECIES encrypted response data (if approved)
     * @param rejectionReason Reason for rejection (if rejected)
     */
    function submitResponse(
        uint256 requestId,
        bool approved,
        bytes calldata encryptedPayload,
        string calldata rejectionReason
    ) external onlyOwner {
        require(requestId > 0 && requestId <= requests.length, "Invalid request ID");

        Request storage request = requests[requestId - 1];
        require(request.status == RequestStatus.Pending, "Request not pending");
        require(block.timestamp <= request.submittedAt + requestExpirationTime, "Request expired");

        if (approved) {
            require(encryptedPayload.length > 0, "Approved response requires payload");
            request.status = RequestStatus.Approved;
            request.responsePayload = encryptedPayload;
        } else {
            request.status = RequestStatus.Rejected;
            request.rejectionReason = rejectionReason;
        }

        request.respondedAt = block.timestamp;

        emit ResponseSubmitted(requestId, request.status, encryptedPayload);
    }

    /**
     * @notice Mark expired requests as expired (can be called by anyone)
     * @param requestIds Array of request IDs to check for expiration
     */
    function markExpired(uint256[] calldata requestIds) external {
        for (uint256 i = 0; i < requestIds.length; i++) {
            uint256 requestId = requestIds[i];
            if (requestId > 0 && requestId <= requests.length) {
                Request storage request = requests[requestId - 1];
                if (
                    request.status == RequestStatus.Pending &&
                    block.timestamp > request.submittedAt + requestExpirationTime
                ) {
                    request.status = RequestStatus.Expired;
                    request.respondedAt = block.timestamp;
                    // Clear NFT contract mapping so they can resubmit
                    delete nftContractToRequestId[request.nftContract];
                    emit RequestExpired(requestId);
                }
            }
        }
    }

    /**
     * @notice Get request by ID
     * @param requestId Request ID (1-indexed)
     * @return request The request details
     */
    function getRequest(uint256 requestId) external view returns (Request memory request) {
        require(requestId > 0 && requestId <= requests.length, "Invalid request ID");
        return requests[requestId - 1];
    }

    /**
     * @notice Get all pending requests
     * @return pendingIds Array of pending request IDs
     * @return pendingRequests Array of pending request details
     */
    function getPendingRequests()
        external
        view
        returns (uint256[] memory pendingIds, Request[] memory pendingRequests)
    {
        // Count pending requests
        uint256 pendingCount = 0;
        for (uint256 i = 0; i < requests.length; i++) {
            if (
                requests[i].status == RequestStatus.Pending &&
                block.timestamp <= requests[i].submittedAt + requestExpirationTime
            ) {
                pendingCount++;
            }
        }

        // Allocate arrays
        pendingIds = new uint256[](pendingCount);
        pendingRequests = new Request[](pendingCount);

        // Fill arrays
        uint256 j = 0;
        for (uint256 i = 0; i < requests.length; i++) {
            if (
                requests[i].status == RequestStatus.Pending &&
                block.timestamp <= requests[i].submittedAt + requestExpirationTime
            ) {
                pendingIds[j] = i + 1;
                pendingRequests[j] = requests[i];
                j++;
            }
        }
    }

    /**
     * @notice Get requests by requester
     * @param requester Address of the requester
     * @return requesterRequests Array of request details
     */
    function getRequestsByRequester(address requester)
        external
        view
        returns (Request[] memory requesterRequests)
    {
        uint256[] storage ids = requesterToRequestIds[requester];
        requesterRequests = new Request[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            requesterRequests[i] = requests[ids[i] - 1];
        }
    }

    /**
     * @notice Get total number of requests
     * @return count Total request count
     */
    function getRequestCount() external view returns (uint256 count) {
        return requests.length;
    }

    /**
     * @notice Update request expiration time (broker only)
     * @param newExpirationTime New expiration time in seconds
     */
    function setRequestExpirationTime(uint256 newExpirationTime) external onlyOwner {
        require(newExpirationTime >= 1 hours, "Expiration time too short");
        require(newExpirationTime <= 7 days, "Expiration time too long");
        requestExpirationTime = newExpirationTime;
    }

    /**
     * @notice Release an allocation (allows NFT contract to request again)
     * @param nftContract Address of the NFT contract to release
     */
    function releaseAllocation(address nftContract) external onlyOwner {
        uint256 requestId = nftContractToRequestId[nftContract];
        require(requestId != 0, "No allocation for this NFT contract");

        delete nftContractToRequestId[nftContract];
    }

    // Internal helper functions

    /**
     * @dev Check if an address is a contract
     */
    function _isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }
        return size > 0;
    }

    /**
     * @dev Check if a contract supports ERC721 interface
     */
    function _isERC721(address nftContract) internal view returns (bool) {
        try IERC165(nftContract).supportsInterface(ERC721_INTERFACE_ID) returns (bool supported) {
            return supported;
        } catch {
            return false;
        }
    }

    /**
     * @dev Check if an address owns a contract (via Ownable)
     */
    function _isOwner(address nftContract, address account) internal view returns (bool) {
        // Try to call owner() function
        (bool success, bytes memory data) = nftContract.staticcall(
            abi.encodeWithSignature("owner()")
        );
        if (success && data.length == 32) {
            address contractOwner = abi.decode(data, (address));
            return contractOwner == account;
        }
        return false;
    }
}
