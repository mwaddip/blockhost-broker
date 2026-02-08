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
    /// @dev Rejected is unused — rejections are silent (broker doesn't respond, request expires).
    ///      Kept for ABI stability and potential future use.
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

    /// @notice Maximum capacity (0 = unlimited)
    uint256 public totalCapacity;

    /// @notice Number of currently approved (allocated) requests
    uint256 public _activeCount;

    /// @notice Number of currently pending requests
    uint256 public _pendingCount;

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
     * @notice Submit an allocation request (overwrites existing request for same NFT contract)
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

        // Verify NFT contract exists and is ERC721
        require(_isContract(nftContract), "NFT contract does not exist");
        require(_isERC721(nftContract), "Not an ERC721 contract");

        // Verify sender owns the NFT contract
        require(_isOwner(nftContract, msg.sender), "Sender does not own NFT contract");

        // Handle overwrite if existing request exists
        uint256 existingId = nftContractToRequestId[nftContract];
        if (existingId != 0) {
            Request storage oldRequest = requests[existingId - 1];
            if (oldRequest.status == RequestStatus.Pending) {
                _pendingCount--;
            } else if (oldRequest.status == RequestStatus.Approved) {
                _activeCount--;
            }
            oldRequest.status = RequestStatus.Expired;
            oldRequest.respondedAt = block.timestamp;
        }

        requests.push(Request({
            id: requests.length + 1, // 1-indexed
            requester: msg.sender,
            nftContract: nftContract,
            encryptedPayload: encryptedPayload,
            status: RequestStatus.Pending,
            responsePayload: "",
            submittedAt: block.timestamp,
            respondedAt: 0
        }));

        requestId = requests.length; // 1-indexed
        nftContractToRequestId[nftContract] = requestId;
        requesterToRequestIds[msg.sender].push(requestId);
        _pendingCount++;

        emit RequestSubmitted(requestId, msg.sender, nftContract, encryptedPayload);
    }

    /**
     * @notice Submit an approval response to an allocation request (broker only)
     * @dev Rejections are silent - broker simply doesn't respond and request expires
     * @param requestId Request ID to approve
     * @param encryptedPayload ECIES encrypted response data
     */
    function submitResponse(
        uint256 requestId,
        bytes calldata encryptedPayload
    ) external onlyOwner {
        require(requestId > 0 && requestId <= requests.length, "Invalid request ID");

        Request storage request = requests[requestId - 1];
        require(request.status == RequestStatus.Pending, "Request not pending");
        require(block.timestamp <= request.submittedAt + requestExpirationTime, "Request expired");
        require(encryptedPayload.length > 0, "Response requires payload");
        require(nftContractToRequestId[request.nftContract] == requestId, "Request superseded");

        request.status = RequestStatus.Approved;
        request.responsePayload = encryptedPayload;
        request.respondedAt = block.timestamp;
        _pendingCount--;
        _activeCount++;

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
                    _pendingCount--;
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
     * @notice Set total capacity (broker only)
     * @param _totalCapacity New total capacity (0 = unlimited)
     */
    function setTotalCapacity(uint256 _totalCapacity) external onlyOwner {
        totalCapacity = _totalCapacity;
    }

    /**
     * @notice Get available capacity
     * @return Available capacity (type(uint256).max if unlimited)
     */
    function getAvailableCapacity() external view returns (uint256) {
        if (totalCapacity == 0) return type(uint256).max;
        uint256 used = _activeCount + _pendingCount;
        if (used >= totalCapacity) return 0;
        return totalCapacity - used;
    }

    /**
     * @notice Release an allocation (allows NFT contract to request again)
     * @param nftContract Address of the NFT contract to release
     */
    function releaseAllocation(address nftContract) external onlyOwner {
        uint256 requestId = nftContractToRequestId[nftContract];
        require(requestId != 0, "No allocation for this NFT contract");

        Request storage request = requests[requestId - 1];
        if (request.status == RequestStatus.Approved) {
            _activeCount--;
        } else if (request.status == RequestStatus.Pending) {
            _pendingCount--;
        }

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
