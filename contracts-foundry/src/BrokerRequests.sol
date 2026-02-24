// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title BrokerRequests
 * @notice Handles IPv6 allocation requests for a specific broker.
 * @dev Each broker deploys their own instance. Responses are delivered as
 *      direct blockchain transactions (not stored on-chain).
 */
contract BrokerRequests is Ownable {
    /// @notice ERC721 interface ID for verification
    bytes4 private constant ERC721_INTERFACE_ID = 0x80ac58cd;

    /// @notice Allocation request structure
    struct Request {
        uint256 id;
        address requester;          // Wallet that submitted the request
        address nftContract;        // Blockhost AccessCredentialNFT contract
        bytes encryptedPayload;     // ECIES encrypted request data
        uint256 submittedAt;
    }

    /// @notice All requests
    Request[] public requests;

    /// @notice Mapping from NFT contract to request ID (1-indexed, 0 = no request)
    mapping(address => uint256) public nftContractToRequestId;

    /// @notice Capacity status: 0 = available, 1 = limited, 2 = closed
    uint8 public capacityStatus;

    // Events
    event RequestSubmitted(
        uint256 indexed requestId,
        address indexed requester,
        address indexed nftContract,
        bytes encryptedPayload
    );

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

        requests.push(Request({
            id: requests.length + 1, // 1-indexed
            requester: msg.sender,
            nftContract: nftContract,
            encryptedPayload: encryptedPayload,
            submittedAt: block.timestamp
        }));

        requestId = requests.length; // 1-indexed
        nftContractToRequestId[nftContract] = requestId;

        emit RequestSubmitted(requestId, msg.sender, nftContract, encryptedPayload);
    }

    /**
     * @notice Set capacity status (broker only)
     * @param status 0 = available, 1 = limited, 2 = closed
     */
    function setCapacityStatus(uint8 status) external onlyOwner {
        require(status <= 2, "Invalid status");
        capacityStatus = status;
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
