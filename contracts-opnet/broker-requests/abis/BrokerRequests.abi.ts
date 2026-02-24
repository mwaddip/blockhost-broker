import { ABIDataTypes, BitcoinAbiTypes, OP_NET_ABI } from 'opnet';

export const BrokerRequestsEvents = [
    {
        name: 'RequestSubmitted',
        values: [
            { name: 'requestId', type: ABIDataTypes.UINT256 },
            { name: 'requester', type: ABIDataTypes.ADDRESS },
            { name: 'nftContract', type: ABIDataTypes.ADDRESS },
            { name: 'encryptedPayload', type: ABIDataTypes.STRING },
        ],
        type: BitcoinAbiTypes.Event,
    },
    {
        name: 'ResponseSubmitted',
        values: [
            { name: 'requestId', type: ABIDataTypes.UINT256 },
            { name: 'status', type: ABIDataTypes.UINT256 },
            { name: 'encryptedPayload', type: ABIDataTypes.STRING },
        ],
        type: BitcoinAbiTypes.Event,
    },
    {
        name: 'RequestExpired',
        values: [{ name: 'requestId', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Event,
    },
];

export const BrokerRequestsAbi = [
    {
        name: 'submitRequest',
        inputs: [
            { name: 'nftContract', type: ABIDataTypes.ADDRESS },
            { name: 'encryptedPayload', type: ABIDataTypes.STRING },
        ],
        outputs: [{ name: 'requestId', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'submitResponse',
        inputs: [
            { name: 'requestId', type: ABIDataTypes.UINT256 },
            { name: 'encryptedPayload', type: ABIDataTypes.STRING },
        ],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'markExpired',
        inputs: [{ name: 'requestIds', type: ABIDataTypes.UINT256 }],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'releaseAllocation',
        inputs: [{ name: 'nftContract', type: ABIDataTypes.ADDRESS }],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'setExpirationBlocks',
        inputs: [{ name: 'blocks', type: ABIDataTypes.UINT256 }],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'setTotalCapacity',
        inputs: [{ name: 'capacity', type: ABIDataTypes.UINT256 }],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'getRequest',
        inputs: [{ name: 'requestId', type: ABIDataTypes.UINT256 }],
        outputs: [
            { name: 'requester', type: ABIDataTypes.ADDRESS },
            { name: 'nftContract', type: ABIDataTypes.ADDRESS },
            { name: 'encryptedPayload', type: ABIDataTypes.STRING },
            { name: 'status', type: ABIDataTypes.UINT256 },
            { name: 'responsePayload', type: ABIDataTypes.STRING },
            { name: 'submittedAt', type: ABIDataTypes.UINT256 },
            { name: 'respondedAt', type: ABIDataTypes.UINT256 },
        ],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'getRequestCount',
        inputs: [],
        outputs: [{ name: 'count', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'getAvailableCapacity',
        inputs: [],
        outputs: [{ name: 'available', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'getRequestsByRequester',
        inputs: [
            { name: 'requester', type: ABIDataTypes.ADDRESS },
            { name: 'offset', type: ABIDataTypes.UINT256 },
            { name: 'limit', type: ABIDataTypes.UINT256 },
        ],
        outputs: [{ name: 'requestIds', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'getRequestCountByRequester',
        inputs: [{ name: 'requester', type: ABIDataTypes.ADDRESS }],
        outputs: [{ name: 'count', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'getRequestIdByNftContract',
        inputs: [{ name: 'nftContract', type: ABIDataTypes.ADDRESS }],
        outputs: [{ name: 'requestId', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'getExpirationBlocks',
        inputs: [],
        outputs: [{ name: 'blocks', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'getTotalCapacity',
        inputs: [],
        outputs: [{ name: 'capacity', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'getActiveCount',
        inputs: [],
        outputs: [{ name: 'count', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'getPendingCount',
        inputs: [],
        outputs: [{ name: 'count', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function,
    },
    ...BrokerRequestsEvents,
    ...OP_NET_ABI,
];

export default BrokerRequestsAbi;
