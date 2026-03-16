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
        name: 'setCapacityStatus',
        inputs: [{ name: 'status', type: ABIDataTypes.UINT256 }],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'getRequest',
        inputs: [{ name: 'requestId', type: ABIDataTypes.UINT256 }],
        outputs: [
            { name: 'id', type: ABIDataTypes.UINT256 },
            { name: 'requester', type: ABIDataTypes.ADDRESS },
            { name: 'nftContract', type: ABIDataTypes.ADDRESS },
            { name: 'encryptedPayload', type: ABIDataTypes.STRING },
            { name: 'submittedAt', type: ABIDataTypes.UINT256 },
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
        name: 'getRequestIdByNftContract',
        inputs: [{ name: 'nftContract', type: ABIDataTypes.ADDRESS }],
        outputs: [{ name: 'requestId', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'getCapacityStatus',
        inputs: [],
        outputs: [{ name: 'status', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function,
    },
    ...BrokerRequestsEvents,
    ...OP_NET_ABI,
];

export default BrokerRequestsAbi;
