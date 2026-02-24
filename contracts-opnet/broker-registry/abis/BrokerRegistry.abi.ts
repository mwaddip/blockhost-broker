import { ABIDataTypes, BitcoinAbiTypes, OP_NET_ABI } from 'opnet';

export const BrokerRegistryEvents = [
    {
        name: 'BrokerRegistered',
        values: [
            { name: 'brokerId', type: ABIDataTypes.UINT256 },
            { name: 'operator', type: ABIDataTypes.ADDRESS },
            { name: 'requestsContract', type: ABIDataTypes.ADDRESS },
            { name: 'region', type: ABIDataTypes.STRING },
        ],
        type: BitcoinAbiTypes.Event,
    },
    {
        name: 'BrokerUpdated',
        values: [
            { name: 'brokerId', type: ABIDataTypes.UINT256 },
            { name: 'operator', type: ABIDataTypes.ADDRESS },
        ],
        type: BitcoinAbiTypes.Event,
    },
    {
        name: 'BrokerDeactivated',
        values: [
            { name: 'brokerId', type: ABIDataTypes.UINT256 },
            { name: 'operator', type: ABIDataTypes.ADDRESS },
        ],
        type: BitcoinAbiTypes.Event,
    },
    {
        name: 'BrokerActivated',
        values: [
            { name: 'brokerId', type: ABIDataTypes.UINT256 },
            { name: 'operator', type: ABIDataTypes.ADDRESS },
        ],
        type: BitcoinAbiTypes.Event,
    },
];

export const BrokerRegistryAbi = [
    {
        name: 'registerBroker',
        inputs: [
            { name: 'operator', type: ABIDataTypes.ADDRESS },
            { name: 'requestsContract', type: ABIDataTypes.ADDRESS },
            { name: 'encryptionPubkey', type: ABIDataTypes.STRING },
            { name: 'region', type: ABIDataTypes.STRING },
        ],
        outputs: [{ name: 'brokerId', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'updateEncryptionPubkey',
        inputs: [{ name: 'encryptionPubkey', type: ABIDataTypes.STRING }],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'updateRegion',
        inputs: [{ name: 'region', type: ABIDataTypes.STRING }],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'deactivate',
        inputs: [],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'activate',
        inputs: [],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'removeBroker',
        inputs: [{ name: 'brokerId', type: ABIDataTypes.UINT256 }],
        outputs: [],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'getBroker',
        inputs: [{ name: 'brokerId', type: ABIDataTypes.UINT256 }],
        outputs: [
            { name: 'operator', type: ABIDataTypes.ADDRESS },
            { name: 'requestsContract', type: ABIDataTypes.ADDRESS },
            { name: 'encryptionPubkey', type: ABIDataTypes.STRING },
            { name: 'region', type: ABIDataTypes.STRING },
            { name: 'active', type: ABIDataTypes.BOOL },
            { name: 'registeredAt', type: ABIDataTypes.UINT256 },
        ],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'getBrokerCount',
        inputs: [],
        outputs: [{ name: 'count', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'isOperator',
        inputs: [{ name: 'operator', type: ABIDataTypes.ADDRESS }],
        outputs: [{ name: 'isRegistered', type: ABIDataTypes.BOOL }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'getBrokerIdByOperator',
        inputs: [{ name: 'operator', type: ABIDataTypes.ADDRESS }],
        outputs: [{ name: 'brokerId', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function,
    },
    {
        name: 'getBrokerIdByRequestsContract',
        inputs: [{ name: 'requestsContract', type: ABIDataTypes.ADDRESS }],
        outputs: [{ name: 'brokerId', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function,
    },
    ...BrokerRegistryEvents,
    ...OP_NET_ABI,
];

export default BrokerRegistryAbi;
