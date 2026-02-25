import {
    getContract,
    JSONRpcProvider,
    ABIDataTypes,
    BitcoinAbiTypes,
    OP_NET_ABI,
    type CallResult,
    type OPNetEvent,
    type IOP_NETContract,
} from 'opnet';
import { Address } from '@btc-vision/transaction';
import type { Network } from '@btc-vision/bitcoin';

// ── ABI (inline to avoid cross-project imports) ─────────────────────

const BrokerRequestsAbi = [
    {
        name: 'getRequestCount',
        inputs: [],
        outputs: [{ name: 'count', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function as BitcoinAbiTypes.Function,
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
        type: BitcoinAbiTypes.Function as BitcoinAbiTypes.Function,
    },
    {
        name: 'getRequestIdByNftContract',
        inputs: [{ name: 'nftContract', type: ABIDataTypes.ADDRESS }],
        outputs: [{ name: 'requestId', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function as BitcoinAbiTypes.Function,
    },
    {
        name: 'getCapacityStatus',
        inputs: [],
        outputs: [{ name: 'status', type: ABIDataTypes.UINT256 }],
        type: BitcoinAbiTypes.Function as BitcoinAbiTypes.Function,
    },
    {
        name: 'setCapacityStatus',
        inputs: [{ name: 'status', type: ABIDataTypes.UINT256 }],
        outputs: [],
        type: BitcoinAbiTypes.Function as BitcoinAbiTypes.Function,
    },
    ...OP_NET_ABI,
];

// ── Types ───────────────────────────────────────────────────────────

interface IBrokerRequests extends IOP_NETContract {
    getRequestCount(): Promise<CallResult<{ count: bigint }, OPNetEvent<never>[]>>;
    getRequest(requestId: bigint): Promise<
        CallResult<
            {
                id: bigint;
                requester: Address;
                nftContract: Address;
                encryptedPayload: string;
                submittedAt: bigint;
            },
            OPNetEvent<never>[]
        >
    >;
    getRequestIdByNftContract(
        nftContract: Address,
    ): Promise<CallResult<{ requestId: bigint }, OPNetEvent<never>[]>>;
    getCapacityStatus(): Promise<CallResult<{ status: bigint }, OPNetEvent<never>[]>>;
    setCapacityStatus(status: bigint): Promise<CallResult<{}, OPNetEvent<never>[]>>;
}

export interface OnChainRequest {
    id: bigint;
    requester: string; // 0x hex
    nftContract: string; // 0x hex
    encryptedPayload: string;
    submittedAt: bigint;
}

// ── Contract wrapper ────────────────────────────────────────────────

export class RequestsContract {
    private contract: IBrokerRequests;

    constructor(
        contractPubkey: string,
        provider: JSONRpcProvider,
        network: Network,
    ) {
        this.contract = getContract<IBrokerRequests>(
            contractPubkey,
            BrokerRequestsAbi,
            provider,
            network,
        );
    }

    async getRequestCount(): Promise<bigint> {
        const result = await this.contract.getRequestCount();
        if ('error' in result) {
            throw new Error(`getRequestCount failed: ${result.error}`);
        }
        return result.properties.count;
    }

    async getRequest(requestId: bigint): Promise<OnChainRequest> {
        const result = await this.contract.getRequest(requestId);
        if ('error' in result) {
            throw new Error(`getRequest(${requestId}) failed: ${result.error}`);
        }
        const p = result.properties;
        return {
            id: p.id,
            requester: p.requester.toHex(),
            nftContract: p.nftContract.toHex(),
            encryptedPayload: p.encryptedPayload,
            submittedAt: p.submittedAt,
        };
    }
}
