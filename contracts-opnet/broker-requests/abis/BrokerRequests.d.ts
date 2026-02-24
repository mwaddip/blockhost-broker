import { Address, AddressMap, ExtendedAddressMap, SchnorrSignature } from '@btc-vision/transaction';
import { CallResult, OPNetEvent, IOP_NETContract } from 'opnet';

// ------------------------------------------------------------------
// Event Definitions
// ------------------------------------------------------------------
export type RequestSubmittedEvent = {
    readonly requestId: bigint;
    readonly requester: Address;
    readonly nftContract: Address;
    readonly encryptedPayload: string;
};
export type ResponseSubmittedEvent = {
    readonly requestId: bigint;
    readonly status: bigint;
    readonly encryptedPayload: string;
};
export type RequestExpiredEvent = {
    readonly requestId: bigint;
};

// ------------------------------------------------------------------
// Call Results
// ------------------------------------------------------------------

/**
 * @description Represents the result of the submitRequest function call.
 */
export type SubmitRequest = CallResult<
    {
        requestId: bigint;
    },
    OPNetEvent<RequestSubmittedEvent>[]
>;

/**
 * @description Represents the result of the submitResponse function call.
 */
export type SubmitResponse = CallResult<{}, OPNetEvent<ResponseSubmittedEvent>[]>;

/**
 * @description Represents the result of the markExpired function call.
 */
export type MarkExpired = CallResult<{}, OPNetEvent<RequestExpiredEvent>[]>;

/**
 * @description Represents the result of the releaseAllocation function call.
 */
export type ReleaseAllocation = CallResult<{}, OPNetEvent<never>[]>;

/**
 * @description Represents the result of the setExpirationBlocks function call.
 */
export type SetExpirationBlocks = CallResult<{}, OPNetEvent<never>[]>;

/**
 * @description Represents the result of the setTotalCapacity function call.
 */
export type SetTotalCapacity = CallResult<{}, OPNetEvent<never>[]>;

/**
 * @description Represents the result of the getRequest function call.
 */
export type GetRequest = CallResult<
    {
        requester: Address;
        nftContract: Address;
        encryptedPayload: string;
        status: bigint;
        responsePayload: string;
        submittedAt: bigint;
        respondedAt: bigint;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the getRequestCount function call.
 */
export type GetRequestCount = CallResult<
    {
        count: bigint;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the getAvailableCapacity function call.
 */
export type GetAvailableCapacity = CallResult<
    {
        available: bigint;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the getRequestsByRequester function call.
 */
export type GetRequestsByRequester = CallResult<
    {
        requestIds: bigint;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the getRequestCountByRequester function call.
 */
export type GetRequestCountByRequester = CallResult<
    {
        count: bigint;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the getRequestIdByNftContract function call.
 */
export type GetRequestIdByNftContract = CallResult<
    {
        requestId: bigint;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the getExpirationBlocks function call.
 */
export type GetExpirationBlocks = CallResult<
    {
        blocks: bigint;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the getTotalCapacity function call.
 */
export type GetTotalCapacity = CallResult<
    {
        capacity: bigint;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the getActiveCount function call.
 */
export type GetActiveCount = CallResult<
    {
        count: bigint;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the getPendingCount function call.
 */
export type GetPendingCount = CallResult<
    {
        count: bigint;
    },
    OPNetEvent<never>[]
>;

// ------------------------------------------------------------------
// IBrokerRequests
// ------------------------------------------------------------------
export interface IBrokerRequests extends IOP_NETContract {
    submitRequest(nftContract: Address, encryptedPayload: string): Promise<SubmitRequest>;
    submitResponse(requestId: bigint, encryptedPayload: string): Promise<SubmitResponse>;
    markExpired(requestIds: bigint): Promise<MarkExpired>;
    releaseAllocation(nftContract: Address): Promise<ReleaseAllocation>;
    setExpirationBlocks(blocks: bigint): Promise<SetExpirationBlocks>;
    setTotalCapacity(capacity: bigint): Promise<SetTotalCapacity>;
    getRequest(requestId: bigint): Promise<GetRequest>;
    getRequestCount(): Promise<GetRequestCount>;
    getAvailableCapacity(): Promise<GetAvailableCapacity>;
    getRequestsByRequester(requester: Address, offset: bigint, limit: bigint): Promise<GetRequestsByRequester>;
    getRequestCountByRequester(requester: Address): Promise<GetRequestCountByRequester>;
    getRequestIdByNftContract(nftContract: Address): Promise<GetRequestIdByNftContract>;
    getExpirationBlocks(): Promise<GetExpirationBlocks>;
    getTotalCapacity(): Promise<GetTotalCapacity>;
    getActiveCount(): Promise<GetActiveCount>;
    getPendingCount(): Promise<GetPendingCount>;
}
