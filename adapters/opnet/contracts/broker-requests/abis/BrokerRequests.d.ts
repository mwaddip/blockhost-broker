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
 * @description Represents the result of the setCapacityStatus function call.
 */
export type SetCapacityStatus = CallResult<{}, OPNetEvent<never>[]>;

/**
 * @description Represents the result of the getRequest function call.
 */
export type GetRequest = CallResult<
    {
        id: bigint;
        requester: Address;
        nftContract: Address;
        encryptedPayload: string;
        submittedAt: bigint;
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
 * @description Represents the result of the getRequestIdByNftContract function call.
 */
export type GetRequestIdByNftContract = CallResult<
    {
        requestId: bigint;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the getCapacityStatus function call.
 */
export type GetCapacityStatus = CallResult<
    {
        status: bigint;
    },
    OPNetEvent<never>[]
>;

// ------------------------------------------------------------------
// IBrokerRequests
// ------------------------------------------------------------------
export interface IBrokerRequests extends IOP_NETContract {
    submitRequest(nftContract: Address, encryptedPayload: string): Promise<SubmitRequest>;
    setCapacityStatus(status: bigint): Promise<SetCapacityStatus>;
    getRequest(requestId: bigint): Promise<GetRequest>;
    getRequestCount(): Promise<GetRequestCount>;
    getRequestIdByNftContract(nftContract: Address): Promise<GetRequestIdByNftContract>;
    getCapacityStatus(): Promise<GetCapacityStatus>;
}
