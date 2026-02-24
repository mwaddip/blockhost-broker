import { Address, AddressMap, ExtendedAddressMap, SchnorrSignature } from '@btc-vision/transaction';
import { CallResult, OPNetEvent, IOP_NETContract } from 'opnet';

// ------------------------------------------------------------------
// Event Definitions
// ------------------------------------------------------------------
export type BrokerRegisteredEvent = {
    readonly brokerId: bigint;
    readonly operator: Address;
    readonly requestsContract: Address;
    readonly region: string;
};
export type BrokerUpdatedEvent = {
    readonly brokerId: bigint;
    readonly operator: Address;
};
export type BrokerLoadUpdatedEvent = {
    readonly brokerId: bigint;
    readonly currentLoad: bigint;
};
export type BrokerDeactivatedEvent = {
    readonly brokerId: bigint;
    readonly operator: Address;
};
export type BrokerActivatedEvent = {
    readonly brokerId: bigint;
    readonly operator: Address;
};

// ------------------------------------------------------------------
// Call Results
// ------------------------------------------------------------------

/**
 * @description Represents the result of the registerBroker function call.
 */
export type RegisterBroker = CallResult<
    {
        brokerId: bigint;
    },
    OPNetEvent<BrokerRegisteredEvent>[]
>;

/**
 * @description Represents the result of the updateEncryptionPubkey function call.
 */
export type UpdateEncryptionPubkey = CallResult<{}, OPNetEvent<BrokerUpdatedEvent>[]>;

/**
 * @description Represents the result of the updateRegion function call.
 */
export type UpdateRegion = CallResult<{}, OPNetEvent<BrokerUpdatedEvent>[]>;

/**
 * @description Represents the result of the updateCapacity function call.
 */
export type UpdateCapacity = CallResult<{}, OPNetEvent<BrokerUpdatedEvent>[]>;

/**
 * @description Represents the result of the updateLoad function call.
 */
export type UpdateLoad = CallResult<{}, OPNetEvent<BrokerLoadUpdatedEvent>[]>;

/**
 * @description Represents the result of the deactivate function call.
 */
export type Deactivate = CallResult<{}, OPNetEvent<BrokerDeactivatedEvent>[]>;

/**
 * @description Represents the result of the activate function call.
 */
export type Activate = CallResult<{}, OPNetEvent<BrokerActivatedEvent>[]>;

/**
 * @description Represents the result of the removeBroker function call.
 */
export type RemoveBroker = CallResult<{}, OPNetEvent<BrokerDeactivatedEvent>[]>;

/**
 * @description Represents the result of the getBroker function call.
 */
export type GetBroker = CallResult<
    {
        operator: Address;
        requestsContract: Address;
        encryptionPubkey: string;
        region: string;
        active: boolean;
        capacity: bigint;
        currentLoad: bigint;
        registeredAt: bigint;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the getBrokerCount function call.
 */
export type GetBrokerCount = CallResult<
    {
        count: bigint;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the isOperator function call.
 */
export type IsOperator = CallResult<
    {
        isRegistered: boolean;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the getBrokerIdByOperator function call.
 */
export type GetBrokerIdByOperator = CallResult<
    {
        brokerId: bigint;
    },
    OPNetEvent<never>[]
>;

/**
 * @description Represents the result of the getBrokerIdByRequestsContract function call.
 */
export type GetBrokerIdByRequestsContract = CallResult<
    {
        brokerId: bigint;
    },
    OPNetEvent<never>[]
>;

// ------------------------------------------------------------------
// IBrokerRegistry
// ------------------------------------------------------------------
export interface IBrokerRegistry extends IOP_NETContract {
    registerBroker(
        operator: Address,
        requestsContract: Address,
        encryptionPubkey: string,
        region: string,
        capacity: bigint,
    ): Promise<RegisterBroker>;
    updateEncryptionPubkey(encryptionPubkey: string): Promise<UpdateEncryptionPubkey>;
    updateRegion(region: string): Promise<UpdateRegion>;
    updateCapacity(capacity: bigint): Promise<UpdateCapacity>;
    updateLoad(currentLoad: bigint): Promise<UpdateLoad>;
    deactivate(): Promise<Deactivate>;
    activate(): Promise<Activate>;
    removeBroker(brokerId: bigint): Promise<RemoveBroker>;
    getBroker(brokerId: bigint): Promise<GetBroker>;
    getBrokerCount(): Promise<GetBrokerCount>;
    isOperator(operator: Address): Promise<IsOperator>;
    getBrokerIdByOperator(operator: Address): Promise<GetBrokerIdByOperator>;
    getBrokerIdByRequestsContract(requestsContract: Address): Promise<GetBrokerIdByRequestsContract>;
}
