import { u256 } from '@btc-vision/as-bignum/assembly';
import {
    Address,
    ADDRESS_BYTE_LENGTH,
    Blockchain,
    BytesWriter,
    Calldata,
    NetEvent,
    OP_NET,
    Revert,
    SafeMath,
    StoredString,
    StoredU256,
    U256_BYTE_LENGTH,
} from '@btc-vision/btc-runtime/runtime';
import { EMPTY_POINTER } from '@btc-vision/btc-runtime/runtime/math/bytes';
import { AddressMemoryMap } from '@btc-vision/btc-runtime/runtime/memory/AddressMemoryMap';
import { StoredMapU256 } from '@btc-vision/btc-runtime/runtime/storage/maps/StoredMapU256';

// ── Storage Pointers ────────────────────────────────────────────────

const nextBrokerIdPointer: u16 = Blockchain.nextPointer;
const brokerOperatorPointer: u16 = Blockchain.nextPointer;
const brokerRequestsContractPointer: u16 = Blockchain.nextPointer;
const brokerEncryptionPubkeyPointer: u16 = Blockchain.nextPointer;
const brokerRegionPointer: u16 = Blockchain.nextPointer;
const brokerActivePointer: u16 = Blockchain.nextPointer;
const brokerCapacityPointer: u16 = Blockchain.nextPointer;
const brokerCurrentLoadPointer: u16 = Blockchain.nextPointer;
const brokerRegisteredAtPointer: u16 = Blockchain.nextPointer;
const operatorToBrokerIdPointer: u16 = Blockchain.nextPointer;
const requestsContractToBrokerIdPointer: u16 = Blockchain.nextPointer;

// ── Events ──────────────────────────────────────────────────────────

@final
class BrokerRegisteredEvent extends NetEvent {
    public constructor(brokerId: u256, operator: Address, requestsContract: Address, region: string) {
        const regionBytes: Uint8Array = Uint8Array.wrap(String.UTF8.encode(region));
        const data: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH + ADDRESS_BYTE_LENGTH + 4 + regionBytes.length,
        );
        data.writeU256(brokerId);
        data.writeAddress(operator);
        data.writeAddress(requestsContract);
        data.writeStringWithLength(region);
        super('BrokerRegistered', data);
    }
}

@final
class BrokerUpdatedEvent extends NetEvent {
    public constructor(brokerId: u256, operator: Address) {
        const data: BytesWriter = new BytesWriter(U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH);
        data.writeU256(brokerId);
        data.writeAddress(operator);
        super('BrokerUpdated', data);
    }
}

@final
class BrokerDeactivatedEvent extends NetEvent {
    public constructor(brokerId: u256, operator: Address) {
        const data: BytesWriter = new BytesWriter(U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH);
        data.writeU256(brokerId);
        data.writeAddress(operator);
        super('BrokerDeactivated', data);
    }
}

@final
class BrokerActivatedEvent extends NetEvent {
    public constructor(brokerId: u256, operator: Address) {
        const data: BytesWriter = new BytesWriter(U256_BYTE_LENGTH + ADDRESS_BYTE_LENGTH);
        data.writeU256(brokerId);
        data.writeAddress(operator);
        super('BrokerActivated', data);
    }
}

@final
class BrokerLoadUpdatedEvent extends NetEvent {
    public constructor(brokerId: u256, currentLoad: u256) {
        const data: BytesWriter = new BytesWriter(U256_BYTE_LENGTH + U256_BYTE_LENGTH);
        data.writeU256(brokerId);
        data.writeU256(currentLoad);
        super('BrokerLoadUpdated', data);
    }
}

// ── Contract ────────────────────────────────────────────────────────

@final
export class BrokerRegistry extends OP_NET {
    private readonly nextBrokerId: StoredU256;
    private readonly brokerOperatorMap: StoredMapU256;
    private readonly brokerRequestsContractMap: StoredMapU256;
    private readonly brokerActiveMap: StoredMapU256;
    private readonly brokerCapacityMap: StoredMapU256;
    private readonly brokerCurrentLoadMap: StoredMapU256;
    private readonly brokerRegisteredAtMap: StoredMapU256;
    private readonly operatorToBrokerId: AddressMemoryMap;
    private readonly requestsContractToBrokerId: AddressMemoryMap;

    public constructor() {
        super();
        this.nextBrokerId = new StoredU256(nextBrokerIdPointer, EMPTY_POINTER);
        this.brokerOperatorMap = new StoredMapU256(brokerOperatorPointer);
        this.brokerRequestsContractMap = new StoredMapU256(brokerRequestsContractPointer);
        this.brokerActiveMap = new StoredMapU256(brokerActivePointer);
        this.brokerCapacityMap = new StoredMapU256(brokerCapacityPointer);
        this.brokerCurrentLoadMap = new StoredMapU256(brokerCurrentLoadPointer);
        this.brokerRegisteredAtMap = new StoredMapU256(brokerRegisteredAtPointer);
        this.operatorToBrokerId = new AddressMemoryMap(operatorToBrokerIdPointer);
        this.requestsContractToBrokerId = new AddressMemoryMap(requestsContractToBrokerIdPointer);
    }

    public override onDeployment(calldata: Calldata): void {
        super.onDeployment(calldata);
        this.nextBrokerId.value = u256.One;
    }

    // ── Register ────────────────────────────────────────────────────

    @method(
        { name: 'operator', type: ABIDataTypes.ADDRESS },
        { name: 'requestsContract', type: ABIDataTypes.ADDRESS },
        { name: 'encryptionPubkey', type: ABIDataTypes.STRING },
        { name: 'region', type: ABIDataTypes.STRING },
        { name: 'capacity', type: ABIDataTypes.UINT256 },
    )
    @returns({ name: 'brokerId', type: ABIDataTypes.UINT256 })
    @emit('BrokerRegistered')
    public registerBroker(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const operator: Address = calldata.readAddress();
        const requestsContract: Address = calldata.readAddress();
        const encryptionPubkey: string = calldata.readStringWithLength();
        const region: string = calldata.readStringWithLength();
        const capacity: u256 = calldata.readU256();

        if (operator === Address.zero()) throw new Revert('Invalid operator address');
        if (requestsContract === Address.zero()) throw new Revert('Invalid requests contract');
        if (encryptionPubkey.length === 0) throw new Revert('Empty encryption pubkey');

        // Check requests contract not already registered
        const existingByContract: u256 = this.requestsContractToBrokerId.get(requestsContract);
        if (!existingByContract.isZero()) throw new Revert('Requests contract already registered');

        // Handle re-registration: deactivate old entry
        const existingByOperator: u256 = this.operatorToBrokerId.get(operator);
        if (!existingByOperator.isZero()) {
            this.brokerActiveMap.set(existingByOperator, u256.Zero);

            // Clear old requests contract mapping
            const oldRequestsContractU256: u256 = this.brokerRequestsContractMap.get(existingByOperator);
            if (!oldRequestsContractU256.isZero()) {
                const oldRequestsContract: Address = this.u256ToAddress(oldRequestsContractU256);
                this.requestsContractToBrokerId.set(oldRequestsContract, u256.Zero);
            }

            this.emitEvent(new BrokerDeactivatedEvent(existingByOperator, operator));
        }

        // Create new broker entry
        const brokerId: u256 = this.nextBrokerId.value;
        this.requireSafeU64(brokerId);

        const brokerIndex: u64 = brokerId.toU64();

        this.brokerOperatorMap.set(brokerId, u256.fromUint8ArrayBE(operator));
        this.brokerRequestsContractMap.set(brokerId, u256.fromUint8ArrayBE(requestsContract));

        const pubkeyStore = new StoredString(brokerEncryptionPubkeyPointer, brokerIndex);
        pubkeyStore.value = encryptionPubkey;

        const regionStore = new StoredString(brokerRegionPointer, brokerIndex);
        regionStore.value = region;

        this.brokerActiveMap.set(brokerId, u256.One);
        this.brokerCapacityMap.set(brokerId, capacity);
        this.brokerCurrentLoadMap.set(brokerId, u256.Zero);
        this.brokerRegisteredAtMap.set(brokerId, u256.fromU64(Blockchain.block.number));

        // Update mappings
        this.operatorToBrokerId.set(operator, brokerId);
        this.requestsContractToBrokerId.set(requestsContract, brokerId);

        this.nextBrokerId.value = SafeMath.add(brokerId, u256.One);

        this.emitEvent(new BrokerRegisteredEvent(brokerId, operator, requestsContract, region));

        const writer: BytesWriter = new BytesWriter(U256_BYTE_LENGTH);
        writer.writeU256(brokerId);
        return writer;
    }

    // ── Operator Updates ────────────────────────────────────────────

    @method({ name: 'encryptionPubkey', type: ABIDataTypes.STRING })
    @emit('BrokerUpdated')
    public updateEncryptionPubkey(calldata: Calldata): BytesWriter {
        const brokerId: u256 = this.requireOperator();
        const encryptionPubkey: string = calldata.readStringWithLength();

        if (encryptionPubkey.length === 0) throw new Revert('Empty encryption pubkey');

        this.requireSafeU64(brokerId);
        const pubkeyStore = new StoredString(brokerEncryptionPubkeyPointer, brokerId.toU64());
        pubkeyStore.value = encryptionPubkey;

        this.emitEvent(new BrokerUpdatedEvent(brokerId, Blockchain.tx.sender));
        return new BytesWriter(0);
    }

    @method({ name: 'region', type: ABIDataTypes.STRING })
    @emit('BrokerUpdated')
    public updateRegion(calldata: Calldata): BytesWriter {
        const brokerId: u256 = this.requireOperator();
        const region: string = calldata.readStringWithLength();

        if (region.length === 0) throw new Revert('Region cannot be empty');

        this.requireSafeU64(brokerId);
        const regionStore = new StoredString(brokerRegionPointer, brokerId.toU64());
        regionStore.value = region;

        this.emitEvent(new BrokerUpdatedEvent(brokerId, Blockchain.tx.sender));
        return new BytesWriter(0);
    }

    @method({ name: 'capacity', type: ABIDataTypes.UINT256 })
    @emit('BrokerUpdated')
    public updateCapacity(calldata: Calldata): BytesWriter {
        const brokerId: u256 = this.requireOperator();
        const capacity: u256 = calldata.readU256();

        this.brokerCapacityMap.set(brokerId, capacity);

        this.emitEvent(new BrokerUpdatedEvent(brokerId, Blockchain.tx.sender));
        return new BytesWriter(0);
    }

    @method({ name: 'currentLoad', type: ABIDataTypes.UINT256 })
    @emit('BrokerLoadUpdated')
    public updateLoad(calldata: Calldata): BytesWriter {
        const brokerId: u256 = this.requireOperator();
        const currentLoad: u256 = calldata.readU256();

        const capacity: u256 = this.brokerCapacityMap.get(brokerId);
        // 0 = unlimited
        if (!capacity.isZero() && currentLoad > capacity) {
            throw new Revert('Load exceeds capacity');
        }

        this.brokerCurrentLoadMap.set(brokerId, currentLoad);

        this.emitEvent(new BrokerLoadUpdatedEvent(brokerId, currentLoad));
        return new BytesWriter(0);
    }

    // ── Activation ──────────────────────────────────────────────────

    @method()
    @emit('BrokerDeactivated')
    public deactivate(_calldata: Calldata): BytesWriter {
        const brokerId: u256 = this.requireOperator();
        this.brokerActiveMap.set(brokerId, u256.Zero);

        this.emitEvent(new BrokerDeactivatedEvent(brokerId, Blockchain.tx.sender));
        return new BytesWriter(0);
    }

    @method()
    @emit('BrokerActivated')
    public activate(_calldata: Calldata): BytesWriter {
        const brokerId: u256 = this.requireOperator();
        this.brokerActiveMap.set(brokerId, u256.One);

        this.emitEvent(new BrokerActivatedEvent(brokerId, Blockchain.tx.sender));
        return new BytesWriter(0);
    }

    // ── Admin ───────────────────────────────────────────────────────

    @method({ name: 'brokerId', type: ABIDataTypes.UINT256 })
    @emit('BrokerDeactivated')
    public removeBroker(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const brokerId: u256 = calldata.readU256();
        this.requireValidBroker(brokerId);

        const operatorU256: u256 = this.brokerOperatorMap.get(brokerId);
        const requestsContractU256: u256 = this.brokerRequestsContractMap.get(brokerId);

        // Clear mappings
        if (!operatorU256.isZero()) {
            const operator: Address = this.u256ToAddress(operatorU256);
            this.operatorToBrokerId.set(operator, u256.Zero);
        }
        if (!requestsContractU256.isZero()) {
            const requestsContract: Address = this.u256ToAddress(requestsContractU256);
            this.requestsContractToBrokerId.set(requestsContract, u256.Zero);
        }

        // Deactivate and clear operator (preserve ID)
        this.brokerActiveMap.set(brokerId, u256.Zero);
        this.brokerOperatorMap.set(brokerId, u256.Zero);

        const removedBy: Address = Blockchain.tx.sender;
        this.emitEvent(new BrokerDeactivatedEvent(brokerId, removedBy));

        return new BytesWriter(0);
    }

    // ── View Functions ──────────────────────────────────────────────

    @method({ name: 'brokerId', type: ABIDataTypes.UINT256 })
    @returns(
        { name: 'operator', type: ABIDataTypes.ADDRESS },
        { name: 'requestsContract', type: ABIDataTypes.ADDRESS },
        { name: 'encryptionPubkey', type: ABIDataTypes.STRING },
        { name: 'region', type: ABIDataTypes.STRING },
        { name: 'active', type: ABIDataTypes.BOOL },
        { name: 'capacity', type: ABIDataTypes.UINT256 },
        { name: 'currentLoad', type: ABIDataTypes.UINT256 },
        { name: 'registeredAt', type: ABIDataTypes.UINT256 },
    )
    public getBroker(calldata: Calldata): BytesWriter {
        const brokerId: u256 = calldata.readU256();
        this.requireValidBroker(brokerId);
        this.requireSafeU64(brokerId);

        const brokerIndex: u64 = brokerId.toU64();

        const operatorU256: u256 = this.brokerOperatorMap.get(brokerId);
        const requestsContractU256: u256 = this.brokerRequestsContractMap.get(brokerId);
        const pubkeyStore = new StoredString(brokerEncryptionPubkeyPointer, brokerIndex);
        const encryptionPubkey: string = pubkeyStore.value;
        const regionStore = new StoredString(brokerRegionPointer, brokerIndex);
        const region: string = regionStore.value;
        const active: bool = !this.brokerActiveMap.get(brokerId).isZero();
        const capacity: u256 = this.brokerCapacityMap.get(brokerId);
        const currentLoad: u256 = this.brokerCurrentLoadMap.get(brokerId);
        const registeredAt: u256 = this.brokerRegisteredAtMap.get(brokerId);

        const writer: BytesWriter = new BytesWriter(
            ADDRESS_BYTE_LENGTH +
                ADDRESS_BYTE_LENGTH +
                4 + encryptionPubkey.length +
                4 + region.length +
                1 +
                U256_BYTE_LENGTH +
                U256_BYTE_LENGTH +
                U256_BYTE_LENGTH,
        );
        writer.writeAddress(this.u256ToAddress(operatorU256));
        writer.writeAddress(this.u256ToAddress(requestsContractU256));
        writer.writeStringWithLength(encryptionPubkey);
        writer.writeStringWithLength(region);
        writer.writeBoolean(active);
        writer.writeU256(capacity);
        writer.writeU256(currentLoad);
        writer.writeU256(registeredAt);
        return writer;
    }

    @method()
    @returns({ name: 'count', type: ABIDataTypes.UINT256 })
    public getBrokerCount(_calldata: Calldata): BytesWriter {
        const count: u256 = SafeMath.sub(this.nextBrokerId.value, u256.One);
        const writer: BytesWriter = new BytesWriter(U256_BYTE_LENGTH);
        writer.writeU256(count);
        return writer;
    }

    @method({ name: 'operator', type: ABIDataTypes.ADDRESS })
    @returns({ name: 'isRegistered', type: ABIDataTypes.BOOL })
    public isOperator(calldata: Calldata): BytesWriter {
        const operator: Address = calldata.readAddress();
        const brokerId: u256 = this.operatorToBrokerId.get(operator);

        const writer: BytesWriter = new BytesWriter(1);
        writer.writeBoolean(!brokerId.isZero());
        return writer;
    }

    @method({ name: 'operator', type: ABIDataTypes.ADDRESS })
    @returns({ name: 'brokerId', type: ABIDataTypes.UINT256 })
    public getBrokerIdByOperator(calldata: Calldata): BytesWriter {
        const operator: Address = calldata.readAddress();
        const brokerId: u256 = this.operatorToBrokerId.get(operator);

        const writer: BytesWriter = new BytesWriter(U256_BYTE_LENGTH);
        writer.writeU256(brokerId);
        return writer;
    }

    @method({ name: 'requestsContract', type: ABIDataTypes.ADDRESS })
    @returns({ name: 'brokerId', type: ABIDataTypes.UINT256 })
    public getBrokerIdByRequestsContract(calldata: Calldata): BytesWriter {
        const requestsContract: Address = calldata.readAddress();
        const brokerId: u256 = this.requestsContractToBrokerId.get(requestsContract);

        const writer: BytesWriter = new BytesWriter(U256_BYTE_LENGTH);
        writer.writeU256(brokerId);
        return writer;
    }

    // ── Internal ────────────────────────────────────────────────────

    private requireOperator(): u256 {
        const brokerId: u256 = this.operatorToBrokerId.get(Blockchain.tx.sender);
        if (brokerId.isZero()) throw new Revert('Not a registered operator');
        return brokerId;
    }

    private requireValidBroker(brokerId: u256): void {
        if (brokerId.isZero() || brokerId >= this.nextBrokerId.value) {
            throw new Revert('Invalid broker ID');
        }
    }

    private requireSafeU64(val: u256): void {
        if (val > u256.fromU64(u64.MAX_VALUE)) {
            throw new Revert('ID exceeds u64 range');
        }
    }

    private u256ToAddress(val: u256): Address {
        const addr: Address = new Address([]);
        const bytes: Uint8Array = val.toUint8Array(true);
        for (let i: i32 = 0; i < 32; i++) {
            addr[i] = bytes[i];
        }
        return addr;
    }
}
