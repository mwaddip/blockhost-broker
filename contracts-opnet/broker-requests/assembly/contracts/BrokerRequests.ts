import { u256 } from '@btc-vision/as-bignum/assembly';
import {
    Address,
    ADDRESS_BYTE_LENGTH,
    Blockchain,
    BytesWriter,
    Calldata,
    encodeSelector,
    NetEvent,
    Revert,
    SafeMath,
    StoredString,
    StoredU256,
    U256_BYTE_LENGTH,
} from '@btc-vision/btc-runtime/runtime';
import { EMPTY_POINTER } from '@btc-vision/btc-runtime/runtime/math/bytes';
import { AddressMemoryMap } from '@btc-vision/btc-runtime/runtime/memory/AddressMemoryMap';
import { StoredMapU256 } from '@btc-vision/btc-runtime/runtime/storage/maps/StoredMapU256';
import {
    ReentrancyGuard,
    ReentrancyLevel,
} from '@btc-vision/btc-runtime/runtime';

// ── Constants ───────────────────────────────────────────────────────

const CAPACITY_AVAILABLE: u256 = u256.Zero;
const CAPACITY_LIMITED: u256 = u256.One;
const CAPACITY_CLOSED: u256 = u256.fromU32(2);

const DEPLOYER_SELECTOR: u32 = encodeSelector('deployer()');

// ── Storage Pointers ────────────────────────────────────────────────

const nextRequestIdPointer: u16 = Blockchain.nextPointer;
const requestRequesterPointer: u16 = Blockchain.nextPointer;
const requestNftContractPointer: u16 = Blockchain.nextPointer;
const requestEncryptedPayloadPointer: u16 = Blockchain.nextPointer;
const requestSubmittedAtPointer: u16 = Blockchain.nextPointer;
const nftContractToRequestIdPointer: u16 = Blockchain.nextPointer;
const capacityStatusPointer: u16 = Blockchain.nextPointer;

// ── Events ──────────────────────────────────────────────────────────

@final
class RequestSubmittedEvent extends NetEvent {
    public constructor(
        requestId: u256,
        requester: Address,
        nftContract: Address,
        encryptedPayload: string,
    ) {
        const payloadBytes: Uint8Array = Uint8Array.wrap(String.UTF8.encode(encryptedPayload));
        const data: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH +
                ADDRESS_BYTE_LENGTH +
                ADDRESS_BYTE_LENGTH +
                4 + payloadBytes.length,
        );
        data.writeU256(requestId);
        data.writeAddress(requester);
        data.writeAddress(nftContract);
        data.writeStringWithLength(encryptedPayload);
        super('RequestSubmitted', data);
    }
}

// ── Contract ────────────────────────────────────────────────────────

@final
export class BrokerRequests extends ReentrancyGuard {
    protected readonly reentrancyLevel: ReentrancyLevel = ReentrancyLevel.STANDARD;

    private readonly nextRequestId: StoredU256;
    private readonly requestRequesterMap: StoredMapU256;
    private readonly requestNftContractMap: StoredMapU256;
    private readonly requestSubmittedAtMap: StoredMapU256;
    private readonly nftContractToRequestId: AddressMemoryMap;
    private readonly capacityStatus: StoredU256;

    public constructor() {
        super();
        this.nextRequestId = new StoredU256(nextRequestIdPointer, EMPTY_POINTER);
        this.requestRequesterMap = new StoredMapU256(requestRequesterPointer);
        this.requestNftContractMap = new StoredMapU256(requestNftContractPointer);
        this.requestSubmittedAtMap = new StoredMapU256(requestSubmittedAtPointer);
        this.nftContractToRequestId = new AddressMemoryMap(nftContractToRequestIdPointer);
        this.capacityStatus = new StoredU256(capacityStatusPointer, EMPTY_POINTER);
    }

    public override onDeployment(calldata: Calldata): void {
        super.onDeployment(calldata);
        this.nextRequestId.value = u256.One;
        this.capacityStatus.value = CAPACITY_AVAILABLE;
    }

    protected override isSelectorExcluded(selector: u32): boolean {
        if (selector === encodeSelector('getRequest(uint256)')) return true;
        if (selector === encodeSelector('getRequestCount()')) return true;
        if (selector === encodeSelector('getRequestIdByNftContract(address)')) return true;
        if (selector === encodeSelector('getCapacityStatus()')) return true;

        return super.isSelectorExcluded(selector);
    }

    // ── Submit Request ──────────────────────────────────────────────

    @method(
        { name: 'nftContract', type: ABIDataTypes.ADDRESS },
        { name: 'encryptedPayload', type: ABIDataTypes.STRING },
    )
    @returns({ name: 'requestId', type: ABIDataTypes.UINT256 })
    @emit('RequestSubmitted')
    public submitRequest(calldata: Calldata): BytesWriter {
        const nftContract: Address = calldata.readAddress();
        const encryptedPayload: string = calldata.readStringWithLength();

        if (nftContract === Address.zero()) throw new Revert('Invalid NFT contract address');
        if (encryptedPayload.length === 0) throw new Revert('Empty payload');

        // Cross-contract call: verify caller owns the NFT contract
        const deployer: Address = this.queryDeployer(nftContract);
        if (deployer !== Blockchain.tx.sender) {
            throw new Revert('Sender does not own NFT contract');
        }

        // Create new request (overwrites existing mapping for same NFT)
        const requestId: u256 = this.nextRequestId.value;
        this.requireSafeU64(requestId);
        const requestIndex: u64 = requestId.toU64();
        const sender: Address = Blockchain.tx.sender;

        this.requestRequesterMap.set(requestId, u256.fromUint8ArrayBE(sender));
        this.requestNftContractMap.set(requestId, u256.fromUint8ArrayBE(nftContract));

        const payloadStore = new StoredString(requestEncryptedPayloadPointer, requestIndex);
        payloadStore.value = encryptedPayload;

        this.requestSubmittedAtMap.set(requestId, u256.fromU64(Blockchain.block.number));

        // Update NFT contract → request ID mapping (overwrites previous)
        this.nftContractToRequestId.set(nftContract, requestId);

        this.nextRequestId.value = SafeMath.add(requestId, u256.One);

        this.emitEvent(new RequestSubmittedEvent(requestId, sender, nftContract, encryptedPayload));

        const writer: BytesWriter = new BytesWriter(U256_BYTE_LENGTH);
        writer.writeU256(requestId);
        return writer;
    }

    // ── Capacity Status ─────────────────────────────────────────────

    @method({ name: 'status', type: ABIDataTypes.UINT256 })
    public setCapacityStatus(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const status: u256 = calldata.readU256();
        if (status > CAPACITY_CLOSED) throw new Revert('Invalid status');

        this.capacityStatus.value = status;
        return new BytesWriter(0);
    }

    // ── View Functions ──────────────────────────────────────────────

    @method({ name: 'requestId', type: ABIDataTypes.UINT256 })
    @returns(
        { name: 'id', type: ABIDataTypes.UINT256 },
        { name: 'requester', type: ABIDataTypes.ADDRESS },
        { name: 'nftContract', type: ABIDataTypes.ADDRESS },
        { name: 'encryptedPayload', type: ABIDataTypes.STRING },
        { name: 'submittedAt', type: ABIDataTypes.UINT256 },
    )
    public getRequest(calldata: Calldata): BytesWriter {
        const requestId: u256 = calldata.readU256();
        this.requireValidRequest(requestId);
        this.requireSafeU64(requestId);

        const requestIndex: u64 = requestId.toU64();

        const requesterU256: u256 = this.requestRequesterMap.get(requestId);
        const nftContractU256: u256 = this.requestNftContractMap.get(requestId);

        const payloadStore = new StoredString(requestEncryptedPayloadPointer, requestIndex);
        const encryptedPayload: string = payloadStore.value;

        const submittedAt: u256 = this.requestSubmittedAtMap.get(requestId);

        const writer: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH +
                ADDRESS_BYTE_LENGTH +
                ADDRESS_BYTE_LENGTH +
                4 + encryptedPayload.length +
                U256_BYTE_LENGTH,
        );
        writer.writeU256(requestId);
        writer.writeAddress(this.u256ToAddress(requesterU256));
        writer.writeAddress(this.u256ToAddress(nftContractU256));
        writer.writeStringWithLength(encryptedPayload);
        writer.writeU256(submittedAt);
        return writer;
    }

    @method()
    @returns({ name: 'count', type: ABIDataTypes.UINT256 })
    public getRequestCount(_calldata: Calldata): BytesWriter {
        const count: u256 = SafeMath.sub(this.nextRequestId.value, u256.One);
        const writer: BytesWriter = new BytesWriter(U256_BYTE_LENGTH);
        writer.writeU256(count);
        return writer;
    }

    @method({ name: 'nftContract', type: ABIDataTypes.ADDRESS })
    @returns({ name: 'requestId', type: ABIDataTypes.UINT256 })
    public getRequestIdByNftContract(calldata: Calldata): BytesWriter {
        const nftContract: Address = calldata.readAddress();
        const requestId: u256 = this.nftContractToRequestId.get(nftContract);
        const writer: BytesWriter = new BytesWriter(U256_BYTE_LENGTH);
        writer.writeU256(requestId);
        return writer;
    }

    @method()
    @returns({ name: 'status', type: ABIDataTypes.UINT256 })
    public getCapacityStatus(_calldata: Calldata): BytesWriter {
        const writer: BytesWriter = new BytesWriter(U256_BYTE_LENGTH);
        writer.writeU256(this.capacityStatus.value);
        return writer;
    }

    // ── Internal ────────────────────────────────────────────────────

    private requireValidRequest(requestId: u256): void {
        if (requestId.isZero() || requestId >= this.nextRequestId.value) {
            throw new Revert('Invalid request ID');
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

    private queryDeployer(contractAddress: Address): Address {
        const writer = new BytesWriter(4);
        writer.writeSelector(DEPLOYER_SELECTOR);

        const result = Blockchain.call(contractAddress, writer, true);
        return result.data.readAddress();
    }
}
