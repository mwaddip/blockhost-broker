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
import { StoredU256Array } from '@btc-vision/btc-runtime/runtime/storage/arrays/StoredU256Array';
import {
    ReentrancyGuard,
    ReentrancyLevel,
} from '@btc-vision/btc-runtime/runtime';

// ── Constants ───────────────────────────────────────────────────────

const BLOCKS_PER_DAY: u64 = 144;
const DEFAULT_EXPIRATION_BLOCKS: u64 = 144; // ~24 hours
const MIN_EXPIRATION_BLOCKS: u64 = 6; // ~1 hour
const MAX_EXPIRATION_BLOCKS: u64 = 1008; // ~7 days
const MAX_BATCH: u32 = 50;

const STATUS_PENDING: u256 = u256.Zero;
const STATUS_APPROVED: u256 = u256.One;
const STATUS_REJECTED: u256 = u256.fromU32(2); // Unused — silent rejection via expiry
const STATUS_EXPIRED: u256 = u256.fromU32(3);

const DEPLOYER_SELECTOR: u32 = encodeSelector('deployer()');

// ── Storage Pointers ────────────────────────────────────────────────

const nextRequestIdPointer: u16 = Blockchain.nextPointer;
const requestRequesterPointer: u16 = Blockchain.nextPointer;
const requestNftContractPointer: u16 = Blockchain.nextPointer;
const requestEncryptedPayloadPointer: u16 = Blockchain.nextPointer;
const requestStatusPointer: u16 = Blockchain.nextPointer;
const requestResponsePayloadPointer: u16 = Blockchain.nextPointer;
const requestSubmittedAtPointer: u16 = Blockchain.nextPointer;
const requestRespondedAtPointer: u16 = Blockchain.nextPointer;
const nftContractToRequestIdPointer: u16 = Blockchain.nextPointer;
const requesterToRequestIdsPointer: u16 = Blockchain.nextPointer;
const requestExpirationBlocksPointer: u16 = Blockchain.nextPointer;
const totalCapacityPointer: u16 = Blockchain.nextPointer;
const activeCountPointer: u16 = Blockchain.nextPointer;
const pendingCountPointer: u16 = Blockchain.nextPointer;

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

@final
class ResponseSubmittedEvent extends NetEvent {
    public constructor(requestId: u256, status: u256, encryptedPayload: string) {
        const payloadBytes: Uint8Array = Uint8Array.wrap(String.UTF8.encode(encryptedPayload));
        const data: BytesWriter = new BytesWriter(
            U256_BYTE_LENGTH + U256_BYTE_LENGTH + 4 + payloadBytes.length,
        );
        data.writeU256(requestId);
        data.writeU256(status);
        data.writeStringWithLength(encryptedPayload);
        super('ResponseSubmitted', data);
    }
}

@final
class RequestExpiredEvent extends NetEvent {
    public constructor(requestId: u256) {
        const data: BytesWriter = new BytesWriter(U256_BYTE_LENGTH);
        data.writeU256(requestId);
        super('RequestExpired', data);
    }
}

// ── Contract ────────────────────────────────────────────────────────

@final
export class BrokerRequests extends ReentrancyGuard {
    protected readonly reentrancyLevel: ReentrancyLevel = ReentrancyLevel.STANDARD;

    private readonly nextRequestId: StoredU256;
    private readonly requestRequesterMap: StoredMapU256;
    private readonly requestNftContractMap: StoredMapU256;
    private readonly requestStatusMap: StoredMapU256;
    private readonly requestSubmittedAtMap: StoredMapU256;
    private readonly requestRespondedAtMap: StoredMapU256;
    private readonly nftContractToRequestId: AddressMemoryMap;
    private readonly requestExpirationBlocks: StoredU256;
    private readonly totalCapacity: StoredU256;
    private readonly activeCount: StoredU256;
    private readonly pendingCount: StoredU256;
    private readonly requesterArrayCache: Map<string, StoredU256Array> = new Map();

    public constructor() {
        super();
        this.nextRequestId = new StoredU256(nextRequestIdPointer, EMPTY_POINTER);
        this.requestRequesterMap = new StoredMapU256(requestRequesterPointer);
        this.requestNftContractMap = new StoredMapU256(requestNftContractPointer);
        this.requestStatusMap = new StoredMapU256(requestStatusPointer);
        this.requestSubmittedAtMap = new StoredMapU256(requestSubmittedAtPointer);
        this.requestRespondedAtMap = new StoredMapU256(requestRespondedAtPointer);
        this.nftContractToRequestId = new AddressMemoryMap(nftContractToRequestIdPointer);
        this.requestExpirationBlocks = new StoredU256(requestExpirationBlocksPointer, EMPTY_POINTER);
        this.totalCapacity = new StoredU256(totalCapacityPointer, EMPTY_POINTER);
        this.activeCount = new StoredU256(activeCountPointer, EMPTY_POINTER);
        this.pendingCount = new StoredU256(pendingCountPointer, EMPTY_POINTER);
    }

    public override onDeployment(calldata: Calldata): void {
        super.onDeployment(calldata);
        this.nextRequestId.value = u256.One;
        this.requestExpirationBlocks.value = u256.fromU64(DEFAULT_EXPIRATION_BLOCKS);
        this.totalCapacity.value = u256.Zero; // unlimited
        this.activeCount.value = u256.Zero;
        this.pendingCount.value = u256.Zero;
    }

    protected override isSelectorExcluded(selector: u32): boolean {
        if (selector === encodeSelector('getRequest(uint256)')) return true;
        if (selector === encodeSelector('getRequestCount()')) return true;
        if (selector === encodeSelector('getAvailableCapacity()')) return true;
        if (selector === encodeSelector('getRequestsByRequester(address,uint256,uint256)')) return true;
        if (selector === encodeSelector('getRequestCountByRequester(address)')) return true;
        if (selector === encodeSelector('getRequestIdByNftContract(address)')) return true;
        if (selector === encodeSelector('getExpirationBlocks()')) return true;
        if (selector === encodeSelector('getTotalCapacity()')) return true;
        if (selector === encodeSelector('getActiveCount()')) return true;
        if (selector === encodeSelector('getPendingCount()')) return true;

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
        // Calls deployer() on the target — if it fails, contract doesn't exist or isn't OPNet
        const deployer: Address = this.queryDeployer(nftContract);
        if (deployer !== Blockchain.tx.sender) {
            throw new Revert('Sender does not own NFT contract');
        }

        // Handle overwrite if existing request exists for this NFT contract
        const existingId: u256 = this.nftContractToRequestId.get(nftContract);
        if (!existingId.isZero()) {
            const oldStatus: u256 = this.requestStatusMap.get(existingId);
            if (oldStatus == STATUS_PENDING) {
                this.pendingCount.value = SafeMath.sub(this.pendingCount.value, u256.One);
            } else if (oldStatus == STATUS_APPROVED) {
                this.activeCount.value = SafeMath.sub(this.activeCount.value, u256.One);
            }
            this.requestStatusMap.set(existingId, STATUS_EXPIRED);
            this.requestRespondedAtMap.set(existingId, u256.fromU64(Blockchain.block.number));
        }

        // Create new request
        const requestId: u256 = this.nextRequestId.value;
        this.requireSafeU64(requestId);
        const requestIndex: u64 = requestId.toU64();
        const sender: Address = Blockchain.tx.sender;

        this.requestRequesterMap.set(requestId, u256.fromUint8ArrayBE(sender));
        this.requestNftContractMap.set(requestId, u256.fromUint8ArrayBE(nftContract));

        const payloadStore = new StoredString(requestEncryptedPayloadPointer, requestIndex);
        payloadStore.value = encryptedPayload;

        this.requestStatusMap.set(requestId, STATUS_PENDING);
        this.requestSubmittedAtMap.set(requestId, u256.fromU64(Blockchain.block.number));
        this.requestRespondedAtMap.set(requestId, u256.Zero);

        // Update mappings
        this.nftContractToRequestId.set(nftContract, requestId);

        const requesterArray = this.getRequesterArray(sender);
        requesterArray.push(requestId);
        requesterArray.save();

        this.pendingCount.value = SafeMath.add(this.pendingCount.value, u256.One);
        this.nextRequestId.value = SafeMath.add(requestId, u256.One);

        this.emitEvent(new RequestSubmittedEvent(requestId, sender, nftContract, encryptedPayload));

        const writer: BytesWriter = new BytesWriter(U256_BYTE_LENGTH);
        writer.writeU256(requestId);
        return writer;
    }

    // ── Submit Response ─────────────────────────────────────────────

    @method(
        { name: 'requestId', type: ABIDataTypes.UINT256 },
        { name: 'encryptedPayload', type: ABIDataTypes.STRING },
    )
    @emit('ResponseSubmitted')
    public submitResponse(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const requestId: u256 = calldata.readU256();
        const encryptedPayload: string = calldata.readStringWithLength();

        this.requireValidRequest(requestId);
        this.requireSafeU64(requestId);

        const status: u256 = this.requestStatusMap.get(requestId);
        if (status != STATUS_PENDING) throw new Revert('Request not pending');

        // Check not expired
        const submittedAt: u256 = this.requestSubmittedAtMap.get(requestId);
        const expirationBlocks: u256 = this.requestExpirationBlocks.value;
        const deadline: u256 = SafeMath.add(submittedAt, expirationBlocks);
        const currentBlock: u256 = u256.fromU64(Blockchain.block.number);
        if (currentBlock > deadline) throw new Revert('Request expired');

        if (encryptedPayload.length === 0) throw new Revert('Response requires payload');

        // Check not superseded (mapping still points to this request)
        const nftContractU256: u256 = this.requestNftContractMap.get(requestId);
        const nftContract: Address = this.u256ToAddress(nftContractU256);
        const currentMappedId: u256 = this.nftContractToRequestId.get(nftContract);
        if (currentMappedId != requestId) throw new Revert('Request superseded');

        // Approve
        this.requestStatusMap.set(requestId, STATUS_APPROVED);
        const requestIndex: u64 = requestId.toU64();
        const responseStore = new StoredString(requestResponsePayloadPointer, requestIndex);
        responseStore.value = encryptedPayload;
        this.requestRespondedAtMap.set(requestId, currentBlock);

        this.pendingCount.value = SafeMath.sub(this.pendingCount.value, u256.One);
        this.activeCount.value = SafeMath.add(this.activeCount.value, u256.One);

        this.emitEvent(new ResponseSubmittedEvent(requestId, STATUS_APPROVED, encryptedPayload));

        return new BytesWriter(0);
    }

    // ── Mark Expired ────────────────────────────────────────────────

    @method({ name: 'requestIds', type: ABIDataTypes.UINT256 })
    @emit('RequestExpired')
    public markExpired(calldata: Calldata): BytesWriter {
        const count: u32 = calldata.readU32();
        if (count > MAX_BATCH) throw new Revert('Batch too large');

        const currentBlock: u256 = u256.fromU64(Blockchain.block.number);
        const expirationBlocks: u256 = this.requestExpirationBlocks.value;
        const maxRequestId: u256 = this.nextRequestId.value;

        for (let i: u32 = 0; i < count; i++) {
            const requestId: u256 = calldata.readU256();
            if (requestId.isZero() || requestId >= maxRequestId) continue;

            const status: u256 = this.requestStatusMap.get(requestId);
            if (status != STATUS_PENDING) continue;

            const submittedAt: u256 = this.requestSubmittedAtMap.get(requestId);
            const deadline: u256 = SafeMath.add(submittedAt, expirationBlocks);
            if (currentBlock <= deadline) continue;

            // Expire it
            this.requestStatusMap.set(requestId, STATUS_EXPIRED);
            this.requestRespondedAtMap.set(requestId, currentBlock);
            this.pendingCount.value = SafeMath.sub(this.pendingCount.value, u256.One);

            // Clear NFT contract mapping so they can resubmit
            const nftContractU256: u256 = this.requestNftContractMap.get(requestId);
            if (!nftContractU256.isZero()) {
                const nftContract: Address = this.u256ToAddress(nftContractU256);
                // Only clear if mapping still points to this request
                const mappedId: u256 = this.nftContractToRequestId.get(nftContract);
                if (mappedId == requestId) {
                    this.nftContractToRequestId.set(nftContract, u256.Zero);
                }
            }

            this.emitEvent(new RequestExpiredEvent(requestId));
        }

        return new BytesWriter(0);
    }

    // ── Release Allocation ──────────────────────────────────────────

    @method({ name: 'nftContract', type: ABIDataTypes.ADDRESS })
    public releaseAllocation(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const nftContract: Address = calldata.readAddress();
        const requestId: u256 = this.nftContractToRequestId.get(nftContract);
        if (requestId.isZero()) throw new Revert('No allocation for this NFT contract');

        const status: u256 = this.requestStatusMap.get(requestId);
        if (status == STATUS_APPROVED) {
            this.activeCount.value = SafeMath.sub(this.activeCount.value, u256.One);
        } else if (status == STATUS_PENDING) {
            this.pendingCount.value = SafeMath.sub(this.pendingCount.value, u256.One);
        }

        this.nftContractToRequestId.set(nftContract, u256.Zero);

        return new BytesWriter(0);
    }

    // ── Configuration ───────────────────────────────────────────────

    @method({ name: 'blocks', type: ABIDataTypes.UINT256 })
    public setExpirationBlocks(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        const blocks: u256 = calldata.readU256();
        if (blocks < u256.fromU64(MIN_EXPIRATION_BLOCKS)) {
            throw new Revert('Expiration too short');
        }
        if (blocks > u256.fromU64(MAX_EXPIRATION_BLOCKS)) {
            throw new Revert('Expiration too long');
        }

        this.requestExpirationBlocks.value = blocks;
        return new BytesWriter(0);
    }

    @method({ name: 'capacity', type: ABIDataTypes.UINT256 })
    public setTotalCapacity(calldata: Calldata): BytesWriter {
        this.onlyDeployer(Blockchain.tx.sender);

        this.totalCapacity.value = calldata.readU256();
        return new BytesWriter(0);
    }

    // ── View Functions ──────────────────────────────────────────────

    @method({ name: 'requestId', type: ABIDataTypes.UINT256 })
    @returns(
        { name: 'requester', type: ABIDataTypes.ADDRESS },
        { name: 'nftContract', type: ABIDataTypes.ADDRESS },
        { name: 'encryptedPayload', type: ABIDataTypes.STRING },
        { name: 'status', type: ABIDataTypes.UINT256 },
        { name: 'responsePayload', type: ABIDataTypes.STRING },
        { name: 'submittedAt', type: ABIDataTypes.UINT256 },
        { name: 'respondedAt', type: ABIDataTypes.UINT256 },
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

        const status: u256 = this.requestStatusMap.get(requestId);

        const responseStore = new StoredString(requestResponsePayloadPointer, requestIndex);
        const responsePayload: string = responseStore.value;

        const submittedAt: u256 = this.requestSubmittedAtMap.get(requestId);
        const respondedAt: u256 = this.requestRespondedAtMap.get(requestId);

        const writer: BytesWriter = new BytesWriter(
            ADDRESS_BYTE_LENGTH +
                ADDRESS_BYTE_LENGTH +
                4 + encryptedPayload.length +
                U256_BYTE_LENGTH +
                4 + responsePayload.length +
                U256_BYTE_LENGTH +
                U256_BYTE_LENGTH,
        );
        writer.writeAddress(this.u256ToAddress(requesterU256));
        writer.writeAddress(this.u256ToAddress(nftContractU256));
        writer.writeStringWithLength(encryptedPayload);
        writer.writeU256(status);
        writer.writeStringWithLength(responsePayload);
        writer.writeU256(submittedAt);
        writer.writeU256(respondedAt);
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

    @method()
    @returns({ name: 'available', type: ABIDataTypes.UINT256 })
    public getAvailableCapacity(_calldata: Calldata): BytesWriter {
        const cap: u256 = this.totalCapacity.value;
        let available: u256;

        if (cap.isZero()) {
            available = u256.Max;
        } else {
            const used: u256 = SafeMath.add(this.activeCount.value, this.pendingCount.value);
            if (used >= cap) {
                available = u256.Zero;
            } else {
                available = SafeMath.sub(cap, used);
            }
        }

        const writer: BytesWriter = new BytesWriter(U256_BYTE_LENGTH);
        writer.writeU256(available);
        return writer;
    }

    @method(
        { name: 'requester', type: ABIDataTypes.ADDRESS },
        { name: 'offset', type: ABIDataTypes.UINT256 },
        { name: 'limit', type: ABIDataTypes.UINT256 },
    )
    @returns({ name: 'requestIds', type: ABIDataTypes.UINT256 })
    public getRequestsByRequester(calldata: Calldata): BytesWriter {
        const requester: Address = calldata.readAddress();
        const offset: u32 = calldata.readU256().toU32();
        const requestedLimit: u32 = calldata.readU256().toU32();

        const reqArray = this.getRequesterArray(requester);
        const total: u32 = reqArray.getLength();

        if (offset >= total) {
            const writer: BytesWriter = new BytesWriter(4);
            writer.writeU32(0);
            return writer;
        }

        const actualLimit: u32 = requestedLimit > MAX_BATCH ? MAX_BATCH : requestedLimit;
        const remaining: u32 = total - offset;
        const count: u32 = remaining < actualLimit ? remaining : actualLimit;

        const writer: BytesWriter = new BytesWriter(4 + count * 32);
        writer.writeU32(count);
        for (let i: u32 = 0; i < count; i++) {
            writer.writeU256(reqArray.get(offset + i));
        }
        return writer;
    }

    @method({ name: 'requester', type: ABIDataTypes.ADDRESS })
    @returns({ name: 'count', type: ABIDataTypes.UINT256 })
    public getRequestCountByRequester(calldata: Calldata): BytesWriter {
        const requester: Address = calldata.readAddress();
        const reqArray = this.getRequesterArray(requester);
        const count: u256 = u256.fromU32(reqArray.getLength());
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
    @returns({ name: 'blocks', type: ABIDataTypes.UINT256 })
    public getExpirationBlocks(_calldata: Calldata): BytesWriter {
        const writer: BytesWriter = new BytesWriter(U256_BYTE_LENGTH);
        writer.writeU256(this.requestExpirationBlocks.value);
        return writer;
    }

    @method()
    @returns({ name: 'capacity', type: ABIDataTypes.UINT256 })
    public getTotalCapacity(_calldata: Calldata): BytesWriter {
        const writer: BytesWriter = new BytesWriter(U256_BYTE_LENGTH);
        writer.writeU256(this.totalCapacity.value);
        return writer;
    }

    @method()
    @returns({ name: 'count', type: ABIDataTypes.UINT256 })
    public getActiveCount(_calldata: Calldata): BytesWriter {
        const writer: BytesWriter = new BytesWriter(U256_BYTE_LENGTH);
        writer.writeU256(this.activeCount.value);
        return writer;
    }

    @method()
    @returns({ name: 'count', type: ABIDataTypes.UINT256 })
    public getPendingCount(_calldata: Calldata): BytesWriter {
        const writer: BytesWriter = new BytesWriter(U256_BYTE_LENGTH);
        writer.writeU256(this.pendingCount.value);
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

    private addressToKey(addr: Address): string {
        const HEX: string = '0123456789abcdef';
        let result: string = '';
        for (let i: i32 = 0; i < 32; i++) {
            const b: u8 = unchecked(addr[i]);
            result += HEX.charAt((b >> 4) & 0xf);
            result += HEX.charAt(b & 0xf);
        }
        return result;
    }

    private getRequesterArray(requester: Address): StoredU256Array {
        const key = this.addressToKey(requester);
        if (!this.requesterArrayCache.has(key)) {
            const array = new StoredU256Array(requesterToRequestIdsPointer, requester.slice(0, 30));
            this.requesterArrayCache.set(key, array);
        }
        return this.requesterArrayCache.get(key);
    }

    private queryDeployer(contractAddress: Address): Address {
        const writer = new BytesWriter(4);
        writer.writeSelector(DEPLOYER_SELECTOR);

        const result = Blockchain.call(contractAddress, writer, true);
        return result.data.readAddress();
    }
}
