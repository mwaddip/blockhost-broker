/**
 * Response delivery via OP_RETURN.
 *
 * Sends a single Bitcoin transaction with an OP_RETURN output containing
 * the encrypted allocation response. The client finds it by attempting
 * decryption — AES-GCM tag verification serves as authentication.
 *
 * OP_RETURN layout (80 bytes):
 *   [1 byte  version]
 *   [79 bytes encrypted payload]
 *
 * Encrypted payload (79 bytes):
 *   AES-256-GCM ciphertext (63 bytes) + tag (16 bytes)
 *   IV is derived deterministically from the ECDH shared secret.
 *
 * Plaintext layout (63 bytes):
 *   [32 bytes broker WireGuard pubkey]
 *   [4  bytes broker endpoint IPv4]
 *   [2  bytes broker endpoint port BE]
 *   [1  byte  prefix mask length]
 *   [16 bytes prefix network (IPv6)]
 *   [8  bytes gateway host part (lower 64 bits of gateway IPv6)]
 *
 * The client establishes the tunnel with this data, then fetches
 * remaining config (dnsZone, etc.) over the tunnel.
 *
 * Encryption: ECDH(broker_ecies_priv, client_serverPubkey) → HKDF → AES-GCM.
 * Both sides can independently derive the same shared secret.
 */

import {
    AddressTypes,
    FundingTransaction,
    MLDSASecurityLevel,
    Mnemonic,
} from '@btc-vision/transaction';
import { opcodes, script, type Network, type Satoshi, type Script } from '@btc-vision/bitcoin';
import type { JSONRpcProvider } from 'opnet';
import {
    encryptCompact,
    serializeResponse,
    type ResponsePayload,
} from '../../../_shared/src/adapter-crypto.js';

const FRAME_VERSION = 0x01;
const AES_TAG_LEN = 16;

// ── OP_RETURN construction ──────────────────────────────────────────

function buildOpReturn(encrypted: Uint8Array): Uint8Array {
    const payload = new Uint8Array(1 + encrypted.length);
    payload[0] = FRAME_VERSION;
    payload.set(encrypted, 1);

    return script.compile([opcodes.OP_RETURN, payload]);
}

// ── Transaction delivery ────────────────────────────────────────────

export class ResponseDelivery {
    private wallet;
    private eciesPrivkey: Uint8Array;
    /** Change UTXO from the last unconfirmed delivery, used to chain txs. */
    private pendingChange: {
        transactionId: string;
        outputIndex: number;
        value: bigint;
        scriptPubKey: { hex: string; address: string };
    } | null = null;

    constructor(
        private provider: JSONRpcProvider,
        private network: Network,
        eciesPrivkeyHex: string,
        operatorMnemonic: string,
    ) {
        const hex = eciesPrivkeyHex.startsWith('0x')
            ? eciesPrivkeyHex.slice(2)
            : eciesPrivkeyHex;
        this.eciesPrivkey = Buffer.from(hex, 'hex');

        const mnemonic = new Mnemonic(
            operatorMnemonic,
            '',
            network,
            MLDSASecurityLevel.LEVEL2,
        );
        this.wallet = mnemonic.deriveOPWallet(AddressTypes.P2TR, 0);
    }

    get operatorAddress(): string {
        return this.wallet.p2tr;
    }

    async deliver(
        response: ResponsePayload,
        recipientServerPubkey: string,
    ): Promise<string> {
        // 1. Serialize and encrypt
        const binary = serializeResponse(response);
        const recipientPub = Buffer.from(recipientServerPubkey, 'hex');
        const encrypted = encryptCompact(binary, this.eciesPrivkey, recipientPub);

        const expectedLen = 63 + AES_TAG_LEN; // 79 bytes
        if (encrypted.length !== expectedLen) {
            throw new Error(
                `Unexpected encrypted length: ${encrypted.length} (expected ${expectedLen})`,
            );
        }

        console.log(
            `[delivery] Payload: ${binary.length}B plaintext → ${encrypted.length}B encrypted → ${1 + encrypted.length}B OP_RETURN`,
        );

        // 2. Build OP_RETURN script
        const opReturnScript = buildOpReturn(encrypted);

        // 3. Get UTXOs — use pending change from previous unconfirmed tx if available
        let utxos;
        if (this.pendingChange) {
            console.log(
                `[delivery] Using chained UTXO from previous tx: ${this.pendingChange.transactionId}:${this.pendingChange.outputIndex} (${this.pendingChange.value} sats)`,
            );
            utxos = [this.pendingChange];
            this.pendingChange = null;
        } else {
            utxos = await this.provider.utxoManager.getUTXOs({
                address: this.wallet.p2tr,
            });
        }

        if (utxos.length === 0) {
            throw new Error('No UTXOs available for response delivery');
        }

        const totalBalance = utxos.reduce((sum: bigint, u: any) => sum + u.value, 0n);
        console.log(
            `[delivery] Operator ${this.wallet.p2tr}: ${utxos.length} UTXO(s), ${totalBalance} sats`,
        );

        // 4. Build transaction: self-send with OP_RETURN
        const tx = new FundingTransaction({
            from: this.wallet.p2tr,
            to: this.wallet.p2tr,
            utxos,
            signer: this.wallet.keypair,
            mldsaSigner: this.wallet.mldsaKeypair,
            network: this.network,
            feeRate: 15,
            priorityFee: 0n,
            gasSatFee: 0n,
            amount: totalBalance,
            autoAdjustAmount: true,
            optionalOutputs: [{ value: 0n as Satoshi, script: opReturnScript as Script }],
        });

        // 5. Sign and broadcast
        const signed = await tx.signTransaction();
        const hex = signed.toHex();

        const result = await this.provider.sendRawTransaction(hex, false);
        if (!result.success) {
            throw new Error(
                `Broadcast failed: ${JSON.stringify(result)}`,
            );
        }

        const txid = result.result ?? signed.getId();
        console.log(`[delivery] Response broadcast: ${txid}`);

        // Track the change output for UTXO chaining
        for (let i = 0; i < signed.outs.length; i++) {
            const out = signed.outs[i];
            if (out.value > 0 && out.script[0] !== opcodes.OP_RETURN) {
                this.pendingChange = {
                    transactionId: txid,
                    outputIndex: i,
                    value: BigInt(out.value),
                    scriptPubKey: {
                        hex: Buffer.from(out.script).toString('hex'),
                        address: this.wallet.p2tr,
                    },
                };
                console.log(
                    `[delivery] Tracked change UTXO: ${txid}:${i} (${out.value} sats)`,
                );
                break;
            }
        }

        return txid;
    }
}
