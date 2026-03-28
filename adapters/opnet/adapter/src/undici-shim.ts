// Shim for undici — maps to native fetch (Node 22+).
// The OPNet SDK uses undici for connection pooling which isn't needed
// for the broker client's handful of RPC calls.
export const fetch = globalThis.fetch;
export class Agent {
    constructor(_opts?: unknown) {}
    async close() {}
}
