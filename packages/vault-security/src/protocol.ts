/**
 * Omni-Vault · protocol constants & wire types.
 *
 * Transport layout (plain HTTP is fine: confidentiality comes from the
 * AES-256-GCM session, authenticity from the Ed25519-pinned handshake).
 *
 *   POST /osh   handshake, plaintext JSON (Hello / Welcome, Welcome is signed)
 *   POST /orpc   session RPC: [12-byte GCM nonce][ciphertext+16-byte tag]
 */
export const PROTOCOL_VERSION = 1;
export const PATH_HANDSHAKE = "/osh";
export const PATH_RPC = "/orpc";
export const HANDSHAKE_FRESHNESS_MS = 300_000;

export class VaultError extends Error {
  readonly code: string;
  readonly httpStatus: number;
  constructor(code: string, message: string, httpStatus = 400) {
    super(`[${code}] ${message}`);
    this.name = "VaultError";
    this.code = code;
    this.httpStatus = httpStatus;
  }
}

export interface Hello {
  v: number;
  token: string;
  clientStaticPub: string;
  clientEphPub: string;
  nonceC: string;
  ts: number;
}

export interface Welcome {
  v: number;
  sid: string;
  serverEphPub: string;
  nonceS: string;
  sig: string;
  ts: number;
}

export interface RpcEnvelope {
  callId: string;
  fn: string;
  args: unknown[];
  proof?: string;
}

export interface RpcOk {
  ok: true;
  callId: string;
  result: unknown;
}

export interface RpcErr {
  ok: false;
  callId: string;
  err: { code: string; message: string };
}

export type RpcResponse = RpcOk | RpcErr;

export const canonical = (o: unknown): string => JSON.stringify(o);
