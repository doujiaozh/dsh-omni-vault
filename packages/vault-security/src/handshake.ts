/**
 * Omni-Vault · ECDH handshake.
 *
 * MITM defense (no PKI, no TLS required):
 *   1. Client sends a signed bearer token + ephemeral X25519 key.
 *   2. Server replies with its ephemeral X25519 key plus an Ed25519 signature
 *      over the full transcript, made with the server's long-term signing key.
 *   3. The shell *pins* the server's verify key at build time. An attacker who
 *      relays or rewrites the handshake cannot re-sign, so the client aborts
 *      and wipes its keys before any secret material is exchanged.
 * Session keys = HKDF(X25519(eph_client, eph_server), nonceC || nonceS).
 * Client possession of its static identity key is proven with an HMAC over
 * the first RPC (key = HKDF(X25519(client_static, server_static))).
 */
import {
  b64,
  x25519Generate,
  x25519FromPrivate,
  x25519FromPublic,
  x25519Shared,
  ed25519FromPublic,
  ed25519Sign,
  ed25519Verify,
  sha256,
  hkdf,
  hmacSha256,
  randomBytes,
  safeEqual,
  type X25519Pair,
} from "./crypto.ts";
import {
  PROTOCOL_VERSION,
  HANDSHAKE_FRESHNESS_MS,
  VaultError as VE,
  type Hello,
  type Welcome,
} from "./protocol.ts";
import { deriveSessionKeys, CipherSession, type SessionKeys } from "./session.ts";
import type { TokenClaims } from "./token.ts";
import type { KeyObject } from "node:crypto";

export interface ClientIdentity {
  privateDer: Buffer;
  publicDer: Buffer;
}

export interface ClientHandshakeInput {
  url: string;
  token: string;
  identity: ClientIdentity;
  serverStaticPubDer: Buffer;
  pinnedVerifyKeyDer: Buffer;
}

export interface ClientHandshakeResult {
  sid: string;
  session: CipherSession;
  /** HMAC key used to prove possession of the client identity on RPC #1. */
  proofKey: Buffer;
}

const PROOF_INFO = "omni-vault/v1/proof";

/** Symmetric transcript for the first-RPC identity proof. */
export function proofTranscript(sid: string, callId: string): string {
  return `omni-vault/proof/${sid}/${callId}`;
}

export function makeProof(proofKey: Buffer, sid: string, callId: string): string {
  return hmacSha256(proofKey, proofTranscript(sid, callId)).toString("hex");
}

export async function clientHandshake(input: ClientHandshakeInput): Promise<ClientHandshakeResult> {
  const { postJson } = await import("./http-util.ts");
  const eph = x25519Generate();
  const nonceC = randomBytes(16);

  const hello: Hello = {
    v: PROTOCOL_VERSION,
    token: input.token,
    clientStaticPub: b64.enc(input.identity.publicDer),
    clientEphPub: b64.enc(eph.publicDer),
    nonceC: b64.enc(nonceC),
    ts: Date.now(),
  };

  const welcome = await postJson<Welcome>(input.url.replace(/\/$/, "") + "/osh", hello);
  if (welcome.v !== PROTOCOL_VERSION) throw new VE("E_VERSION", "protocol version mismatch");
  if (!welcome.sid || !welcome.serverEphPub || !welcome.nonceS || !welcome.sig) {
    throw new VE("E_PROTOCOL", "malformed welcome");
  }
  const nonceS = b64.dec(welcome.nonceS);
  const serverEphPub = b64.dec(welcome.serverEphPub);

  const unsigned: Welcome = {
    v: welcome.v,
    sid: welcome.sid,
    serverEphPub: welcome.serverEphPub,
    nonceS: welcome.nonceS,
    ts: welcome.ts,
  };
  const transcript = sha256(JSON.stringify(hello) + "." + JSON.stringify(unsigned));
  if (!ed25519Verify(transcript, b64.dec(welcome.sig), ed25519FromPublic(input.pinnedVerifyKeyDer))) {
    throw new VE("E_PIN", "server signature verification failed — suspected MITM, aborting");
  }

  const shared = x25519Shared(eph.private, x25519FromPublic(serverEphPub));
  const keys: SessionKeys = deriveSessionKeys(shared, Buffer.concat([nonceC, nonceS]));
  const session = new CipherSession(keys, "client");

  const staticShared = x25519Shared(
    x25519FromPrivate(input.identity.privateDer),
    x25519FromPublic(input.serverStaticPubDer),
  );
  const proofKey = hkdf(staticShared, nonceS, PROOF_INFO, 32);

  return { sid: welcome.sid, session, proofKey };
}

/* ---------------------------------- server side --------------------------------- */

export interface ServerSessionState {
  sid: string;
  session: CipherSession;
  claims: TokenClaims;
  clientStaticPubDer: Buffer;
  proofExpected: Buffer;
  verified: boolean;
  createdAt: number;
}

export interface ServerHandshakeDeps {
  signPrivate: KeyObject;
  serverStaticPair: X25519Pair;
  verifyToken: (token: string) => TokenClaims | null;
  seenNonceC?: Set<string>;
}

export class HandshakeServer {
  private deps: ServerHandshakeDeps;
  private seenNonceC: Set<string>;

  constructor(deps: ServerHandshakeDeps) {
    this.deps = deps;
    this.seenNonceC = deps.seenNonceC ?? new Set();
  }

  handleHello(hello: Hello): { welcome: Welcome; state: ServerSessionState } {
    if (hello.v !== PROTOCOL_VERSION) throw new VE("E_VERSION", "protocol version mismatch");
    const now = Date.now();
    if (Math.abs(now - hello.ts) > HANDSHAKE_FRESHNESS_MS) {
      throw new VE("E_STALE", "handshake timestamp out of window");
    }
    const nonceCKey = b64.dec(hello.nonceC).toString("hex");
    if (this.seenNonceC.has(nonceCKey)) throw new VE("E_REPLAY", "handshake nonce reuse rejected");
    this.seenNonceC.add(nonceCKey);
    if (this.seenNonceC.size > 4096) this.seenNonceC.clear();

    const claims = this.deps.verifyToken(hello.token);
    if (!claims) throw new VE("E_TOKEN", "invalid or expired token");
    if (claims.pub !== hello.clientStaticPub) {
      throw new VE("E_IDENTITY", "token is not bound to this client identity");
    }

    const clientStaticPub = b64.dec(hello.clientStaticPub);
    const clientEphPub = b64.dec(hello.clientEphPub);

    const eph = x25519Generate();
    const nonceS = randomBytes(16);
    const sid = randomBytes(16).toString("hex");

    const welcome: Welcome = {
      v: PROTOCOL_VERSION,
      sid,
      serverEphPub: b64.enc(eph.publicDer),
      nonceS: b64.enc(nonceS),
      sig: "",
      ts: now,
    };
    // the transcript covers exactly the fields the client re-derives — no sig
    const unsigned = {
      v: welcome.v,
      sid: welcome.sid,
      serverEphPub: welcome.serverEphPub,
      nonceS: welcome.nonceS,
      ts: welcome.ts,
    };
    const transcript = sha256(JSON.stringify(hello) + "." + JSON.stringify(unsigned));
    welcome.sig = b64.enc(ed25519Sign(transcript, this.deps.signPrivate));

    const shared = x25519Shared(eph.private, x25519FromPublic(clientEphPub));
    const keys = deriveSessionKeys(shared, Buffer.concat([b64.dec(hello.nonceC), nonceS]));
    const session = new CipherSession(keys, "server");

    const staticShared = x25519Shared(this.deps.serverStaticPair.private, x25519FromPublic(clientStaticPub));
    const proofExpected = hkdf(staticShared, nonceS, PROOF_INFO, 32);

    const state: ServerSessionState = {
      sid,
      session,
      claims,
      clientStaticPubDer: clientStaticPub,
      proofExpected,
      verified: false,
      createdAt: now,
    };
    return { welcome, state };
  }

  /** Verifies the client's proof-of-possession attached to RPC #1. Throws on mismatch. */
  verifyProof(state: ServerSessionState, proofHex: string, sid: string, callId: string): void {
    const expected = makeProof(state.proofExpected, sid, callId);
    if (!safeEqual(Buffer.from(proofHex, "hex"), Buffer.from(expected, "hex"))) {
      throw new VE("E_PROOF", "client identity proof failed — stolen token?");
    }
    state.verified = true;
  }
}

export { ed25519Verify };
