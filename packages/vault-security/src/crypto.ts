/**
 * Omni-Vault · cryptographic primitives.
 *
 * Zero dependencies: everything is built on Node's builtin `node:crypto`.
 *   - X25519 ephemeral-static ECDH           (key agreement)
 *   - Ed25519                                (server signature / pinning)
 *   - HKDF-SHA256                            (key derivation)
 *   - AES-256-GCM                            (authenticated session encryption)
 */
import {
  randomBytes as nodeRandomBytes,
  generateKeyPairSync,
  createPublicKey,
  createPrivateKey,
  diffieHellman,
  createCipheriv,
  createDecipheriv,
  createHmac,
  createHash,
  sign as nodeSign,
  verify as nodeVerify,
  hkdfSync,
  timingSafeEqual,
  type KeyObject,
} from "node:crypto";

export const b64 = {
  enc: (b: Buffer | Uint8Array): string => Buffer.from(b).toString("base64"),
  dec: (s: string): Buffer => Buffer.from(s, "base64"),
};

export function randomBytes(n: number): Buffer {
  return nodeRandomBytes(n);
}

function asBuf(data: string | Buffer | Uint8Array): Buffer {
  return typeof data === "string" ? Buffer.from(data, "utf8") : Buffer.from(data);
}

export function sha256(data: string | Buffer | Uint8Array): Buffer {
  return createHash("sha256").update(asBuf(data)).digest();
}

export function sha256Hex(data: string | Buffer | Uint8Array): string {
  return sha256(data).toString("hex");
}

export function hmacSha256(key: string | Buffer | Uint8Array, data: string | Buffer | Uint8Array): Buffer {
  return createHmac("sha256", asBuf(key)).update(asBuf(data)).digest();
}

export function hkdf(
  ikm: string | Buffer | Uint8Array,
  salt: string | Buffer | Uint8Array,
  info: string | Buffer | Uint8Array,
  length = 32,
): Buffer {
  // Node 26's hkdfSync returns ArrayBuffer (not Buffer) — wrap it
  return Buffer.from(hkdfSync("sha256", asBuf(ikm), asBuf(salt), asBuf(info), length));
}

/* ----------------------------------- X25519 ----------------------------------- */

export interface X25519Pair {
  private: KeyObject;
  public: KeyObject;
  publicDer: Buffer;
  privateDer: Buffer;
}

function exportPair(privateKey: KeyObject, publicKey: KeyObject): X25519Pair {
  return {
    private: privateKey,
    public: publicKey,
    publicDer: publicKey.export({ type: "spki", format: "der" }) as Buffer,
    privateDer: privateKey.export({ type: "pkcs8", format: "der" }) as Buffer,
  };
}

export function x25519Generate(): X25519Pair {
  const { privateKey, publicKey } = generateKeyPairSync("x25519");
  return exportPair(privateKey, publicKey);
}

export function x25519FromPrivate(der: Buffer): KeyObject {
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

export function x25519FromPublic(der: Buffer): KeyObject {
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

export function x25519Shared(ourPriv: KeyObject, theirPub: KeyObject): Buffer {
  return diffieHellman({ privateKey: ourPriv, publicKey: theirPub });
}

/* ----------------------------------- Ed25519 ---------------------------------- */

export interface Ed25519Pair {
  private: KeyObject;
  public: KeyObject;
  publicDer: Buffer;
  privateDer: Buffer;
}

export function ed25519Generate(): Ed25519Pair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    private: privateKey,
    public: publicKey,
    publicDer: publicKey.export({ type: "spki", format: "der" }) as Buffer,
    privateDer: privateKey.export({ type: "pkcs8", format: "der" }) as Buffer,
  };
}

export function ed25519FromPrivate(der: Buffer): KeyObject {
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

export function ed25519FromPublic(der: Buffer): KeyObject {
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

export function ed25519Sign(data: string | Buffer | Uint8Array, priv: KeyObject): Buffer {
  return nodeSign(null, asBuf(data), priv);
}

export function ed25519Verify(
  data: string | Buffer | Uint8Array,
  sig: Buffer | Uint8Array,
  pub: KeyObject,
): boolean {
  try {
    return nodeVerify(null, asBuf(data), pub, asBuf(sig));
  } catch {
    return false;
  }
}

/* --------------------------------- AES-256-GCM -------------------------------- */

export function aesGcmSeal(
  key: Buffer,
  nonce: Buffer,
  plaintext: Buffer | Uint8Array,
  aad?: Buffer | Uint8Array,
): Buffer {
  const c = createCipheriv("aes-256-gcm", key, nonce);
  if (aad) c.setAAD(asBuf(aad));
  const out = [c.update(asBuf(plaintext)), c.final(), c.getAuthTag()];
  return Buffer.concat(out);
}

export function aesGcmOpen(
  key: Buffer,
  nonce: Buffer,
  frame: Buffer | Uint8Array,
  aad?: Buffer | Uint8Array,
): Buffer {
  const buf = asBuf(frame);
  const ct = buf.subarray(0, buf.length - 16);
  const tag = buf.subarray(buf.length - 16);
  const d = createDecipheriv("aes-256-gcm", key, nonce);
  d.setAuthTag(tag);
  if (aad) d.setAAD(asBuf(aad));
  return Buffer.concat([d.update(ct), d.final()]);
}

/* ---------------------------------- helpers ----------------------------------- */

export function safeEqual(a: Buffer | Uint8Array, b: Buffer | Uint8Array): boolean {
  const ba = asBuf(a);
  const bb = asBuf(b);
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

/** Shannon entropy in bits/byte — used by the reverser to prove "it's all ciphertext". */
export function shannonEntropy(data: Buffer | Uint8Array): number {
  const buf = asBuf(data);
  const counts = new Array(256).fill(0);
  for (let i = 0; i < buf.length; i++) counts[buf[i]]++;
  let h = 0;
  for (const c of counts) {
    if (c === 0) continue;
    const p = c / buf.length;
    h -= p * Math.log2(p);
  }
  return h;
}
