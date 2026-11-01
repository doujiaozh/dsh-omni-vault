/**
 * Omni-Vault · AES-256-GCM session cipher.
 *
 * Per-direction 256-bit keys and 96-bit nonce bases are HKDF-derived from the
 * ECDH shared secret. The last 4 bytes of each nonce act as a strict
 * message counter, giving built-in replay protection (receiver rejects any
 * frame whose counter is not strictly greater than the last accepted one).
 */
import { aesGcmSeal, aesGcmOpen, hkdf } from "./crypto.ts";
import { VaultError as VE } from "./protocol.ts";

export interface SessionKeys {
  c2sKey: Buffer;
  s2cKey: Buffer;
  c2sIv: Buffer;
  s2cIv: Buffer;
}

export function deriveSessionKeys(shared: Buffer, salt: Buffer): SessionKeys {
  const c2sKey = hkdf(shared, salt, "omni-vault/v1/c2s/key", 32);
  const s2cKey = hkdf(shared, salt, "omni-vault/v1/s2c/key", 32);
  const c2sIv = hkdf(shared, salt, "omni-vault/v1/c2s/iv", 12);
  const s2cIv = hkdf(shared, salt, "omni-vault/v1/s2c/iv", 12);
  return { c2sKey, s2cKey, c2sIv, s2cIv };
}

const NONCE_PREFIX_LEN = 8;

export class CipherSession {
  readonly keys: SessionKeys;
  readonly role: "client" | "server";
  private sendSeq = 0;
  private recvSeq = -1; // strict increase, yet the very first frame (seq=0) is lawful
  private readonly sendKey: Buffer;
  private readonly sendIv: Buffer;
  private readonly recvKey: Buffer;
  private readonly recvIv: Buffer;

  constructor(keys: SessionKeys, role: "client" | "server") {
    this.keys = keys;
    this.role = role;
    if (role === "client") {
      this.sendKey = keys.c2sKey;
      this.sendIv = keys.c2sIv;
      this.recvKey = keys.s2cKey;
      this.recvIv = keys.s2cIv;
    } else {
      this.sendKey = keys.s2cKey;
      this.sendIv = keys.s2cIv;
      this.recvKey = keys.c2sKey;
      this.recvIv = keys.c2sIv;
    }
  }

  get sentFrames(): number {
    return this.sendSeq;
  }

  seal(plaintext: Buffer | Uint8Array): Buffer {
    const nonce = Buffer.from(this.sendIv);
    nonce.writeUInt32BE(this.sendSeq, NONCE_PREFIX_LEN);
    const ct = aesGcmSeal(this.sendKey, nonce, plaintext);
    this.sendSeq++;
    return Buffer.concat([nonce, ct]);
  }

  open(frame: Buffer | Uint8Array): Buffer {
    if (frame.length < 12 + 16) throw new VE("E_FRAME", "frame too short");
    const nonce = Buffer.from(frame.subarray(0, 12));
    const ct = frame.subarray(12);
    if (!nonce.subarray(0, NONCE_PREFIX_LEN).equals(this.recvIv.subarray(0, NONCE_PREFIX_LEN))) {
      throw new VE("E_REPLAY", "nonce prefix mismatch — wrong session or forged frame");
    }
    const seq = nonce.readUInt32BE(NONCE_PREFIX_LEN);
    if (seq <= this.recvSeq) {
      throw new VE("E_REPLAY", `counter regression (seq=${seq}, seen=${this.recvSeq}) — replay rejected`);
    }
    const pt = aesGcmOpen(this.recvKey, nonce, ct);
    this.recvSeq = seq;
    return pt;
  }
}
