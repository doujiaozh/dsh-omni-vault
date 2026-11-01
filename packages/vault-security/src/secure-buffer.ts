/**
 * Omni-Vault · secure buffer.
 *
 * Session secrets live in a guarded buffer that is zero-filled on demand.
 * Used by the shell: the moment anti-debug or tamper detection trips
 * (or the RPC finishes / the process dies), the key material is wiped.
 */

export class SecureBuffer {
  private buf: Buffer | null;

  constructor(data: Buffer | Uint8Array) {
    this.buf = Buffer.from(data);
    registerWipe(this);
  }

  get value(): Buffer {
    if (this.buf === null) throw new Error("[VAULT] buffer already destroyed");
    return this.buf;
  }

  get destroyed(): boolean {
    return this.buf === null;
  }

  destroy(): void {
    if (this.buf !== null) {
      this.buf.fill(0);
      this.buf = null;
    }
  }
}

const live: Set<SecureBuffer> = new Set();

function registerWipe(sb: SecureBuffer): void {
  live.add(sb);
}

/** Wipe every live SecureBuffer. Call on trip / shutdown. */
export function wipeAllSecureBuffers(): number {
  let n = 0;
  for (const sb of live) {
    if (!sb.destroyed) {
      sb.destroy();
      n++;
    }
  }
  live.clear();
  return n;
}

for (const ev of ["exit", "SIGINT", "SIGTERM", "uncaughtException"] as const) {
  process.on(ev, () => wipeAllSecureBuffers());
}
