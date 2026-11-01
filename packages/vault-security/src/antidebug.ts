/**
 * Omni-Vault · anti-debug & self-integrity checks (shell side).
 *
 * On any trip the caller wipes its SecureBuffers and refuses to talk to the
 * cloud. The philosophy: we cannot stop someone from running the local shell
 * under a debugger — but we can guarantee the shell never hand-feeding the
 * cloud session to the instrumented process.
 *
 * Checks:
 *   1. process.execArgv / NODE_OPTIONS: --inspect, --inspect-brk, --debug*
 *   2. node:inspector.url() — set when a debugger session is attached
 *   3. timing heist — a tight loop measured against a startup baseline
 *   4. self-integrity — the shell's own file hash vs the build-time digest
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { url as inspectorUrl } from "node:inspector";

const DEBUG_ARG_RE = /(^|[\s=])(--inspect[^=]*|--debug(-brk|-port)?(=|\s|$)|inspect(=|\s|$))/i;

function tryInspectorUrl(): string | undefined {
  try {
    return inspectorUrl();
  } catch {
    return undefined;
  }
}

const baselineMs = timeProbe();

function timeProbe(): number {
  const t0 = process.hrtime.bigint();
  let sink = 0;
  for (let i = 0; i < 200_000; i++) sink += Math.sqrt(i) | 0;
  const t1 = process.hrtime.bigint();
  void sink;
  return Number(t1 - t0) / 1e6;
}

export interface AntiDebugResult {
  tripped: boolean;
  reasons: string[];
}

export interface IntegritySpec {
  /** Path of the file to verify (usually the shell itself). */
  path: string;
  /** sha256(hex) recorded at build time. */
  expected: string;
  /** The build-time slot inside the file that held the digest (marker string). */
  marker: string;
}

export function checkAntiDebug(integrity?: IntegritySpec): AntiDebugResult {
  const reasons: string[] = [];

  for (const arg of process.execArgv) {
    if (DEBUG_ARG_RE.test(arg)) reasons.push(`debugger flag in execArgv: ${arg}`);
  }
  const nodeOptions = process.env.NODE_OPTIONS ?? "";
  if (DEBUG_ARG_RE.test(nodeOptions)) reasons.push("inspector reachable via NODE_OPTIONS");
  if (process.env.INSP === "TRUE") reasons.push("INSP env probe");

  const url: string | undefined = tryInspectorUrl();
  if (url) reasons.push(`debugger attached: inspector.url() = ${url}`);

  const probe = timeProbe();
  if (baselineMs > 0.5 && probe > baselineMs * 8) {
    reasons.push(`timing heist: probe ${probe.toFixed(1)}ms vs baseline ${baselineMs.toFixed(1)}ms`);
  }

  if (integrity) {
    try {
      const src = readFileSync(integrity.path, "utf8");
      const restored = src.replace(integrity.expected, integrity.marker);
      const digest = createHash("sha256").update(restored, "utf8").digest("hex");
      if (digest !== integrity.expected) {
        reasons.push(`self-integrity violated (expected ${integrity.expected.slice(0, 12)}…)`);
      }
    } catch (e) {
      reasons.push(`self-integrity unreadable: ${(e as Error).message}`);
    }
  }

  return { tripped: reasons.length > 0, reasons };
}

/** Convenience hook: run the checks, wipe everything, exit nonzero. */
export function guardOrDie(options: {
  integrity?: IntegritySpec;
  onTrip?: (reasons: string[]) => void;
  exitCode?: number;
}): boolean {
  const res = checkAntiDebug(options.integrity);
  if (res.tripped) {
    options.onTrip?.(res.reasons);
    console.error("[VAULT] anti-debug / tamper trip:");
    for (const r of res.reasons) console.error(`[VAULT]   · ${r}`);
    console.error("[VAULT] keys wiped — refusing to communicate with the cloud vault.");
    import("./secure-buffer.ts").then(({ wipeAllSecureBuffers }) => {
      wipeAllSecureBuffers();
      process.exit(options.exitCode ?? 13);
    });
    return false;
  }
  return true;
}
