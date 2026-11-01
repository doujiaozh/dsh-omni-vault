/**
 * Omni-Vault · extraction orchestrator.
 *
 * Consumes the local sources, lifts the marked core logic into a cloud bundle,
 * emits the wasm delegates, provisions identities/tokens, and stamps the thin
 * shell with a build-time self-hash. The local program keeps nothing but
 * network calls, the handshake, and presentation.
 */
import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256Hex, b64 } from "../../vault-security/src/index.ts";
import { scanSource, hollowOut, type ScanReport } from "./scanner.ts";
import { emitPricingModule } from "./wasm.ts";
import { provisionServer, provisionClient } from "./provision.ts";

export interface WasmDelegateSpec {
  /** Cloud-facing function name. */
  fn: string;
  /** Exported wasm function name. */
  wasmExport: string;
  params: ("i32" | "i64")[];
  result: "i32" | "i64";
}

export interface ExtractInput {
  files: { path: string; src: string }[];
  outDir: string;
  /** Origin the shell dials, e.g. http://127.0.0.1:8787 */
  url: string;
  scope: string[];
  ttlMs: number;
  wasmDelegates?: WasmDelegateSpec[];
}

export interface ExtractionReport {
  buildTs: string;
  url: string;
  scope: string[];
  stats: {
    sourceBytes: number;
    liftedFnBytes: number;
    strTableEntries: number;
    wasmBytes: number;
    shellBytes: number;
    cloudBytes: number;
  };
  lifted: Array<{ file: string; functions: string[]; hollowed: string }>;
  wasmDelegates: WasmDelegateSpec[];
  shell: { path: string; sha256: string };
  declaration: string;
}

const DECLARATION = "Omni-Vault：只要不把代码交出去，就绝对没有人能逆向它。";

const here = dirname(fileURLToPath(import.meta.url));
const asset = (name: string) => join(here, name);
const securitySrc = resolve(here, "../../vault-security/src");

function toI64(v: unknown): bigint {
  if (typeof v === "bigint") return v;
  if (typeof v === "number") return BigInt(Math.trunc(v));
  if (typeof v === "string") return BigInt(v);
  throw new TypeError(`cannot coerce ${typeof v} to i64`);
}
function toI32(v: unknown): number {
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isFinite(n)) throw new TypeError("cannot coerce to i32");
  return Math.trunc(n);
}

/** Generate the wasm-delegates module bridging JSON RPC to the wasm core. */
function emitWasmDelegates(specs: WasmDelegateSpec[]): string {
  const entries = specs.map((s) => {
    const args = s.params.map((p, i) => (p === "i64" ? `toI64(args[${i}])` : `toI32(args[${i}])`)).join(", ");
    const ret = s.result === "i64"
      ? `const r = fn(${args}) as bigint;\n      return typeof r === "bigint" ? (r > BigInt(Number.MAX_SAFE_INTEGER) ? r.toString() : Number(r)) : r;`
      : `return fn(${args}) as number;`;
    return `  "${s.fn}": async (...args: unknown[]) => {
    const m = await mod();
    const fn = m.exports.${s.wasmExport} as (...a: never[]) => unknown;
    ${ret}
  },`;
  });
  return `/**
 * Omni-Vault · wasm delegates (generated).
 * The pricing core exists ONLY as wasm bytecode here — no JS source of the
 * algorithm is present anywhere in the generated bundle.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const bytes = readFileSync(fileURLToPath(new URL("./pricing.wasm", import.meta.url)));
let instance: WebAssembly.Instance | null = null;
async function mod(): Promise<WebAssembly.Instance> {
  if (!instance) {
    // Node 26 returns {module, instance}; older runtimes return the instance directly
    const wasm = (await WebAssembly.instantiate(bytes)) as unknown as
      | { instance?: WebAssembly.Instance }
      | WebAssembly.Instance;
    instance = "instance" in (wasm as object) ? (wasm as { instance: WebAssembly.Instance }).instance : (wasm as WebAssembly.Instance);
  }
  return instance;
}

function toI64(v: unknown): bigint {
  if (typeof v === "bigint") return v;
  if (typeof v === "number") return BigInt(Math.trunc(v));
  if (typeof v === "string") return BigInt(v);
  throw new TypeError("cannot coerce " + typeof v + " to i64");
}
function toI32(v: unknown): number {
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isFinite(n)) throw new TypeError("cannot coerce to i32");
  return Math.trunc(n);
}

export const WASM_DELEGATES: Record<string, (...args: unknown[]) => Promise<unknown>> = {
${entries.join("\n")}
};
`;
}

export function extract(input: ExtractInput): ExtractionReport {
  const cloudDir = join(input.outDir, "cloud");
  const clientDir = join(input.outDir, "client");
  const localDir = join(input.outDir, "local");
  for (const d of [cloudDir, clientDir, localDir]) mkdirSync(d, { recursive: true });

  // 1. scan every source and lift the marked core logic
  const reports: ScanReport[] = [];
  const fnNames: string[] = [];
  let sourceBytes = 0;
  let liftedFnBytes = 0;
  let strCount = 0;

  const tableParts: string[] = [];
  const fnParts: string[] = [];
  const registry: string[] = [];

  input.files.forEach((f, i) => {
    sourceBytes += Buffer.byteLength(f.src, "utf8");
    const report = scanSource(f.path, f.src);
    reports.push(report);
    if (report.functions.length) fnNames.push(...report.functions.map((x) => x.name));
    liftedFnBytes += report.functions.reduce((n, x) => n + x.source.length, 0);
    strCount += Object.keys(report.strTable).length;

    // merged string table: scope per file to avoid S-key collisions across files
    const entries = Object.entries(report.strTable)
      .map(([k, v]) => `  ${k}: ${JSON.stringify(v)},`)
      .join("\n");
    tableParts.push(`const __V_f${i}: Record<string, string> = {\n${entries}\n};`);
    for (const fn of report.functions) {
      const body = fn.source.split("__V.").join(`__V_f${i}.`);
      fnParts.push(body);
      registry.push(`  ${fn.name},`);
    }
    const hollow = hollowOut(f.src, report);
    writeFileSync(join(localDir, `${basename(f.path)}.hollow.ts`), hollow, "utf8");
  });

  if (fnNames.length === 0 && !(input.wasmDelegates?.length ?? 0)) {
    throw new Error("extraction found no core logic: mark functions with /* @vault */");
  }

  // 2. cloud module: string tables + lifted functions + registry
  const liftedModule = `/**
 * Omni-Vault · lifted cloud module (generated by vault_extractor).
 * The core business logic that used to live in the local program.
 * THIS FILE NEVER SHIPS TO THE CLIENT.
 */
${tableParts.join("\n\n")}

${fnParts.join("\n\n")}

export const __VAULT_FUNCTIONS: Record<string, (...args: unknown[]) => unknown> = {
${registry.join("\n")}
};
`;
  writeFileSync(join(cloudDir, "lifted.ts"), liftedModule, "utf8");

  // 3. wasm core + delegates
  const wasm = emitPricingModule();
  writeFileSync(join(cloudDir, "pricing.wasm"), wasm);
  writeFileSync(join(cloudDir, "wasm-delegates.ts"), emitWasmDelegates(input.wasmDelegates ?? []), "utf8");

  // 4. provision identities and tokens
  const serverKeys = provisionServer();
  writeFileSync(join(cloudDir, "server-keys.json"), JSON.stringify(serverKeys, null, 2), "utf8");
  const port = new URL(input.url).port || "80";
  writeFileSync(join(cloudDir, "server-config.json"), JSON.stringify({ origin: input.url, port: Number(port) }, null, 2), "utf8");

  const scope = input.scope.length ? input.scope : [...fnNames, ...(input.wasmDelegates ?? []).map((d) => d.fn)];
  const client = provisionClient(serverKeys, scope, input.ttlMs);

  // 5. cloud server (from template, security import path rewritten to match outDir)
  const secRel = relative(cloudDir, securitySrc).split(sep).join("/");
  const serverTpl = readFileSync(asset("server-template.ts"), "utf8").split("__OMNI_SECURITY__").join(secRel);
  writeFileSync(join(cloudDir, "vault-server.ts"), serverTpl, "utf8");

  // 6. thin shell: manifest injected, then self-hash stamped over the marker
  const manifest = {
    url: input.url,
    token: client.token,
    clientPrivateDer: client.privateDer,
    pinnedVerifyKeyDer: serverKeys.signPublicDer,
    serverStaticPubDer: serverKeys.x25519PublicDer,
    scope: client.scope,
    fns: [...fnNames, ...(input.wasmDelegates ?? []).map((d) => d.fn)],
    buildTs: new Date().toISOString(),
  };
  const shellTpl = readFileSync(asset("shell-template.mjs"), "utf8");
  const injected = shellTpl.split("/*__OMNI_MANIFEST__*/ null").join(JSON.stringify(manifest));
  const selfHash = sha256Hex(injected);
  const shell = injected.split("__OMNI_VAULT_SELF_HASH__").join(selfHash);
  const shellPath = join(clientDir, "vault-shell.mjs");
  writeFileSync(shellPath, shell, "utf8");
  writeFileSync(join(clientDir, "client.json"), JSON.stringify({ ...manifest, sha256: selfHash }, null, 2), "utf8");

  // 7. extraction report
  const cloudBytes = liftedModule.length + wasm.length + serverTpl.length;
  const report: ExtractionReport = {
    buildTs: manifest.buildTs,
    url: input.url,
    scope,
    stats: {
      sourceBytes,
      liftedFnBytes,
      strTableEntries: strCount,
      wasmBytes: wasm.length,
      shellBytes: shell.length,
      cloudBytes,
    },
    lifted: reports.map((r) => ({
      file: r.file,
      functions: r.functions.map((f) => `${f.name} (${f.kind}, L${f.startLine}-${f.endLine})`),
      hollowed: `${basename(r.file)}.hollow.ts`,
    })),
    wasmDelegates: input.wasmDelegates ?? [],
    shell: { path: shellPath, sha256: selfHash },
    declaration: DECLARATION,
  };
  writeFileSync(join(input.outDir, "extraction-report.json"), JSON.stringify(report, null, 2), "utf8");
  return report;
}

function basename(p: string): string {
  return p.replace(/[\\/]/g, "/").split("/").pop()!.replace(/\.\w+$/, "");
}

export { emitPricingModule, scanSource, hollowOut, provisionServer, provisionClient, b64 };
