/**
 * Omni-Vault demo · stage 1 — extraction.
 *
 * Feeds the original billing module to vault_extractor and produces the
 * demo-gen tree:
 *   demo-gen/cloud/   the lifted module, wasm bytecode, keys, the server
 *   demo-gen/client/  the thin shell (self-hash stamped) + client record
 *   demo-gen/local/   the hollowed-out local source — proof of what remains
 *   demo-gen/extraction-report.json
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { extract } from "../../vault-extractor/src/index.ts";

const here = dirname(fileURLToPath(import.meta.url));
const VAULT_ORIGIN = process.env.VAULT_ORIGIN ?? "http://127.0.0.1:8787";

const billingSrc = readFileSync(join(here, "billing.ts"), "utf8");
const outDir = join(here, "..", "demo-gen");

const report = extract({
  files: [{ path: "billing.ts", src: billingSrc }],
  outDir,
  url: VAULT_ORIGIN,
  scope: ["computeInvoice", "renderInvoice"],
  ttlMs: 365 * 24 * 3600 * 1000,
  wasmDelegates: [
    { fn: "computeInvoice", wasmExport: "compute", params: ["i64", "i32", "i32"], result: "i64" },
  ],
});

const shellBytes = report.stats.shellBytes;
console.log("╔══════════════════════════════════════════════════════════════╗");
console.log("║           Omni-Vault · extraction complete                     ║");
console.log("╠══════════════════════════════════════════════════════════════╣");
console.log(`║  source scanned        : ${report.stats.sourceBytes} bytes`);
console.log(`║  logic lifted          : ${report.stats.liftedFnBytes} bytes (${report.lifted.flatMap((l) => l.functions).join(", ")})`);
console.log(`║  secrets lifted        : ${report.stats.strTableEntries} strings → cloud string table`);
console.log(`║  wasm core             : ${report.stats.wasmBytes} bytes of bytecode`);
console.log(`║  thin shell produced   : ${shellBytes} bytes (self-hash ${report.shell.sha256.slice(0, 16)}…)`);
console.log(`║  cloud fns             : ${report.scope.join(", ")}`);
console.log("╚══════════════════════════════════════════════════════════════╝");
console.log(`\nNext: node --experimental-strip-types src/demo.ts  (cloud + shell e2e)`);
console.log(`      node --experimental-strip-types src/reverser.ts  (attack the shell)`);
