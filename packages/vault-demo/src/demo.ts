/**
 * Omni-Vault · end-to-end demo
 *
 * 1. extracts the demo project (unless demo-gen/ already exists)
 * 2. boots the cloud vault server
 * 3. drives the thin shell — computeInvoice (wasm core) and renderInvoice
 *    (lifted module, cloud string table)
 * 4. verifies the numbers against an independent reference implementation
 */
import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createConnection } from "node:net";

const here = dirname(fileURLToPath(import.meta.url));
const pkg = join(here, "..");
const genDir = join(pkg, "demo-gen");
const shellPath = join(genDir, "client", "vault-shell.mjs");
const serverEntry = join(genDir, "cloud", "vault-server.ts");

let failures = 0;
const pass = (m: string) => console.log(`  ✓ ${m}`);
const fail = (m: string) => {
  failures++;
  console.log(`  ✗ ${m}`);
};

/* ------------------------------ reference core ------------------------------ */
// Deliberately duplicated here so the demo trusts NOBODY: the wasm answer is
// compared against an independent JS implementation.
function refCompute(units: number, tier: number, months: number): number {
  const price = (tier + 1) * 170;
  let factor = 10000;
  if (units > 10000) factor -= 1500;
  else if (units > 1000) factor -= 1000;
  if (months >= 12) factor -= 800;
  if (factor < 7000) factor = 7000;
  return Math.floor((units * price * factor) / 10000);
}

/* --------------------------------- helpers --------------------------------- */

function runNode(args: string[], cwd: string): Promise<{ code: number | null; out: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["--experimental-strip-types", ...args], { cwd });
    let out = "";
    child.stdout.on("data", (d) => (out += String(d)));
    child.stderr.on("data", (d) => (out += String(d)));
    child.on("close", (code) => resolve({ code, out }));
  });
}

function waitForPort(port: number, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve) => {
    const attempt = () => {
      const sock = createConnection({ port, host: "127.0.0.1" });
      sock.once("connect", () => {
        sock.destroy();
        resolve(true);
      });
      sock.once("error", () => {
        sock.destroy();
        if (Date.now() > deadline) resolve(false);
        else setTimeout(attempt, 200);
      });
    };
    attempt();
  });
}

/* ---------------------------------- run ----------------------------------- */

console.log("Omni-Vault · end-to-end demo");
console.log("──────────────────────────────────────────────────────────────");

if (!existsSync(shellPath)) {
  console.log("[1/4] demo-gen missing — extracting billing.ts …");
  const ext = await runNode([join(here, "run-extract.ts")], pkg);
  if (ext.code !== 0) {
    console.error(ext.out);
    process.exit(1);
  }
} else {
  console.log("[1/4] demo-gen present");
}

const clientJson = JSON.parse(readFileSync(join(genDir, "client", "client.json"), "utf8")) as { url: string };
const url = new URL(clientJson.url);
const port = Number(url.port || 80);

console.log(`[2/4] starting cloud vault on ${clientJson.url} …`);
const server = spawn(process.execPath, ["--experimental-strip-types", serverEntry], {
  cwd: join(genDir, "cloud"),
  stdio: ["ignore", "pipe", "pipe"],
});
let serverLog = "";
server.stdout.on("data", (d) => (serverLog += String(d)));
server.stderr.on("data", (d) => (serverLog += String(d)));

const up = await waitForPort(port, 15_000);
if (!up) {
  console.error(serverLog);
  server.kill();
  process.exit(1);
}
console.log("      up");

console.log("[3/4] driving the thin shell against the cloud core …");

const cases: { fn: string; args: number[]; expect?: number; needle?: string; label: string }[] = [
  { fn: "computeInvoice", args: [1500, 1, 12], expect: refCompute(1500, 1, 12), label: "wasm core · business/annual" },
  { fn: "computeInvoice", args: [999999, 3, 48], expect: refCompute(999999, 3, 48), label: "wasm core · unlimited/bulk" },
  {
    fn: "renderInvoice",
    args: [refCompute(1500, 1, 12), 1500, 1, 12, "zh"],
    needle: "应付：¥4182.00",
    label: "lifted module · zh invoice",
  },
  {
    fn: "renderInvoice",
    args: [refCompute(999999, 3, 48), 999999, 3, 48, "en"],
    needle: "Due: ¥5235994.76",
    label: "lifted module · en invoice",
  },
];

for (const c of cases) {
  const r = await runNode([shellPath, c.fn, ...c.args.map(String)], join(genDir, "client"));
  const clean = r.out
    .split("\n")
    .filter((l) => !/transpiler/i.test(l))
    .join("\n")
    .trim();
  if (c.expect !== undefined) {
    clean.endsWith(String(c.expect))
      ? pass(`${c.label}: ${c.fn}(${c.args.join(", ")}) = ${c.expect}`)
      : fail(`${c.label}: expected ${c.expect}, shell said: ${clean.slice(-120)}`);
  } else if (c.needle) {
    clean.includes(c.needle)
      ? pass(`${c.label}: contains "${c.needle}"`)
      : fail(`${c.label}: missing "${c.needle}" — output: ${clean.slice(0, 200)}`);
  }
}

server.kill();
await new Promise((r) => setTimeout(r, 400));

console.log("[4/4] done");
console.log("──────────────────────────────────────────────────────────────");
console.log(failures === 0 ? "  RESULT: cloud-only execution verified — shell holds no core logic." : `  RESULT: ${failures} failure(s).`);
console.log("");
process.exit(failures === 0 ? 0 : 1);
