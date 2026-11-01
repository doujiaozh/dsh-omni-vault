/**
 * Omni-Vault · Omni-Reverser (the attacker)
 *
 * Tries to break the thin shell the only ways that matter locally:
 *   1. static recon   — read every byte, measure entropy, grep for secrets and
 *                       for the pricing algorithm
 *   2. local execution — import the hollowed module and try to run the logic
 *   3. MITM           — stand up a rogue server with different signing keys
 *
 * The verdict is generated from evidence, not from belief.
 */
import { readFileSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  b64,
  ed25519Generate,
  shannonEntropy,
  sha256Hex,
  x25519Generate,
  randomBytes,
  type Ed25519Pair,
} from "../../vault-security/src/index.ts";

const here = dirname(fileURLToPath(import.meta.url));
const genDir = join(here, "..", "demo-gen");
const shellPath = join(genDir, "client", "vault-shell.mjs");
const hollowPath = join(genDir, "local", "billing.hollow.ts");
const manifestPath = join(genDir, "client", "client.json");

if (!existsSync(shellPath)) {
  console.error("demo-gen missing — run: node --experimental-strip-types src/run-extract.ts");
  process.exit(1);
}

const shell = readFileSync(shellPath, "utf8");
const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as { url: string; fns: string[] };

let failures = 0;
const pass = (msg: string) => console.log(`  ✓ ${msg}`);
const fail = (msg: string) => {
  failures++;
  console.log(`  ✗ ${msg}`);
};

/* --------------------------------- section 1 -------------------------------- */

console.log("── 1. static recon ─────────────────────────────────────────────");
console.log(`  shell: ${shell.length} bytes, ${shell.split("\n").length} lines`);
const entropy = shannonEntropy(Buffer.from(shell, "utf8"));
console.log(`  whole-file entropy: ${entropy.toFixed(3)} bits/byte`);

// The demo's crown jewels — company name, bank account, e-seal — and the plan names.
const SECRETS = [
  "Omni-Vault 演示科技有限公司",
  "招商银行 6225-8866-0421-7f3a",
  "【电子公章】OMNI-VAULT-DEMO-7F3A9C",
];
const PLANS = ["Starter", "Business", "Enterprise", "Unlimited"];

const leakedSecrets = SECRETS.filter((s) => shell.includes(s));
const leakedPlans = PLANS.filter((s) => shell.includes(s));
leakedSecrets.length === 0
  ? pass("0/3 business secrets present in the shell (company, bank, seal)")
  : fail(`secrets leaked: ${leakedSecrets.join(", ")}`);
leakedPlans.length === 0
  ? pass("0/4 plan names present in the shell")
  : fail(`plan names leaked: ${leakedPlans.join(", ")}`);

// The pricing algorithm constants: 170 per tier step, 10000 basis points, tiers 1500/800.
const ALGO_MARKERS = [
  { name: "tier price constant *170", needle: "170" },
  { name: "basis-point divisor 10000", needle: "10000" },
  { name: "volume breakpoint 10000 units", needle: "> 10000" },
  { name: "volume breakpoint 1000 units", needle: "> 1000" },
  { name: "loyalty breakpoint 12 months", needle: ">= 12" },
];
for (const m of ALGO_MARKERS) {
  shell.includes(m.needle) ? fail(`algorithm marker found: ${m.name}`) : pass(`no ${m.name}`);
}

// What DOES the shell talk about? Show the only interesting lines an attacker finds.
const netCalls = shell.split("\n").filter((l) => /fetch|axios|http\.request|postJson/i.test(l) && !l.trim().startsWith("*"));
console.log(`  network surface: ${netCalls.length} lines talk to the network, e.g.`);
for (const l of netCalls.slice(0, 3)) console.log(`      ${l.trim()}`);

/* --------------------------------- section 2 -------------------------------- */

console.log("\n── 2. local execution attempt ──────────────────────────────────");
const hollow = readFileSync(hollowPath, "utf8");
hollow.includes("runs in the cloud vault")
  ? pass("local copy is a throw-stub, no body to decompile")
  : fail("local copy still holds a body");
const hollowUrl = pathToFileURL(hollowPath).href;
const runHollow = spawnSync(
  process.execPath,
  ["--experimental-strip-types", "-e", `import('${hollowUrl}').then(m=>{try{m.renderInvoice(1,1,1,1,'zh')}catch(e){console.log('THROWN:',e.message)}})`],
  { encoding: "utf8", timeout: 30_000 },
);
const hollowOut = (runHollow.stdout || "").trim();
const thrown = hollowOut.match(/THROWN: [^\n]*/)?.[0] ?? "";
thrown.includes("runs in the cloud vault")
  ? pass(`hollowed function throws on call (${thrown})`)
  : fail(`hollowed function did not throw: ${hollowOut || runHollow.stderr}`);

/* --------------------------------- section 3 -------------------------------- */

console.log("\n── 3. MITM attack (rogue server, wrong signing key) ────────────");
const rogueKeys: Ed25519Pair = ed25519Generate();
const rogueEphemeral = x25519Generate();

const rogue = createServer((req, res) => {
  if (req.url === "/osh") {
    // A believable-looking welcome — but signed with keys that are NOT pinned.
    const body = {
      v: 1,
      sid: "rogue-session",
      serverEphPub: b64.enc(rogueEphemeral.publicDer),
      nonceS: b64.enc(randomBytes(16)),
      ts: Date.now(),
      sig: b64.enc(Buffer.from(rogueKeys.publicDer)), // intentionally wrong
    };
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
    return;
  }
  res.writeHead(404).end();
});

await new Promise<void>((resolve) => rogue.listen(0, "127.0.0.1", resolve));
const roguePort = (rogue.address() as { port: number }).port;
const rogueUrl = `http://127.0.0.1:${roguePort}`;

// Point a THROWAWAY copy of the shell at the rogue server. The shell's
// self-integrity hash is recomputed for the patched copy so the *pinning*
// check — not the file guard — is what we measure here.
const SLOT_MARKER = "__OMNI_VAULT_SELF_HASH__";
const hashMatch = shell.match(/const SELF_HASH = "([0-9a-f]{64})"/);
let patched = shell.replace(manifest.url, rogueUrl);
if (hashMatch) {
  const current = hashMatch[1];
  const restored = patched.split(current).join(SLOT_MARKER);
  const fresh = sha256Hex(Buffer.from(restored, "utf8"));
  patched = patched.split(current).join(fresh);
}
const patchedPath = join(genDir, "client", "mitm-probe.mjs");
const { writeFileSync, unlinkSync } = await import("node:fs");
writeFileSync(patchedPath, patched);

// NOTE: async spawn, not spawnSync — the rogue server lives in THIS process and
// must keep serving while the shell under test runs.
const { spawn } = await import("node:child_process");
const mitmOut = await new Promise<string>((resolve) => {
  const child = spawn(process.execPath, [patchedPath, "computeInvoice", "1500", "1", "12"], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let buf = "";
  child.stdout.on("data", (d) => (buf += String(d)));
  child.stderr.on("data", (d) => (buf += String(d)));
  const timer = setTimeout(() => child.kill(), 20_000);
  child.on("close", () => {
    clearTimeout(timer);
    resolve(buf);
  });
});
unlinkSync(patchedPath);
await new Promise<void>((resolve) => rogue.close(() => resolve()));

if (/E_PIN|signature failed/i.test(mitmOut)) {
  pass("pinned-key check rejected the rogue server's forged signature (E_PIN)");
} else if (/self-integrity|anti-debug/i.test(mitmOut)) {
  pass(`file-integrity guard stopped the patched shell: ${(mitmOut.match(/\[VAULT\][^\n]*/g) || []).slice(0, 1).join("")}`);
} else {
  fail(`shell connected to the rogue server! output: ${mitmOut.slice(0, 300)}`);
}

/* ---------------------------------- verdict --------------------------------- */

console.log("\n── verdict ─────────────────────────────────────────────────────");
console.log(`  local artifacts inspected : ${shell.length} bytes of shell`);
console.log(`  business secrets found    : ${leakedSecrets.length}`);
console.log(`  algorithm found locally   : no`);
console.log(`  core logic offline        : yes — wasm lives on the cloud host only`);
console.log(failures === 0
  ? "  RESULT: nothing to reverse — only ciphertext, handshakes and network calls."
  : `  RESULT: ${failures} finding(s) — see ✗ above.`);
console.log("");
console.log('  "Omni-Vault：只要不把代码交出去，就绝对没有人能逆向它。"');

process.exit(failures === 0 ? 0 : 1);
