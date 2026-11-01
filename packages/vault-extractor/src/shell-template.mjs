#!/usr/bin/env node
/**
 * Omni-Vault · thin shell (generated artifact).
 *
 * 没有任何核心业务逻辑。No core business logic lives in this file.
 * It contains only: network I/O, the cryptographic handshake, the GCM session,
 * anti-debug/self-integrity guards, and result presentation.
 *
 * Core logic executes remotely; this shell merely asks it questions.
 * Omni-Vault：只要不把代码交出去，就绝对没有人能逆向它。
 */
import { createHash, createHmac, generateKeyPairSync, diffieHellman, createPrivateKey, createPublicKey, hkdfSync, sign as edSign, verify as edVerify, createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import * as http from "node:http";

const MANIFEST = /*__OMNI_MANIFEST__*/ null;
const SELF_HASH = "__OMNI_VAULT_SELF_HASH__";
const PROTOCOL_VERSION = 1;

/* ============================ anti-debug / integrity ============================ */

const DEBUG_ARG_RE = /--inspect[^=]*|--debug(-brk|-port)?(=|\s|$)|inspect(=|\s|$)/i;

function timingBaseline() {
  const t0 = process.hrtime.bigint();
  let sink = 0;
  for (let i = 0; i < 200000; i++) sink += Math.sqrt(i) | 0;
  return Number(process.hrtime.bigint() - t0) / 1e6 || 1;
}
const BASELINE = timingBaseline();

async function guard() {
  const reasons = [];
  for (const arg of process.execArgv) if (DEBUG_ARG_RE.test(arg)) reasons.push(`debugger flag in execArgv: ${arg}`);
  if (DEBUG_ARG_RE.test(process.env.NODE_OPTIONS || "")) reasons.push("inspector reachable via NODE_OPTIONS");
  try {
    const { url } = await import("node:inspector");
    const inspectorUrl = url();
    if (inspectorUrl) reasons.push(`debugger attached: ${inspectorUrl}`);
  } catch { /* inspector module unavailable */ }
  const probe = timingBaseline();
  if (BASELINE > 0.5 && probe > BASELINE * 8) reasons.push(`timing heist: probe ${probe.toFixed(1)}ms vs baseline ${BASELINE.toFixed(1)}ms`);
  try {
    const self = readFileSync(new URL(import.meta.url), "utf8");
    // rebuild the pre-stamp text: the digest was computed over the file with
    // the slot still holding the placeholder (split so the build-time global
    // replace cannot touch this literal too)
    const SLOT = "__OMNI_VAULT_" + "SELF_HASH__";
    const restored = self.split(SELF_HASH).join(SLOT);
    if (createHash("sha256").update(restored, "utf8").digest("hex") !== SELF_HASH) reasons.push("self-integrity violated");
  } catch (e) { reasons.push(`self-integrity unreadable: ${e.message}`); }
  return reasons;
}

/* ============================ vault session state ============================ */

let session = null; // { sid, keys, sendSeq, recvSeq, proofKey }
function wipeSession() {
  if (!session) return;
  for (const k of Object.values(session.keys || {})) if (Buffer.isBuffer(k)) k.fill(0);
  session = null;
}
for (const ev of ["exit", "SIGINT", "SIGTERM"]) process.on(ev, wipeSession);

/* ============================ crypto helpers ============================ */

const b64 = { enc: (b) => b.toString("base64"), dec: (s) => Buffer.from(s, "base64") };
const sha256 = (d) => createHash("sha256").update(d).digest();
const hkdf = (ikm, salt, info, len) => Buffer.from(hkdfSync("sha256", ikm, salt, info, len));

function deriveKeys(shared, salt) {
  return {
    c2sKey: hkdf(shared, salt, "omni-vault/v1/c2s/key", 32),
    s2cKey: hkdf(shared, salt, "omni-vault/v1/s2c/key", 32),
    c2sIv: hkdf(shared, salt, "omni-vault/v1/c2s/iv", 12),
    s2cIv: hkdf(shared, salt, "omni-vault/v1/s2c/iv", 12),
  };
}

function seal(plaintext) {
  const nonce = Buffer.from(session.keys.c2sIv);
  nonce.writeUInt32BE(session.sendSeq, 8);
  const c = createCipheriv("aes-256-gcm", session.keys.c2sKey, nonce);
  const out = Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]);
  session.sendSeq++;
  return Buffer.concat([nonce, out]);
}

function open(frame) {
  if (frame.length < 28) throw new Error("[shell] frame too short");
  const nonce = frame.subarray(0, 12);
  const ct = frame.subarray(12);
  if (!nonce.subarray(0, 8).equals(session.keys.s2cIv.subarray(0, 8))) throw new Error("[shell] E_REPLAY nonce prefix mismatch");
  const seq = nonce.readUInt32BE(8);
  if (seq <= session.recvSeq) throw new Error(`[shell] E_REPLAY counter regression (seq=${seq}, seen=${session.recvSeq})`);
  const d = createDecipheriv("aes-256-gcm", session.keys.s2cKey, nonce);
  d.setAuthTag(ct.subarray(ct.length - 16));
  const pt = Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
  session.recvSeq = seq;
  return pt;
}

/* ============================ transport ============================ */

function post(path, body, headers) {
  return new Promise((resolve, reject) => {
    const u = new URL(MANIFEST.url);
    const req = http.request({
      hostname: u.hostname, port: u.port, path,
      method: "POST",
      headers: { "content-length": String(body.length), ...headers },
    }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
    });
    req.on("error", reject);
    req.end(body);
  });
}

async function handshake() {
  const eph = generateKeyPairSync("x25519");
  const clientStatic = createPrivateKey({ key: b64.dec(MANIFEST.clientPrivateDer), format: "der", type: "pkcs8" });
  const clientStaticPub = createPublicKey(clientStatic).export({ type: "spki", format: "der" });
  const nonceC = randomBytes(16);

  const hello = {
    v: PROTOCOL_VERSION,
    token: MANIFEST.token,
    clientStaticPub: b64.enc(clientStaticPub),
    clientEphPub: b64.enc(eph.publicKey.export({ type: "spki", format: "der" })),
    nonceC: b64.enc(nonceC),
    ts: Date.now(),
  };
  const res = await post("/osh", Buffer.from(JSON.stringify(hello), "utf8"), { "content-type": "application/json" });
  if (res.status !== 200) throw new Error(`[shell] handshake HTTP ${res.status}: ${res.body}`);
  const w = JSON.parse(res.body.toString("utf8"));
  if (w.v !== PROTOCOL_VERSION) throw new Error("[shell] E_VERSION");
  const unsigned = { v: w.v, sid: w.sid, serverEphPub: w.serverEphPub, nonceS: w.nonceS, ts: w.ts };
  const transcript = sha256(JSON.stringify(hello) + "." + JSON.stringify(unsigned));

  const pinnedVerify = createPublicKey({ key: b64.dec(MANIFEST.pinnedVerifyKeyDer), format: "der", type: "spki" });
  if (!edVerify(null, transcript, pinnedVerify, b64.dec(w.sig))) {
    throw new Error("[shell] E_PIN — server signature failed (MITM?), wiping");
  }

  const shared = diffieHellman({ privateKey: eph.privateKey, publicKey: createPublicKey({ key: b64.dec(w.serverEphPub), format: "der", type: "spki" }) });
  const nonceS = b64.dec(w.nonceS);
  const keys = deriveKeys(shared, Buffer.concat([nonceC, nonceS]));

  const staticShared = diffieHellman({
    privateKey: clientStatic,
    publicKey: createPublicKey({ key: b64.dec(MANIFEST.serverStaticPubDer), format: "der", type: "spki" }),
  });
  const proofKey = hkdf(staticShared, nonceS, "omni-vault/v1/proof", 32);

  session = { sid: w.sid, keys, sendSeq: 0, recvSeq: -1, proofKey };
  return session;
}

async function rpc(fn, args) {
  if (!session) await handshake();
  const callId = randomBytes(8).toString("hex");
  const envelope = { callId, fn, args };
  if (session.sendSeq === 0) {
    envelope.proof = createHmac("sha256", session.proofKey).update(`omni-vault/proof/${session.sid}/${callId}`).digest("hex");
  }
  const res = await post("/orpc", seal(Buffer.from(JSON.stringify(envelope), "utf8")), { "content-type": "application/octet-stream", "x-omni-sid": session.sid });
  if (res.status !== 200) throw new Error(`[shell] rpc HTTP ${res.status}: ${res.body}`);
  const reply = JSON.parse(open(res.body).toString("utf8"));
  if (!reply.ok) throw new Error(`[shell] remote ${reply.err.code}: ${reply.err.message}`);
  return reply.result;
}

/* ============================ CLI ============================ */

async function main() {
  const reasons = await guard();
  if (reasons.length) {
    console.error("[VAULT] anti-debug / tamper trip — wiping session keys and refusing to dial the cloud:");
    for (const r of reasons) console.error(`[VAULT]   · ${r}`);
    wipeSession();
    process.exit(13);
  }

  const args = process.argv.slice(2);
  if (args.length === 0 || args[0] === "--help") {
    console.log("usage: node vault-shell.mjs <fn> [args...]   (args parsed as JSON, else string)");
    console.log("       node vault-shell.mjs --self-test");
    return;
  }
  if (args[0] === "--self-test") {
    console.log("Omni-Vault thin shell — self-test");
    console.log(`  server          : ${MANIFEST.url}`);
    console.log(`  scope           : ${MANIFEST.scope.join(", ")}`);
    console.log(`  token jti       : ${MANIFEST.token.split(".")[1] ? MANIFEST.token.split(".")[1].slice(0, 24) + "…" : "?"}`);
    console.log(`  self-integrity  : ok (sha256 ${SELF_HASH.slice(0, 16)}…)`);
    console.log(`  core logic      : 0 bytes — none present in this file`);
    console.log('  declaration     : "只要不把代码交出去，就绝对没有人能逆向它。"');
    return;
  }

  const fn = args[0];
  const callArgs = args.slice(1).map((a) => {
    try { return JSON.parse(a); } catch { return a; }
  });
  const result = await rpc(fn, callArgs);
  if (typeof result === "object" && result !== null) console.log(JSON.stringify(result, null, 2));
  else console.log(result);
}

main().catch((e) => {
  console.error(String(e.message || e));
  wipeSession();
  process.exit(1);
});
