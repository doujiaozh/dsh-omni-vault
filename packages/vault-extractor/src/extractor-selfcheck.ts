/**
 * Extractor self-check: scan a sample module, lift it, hollow it out, and
 * assert that (a) the lifted body exists and (b) the hollowed copy contains
 * none of the secret strings. Run:
 *   node --experimental-strip-types src/extractor-selfcheck.ts
 */
import { scanSource, hollowOut } from "./scanner.ts";

const sample = `const BANK = /* @vault-str */ "招行 6225-8866-0000-7f3a";

/** @vault */
export function priceOf(units: number, tier: number): number {
  const SECRET_TAG = /* @vault-str */ "OMNI-PRICING-CORE-V7";
  const sk = "sk_demo_12345";
  return units * (tier + 1) * 170 + SECRET_TAG.length;
}

export function notCore(x: number): number {
  return x + 1;
}
`;

const report = scanSource("sample.ts", sample);
let failures = 0;
const check = (name: string, cond: boolean, detail = "") => {
  console.log(`${cond ? "PASS" : "FAIL"} ${name}${detail ? " — " + detail : ""}`);
  if (!cond) failures++;
};

check("lifts the @vault function", report.functions.length === 1, report.functions.map((f) => f.name).join(","));
check("table has 3 secrets", Object.keys(report.strTable).length === 3, Object.keys(report.strTable).join(","));
check("auto-flags the sk_ literal", report.strings.some((s) => s.auto && s.value.startsWith("sk_")));

const lifted = report.functions[0]?.source ?? "";
check("lifted body rewrites literals to __V slots", lifted.includes("__V.S"), lifted.split("\n").filter((l) => l.includes("__V")).join(" | "));

const hollow = hollowOut(sample, report);
for (const [k, v] of Object.entries(report.strTable)) {
  check(`hollowed copy is free of ${k}`, !hollow.includes(v), v.slice(0, 24));
}
check("hollowed copy stubs priceOf", hollow.includes('priceOf() { throw new Error("[omni-vault] priceOf runs in the cloud vault")'));
check("hollowed copy keeps non-core code", hollow.includes("notCore"));

console.log(
  failures === 0
    ? "\nextractor self-check: all passed — core logic leaves the local program"
    : `\nextractor self-check: ${failures} FAILURE(S)`,
);
process.exit(failures === 0 ? 0 : 1);
