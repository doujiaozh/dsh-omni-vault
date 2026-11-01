import { writeFileSync } from "node:fs";
import { emitPricingModule, uleb } from "./wasm.ts";

/** Pure-JS reference of the same billing policy, for cross-validation. */
export function refCompute(units: number, tier: number, months: number): number {
  const price = (tier + 1) * 170;
  const base = units * price;
  let factor = 10000;
  if (units > 10000) factor -= 1500;
  else if (units > 1000) factor -= 1000;
  if (months >= 12) factor -= 800;
  if (factor < 7000) factor = 7000;
  return Math.floor((base * factor) / 10000);
}

export async function main(): Promise<void> {
  const wasm = emitPricingModule();
  writeFileSync("pricing.wasm", wasm);
  const { instance } = await WebAssembly.instantiate(wasm);
  const compute = instance.exports.compute as (u: bigint, t: number, m: number) => bigint;

  const cases: Array<[number, number, number]> = [
    [500, 1, 6],       // no discount
    [1500, 1, 3],      // volume 10%
    [1500, 1, 12],     // volume 10% + loyalty 8%
    [50000, 2, 24],    // volume 15% + loyalty 8% → floored at 30%
    [1200, 0, 1],      // base tier
    [999999, 3, 48],   // stress
  ];

  let pass = 0;
  for (const [u, t, m] of cases) {
    const got = Number(compute(BigInt(u), t, m));
    const want = refCompute(u, t, m);
    const ok = got === want;
    if (ok) pass++;
    console.log(
      `${ok ? "PASS" : "FAIL"}  compute(${u}, ${t}, ${m}) = ${got} (ref ${want})`,
    );
  }

  // LEB128 sanity: 0 → [0], 127 → [127], 128 → [128,1]
  const leb = (n: number) => uleb(n).map((b) => b.toString(16)).join(",");
  console.log("leb(0)=" + leb(0), "leb(127)=" + leb(127), "leb(128)=" + leb(128));

  if (pass !== cases.length) {
    console.error(`wasm self-check: ${pass}/${cases.length} passed`);
    process.exit(1);
  }
  console.log(`wasm self-check: ${pass}/${cases.length} passed — pricing.wasm is ${wasm.length} bytes`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
