/**
 * Omni-Vault · hand-rolled WebAssembly bytecode emitter.
 *
 * The environment forbids C/C++ toolchains, so we do not *compile* to wasm —
 * we emit raw wasm bytecode directly. This is the "encrypted WASM bytecode"
 * backend of the extractor: the core billing algorithm exists only as binary
 * `pricing.wasm`, instantiated at runtime by the cloud side. The local shell
 * never sees source, text, or even the module — only RPC responses.
 *
 * Module shape (MVP, hand-verified):
 *   (module
 *     (func (export "compute") (param $units i64) (param $tier i32) (param $months i32) (result i64)
 *       (local $factor i64) (local $base i64) ...))
 */

/* ---------------------------------- LEB128 ----------------------------------- */

export function uleb(n: number): number[] {
  const out: number[] = [];
  do {
    let b = n & 0x7f;
    n >>>= 7;
    if (n !== 0) b |= 0x80;
    out.push(b);
  } while (n !== 0);
  return out;
}

export function sleb(n: number): number[] {
  const out: number[] = [];
  let more = true;
  while (more) {
    let b = n & 0x7f;
    n >>= 7;
    const sign = (b & 0x40) !== 0;
    if ((n === 0 && !sign) || (n === -1 && sign)) {
      more = false;
    } else {
      b |= 0x80;
    }
    out.push(b);
  }
  return out;
}

function vec(elements: number[][]): number[] {
  return [...uleb(elements.length), ...elements.flat()];
}

function section(id: number, payload: number[]): number[] {
  return [id, ...uleb(payload.length), ...payload];
}

function bytes(s: string): number[] {
  const b = Buffer.from(s, "utf8");
  return [...uleb(b.length), ...b];
}

const I32 = 0x7f;
const I64 = 0x7e;

/* --------------------------------- opcodes ----------------------------------- */

const OP = {
  unreachable: 0x00,
  block: 0x02,
  loop: 0x03,
  if: 0x04,
  else: 0x05,
  end: 0x0b,
  br: 0x0c,
  return: 0x0f,
  local_get: 0x20,
  local_set: 0x21,
  i32_const: 0x41,
  i64_const: 0x42,
  i32_ge_s: 0x4e,
  i64_gt_s: 0x55,
  i64_lt_s: 0x53,
  i32_add: 0x6a,
  i32_mul: 0x6c,
  i64_add: 0x7c,
  i64_sub: 0x7d,
  i64_mul: 0x7e,
  i64_div_u: 0x80,
  i64_extend_i32_u: 0xad,
} as const;

/* --------------------------------- builder ----------------------------------- */

export class WasmBuilder {
  private types: number[][] = [];
  private funcTypeIdx: number[] = [];
  private exports: { name: string; kind: number; idx: number }[] = [];
  private bodies: number[][] = [];

  /** Returns the type index. */
  addType(params: number[], results: number[]): number {
    this.types.push([0x60, ...vec(params.map((p) => [p])), ...vec(results.map((r) => [r]))]);
    return this.types.length - 1;
  }

  addFunction(typeIdx: number, locals: number[], body: number[]): number {
    this.funcTypeIdx.push(typeIdx);
    // locals: run-length group same-type locals → (count, type) declarations
    const groups: Array<[number, number]> = [];
    for (const t of locals) {
      const last = groups[groups.length - 1];
      if (last && last[1] === t) last[0]++;
      else groups.push([1, t]);
    }
    const localDecls = [groups.length, ...groups.flatMap(([c, t]) => [c, t])];
    const full = [...localDecls, ...body, OP.end];
    this.bodies.push(full);
    return this.funcTypeIdx.length - 1;
  }

  exportFunction(name: string, funcIdx: number): void {
    this.exports.push({ name, kind: 0x00, idx: funcIdx });
  }

  build(): Buffer {
    const header = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    const typeSec = section(1, vec(this.types));
    const funcSec = section(3, vec(this.funcTypeIdx.map((i) => uleb(i))));
    const exportSec = this.exports.length
      ? section(7, vec(this.exports.map((e) => [...bytes(e.name), e.kind, ...uleb(e.idx)])))
      : [];
    const codeSec = section(10, vec(this.bodies.map((b) => [...uleb(b.length), ...b])));
    return Buffer.from([...header, ...typeSec, ...funcSec, ...exportSec, ...codeSec]);
  }
}

/* ------------------------- reference billing module -------------------------- */

/**
 * Emits `pricing.wasm`:
 *   compute(units, tier, months) -> i64  (amount in cents)
 *
 *   price_per_unit = (tier + 1) * 170               // tiered unit price, cents
 *   base           = units * price_per_unit
 *   factor         = 10000                          // discount basis points
 *   if units  > 10000   factor -= 1500              // volume tier 2 (15%)
 *   else if units > 1000    factor -= 1000          // volume tier 1 (10%)
 *   if months >= 12      factor -= 800              // loyalty (8%)
 *   if factor < 7000     factor = 7000              // max 30% total discount
 *   total = base * factor / 10000
 *
 * Params: 0=units(i64) 1=tier(i32) 2=months(i32); locals: 3=factor 4=base (i64).
 */
export function emitPricingModule(): Buffer {
  const b = new WasmBuilder();
  const typeIdx = b.addType([I64, I32, I32], [I64]);
  const body = [
    // price = (tier + 1) * 170  → i64
    //   stack: [tier] → [tier,1] --i32.add--> [t+1] → [t+1,170] --i32.mul--> [(t+1)*170] --extend_i32_u--> [price]
    OP.local_get, 1,
    OP.i32_const, ...sleb(1),
    OP.i32_add,
    OP.i32_const, ...sleb(170),
    OP.i32_mul,
    OP.i64_extend_i32_u,
    // base = units * price
    OP.local_get, 0,
    OP.i64_mul,
    OP.local_set, 4,
    // factor = 10000
    OP.i64_const, ...sleb(10000),
    OP.local_set, 3,
    // volume discount
    OP.local_get, 0,
    OP.i64_const, ...sleb(10000),
    OP.i64_gt_s,
    OP.if, 0x40,
    OP.local_get, 3, OP.i64_const, ...sleb(1500), OP.i64_sub, OP.local_set, 3,
    OP.else,
    OP.local_get, 0, OP.i64_const, ...sleb(1000), OP.i64_gt_s,
    OP.if, 0x40,
    OP.local_get, 3, OP.i64_const, ...sleb(1000), OP.i64_sub, OP.local_set, 3,
    OP.end,
    OP.end,
    // loyalty discount
    OP.local_get, 2, OP.i32_const, ...sleb(12), OP.i32_ge_s,
    OP.if, 0x40,
    OP.local_get, 3, OP.i64_const, ...sleb(800), OP.i64_sub, OP.local_set, 3,
    OP.end,
    // floor the discount: factor = max(factor, 7000)
    OP.local_get, 3, OP.i64_const, ...sleb(7000), OP.i64_lt_s,
    OP.if, 0x40,
    OP.i64_const, ...sleb(7000), OP.local_set, 3,
    OP.end,
    // total = base * factor / 10000
    OP.local_get, 4,
    OP.local_get, 3,
    OP.i64_mul,
    OP.i64_const, ...sleb(10000),
    OP.i64_div_u,
  ];
  const fnIdx = b.addFunction(typeIdx, [I64, I64], body);
  b.exportFunction("compute", fnIdx);
  return b.build();
}
