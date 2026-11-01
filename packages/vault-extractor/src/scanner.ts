/**
 * Omni-Vault · lightweight AST scanner.
 *
 * A dependency-free, tokenizing scanner for TypeScript/JavaScript sources. It
 * is deliberately focused (not a full parser): it finds the constructs the
 * extractor cares about and lifts them verbatim.
 *
 * Markers (written as @vault / @vault-str inside real comments):
 *   @vault            marks the next function as core logic to lift
 *   @vault-str "..."  marks a string literal as sensitive (goes to the
 *                     cloud string table; the local copy is purged)
 *
 * Strings that look like credentials (sk_*, pk_*, AKIA*, ghp_*, 密钥/密码) are
 * auto-flagged even without a marker. Lifted function bodies are rewritten so
 * marked literals reference `__V.S0`-style slots served only by the cloud.
 */

export interface LiftedFunction {
  name: string;
  params: string[];
  kind: "function" | "arrow" | "method";
  source: string;
  /** Byte offsets of the original (pre-rewrite) function text in the file. */
  spanStart: number;
  spanEnd: number;
  startLine: number;
  endLine: number;
}

export interface SecretString {
  key: string;
  value: string;
  line: number;
  auto: boolean;
}

export interface ScanReport {
  file: string;
  functions: LiftedFunction[];
  strings: SecretString[];
  strTable: Record<string, string>;
}

const SECRET_CONTENT_RE = /^(sk_|pk_|AKIA|ghp_|gho_|-----BEGIN|MIIB|密钥|密码|私钥)/;

type CharClass = "plain" | "sq" | "dq" | "tpl" | "line" | "block";

/** Walk the source; call back for string-literal spans and comment ranges. */
function tokenize(
  src: string,
  onString: (start: number, end: number, quote: string) => void,
  onComment: (start: number, end: number, kind: "line" | "block") => void,
): void {
  let i = 0;
  let cls: CharClass = "plain";
  let strStart = 0;
  let lineStart = false;
  while (i < src.length) {
    const c = src[i];
    const next = src[i + 1] ?? "";
    switch (cls) {
      case "plain":
        if (c === "/" && next === "/") {
          onComment(i, 0, "line");
          i += 2;
          cls = "line";
        } else if (c === "/" && next === "*") {
          onComment(i, 0, "block");
          i += 2;
          cls = "block";
        } else if (c === "'" || c === '"') {
          strStart = i;
          cls = c === "'" ? "sq" : "dq";
          i++;
        } else if (c === "`") {
          strStart = i;
          cls = "tpl";
          i++;
        } else {
          i++;
        }
        break;
      case "sq":
      case "dq":
        if (c === "\\") i += 2;
        else if ((cls === "sq" && c === "'") || (cls === "dq" && c === '"')) {
          onString(strStart, i + 1, c);
          cls = "plain";
          i++;
        } else i++;
        break;
      case "tpl":
        if (c === "\\") i += 2;
        else if (c === "`") {
          onString(strStart, i + 1, "`");
          cls = "plain";
          i++;
        } else if (c === "$" && next === "{") {
          // skip the interpolation expression (brace-balanced, naive)
          let depth = 1;
          i += 2;
          while (i < src.length && depth > 0) {
            if (src[i] === "{") depth++;
            else if (src[i] === "}") depth--;
            i++;
          }
        } else i++;
        break;
      case "line":
        if (c === "\n") {
          cls = "plain";
        } else i++;
        break;
      case "block":
        if (c === "*" && next === "/") {
          i += 2;
          cls = "plain";
        } else i++;
        break;
    }
    lineStart = false;
    void lineStart;
  }
}

function lineOf(src: string, idx: number): number {
  let n = 1;
  for (let i = 0; i < idx && i < src.length; i++) if (src[i] === "\n") n++;
  return n;
}

/** Match braces span-aware (skips strings/comments). Returns end index of '}'. */
function matchBrace(src: string, openIdx: number): number {
  let depth = 0;
  let i = openIdx;
  let cls: CharClass = "plain";
  while (i < src.length) {
    const c = src[i];
    const next = src[i + 1] ?? "";
    if (cls === "plain") {
      if (c === "/" && next === "/") { i += 2; cls = "line"; continue; }
      if (c === "/" && next === "*") { i += 2; cls = "block"; continue; }
      if (c === "'" || c === '"' || c === "`") { cls = c === "'" ? "sq" : c === '"' ? "dq" : "tpl"; i++; continue; }
      if (c === "{") depth++;
      else if (c === "}") {
        depth--;
        if (depth === 0) return i;
      }
      i++;
    } else if (cls === "sq" || cls === "dq") {
      if (c === "\\") i += 2;
      else if ((cls === "sq" && c === "'") || (cls === "dq" && c === '"')) { cls = "plain"; i++; }
      else i++;
    } else if (cls === "tpl") {
      if (c === "\\") i += 2;
      else if (c === "`") { cls = "plain"; i++; }
      else i++;
    } else if (cls === "line") {
      if (c === "\n") cls = "plain";
      i++;
    } else {
      if (c === "*" && next === "/") { i += 2; cls = "plain"; }
      else i++;
    }
  }
  return -1;
}

/** Parse the parameter list of a function header, starting at '('. */
function parseParams(src: string, openIdx: number): string[] {
  const close = src.indexOf(")", openIdx);
  if (close === -1) return [];
  const raw = src.slice(openIdx + 1, close);
  const params: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of raw) {
    if (ch === "(" || ch === "{" || ch === "[") depth++;
    else if (ch === ")" || ch === "}" || ch === "]") depth--;
    if (ch === "," && depth === 0) {
      params.push(cur.trim().replace(/[:?].*$/, "").replace(/\.\.\./, ""));
      cur = "";
    } else {
      cur += ch;
    }
  }
  if (cur.trim()) params.push(cur.trim().replace(/[:?].*$/, "").replace(/\.\.\./, ""));
  return params.filter(Boolean);
}

export interface ScanOptions {
  /** Treat these function names as core logic even without a @vault marker. */
  alsoMatch?: RegExp;
}

export function scanSource(file: string, src: string, opts: ScanOptions = {}): ScanReport {
  const comments: Array<{ start: number; end: number; kind: "line" | "block" }> = [];
  const literals: Array<{ start: number; end: number; quote: string }> = [];

  tokenize(
    src,
    (s, e, q) => literals.push({ start: s, end: e, quote: q }),
    (s, _e, kind) => {
      if (kind === "line") {
        let j = s + 2;
        while (j < src.length && src[j] !== "\n") j++;
        comments.push({ start: s, end: j, kind });
      } else {
        const j = src.indexOf("*/", s + 2);
        comments.push({ start: s, end: j === -1 ? src.length : j + 2, kind });
      }
    },
  );

  /** A literal is "marked" when the nearest preceding comment touches it. */
  const markedComment = (pos: number): boolean => {
    for (const c of comments) {
      if (c.end <= pos && src.slice(c.end, pos).trim().length < 3) {
        if (src.slice(c.start, c.end).includes("@vault-str")) return true;
      }
    }
    return false;
  };

  // ---- collect @vault markers ----
  const vaultMarks: number[] = [];
  for (const c of comments) {
    // a marker counts as a function marker only for @vault outside @vault-str
    const tail = src.slice(c.start, c.end).replaceAll("@vault-str", "");
    if (tail.includes("@vault")) vaultMarks.push(c.end);
  }

  // ---- collect secret strings ----
  const strings: SecretString[] = [];
  const replacements: Array<{ start: number; end: number; key: string }> = [];
  const strTable: Record<string, string> = {};

  for (const lit of literals) {
    if (lit.quote === "`") continue; // template handled as code for now
    const inner = src.slice(lit.start + 1, lit.end - 1);
    const auto = SECRET_CONTENT_RE.test(inner);
    const marked = markedComment(lit.start);
    if (!auto && !marked) continue;
    const key = `S${strings.length}`;
    strings.push({ key, value: inner, line: lineOf(src, lit.start), auto });
    strTable[key] = inner;
    replacements.push({ start: lit.start, end: lit.end, key });
  }

  const rewrite = (text: string, base: number): string => {
    let out = text;
    let delta = 0;
    for (const r of replacements) {
      if (r.start < base || r.end > base + text.length) continue;
      const rel = r.start - base + delta;
      const relEnd = r.end - base + delta;
      out = out.slice(0, rel) + `__V.${r.key}` + out.slice(relEnd);
      delta += `__V.${r.key}`.length - (relEnd - rel);
    }
    return out;
  };

  // ---- lift functions ----
  const functions: LiftedFunction[] = [];
  const spans: Array<{ start: number; end: number }> = [];

  const candidates: Array<{ mark: number; auto: boolean }> = vaultMarks.map((m) => ({ mark: m, auto: false }));

  const tryLift = (name: string, headerStart: number, bodyOpen: number, kind: LiftedFunction["kind"], auto: boolean): boolean => {
    if (!name) return false;
    const end = matchBrace(src, bodyOpen);
    if (end === -1) return false;
    if (spans.some((s) => !(end < s.start || headerStart > s.end))) return false; // overlap
    const source = rewrite(src.slice(headerStart, end + 1), headerStart);
    functions.push({
      name,
      params: parseParams(src, src.indexOf("(", headerStart)),
      kind,
      source: source.trim(),
      spanStart: headerStart,
      spanEnd: end + 1,
      startLine: lineOf(src, headerStart),
      endLine: lineOf(src, end),
    });
    spans.push({ start: headerStart, end });
    if (auto) vaultMarks.push(end + 1);
    return true;
  };

  const FN_RE = /(?:export\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/g;
  const ARR_RE = /(?:export\s+)?const\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/g;
  const MET_RE = /(?:async\s*)?([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{/g;

  const near = (pos: number): boolean => {
    const nearest = candidates.reduce<{ d: number } | null>((best, c) => {
      const d = pos - c.mark;
      if (d < 0) return best;
      if (!best || d < best.d) return { d };
      return best;
    }, null);
    return nearest !== null && nearest.d < 80;
  };

  let m: RegExpExecArray | null;
  while ((m = FN_RE.exec(src))) {
    if (!near(m.index)) continue;
    const bodyOpen = src.indexOf("{", m.index);
    tryLift(m[1], m.index, bodyOpen, "function", false);
  }
  while ((m = ARR_RE.exec(src))) {
    if (!near(m.index)) continue;
    const after = src.slice(m.index + m[0].length);
    if (!/^\s*\{/.test(after)) continue; // only block-bodied arrows are liftable
    const bodyOpen = src.indexOf("{", m.index);
    if (bodyOpen === -1) continue;
    tryLift(m[1], m.index, bodyOpen, "arrow", false);
  }
  if (opts.alsoMatch) {
    while ((m = MET_RE.exec(src))) {
      if (!opts.alsoMatch.test(m[1])) continue;
      if (spans.some((s) => m.index >= s.start && m.index <= s.end)) continue;
      const bodyOpen = src.indexOf("{", m.index);
      if (bodyOpen === -1) continue;
      tryLift(m[1], m.index, bodyOpen, "method", true);
    }
  }

  return { file, functions, strings, strTable };
}

/** The hollowed-out local source: lifted bodies are replaced by stubs. */
export function hollowOut(src: string, report: ScanReport): string {
  let out = src;
  for (const fn of [...report.functions].sort((a, b) => b.spanStart - a.spanStart)) {
    const stub = `// [omni-vault] core logic lifted to the cloud — no body ships locally\nexport function ${fn.name}() { throw new Error("[omni-vault] ${fn.name} runs in the cloud vault"); }`;
    out = out.slice(0, fn.spanStart) + stub + out.slice(fn.spanEnd);
  }
  // purge remaining secret literals from the local copy
  for (const [key, value] of Object.entries(report.strTable)) {
    let idx = 0;
    while ((idx = out.indexOf(value, idx)) !== -1) {
      out = out.slice(0, idx) + `[lifted:${key}]` + out.slice(idx + value.length);
      idx += `[lifted:${key}]`.length;
    }
  }
  return out;
}
