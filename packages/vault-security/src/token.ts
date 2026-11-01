/**
 * Omni-Vault · client bearer tokens.
 *
 * A token is minted by the provisioning authority (vault_extractor) and binds:
 *   - the client's static X25519 public key (identity, `pub`)
 *   - the callable cloud function scope
 *   - an expiry
 * The token is signed with the server's Ed25519 signing key. The matching
 * verify key is *pinned* into the shell at build time, so a man-in-the-middle
 * cannot forge tokens or impersonate the server.
 */
import { b64, ed25519Sign, ed25519Verify, ed25519FromPrivate, ed25519FromPublic, randomBytes } from "./crypto.ts";
import type { KeyObject } from "node:crypto";

export interface TokenClaims {
  v: 1;
  iss: "omni-vault";
  jti: string;
  scope: string[];
  pub: string;
  iat: number;
  exp: number;
}

export interface IssueInput {
  scope: string[];
  clientPublicDer: Buffer;
  ttlMs: number;
}

export function issueToken(signPrivate: KeyObject, input: IssueInput): string {
  const iat = Date.now();
  const claims: TokenClaims = {
    v: 1,
    iss: "omni-vault",
    jti: randomBytes(16).toString("hex"),
    scope: input.scope,
    pub: b64.enc(input.clientPublicDer),
    iat,
    exp: iat + input.ttlMs,
  };
  const payload = b64.enc(Buffer.from(JSON.stringify(claims), "utf8"));
  const sig = ed25519Sign(payload, signPrivate);
  return `ov1.${payload}.${b64.enc(sig)}`;
}

export function verifyToken(token: string, signPublic: KeyObject): TokenClaims | null {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== "ov1") return null;
  const [, payload, sig] = parts;
  if (!ed25519Verify(payload, b64.dec(sig), signPublic)) return null;
  let claims: TokenClaims;
  try {
    claims = JSON.parse(b64.dec(payload).toString("utf8"));
  } catch {
    return null;
  }
  if (claims.v !== 1 || claims.iss !== "omni-vault") return null;
  if (typeof claims.exp !== "number" || Date.now() > claims.exp) return null;
  return claims;
}

/** Which cloud functions may this token invoke? Supports `pkg:*` wildcards. */
export function scopeAllows(claims: TokenClaims, fn: string): boolean {
  return claims.scope.some((s) => s === fn || (s.endsWith(".*") && fn.startsWith(s.slice(0, -1))));
}

export function tokenToKeyObjects() {
  return { ed25519FromPrivate, ed25519FromPublic };
}
