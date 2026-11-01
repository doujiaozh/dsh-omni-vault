/**
 * Omni-Vault · provisioning.
 *
 * Minted once by vault_extractor at build time:
 *   - the cloud side gets a long-term Ed25519 signing key (handshake
 *     signatures) + a static X25519 key (client identity proof)
 *   - the client gets a static X25519 identity key + a bearer token bound to
 *     that key and to a function scope
 * Nothing here is business logic — only identity.
 */
import {
  ed25519FromPrivate,
  ed25519Generate,
  x25519Generate,
  issueToken,
  b64,
} from "../../vault-security/src/index.ts";

export interface ServerKeys {
  signPrivateDer: string;
  signPublicDer: string;
  x25519PrivateDer: string;
  x25519PublicDer: string;
}

export interface ClientBundle {
  privateDer: string;
  publicDer: string;
  token: string;
  scope: string[];
}

export function provisionServer(): ServerKeys {
  const sign = ed25519Generate();
  const x = x25519Generate();
  return {
    signPrivateDer: b64.enc(sign.privateDer),
    signPublicDer: b64.enc(sign.publicDer),
    x25519PrivateDer: b64.enc(x.privateDer),
    x25519PublicDer: b64.enc(x.publicDer),
  };
}

export function provisionClient(
  serverKeys: ServerKeys,
  scope: string[],
  ttlMs: number,
): ClientBundle {
  const client = x25519Generate();
  const signPrivate = ed25519FromPrivate(Buffer.from(serverKeys.signPrivateDer, "base64"));
  const token = issueToken(signPrivate, { scope, clientPublicDer: client.publicDer, ttlMs });
  return {
    privateDer: b64.enc(client.privateDer),
    publicDer: b64.enc(client.publicDer),
    token,
    scope,
  };
}
