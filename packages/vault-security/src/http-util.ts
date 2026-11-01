/**
 * Omni-Vault · tiny HTTP helpers (JSON handshake frames + binary RPC frames).
 */
import * as http from "node:http";

export interface HttpResponse {
  status: number;
  body: Buffer;
}

function request(
  url: string,
  method: string,
  body: Buffer,
  headers: Record<string, string>,
): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port || 80,
        path: u.pathname + u.search,
        method,
        headers: { ...headers, "content-length": String(body.length) },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 500, body: Buffer.concat(chunks) }));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

export async function postJson<T>(url: string, payload: unknown): Promise<T> {
  const res = await request(
    url,
    "POST",
    Buffer.from(JSON.stringify(payload), "utf8"),
    { "content-type": "application/json" },
  );
  if (res.status >= 400) {
    let detail = res.body.toString("utf8");
    try {
      detail = JSON.parse(detail)?.message ?? detail;
    } catch {
      /* keep raw */
    }
    throw new Error(`HTTP ${res.status}: ${detail}`);
  }
  return JSON.parse(res.body.toString("utf8")) as T;
}

export async function postBinary(
  url: string,
  body: Buffer,
  sid: string,
): Promise<HttpResponse> {
  return request(url, "POST", body, {
    "content-type": "application/octet-stream",
    "x-omni-sid": sid,
  });
}
