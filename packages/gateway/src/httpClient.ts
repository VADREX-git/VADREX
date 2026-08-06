import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { RequestOptions } from "node:https";

export interface TlsMaterial {
  cert?: Buffer | string;
  key?: Buffer | string;
  ca?: Buffer | string;
  rejectUnauthorized?: boolean;
}

export interface HttpResponseBuffer {
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}

export interface HttpRequestOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: Buffer | string;
  tls?: TlsMaterial;
  timeoutMs?: number;
}

export function requestBuffer(urlString: string, options: HttpRequestOptions = {}): Promise<HttpResponseBuffer> {
  const url = new URL(urlString);
  const body = typeof options.body === "string" ? Buffer.from(options.body) : options.body;
  const headers = { ...(options.headers ?? {}) };
  if (body && !("content-length" in lowerHeaderMap(headers))) {
    headers["content-length"] = String(body.length);
  }
  const requestOptions: RequestOptions = {
    protocol: url.protocol,
    hostname: url.hostname,
    port: url.port,
    path: `${url.pathname}${url.search}`,
    method: options.method ?? "GET",
    headers,
    cert: options.tls?.cert,
    key: options.tls?.key,
    ca: options.tls?.ca,
    rejectUnauthorized: options.tls?.rejectUnauthorized
  };
  const transport = url.protocol === "https:" ? httpsRequest : httpRequest;

  return new Promise((resolve, reject) => {
    const req = transport(requestOptions, (res) => {
      const chunks: Uint8Array[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(new Uint8Array(chunk)));
      res.on("end", () => {
        resolve({
          statusCode: res.statusCode ?? 0,
          headers: res.headers,
          body: Buffer.concat(chunks)
        });
      });
    });
    req.on("error", reject);
    if (options.timeoutMs) {
      req.setTimeout(options.timeoutMs, () => {
        req.destroy(new Error(`request timed out after ${options.timeoutMs}ms`));
      });
    }
    if (body) {
      req.write(body);
    }
    req.end();
  });
}

export async function requestJson<T>(url: string, body: unknown, options: HttpRequestOptions = {}): Promise<T> {
  const response = await requestBuffer(url, {
    ...options,
    method: options.method ?? "POST",
    headers: {
      "content-type": "application/json",
      ...(options.headers ?? {})
    },
    body: JSON.stringify(body)
  });
  const text = response.body.toString("utf8");
  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw new Error(`HTTP ${response.statusCode} from ${url}: ${text}`);
  }
  return (text ? JSON.parse(text) : null) as T;
}

function lowerHeaderMap(headers: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));
}
