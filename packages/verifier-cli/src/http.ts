import { readFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { RequestOptions } from "node:https";

export interface TlsOptions {
  caPath?: string;
  certPath?: string;
  keyPath?: string;
  insecure?: boolean;
}

export interface CallCounter {
  apiCalls: number;
  rpcCalls: number;
  apiRequestBytes?: number;
  apiResponseBytes?: number;
}

export class HttpError extends Error {
  constructor(
    readonly url: string,
    readonly statusCode: number,
    readonly body: string
  ) {
    super(`GET ${url} returned HTTP ${statusCode}: ${body}`);
  }
}

function tlsRequestOptions(url: URL, tls: TlsOptions): RequestOptions {
  return {
    protocol: url.protocol,
    hostname: url.hostname,
    port: url.port,
    path: `${url.pathname}${url.search}`,
    method: "GET",
    ca: tls.caPath ? readFileSync(tls.caPath) : undefined,
    cert: tls.certPath ? readFileSync(tls.certPath) : undefined,
    key: tls.keyPath ? readFileSync(tls.keyPath) : undefined,
    rejectUnauthorized: tls.insecure ? false : undefined
  };
}

export class GatewayClient {
  readonly baseUrl: string;

  constructor(
    baseUrl: string,
    private readonly tls: TlsOptions,
    private readonly counter: CallCounter,
    readonly label: string
  ) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  async get<T>(path: string): Promise<T> {
    const maybe = await this.tryGet<T>(path);
    if (!maybe.ok) {
      throw new HttpError(maybe.url, maybe.statusCode, maybe.body);
    }
    return maybe.value;
  }

  async tryGet<T>(path: string): Promise<
    | { ok: true; url: string; value: T }
    | { ok: false; url: string; statusCode: number; body: string }
  > {
    const url = new URL(path, `${this.baseUrl}/`);
    this.counter.apiCalls += 1;
    this.counter.apiRequestBytes = (this.counter.apiRequestBytes ?? 0) + Buffer.byteLength(`${url.pathname}${url.search}`, "utf8");
    return new Promise((resolve, reject) => {
      const transport = url.protocol === "https:" ? httpsRequest : httpRequest;
      const request = transport(tlsRequestOptions(url, this.tls), (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () => {
          const bodyBuffer = Buffer.concat(chunks);
          this.counter.apiResponseBytes = (this.counter.apiResponseBytes ?? 0) + bodyBuffer.length;
          const body = bodyBuffer.toString("utf8");
          const statusCode = response.statusCode ?? 0;
          if (statusCode < 200 || statusCode >= 300) {
            resolve({ ok: false, url: url.toString(), statusCode, body });
            return;
          }
          try {
            resolve({ ok: true, url: url.toString(), value: JSON.parse(body) as T });
          } catch (error) {
            reject(error);
          }
        });
      });
      request.on("error", reject);
      request.end();
    });
  }
}
