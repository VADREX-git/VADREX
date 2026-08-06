import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createHttpsServer, type ServerOptions as HttpsServerOptions } from "node:https";
import type { TLSSocket } from "node:tls";
import type { AuditAggregator, AuditEntryInput } from "./aggregator.js";
import type { AnchorHistoryRecord } from "./aggregator.js";
import type { TransferService } from "./transfer.js";
import { EntryValidationError } from "./validation.js";

export type AnchorNow = () => Promise<AnchorHistoryRecord | null>;

export interface GatewayServerOptions {
  enableDevEndpoints?: boolean;
  anchorContractAddress?: string;
  signingPublicKeyPem?: string;
  transferService?: TransferService;
  requireMtlsForInstitutionEndpoints?: boolean;
  peerCertificateCommonName?: string;
  dicomBodyLimitBytes?: number;
}

const DEFAULT_BODY_LIMIT_BYTES = 1_000_000;
// A DICOM relay carries the whole study base64-encoded, so the ordinary JSON limit is far
// too small for the study sizes used in evaluation.
const DEFAULT_DICOM_BODY_LIMIT_BYTES = 64 * 1024 * 1024;

class PayloadTooLargeError extends Error {}

function sendJson(response: ServerResponse, statusCode: number, body: unknown): void {
  const json = JSON.stringify(body);
  response.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(json)
  });
  response.end(json);
}

function sendNotFound(response: ServerResponse): void {
  sendJson(response, 404, { error: "not found" });
}

function readJson(request: IncomingMessage, maxBytes = DEFAULT_BODY_LIMIT_BYTES): Promise<unknown> {
  return new Promise((resolve, reject) => {
    // Reject on the declared length rather than reading the body first, so an oversized
    // request takes a clean 413 path instead of buffering hundreds of megabytes.
    const declared = Number(request.headers["content-length"]);
    if (Number.isFinite(declared) && declared > maxBytes) {
      reject(new PayloadTooLargeError(`request body exceeds ${maxBytes} bytes`));
      request.resume();
      return;
    }

    const chunks: Uint8Array[] = [];
    let totalLength = 0;

    request.on("data", (chunk: Buffer) => {
      totalLength += chunk.length;
      if (totalLength > maxBytes) {
        reject(new PayloadTooLargeError(`request body exceeds ${maxBytes} bytes`));
        request.destroy();
        return;
      }
      chunks.push(new Uint8Array(chunk));
    });
    request.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve(raw === "" ? null : JSON.parse(raw));
      } catch (error) {
        reject(error);
      }
    });
    request.on("error", reject);
  });
}

function extractEntries(body: unknown): AuditEntryInput[] {
  if (Array.isArray(body)) {
    return body as AuditEntryInput[];
  }
  if (typeof body === "object" && body !== null && Array.isArray((body as { entries?: unknown }).entries)) {
    return (body as { entries: AuditEntryInput[] }).entries;
  }
  throw new Error("expected JSON array or object with entries array");
}

function parsePositiveQueryInteger(value: string | null, name: string): number | null {
  if (value === null || value === "") {
    return null;
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

function statusBody(aggregator: AuditAggregator) {
  return {
    ok: true,
    institutionId: aggregator.institutionId,
    treeSize: aggregator.treeSize(),
    rootHash: aggregator.currentRoot(),
    mapRoot: aggregator.mapRoot(),
    latestAnchor: aggregator.latestAnchor()
  };
}

function isInstitutionEndpoint(pathname: string): boolean {
  return pathname === "/transfer/request" || pathname === "/transfer/dicom" || pathname === "/transfer/receipt";
}

function assertMtlsPeer(request: IncomingMessage, options: GatewayServerOptions): void {
  if (!options.requireMtlsForInstitutionEndpoints) {
    return;
  }
  const socket = request.socket as TLSSocket;
  if (!socket.authorized) {
    throw new Error(`mTLS client certificate was not authorized: ${socket.authorizationError ?? "missing certificate"}`);
  }
  if (options.peerCertificateCommonName) {
    const peer = socket.getPeerCertificate();
    if (!peer || peer.subject?.CN !== options.peerCertificateCommonName) {
      throw new Error(`mTLS peer common name mismatch`);
    }
  }
}

function isClientError(error: unknown): boolean {
  if (error instanceof EntryValidationError || error instanceof SyntaxError) {
    return true;
  }
  if (!(error instanceof Error)) {
    return false;
  }
  return [
    "anchor batch ",
    "anchorBatchId",
    "consent ",
    "consent request body",
    "entryHash ",
    "entryHash query parameter",
    "fromBatchId",
    "key query parameter",
    "peerInstitutionId",
    "purpose must",
    "receiverInstitutionId",
    "studyInstanceUids",
    "toBatchId",
    "validUntil"
  ].some((prefix) => error.message.startsWith(prefix));
}

export function createGatewayRequestHandler(
  aggregator: AuditAggregator,
  anchorNow?: AnchorNow,
  options: GatewayServerOptions = {}
) {
  return (request: IncomingMessage, response: ServerResponse) => {
    void (async () => {
      const url = new URL(request.url ?? "/", "http://localhost");
      if (isInstitutionEndpoint(url.pathname)) {
        assertMtlsPeer(request, options);
      }

      if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
        sendJson(response, 200, statusBody(aggregator));
        return;
      }

      if (request.method === "GET" && url.pathname === "/public-key") {
        if (!options.signingPublicKeyPem) {
          sendJson(response, 404, { error: "signing public key is not configured" });
          return;
        }
        sendJson(response, 200, {
          institutionId: aggregator.institutionId,
          algorithm: "Ed25519",
          publicKeyPem: options.signingPublicKeyPem
        });
        return;
      }

      if (request.method === "POST" && url.pathname === "/consents") {
        const created = aggregator.createConsent(await readJson(request));
        sendJson(response, 200, created);
        return;
      }

      if (request.method === "POST" && url.pathname === "/transfers") {
        if (!options.transferService) {
          sendJson(response, 503, { error: "transfer service is not configured" });
          return;
        }
        sendJson(response, 200, await options.transferService.startTransfer(await readJson(request)));
        return;
      }

      const revokeMatch = url.pathname.match(/^\/consents\/([^/]+)\/revoke$/);
      if (request.method === "POST" && revokeMatch) {
        const consentId = decodeURIComponent(revokeMatch[1]);
        const revoked = options.transferService
          ? await options.transferService.revokeConsentWithBarrier(consentId)
          : aggregator.revokeConsent(consentId);
        sendJson(response, 200, revoked);
        return;
      }

      if (request.method === "POST" && url.pathname === "/transfer/request") {
        if (!options.transferService) {
          sendJson(response, 503, { error: "transfer service is not configured" });
          return;
        }
        sendJson(response, 200, await options.transferService.handleTransferRequest(await readJson(request)));
        return;
      }

      if (request.method === "POST" && url.pathname === "/transfer/dicom") {
        if (!options.transferService) {
          sendJson(response, 503, { error: "transfer service is not configured" });
          return;
        }
        const dicomBody = await readJson(request, options.dicomBodyLimitBytes ?? DEFAULT_DICOM_BODY_LIMIT_BYTES);
        sendJson(response, 200, await options.transferService.handleDicomDelivery(dicomBody));
        return;
      }

      if (request.method === "POST" && url.pathname === "/transfer/receipt") {
        if (!options.transferService) {
          sendJson(response, 503, { error: "transfer service is not configured" });
          return;
        }
        sendJson(response, 200, options.transferService.handleReceipt(await readJson(request)));
        return;
      }

      const chainEntriesMatch = url.pathname.match(/^\/consents\/([^/]+)\/chain-entries$/);
      if (request.method === "GET" && chainEntriesMatch) {
        sendJson(response, 200, {
          entries: aggregator.chainEntries(decodeURIComponent(chainEntriesMatch[1]))
        });
        return;
      }

      if (request.method === "GET" && url.pathname === "/audit-entries") {
        const batchId = parsePositiveQueryInteger(url.searchParams.get("anchorBatchId"), "anchorBatchId");
        const anchor = batchId === null ? null : aggregator.anchorByBatchId(batchId);
        const treeSize = anchor?.treeSize ?? aggregator.treeSize();
        sendJson(response, 200, {
          rootHash: anchor?.rootHash ?? aggregator.currentRoot(),
          treeSize,
          entries: aggregator.auditEntries(treeSize)
        });
        return;
      }

      if (request.method === "GET" && url.pathname === "/proofs/smt") {
        const key = url.searchParams.get("key");
        if (!key) {
          throw new Error("key query parameter is required");
        }
        const batchId = parsePositiveQueryInteger(url.searchParams.get("anchorBatchId"), "anchorBatchId");
        const anchor = batchId === null ? null : aggregator.anchorByBatchId(batchId);
        const mapRoot = anchor?.mapRoot ?? aggregator.mapRoot();
        sendJson(response, 200, {
          mapRoot,
          proof: aggregator.smtProof(key, mapRoot)
        });
        return;
      }

      if (request.method === "GET" && url.pathname === "/proofs/inclusion") {
        const entryHash = url.searchParams.get("entryHash");
        if (!entryHash) {
          throw new Error("entryHash query parameter is required");
        }
        const batchId = parsePositiveQueryInteger(url.searchParams.get("anchorBatchId"), "anchorBatchId");
        const anchor = batchId === null ? null : aggregator.anchorByBatchId(batchId);
        sendJson(response, 200, {
          rootHash: anchor?.rootHash ?? aggregator.currentRoot(),
          treeSize: anchor?.treeSize ?? aggregator.treeSize(),
          ...aggregator.inclusionProofByEntryHash(entryHash, anchor?.treeSize ?? aggregator.treeSize())
        });
        return;
      }

      if (request.method === "GET" && url.pathname === "/proofs/consistency") {
        const fromBatchId = parsePositiveQueryInteger(url.searchParams.get("fromBatchId"), "fromBatchId");
        const toBatchId = parsePositiveQueryInteger(url.searchParams.get("toBatchId"), "toBatchId");
        if (fromBatchId === null || toBatchId === null) {
          throw new Error("fromBatchId and toBatchId are required");
        }
        const from = aggregator.anchorByBatchId(fromBatchId);
        const to = aggregator.anchorByBatchId(toBatchId);
        sendJson(response, 200, {
          proof: aggregator.consistencyProof(from.treeSize, to.treeSize)
        });
        return;
      }

      if (request.method === "GET" && url.pathname === "/anchors") {
        sendJson(response, 200, {
          contractAddress: options.anchorContractAddress ?? null,
          anchors: aggregator.listAnchors()
        });
        return;
      }

      const anchorMatch = url.pathname.match(/^\/anchors\/(\d+)$/);
      if (request.method === "GET" && anchorMatch) {
        sendJson(response, 200, {
          contractAddress: options.anchorContractAddress ?? null,
          anchor: aggregator.anchorByBatchId(Number(anchorMatch[1]))
        });
        return;
      }

      if (options.enableDevEndpoints) {
        if (request.method === "GET" && url.pathname === "/dev/tree") {
          sendJson(response, 200, statusBody(aggregator));
          return;
        }

        if (request.method === "GET" && url.pathname === "/dev/anchors") {
          sendJson(response, 200, { anchors: aggregator.listAnchors() });
          return;
        }

        if (request.method === "POST" && url.pathname === "/dev/audit-entries") {
          const entries = extractEntries(await readJson(request));
          const appended = aggregator.appendEntries(entries);
          sendJson(response, 200, {
            count: appended.length,
            entries: appended,
            treeSize: aggregator.treeSize(),
            rootHash: aggregator.currentRoot(),
            mapRoot: aggregator.mapRoot()
          });
          return;
        }

        if (request.method === "POST" && url.pathname === "/dev/release-peer-hold") {
          const body = await readJson(request);
          const peer = (body as { peerInstitutionId?: unknown } | null)?.peerInstitutionId;
          if (typeof peer !== "string" || peer.length === 0) {
            throw new Error("peerInstitutionId must be a non-empty string");
          }
          sendJson(response, 200, { released: aggregator.releasePeerHold(peer) });
          return;
        }

        if (request.method === "POST" && url.pathname === "/dev/anchor-now") {
          if (!anchorNow) {
            sendJson(response, 503, { error: "anchoring is not configured" });
            return;
          }
          const anchor = await anchorNow();
          sendJson(response, 200, {
            anchored: anchor !== null,
            anchor,
            treeSize: aggregator.treeSize(),
            rootHash: aggregator.currentRoot(),
            mapRoot: aggregator.mapRoot()
          });
          return;
        }
      }

      sendNotFound(response);
    })().catch((error: unknown) => {
      // The socket may already be gone (for example after a body-limit rejection); writing
      // to it then raises an unhandled error and takes the process down.
      if (response.writableEnded || response.destroyed) {
        return;
      }
      try {
        if (error instanceof PayloadTooLargeError) {
          sendJson(response, 413, { error: error.message });
          return;
        }
        if (error instanceof EntryValidationError) {
          sendJson(response, 400, { error: error.message, entryIndex: error.entryIndex });
          return;
        }
        if (error instanceof Error && error.message.startsWith("mTLS ")) {
          sendJson(response, 401, { error: error.message });
          return;
        }
        sendJson(response, isClientError(error) ? 400 : 500, {
          error: error instanceof Error ? error.message : String(error)
        });
      } catch {
        response.destroy();
      }
    });
  };
}

export function createGatewayServer(
  aggregator: AuditAggregator,
  anchorNow?: AnchorNow,
  options: GatewayServerOptions = {}
) {
  return createServer(createGatewayRequestHandler(aggregator, anchorNow, options));
}

export function createGatewayHttpsServer(
  tlsOptions: HttpsServerOptions,
  aggregator: AuditAggregator,
  anchorNow?: AnchorNow,
  options: GatewayServerOptions = {}
) {
  return createHttpsServer(tlsOptions, createGatewayRequestHandler(aggregator, anchorNow, options));
}
