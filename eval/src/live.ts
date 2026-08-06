import { join } from "node:path";
import type { AuditEntry } from "@vadrex/shared";
import { defaultDeploymentPath, readAnchorAddress } from "../../packages/gateway/src/config.js";
import { AnchorReader } from "../../packages/verifier-cli/src/anchor.js";
import { GatewayClient, type TlsOptions } from "../../packages/verifier-cli/src/http.js";
import { gatewayUrl, getGateway, patientTransferBody, postGateway, rootDir } from "../../scripts/scenario-client.js";
import { run } from "./common.js";

export interface CreatedConsent {
  consentId: string;
  secretC: string;
}

export interface RevokedResponse {
  seq: number;
  entryHash: string;
}

export interface TransferResponse {
  status: string;
  seq: number;
  approvalEntryHash: string;
}

export interface PinnedAnchors {
  a: string;
  b: string;
}

export function rpcUrl(): string {
  return process.env.CHAIN_RPC_URL_HOST ?? process.env.CHAIN_RPC_URL ?? "http://127.0.0.1:8545";
}

export function pinnedAnchors(): PinnedAnchors {
  const deploymentPath = defaultDeploymentPath(rootDir);
  return {
    a: readAnchorAddress(deploymentPath, "A"),
    b: readAnchorAddress(deploymentPath, "B")
  };
}

export function verifierTlsOptions(): TlsOptions {
  const instDir = join(rootDir, "scripts", "out", "inst-a");
  return {
    caPath: join(instDir, "ca.cert.pem"),
    certPath: join(instDir, "cert.pem"),
    keyPath: join(instDir, "key.pem")
  };
}

export async function waitForGateway(id: "A" | "B", timeoutMs = 120_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await getGateway(id, "/health", id === "A" ? "b" : "a");
      await getGateway(id, "/anchors", id === "A" ? "b" : "a");
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 1_000));
    }
  }
  throw new Error(`gateway-${id.toLowerCase()} did not become healthy within ${timeoutMs}ms`);
}

export async function createConsent(studyInstanceUid: string, purpose = "research"): Promise<CreatedConsent> {
  return postGateway<CreatedConsent>("A", "/consents", {
    receiverInstitutionId: "B",
    studyInstanceUids: [studyInstanceUid],
    purpose,
    validUntil: Math.floor(Date.now() / 1000) + 3600
  }, "b");
}

export async function revokeConsent(consentId: string): Promise<RevokedResponse> {
  return postGateway<RevokedResponse>("A", `/consents/${consentId}/revoke`, {}, "b");
}

export async function startTransfer(consent: CreatedConsent, studyInstanceUid: string, purpose = "research"): Promise<TransferResponse> {
  return postGateway<TransferResponse>("B", "/transfers", patientTransferBody(consent, studyInstanceUid, purpose), "a");
}

export async function anchorNow(id: "A" | "B"): Promise<void> {
  await retryTransient(`anchorNow(${id})`, () => postGateway(id, "/dev/anchor-now", {}, id === "A" ? "b" : "a"));
}

export async function releasePeerHold(peerInstitutionId = "B"): Promise<void> {
  await retryTransient("releasePeerHold", () => postGateway("A", "/dev/release-peer-hold", { peerInstitutionId }, "b"));
}

export async function addCheckpointAndAnchor(id: "A" | "B", label: string): Promise<void> {
  const entry: Omit<AuditEntry, "entryHash"> = {
    eventType: "CROSS_CHECKPOINT",
    timestamp: Math.floor(Date.now() / 1000),
    institutionId: id,
    consentId: null,
    seq: null,
    prevHash: null,
    requestContext: { eval: "8A", label },
    peerEntryHash: null,
    peerSignature: null
  };
  await postGateway(id, "/dev/audit-entries", { entries: [entry] }, id === "A" ? "b" : "a");
  await anchorNow(id);
}

export async function createAnchors(id: "A" | "B", count: number, label: string): Promise<void> {
  for (let index = 0; index < count; index += 1) {
    await addCheckpointAndAnchor(id, `${label}-${index + 1}`);
  }
}

export async function chainAnchors(address: string) {
  const counter = { apiCalls: 0, rpcCalls: 0, apiRequestBytes: 0, apiResponseBytes: 0 };
  const reader = new AnchorReader(rpcUrl(), address, counter);
  return reader.anchors();
}

export async function waitForAnchoredEntry(
  gatewayId: "A" | "B",
  address: string,
  entryHash: string,
  timeoutMs: number
): Promise<{ batchId: number; anchoredAt: number; treeSize: number }> {
  const started = Date.now();
  const gateway = new GatewayClient(gatewayUrl(gatewayId), verifierTlsOptions(), {
    apiCalls: 0,
    rpcCalls: 0,
    apiRequestBytes: 0,
    apiResponseBytes: 0
  }, gatewayId);
  while (Date.now() - started < timeoutMs) {
    const anchors = await chainAnchors(address);
    // A just-anchored entry sits in the newest anchor. Scanning oldest-first costs one inclusion
    // query per accumulated anchor, which grows into thousands of requests and times out in the
    // measurements that run once anchors have piled up.
    for (const anchor of [...anchors].reverse()) {
      const proof = await gateway.tryGet(`/proofs/inclusion?entryHash=${encodeURIComponent(entryHash)}&anchorBatchId=${anchor.batchId}`);
      if (proof.ok) {
        return { batchId: anchor.batchId, anchoredAt: anchor.anchoredAt, treeSize: anchor.treeSize };
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  throw new Error(`entry ${entryHash} was not anchored by gateway ${gatewayId} within ${timeoutMs}ms`);
}

export async function restartGatewaysWithAnchorInterval(intervalSeconds: number, maxIntervalSeconds = intervalSeconds): Promise<void> {
  const env = {
    ...process.env,
    ANCHOR_INTERVAL_SEC: String(intervalSeconds),
    ANCHOR_MAX_INTERVAL_SEC: String(maxIntervalSeconds),
    ENABLE_DEV_ENDPOINTS: "true"
  };
  run("docker", ["compose", "up", "-d", "gateway-a", "gateway-b"], { env });
  await waitForGateway("A");
  await waitForGateway("B");
}

export async function restartGatewaysWithRuntimeEnv(options: {
  anchorIntervalSec?: number;
  anchorMaxIntervalSec?: number;
  receiptTimeoutSec?: number;
  simulatedReceiptDelayMs?: number;
  dicomMaxBodyBytes?: number;
} = {}): Promise<void> {
  const env = {
    ...process.env,
    ANCHOR_INTERVAL_SEC: String(options.anchorIntervalSec ?? parsePositiveEnv(process.env.ANCHOR_INTERVAL_SEC, 30)),
    ANCHOR_MAX_INTERVAL_SEC: String(options.anchorMaxIntervalSec ?? parsePositiveEnv(process.env.ANCHOR_MAX_INTERVAL_SEC, options.anchorIntervalSec ?? 30)),
    RECEIPT_TIMEOUT_SEC: String(options.receiptTimeoutSec ?? parsePositiveEnv(process.env.RECEIPT_TIMEOUT_SEC, 30)),
    SIMULATED_RECEIPT_DELAY_MS: String(options.simulatedReceiptDelayMs ?? parseNonNegativeEnv(process.env.SIMULATED_RECEIPT_DELAY_MS, 0)),
    DICOM_MAX_BODY_BYTES: String(options.dicomMaxBodyBytes ?? parsePositiveEnv(process.env.DICOM_MAX_BODY_BYTES, 64 * 1024 * 1024)),
    ENABLE_DEV_ENDPOINTS: "true"
  };
  run("docker", ["compose", "up", "-d", "gateway-a", "gateway-b"], { env });
  await waitForGateway("A");
  await waitForGateway("B");
}

export async function restoreGatewaysFromProcessEnv(): Promise<void> {
  await restartGatewaysWithRuntimeEnv();
}

function parsePositiveEnv(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function parseNonNegativeEnv(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : fallback;
}

/**
 * Retries a transient failure in a measurement's setup step.
 *
 * The failures observed here come from the host to Orthanc STOW/WADO path through the Docker
 * Desktop proxy, not from the gateway transfer, so the transfer-level retries do not cover them.
 * Retrying a STOW is safe because Orthanc deduplicates a re-upload of the same SOP instance.
 * When fn wraps timed(), only the successful attempt is timed, so the measurement stays clean.
 */
export async function retryTransientStep<T>(fn: () => Promise<T>, attempts = 8): Promise<T> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (attempt === attempts || !isTransientError(error)) {
        throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, Math.min(10_000, 3_000 * attempt)));
    }
  }
  throw lastError;
}

async function retryTransient<T>(label: string, fn: () => Promise<T>, attempts = 4): Promise<T> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (attempt === attempts || !isTransientError(error)) {
        throw error;
      }
      const delayMs = 500 * attempt;
      console.warn(`${label} transient failure (${error instanceof Error ? error.message : String(error)}); retrying in ${delayMs}ms`);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  throw lastError;
}

export function isTransientError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /NONCE_EXPIRED|Nonce too low|nonce has already been used|ECONNRESET|socket hang up|ECONNREFUSED|ETIMEDOUT/i.test(message);
}
