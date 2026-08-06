import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import { deriveReceiverSecret } from "@vadrex/merkle";
import { requestBuffer, requestJson, type TlsMaterial } from "../packages/gateway/src/httpClient.js";
import { createTransferToken } from "../packages/gateway/src/token.js";

export const rootDir = resolve(fileURLToPath(new URL("..", import.meta.url)));

export function gatewayUrl(id: "A" | "B"): string {
  const env = id === "A" ? process.env.GATEWAY_A_URL : process.env.GATEWAY_B_URL;
  return (env ?? `https://localhost:${id === "A" ? 7001 : 7002}`).replace(/\/$/, "");
}

export function tlsForClient(institution: "a" | "b"): TlsMaterial {
  const instDir = join(rootDir, "scripts", "out", `inst-${institution}`);
  return {
    cert: readFileSync(join(instDir, "cert.pem")),
    key: readFileSync(join(instDir, "key.pem")),
    ca: readFileSync(join(instDir, "ca.cert.pem")),
    rejectUnauthorized: true
  };
}

export async function postGateway<T>(id: "A" | "B", path: string, body: unknown, institution: "a" | "b" = "a"): Promise<T> {
  return requestJson<T>(`${gatewayUrl(id)}${path}`, body, { tls: tlsForClient(institution), timeoutMs: 60_000 });
}

export async function getGateway<T>(id: "A" | "B", path: string, institution: "a" | "b" = "a"): Promise<T> {
  const response = await requestBuffer(`${gatewayUrl(id)}${path}`, {
    tls: tlsForClient(institution),
    timeoutMs: 30_000
  });
  const text = response.body.toString("utf8");
  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw new Error(`GET ${path} returned HTTP ${response.statusCode}: ${text}`);
  }
  return JSON.parse(text) as T;
}

export function orthancAUrl(): string {
  return (process.env.ORTHANC_A_URL ?? "https://localhost:8042").replace(/\/$/, "");
}

// Without SCENARIO_STUDY_UID the first study in Orthanc A is used. A default that is not an
// actual study UID makes the transfer end in FAILED with little to explain why.
export async function resolveStudyUid(): Promise<string> {
  if (process.env.SCENARIO_STUDY_UID) {
    return process.env.SCENARIO_STUDY_UID;
  }
  const response = await requestBuffer(`${orthancAUrl()}/dicom-web/studies`, {
    tls: tlsForClient("a"),
    headers: { accept: "application/dicom+json" },
    timeoutMs: 30_000
  });
  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw new Error(`Orthanc A QIDO returned HTTP ${response.statusCode}: ${response.body.toString("utf8")}`);
  }
  const text = response.body.toString("utf8");
  const studies = text ? (JSON.parse(text) as { "0020000D"?: { Value?: string[] } }[]) : [];
  const uid = Array.isArray(studies) ? studies[0]?.["0020000D"]?.Value?.[0] : undefined;
  if (!uid) {
    throw new Error("Orthanc A has no studies; run scripts/load-dicom.ps1 first or set SCENARIO_STUDY_UID");
  }
  return uid;
}

// Patient-role helper. B is given the derived key and a signed token, never the raw secretC;
// verifying the token is the provider's job.
export function patientTransferBody(
  consent: { consentId: string; secretC: string },
  studyInstanceUid: string,
  purpose: string
): Record<string, unknown> {
  const ttlSeconds = process.env.AUTH_TOKEN_TTL_SEC ? Number(process.env.AUTH_TOKEN_TTL_SEC) : 60;
  return {
    consentId: consent.consentId,
    receiverSecret: `0x${Buffer.from(deriveReceiverSecret(consent.secretC)).toString("hex")}`,
    authorizationToken: createTransferToken(
      consent.secretC,
      { consentId: consent.consentId, studyInstanceUid, purpose },
      ttlSeconds
    ).token,
    studyInstanceUid,
    purpose
  };
}
