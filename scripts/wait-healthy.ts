// Bounded wait for the stack to become healthy, naming the services that did not come up.
//
// Some of the probes need mTLS, so this reuses the repository's TLS helper rather than living in
// the PowerShell bootstrap.
import { requestBuffer } from "../packages/gateway/src/httpClient.js";
import { getGateway, tlsForClient } from "./scenario-client.js";

interface Check {
  name: string;
  probe: () => Promise<void>;
}

function orthancUrl(institution: "a" | "b"): string {
  const fallback = institution === "a" ? "https://localhost:8042" : "https://localhost:8043";
  const configured = institution === "a" ? process.env.ORTHANC_A_URL : process.env.ORTHANC_B_URL;
  return (configured ?? fallback).replace(/\/$/, "");
}

async function probeOrthanc(institution: "a" | "b"): Promise<void> {
  const response = await requestBuffer(`${orthancUrl(institution)}/dicom-web/studies`, {
    tls: tlsForClient(institution),
    headers: { accept: "application/dicom+json" },
    timeoutMs: 10_000
  });
  // With no studies loaded the response is 204; any 2xx means mTLS and DICOMweb are up.
  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw new Error(`HTTP ${response.statusCode}`);
  }
}

async function probeGateway(id: "A" | "B"): Promise<void> {
  const peer = id === "A" ? "b" : "a";
  await getGateway(id, "/health", peer);
  await getGateway(id, "/anchors", peer);
}

const checks: Check[] = [
  { name: "orthanc-a", probe: () => probeOrthanc("a") },
  { name: "orthanc-b", probe: () => probeOrthanc("b") },
  { name: "gateway-a", probe: () => probeGateway("A") },
  { name: "gateway-b", probe: () => probeGateway("B") }
];

function parseTimeoutSeconds(): number {
  const index = process.argv.indexOf("--timeout");
  const parsed = index >= 0 ? Number(process.argv[index + 1]) : Number.NaN;
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : 300;
}

async function main(): Promise<void> {
  const deadline = Date.now() + parseTimeoutSeconds() * 1000;
  const pending = new Map(checks.map((check) => [check.name, check]));
  let lastError = "";

  while (pending.size > 0) {
    for (const [name, check] of Array.from(pending)) {
      try {
        await check.probe();
        pending.delete(name);
        console.log(`  healthy: ${name}`);
      } catch (error) {
        lastError = `${name}: ${error instanceof Error ? error.message : String(error)}`;
      }
    }
    if (pending.size === 0) {
      break;
    }
    if (Date.now() >= deadline) {
      throw new Error(`not healthy within timeout: ${Array.from(pending.keys()).join(", ")} (last error — ${lastError})`);
    }
    await new Promise((resolve) => setTimeout(resolve, 3_000));
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
