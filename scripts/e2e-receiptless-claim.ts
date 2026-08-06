import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { gatewayUrl, getGateway, patientTransferBody, postGateway, resolveStudyUid, rootDir } from "./scenario-client.js";
import { defaultDeploymentPath, readAnchorAddress } from "../packages/gateway/src/config.js";
import { VERIFIER_VERDICTS } from "../packages/verifier-cli/src/verdicts.js";

// S3 injection: provider A claims a transfer completed without holding a receipt for it.
// The receipt times out, so A never records TRANSFER_COMPLETED, and resolve-dispute must
// reject the claim for want of anchored receipt evidence even though A can point at its
// approval entry.

interface CreatedConsent {
  consentId: string;
  secretC: string;
}

interface TransferResponse {
  status: string;
}

interface ChainResponse {
  entries: { eventType: string; entryHash: string; leafIndex: number }[];
}

interface AnchorsResponse {
  anchors: { batchId: number; treeSize: number }[];
}

const REJECTION_VERDICT = VERIFIER_VERDICTS.aClaimNotEstablished;

function tlsOptions() {
  const instDir = join(rootDir, "scripts", "out", "inst-a");
  return {
    caPath: join(instDir, "ca.cert.pem"),
    certPath: join(instDir, "cert.pem"),
    keyPath: join(instDir, "key.pem")
  };
}

function verifierCliPath(): string {
  return join(rootDir, "packages", "verifier-cli", "dist", "index.js");
}

function publicKeyPath(institution: "a" | "b"): string {
  return join(rootDir, "scripts", "out", `inst-${institution}`, "ed25519.pub");
}

function runVerifierCliExpectRejection(args: string[], expectedVerdict: string): void {
  const result = spawnSync(process.execPath, [verifierCliPath(), ...args], {
    cwd: rootDir,
    env: process.env,
    encoding: "utf8"
  });
  if (result.stdout) {
    process.stdout.write(result.stdout);
  }
  if (result.stderr) {
    process.stderr.write(result.stderr);
  }
  if (result.error) {
    throw result.error;
  }
  if (result.status === 0) {
    throw new Error("resolve-dispute accepted a transfer claim that has no anchored receipt");
  }
  const output = `${result.stdout}\n${result.stderr}`;
  if (!output.includes(expectedVerdict)) {
    throw new Error(`claim was rejected, but not with the expected verdict: ${expectedVerdict}`);
  }
}

async function waitForChainEntry(
  institution: "A" | "B",
  consentId: string,
  eventType: string,
  peerCertDir: "a" | "b",
  timeoutMs = 60_000
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  do {
    const chain = await getGateway<ChainResponse>(institution, `/consents/${consentId}/chain-entries`, peerCertDir);
    if (chain.entries.some((entry) => entry.eventType === eventType)) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  } while (Date.now() < deadline);
  throw new Error(`${institution} did not record ${eventType} within ${timeoutMs}ms`);
}

async function anchorUntilCovered(
  institution: "A" | "B",
  consentId: string,
  eventType: string,
  peerCertDir: "a" | "b"
): Promise<void> {
  // A periodic anchor can land just before the entry was written, so keep anchoring until one
  // covers that leaf.
  const deadline = Date.now() + 30_000;
  do {
    await postGateway(institution, "/dev/anchor-now", {}, peerCertDir);
    const chain = await getGateway<ChainResponse>(institution, `/consents/${consentId}/chain-entries`, peerCertDir);
    const entry = chain.entries.find((candidate) => candidate.eventType === eventType);
    const anchors = await getGateway<AnchorsResponse>(institution, "/anchors", peerCertDir);
    if (entry && anchors.anchors.some((anchor) => anchor.treeSize > entry.leafIndex)) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  } while (Date.now() < deadline);
  throw new Error(`${institution} ${eventType} was not anchored within timeout`);
}

async function main(): Promise<void> {
  const studyInstanceUid = await resolveStudyUid();
  const purpose = process.env.SCENARIO_PURPOSE ?? "research";
  const rpcUrl = process.env.CHAIN_RPC_URL_HOST ?? process.env.CHAIN_RPC_URL ?? "http://127.0.0.1:8545";
  // Trust anchor: contract addresses come from the local deployment file, not from the gateway.
  const deploymentPath = defaultDeploymentPath(rootDir);
  const aAnchorAddress = readAnchorAddress(deploymentPath, "A");
  const bAnchorAddress = readAnchorAddress(deploymentPath, "B");
  console.log(`  studyInstanceUid=${studyInstanceUid}`);

  console.log("[1/4] Start a transfer whose receipt does not arrive before the timeout");
  const consent = await postGateway<CreatedConsent>("A", "/consents", {
    receiverInstitutionId: "B",
    studyInstanceUids: [studyInstanceUid],
    purpose,
    validUntil: Math.floor(Date.now() / 1000) + 3600
  }, "b");
  const transfer = await postGateway<TransferResponse>("B", "/transfers",
    patientTransferBody(consent, studyInstanceUid, purpose), "a");
  console.log(`  transferStatus=${transfer.status}`);
  if (transfer.status !== "UNCONFIRMED") {
    throw new Error(
      `expected UNCONFIRMED, got ${transfer.status}; start compose with SIMULATED_RECEIPT_DELAY_MS greater than RECEIPT_TIMEOUT_SEC * 1000`
    );
  }

  console.log("[2/4] Wait for B's late receive entry and anchor both institutions");
  // A keeps the late receipt as RECEIPT_LATE, off the chain, so its consent chain never gains a
  // TRANSFER_COMPLETED. B's RECEIVE_COMPLETED appears later.
  await waitForChainEntry("B", consent.consentId, "RECEIVE_COMPLETED", "a");
  await anchorUntilCovered("B", consent.consentId, "RECEIVE_COMPLETED", "a");
  await anchorUntilCovered("A", consent.consentId, "TRANSFER_APPROVED", "b");

  const chainA = await getGateway<ChainResponse>("A", `/consents/${consent.consentId}/chain-entries`, "b");
  if (chainA.entries.some((entry) => entry.eventType === "TRANSFER_COMPLETED")) {
    throw new Error("A recorded TRANSFER_COMPLETED; this scenario requires a settled-unconfirmed transfer");
  }
  const approved = chainA.entries.find((entry) => entry.eventType === "TRANSFER_APPROVED");
  if (!approved) {
    throw new Error("missing TRANSFER_APPROVED entry");
  }
  console.log(`  transferRef=${approved.entryHash} (A holds no TRANSFER_COMPLETED)`);

  console.log("[3/4] A claims the transfer completed; resolve-dispute must reject the claim");
  const tls = tlsOptions();
  runVerifierCliExpectRejection([
    "resolve-dispute",
    "--transfer-ref", approved.entryHash,
    "--a-gateway", gatewayUrl("A"),
    "--b-gateway", gatewayUrl("B"),
    "--rpc-url", rpcUrl,
    "--a-anchor-address", aAnchorAddress,
    "--b-anchor-address", bAnchorAddress,
    "--a-public-key", publicKeyPath("a"),
    "--b-public-key", publicKeyPath("b"),
    "--tls-ca", tls.caPath,
    "--tls-cert", tls.certPath,
    "--tls-key", tls.keyPath
  ], REJECTION_VERDICT);
  console.log("  claim rejected as incomplete: no anchored receipt binds the transfer to A");

  console.log("[4/4] Release the peer hold so later scenarios are not blocked");
  // The verdict is already settled above. Failing the scenario on a transient error in this
  // cleanup would record a successful detection as a failure, so a persistent error only warns:
  // the evaluation harness clears stale holds between scenarios anyway.
  let released: boolean | null = null;
  for (let attempt = 1; attempt <= 3 && released === null; attempt += 1) {
    try {
      const response = await postGateway<{ released: boolean }>("A", "/dev/release-peer-hold", { peerInstitutionId: "B" }, "b");
      released = response.released;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (attempt === 3) {
        console.warn(`  WARN: peer hold release failed after ${attempt} attempts (${message}); harness will retry between scenarios`);
        break;
      }
      console.warn(`  peer hold release transient failure (${message}); retrying`);
      await new Promise((resolve) => setTimeout(resolve, 750 * attempt));
    }
  }
  if (released !== null) {
    console.log(`  released=${released}`);
  }

  console.log("e2e-receiptless-claim SUCCESS");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
