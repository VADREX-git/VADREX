import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { getGateway, gatewayUrl, patientTransferBody, postGateway, resolveStudyUid, rootDir } from "./scenario-client.js";
import { defaultDeploymentPath, readAnchorAddress } from "../packages/gateway/src/config.js";

interface CreatedConsent {
  consentId: string;
  secretC: string;
}

interface TransferResponse {
  status: string;
}

interface RevokedResponse {
  seq: number;
  entryHash: string;
}

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

function runVerifierCli(args: string[]): void {
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
  if (result.status !== 0) {
    throw new Error(`verify-non-transfer did not succeed: exit ${result.status ?? "unknown"}`);
  }
}

async function main(): Promise<void> {
  const studyInstanceUid = await resolveStudyUid();
  const purpose = process.env.SCENARIO_PURPOSE ?? "research";
  const graceSeconds = process.env.E2E_GRACE_SEC ? Number(process.env.E2E_GRACE_SEC) : 0;
  const rpcUrl = process.env.CHAIN_RPC_URL_HOST ?? process.env.CHAIN_RPC_URL ?? "http://127.0.0.1:8545";
  // Trust anchor: contract addresses come from the local deployment file, not from a gateway
  // response. With the override set the verifier never asks a gateway for an address.
  const deploymentPath = defaultDeploymentPath(rootDir);
  const providerAnchorAddress = readAnchorAddress(deploymentPath, "A");
  const receiverAnchorAddress = readAnchorAddress(deploymentPath, "B");

  console.log("[1/5] Create consent and complete a normal transfer");
  const consent = await postGateway<CreatedConsent>("A", "/consents", {
    receiverInstitutionId: "B",
    studyInstanceUids: [studyInstanceUid],
    purpose,
    validUntil: Math.floor(Date.now() / 1000) + 3600
  }, "b");
  const transfer = await postGateway<TransferResponse>("B", "/transfers", patientTransferBody(consent, studyInstanceUid, purpose), "a");
  console.log(`  consentId=${consent.consentId}`);
  console.log(`  transferStatus=${transfer.status}`);
  if (transfer.status !== "COMPLETED") {
    throw new Error("compliant e2e expected a COMPLETED transfer");
  }

  console.log("[2/5] Revoke consent and keep the patient-held response values");
  const revoked = await postGateway<RevokedResponse>("A", `/consents/${consent.consentId}/revoke`, {}, "b");
  console.log(`  revocationSeq=${revoked.seq}`);
  console.log(`  revocationEntryHash=${revoked.entryHash}`);

  console.log("[3/5] Anchor both institutions");
  await postGateway("A", "/dev/anchor-now", {}, "b");
  await postGateway("B", "/dev/anchor-now", {}, "a");
  await getGateway("A", "/anchors", "b");
  await getGateway("B", "/anchors", "a");

  console.log("[4/5] Run verify-non-transfer");
  const tls = tlsOptions();
  runVerifierCli([
    "verify-non-transfer",
    "--consent-id", consent.consentId,
    "--secret-c", consent.secretC,
    "--revocation-seq", String(revoked.seq),
    "--revocation-entry-hash", revoked.entryHash,
    "--provider-gateway", gatewayUrl("A"),
    "--receiver-gateway", gatewayUrl("B"),
    "--rpc-url", rpcUrl,
    "--provider-anchor-address", providerAnchorAddress,
    "--receiver-anchor-address", receiverAnchorAddress,
    "--grace-sec", String(graceSeconds),
    "--tls-ca", tls.caPath,
    "--tls-cert", tls.certPath,
    "--tls-key", tls.keyPath
  ]);

  console.log("[5/5] e2e-compliant SUCCESS");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
