import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { gatewayUrl, getGateway, patientTransferBody, postGateway, resolveStudyUid, rootDir } from "./scenario-client.js";
import { defaultDeploymentPath, readAnchorAddress } from "../packages/gateway/src/config.js";
import { VERIFIER_VERDICTS } from "../packages/verifier-cli/src/verdicts.js";

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

function runVerifierCli(args: string[]): string {
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
    throw new Error(`resolve-dispute did not succeed: exit ${result.status ?? "unknown"}`);
  }
  return result.stdout;
}

async function anchorUntilCovered(
  institution: "A" | "B",
  consentId: string,
  eventType: string,
  peerCertDir: "a" | "b"
): Promise<void> {
  // Under load a periodic anchor can leave the latest anchor short of the
  // just-written entry, so resolve-dispute would not find the anchored evidence
  // Anchor and wait until an anchor covers the entry's leaf.
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

  console.log("[1/4] Complete a normal transfer");
  const consent = await postGateway<CreatedConsent>("A", "/consents", {
    receiverInstitutionId: "B",
    studyInstanceUids: [studyInstanceUid],
    purpose,
    validUntil: Math.floor(Date.now() / 1000) + 3600
  }, "b");
  const transfer = await postGateway<TransferResponse>("B", "/transfers", patientTransferBody(consent, studyInstanceUid, purpose), "a");
  console.log(`  transferStatus=${transfer.status}`);
  if (transfer.status !== "COMPLETED") {
    throw new Error("dispute e2e expected a COMPLETED transfer");
  }

  console.log("[2/4] Anchor both institutions and identify the transfer-ref");
  await anchorUntilCovered("A", consent.consentId, "TRANSFER_COMPLETED", "b");
  await anchorUntilCovered("B", consent.consentId, "RECEIVE_COMPLETED", "a");
  const chainA = await getGateway<ChainResponse>("A", `/consents/${consent.consentId}/chain-entries`, "b");
  const approved = chainA.entries.find((entry) => entry.eventType === "TRANSFER_APPROVED");
  if (!approved) {
    throw new Error("missing TRANSFER_APPROVED entry");
  }
  console.log(`  transferRef=${approved.entryHash}`);

  console.log("[3/4] Resolve a B-denial dispute claim");
  const tls = tlsOptions();
  const output = runVerifierCli([
    "resolve-dispute",
    "--transfer-ref", approved.entryHash,
    "--a-gateway", gatewayUrl("A"),
    "--b-gateway", gatewayUrl("B"),
    "--rpc-url", rpcUrl,
    "--a-anchor-address", aAnchorAddress,
    "--b-anchor-address", bAnchorAddress,
    "--a-public-key", publicKeyPath("a"),
    "--b-public-key", publicKeyPath("b"),
    "--claim", "b-denies",
    "--tls-ca", tls.caPath,
    "--tls-cert", tls.certPath,
    "--tls-key", tls.keyPath
  ]);
  if (!output.includes(VERIFIER_VERDICTS.bDenialRejected)) {
    throw new Error("resolve-dispute did not reject B's denial");
  }

  console.log("[4/4] e2e-dispute SUCCESS");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
