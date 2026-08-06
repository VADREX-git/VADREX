import { execFileSync, spawnSync } from "node:child_process";
import { join } from "node:path";
import { gatewayUrl, getGateway, postGateway, rootDir } from "./scenario-client.js";
import { defaultDeploymentPath, readAnchorAddress } from "../packages/gateway/src/config.js";
import { violationCaseMarker } from "./detection-markers.js";

interface CreatedConsent {
  consentId: string;
  secretC: string;
}

interface RevokedResponse {
  seq: number;
  entryHash: string;
}

interface CaseSpec {
  name: string;
  seqOffset: number;
  noHeadUpdate: boolean;
  expectedFailure: string;
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

function run(command: string, args: string[], env: NodeJS.ProcessEnv = process.env): void {
  console.log(`  > ${command} ${args.join(" ")}`);
  execFileSync(command, args, {
    cwd: rootDir,
    stdio: "inherit",
    env,
    shell: process.platform === "win32"
  });
}

function runVerifierCliExpectFailure(args: string[], expectedFailure: string): void {
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
    throw new Error("verify-non-transfer unexpectedly passed verification");
  }
  const output = `${result.stdout}\n${result.stderr}`;
  if (!output.includes(expectedFailure)) {
    throw new Error(`verification failed, but not at expected stage ${expectedFailure}`);
  }
}

async function waitForGatewayA(): Promise<void> {
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    try {
      await getGateway("A", "/health", "b");
      await getGateway("A", "/dev/tree", "b");
      await getGateway("A", "/anchors", "b");
      await new Promise((resolve) => setTimeout(resolve, 1_000));
      return;
    } catch {
      // keep polling
    }
    await new Promise((resolve) => setTimeout(resolve, 2_000));
  }
  throw new Error("gateway-a did not become healthy after restart");
}

async function createRevokedConsent(): Promise<{ consent: CreatedConsent; revoked: RevokedResponse }> {
  const consent = await retryTransient(() => postGateway<CreatedConsent>("A", "/consents", {
    receiverInstitutionId: "B",
    studyInstanceUids: ["1.2.violation"],
    purpose: "research",
    validUntil: Math.floor(Date.now() / 1000) + 3600
  }, "b"), "create consent");
  const revoked = await retryTransient(() => postGateway<RevokedResponse>("A", `/consents/${consent.consentId}/revoke`, {}, "b"), "revoke consent");
  await retryTransient(() => postGateway("A", "/dev/anchor-now", {}, "b"), "anchor revocation");
  return { consent, revoked };
}

async function runCase(spec: CaseSpec): Promise<void> {
  console.log(`${violationCaseMarker(spec.name)} Prepare revoked consent`);
  const { consent, revoked } = await createRevokedConsent();
  console.log(`  consentId=${consent.consentId}`);
  console.log(`  revocationSeq=${revoked.seq}`);
  console.log(`  revocationEntryHash=${revoked.entryHash}`);

  console.log(`${violationCaseMarker(spec.name)} Stop gateway-a and inject violation directly into audit.db`);
  run("docker", ["compose", "stop", "gateway-a"]);
  try {
    const args = [
      "scripts/inject-violation.ts",
      "--consentId",
      consent.consentId,
      "--seq",
      String(revoked.seq + spec.seqOffset)
    ];
    if (spec.noHeadUpdate) {
      args.push("--no-head-update");
    }
    run("npx", ["tsx", ...args]);
  } finally {
    console.log(`${violationCaseMarker(spec.name)} Restart gateway-a`);
    run("docker", ["compose", "up", "-d", "gateway-a"]);
  }

  await waitForGatewayA();
  await retryTransient(() => postGateway("A", "/dev/anchor-now", {}, "b"), "anchor injected violation");

  console.log(`${violationCaseMarker(spec.name)} Run verify-non-transfer and expect detection`);
  // Trust anchor: contract addresses come from the local deployment file, not from the gateway.
  const deploymentPath = defaultDeploymentPath(rootDir);
  const providerAnchorAddress = readAnchorAddress(deploymentPath, "A");
  const receiverAnchorAddress = readAnchorAddress(deploymentPath, "B");
  const tls = tlsOptions();
  runVerifierCliExpectFailure([
    "verify-non-transfer",
    "--consent-id", consent.consentId,
    "--secret-c", consent.secretC,
    "--revocation-seq", String(revoked.seq),
    "--revocation-entry-hash", revoked.entryHash,
    "--provider-gateway", gatewayUrl("A"),
    "--receiver-gateway", gatewayUrl("B"),
    "--rpc-url", process.env.CHAIN_RPC_URL_HOST ?? process.env.CHAIN_RPC_URL ?? "http://127.0.0.1:8545",
    "--provider-anchor-address", providerAnchorAddress,
    "--receiver-anchor-address", receiverAnchorAddress,
    "--grace-sec", "0",
    "--tls-ca", tls.caPath,
    "--tls-cert", tls.certPath,
    "--tls-key", tls.keyPath
  ], spec.expectedFailure);
}

async function main(): Promise<void> {
  const cases: CaseSpec[] = [
    { name: "k-plus-one", seqOffset: 1, noHeadUpdate: false, expectedFailure: "provider head" },
    { name: "skip-seq", seqOffset: 7, noHeadUpdate: false, expectedFailure: "provider head" },
    { name: "no-head-update", seqOffset: 1, noHeadUpdate: true, expectedFailure: "provider cross-check" }
  ];
  for (const spec of cases) {
    await runCase(spec);
  }
  console.log("e2e-violation SUCCESS");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

async function retryTransient<T>(fn: () => Promise<T>, label: string, attempts = 4): Promise<T> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (attempt === attempts || !isTransientError(error)) {
        throw error;
      }
      const delayMs = 750 * attempt;
      console.warn(`  ${label} transient failure (${error instanceof Error ? error.message : String(error)}); retrying in ${delayMs}ms`);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
  throw lastError;
}

function isTransientError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /ECONNRESET|socket hang up|ECONNREFUSED|ETIMEDOUT|NONCE_EXPIRED|Nonce too low|nonce has already been used/i.test(message);
}
