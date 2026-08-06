import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const ZERO_MAP_ROOT = "0x0000000000000000000000000000000000000000000000000000000000000000";

const ROOT_PACKAGE_NAME = "vadrex-proto";

// Locate the root by the workspace package name. Keying on the presence of a documentation
// file would break the moment that file is left out of a distribution; nested packages carry
// a different name, so the walk continues past them.
function isRepoRoot(dir: string): boolean {
  const manifestPath = join(dir, "package.json");
  if (!existsSync(manifestPath)) {
    return false;
  }
  try {
    return (JSON.parse(readFileSync(manifestPath, "utf8")) as { name?: string }).name === ROOT_PACKAGE_NAME;
  } catch {
    return false;
  }
}

function findRepoRoot(startDir: string): string {
  let current = resolve(startDir);
  while (true) {
    if (isRepoRoot(current)) {
      return current;
    }
    const parent = dirname(current);
    if (parent === current) {
      throw new Error(`could not find repo root from ${startDir}`);
    }
    current = parent;
  }
}

export function repoRoot(): string {
  if (process.env.VADREX_ROOT) {
    return resolve(process.env.VADREX_ROOT);
  }

  const moduleDir = dirname(fileURLToPath(import.meta.url));
  return findRepoRoot(moduleDir);
}

export function defaultAuditDbPath(rootDir = repoRoot()): string {
  return defaultInstitutionAuditDbPath("A", rootDir);
}

export function defaultInstitutionAuditDbPath(institutionId: string, rootDir = repoRoot()): string {
  return join(rootDir, "data", `inst-${institutionId.toLowerCase()}`, "audit.db");
}

export function defaultDeploymentPath(rootDir = repoRoot()): string {
  return join(rootDir, "data", "deployments.local.json");
}

export function defaultWalletKeyPath(rootDir = repoRoot()): string {
  return defaultInstitutionWalletKeyPath("A", rootDir);
}

export function defaultInstitutionWalletKeyPath(institutionId: string, rootDir = repoRoot()): string {
  return join(rootDir, "scripts", "out", `inst-${institutionId.toLowerCase()}`, "wallet.key");
}

export function defaultInstitutionEd25519KeyPath(institutionId: string, rootDir = repoRoot()): string {
  return join(rootDir, "scripts", "out", `inst-${institutionId.toLowerCase()}`, "ed25519.key");
}

export function defaultInstitutionEd25519PublicKeyPath(institutionId: string, rootDir = repoRoot()): string {
  return join(rootDir, "scripts", "out", `inst-${institutionId.toLowerCase()}`, "ed25519.pub");
}

export function defaultInstitutionTlsCertPath(institutionId: string, rootDir = repoRoot()): string {
  return join(rootDir, "scripts", "out", `inst-${institutionId.toLowerCase()}`, "cert.pem");
}

export function defaultInstitutionTlsKeyPath(institutionId: string, rootDir = repoRoot()): string {
  return join(rootDir, "scripts", "out", `inst-${institutionId.toLowerCase()}`, "key.pem");
}

export function defaultInstitutionCaCertPath(institutionId: string, rootDir = repoRoot()): string {
  return join(rootDir, "scripts", "out", `inst-${institutionId.toLowerCase()}`, "ca.cert.pem");
}

export function readAnchorAddress(deploymentPath: string, institutionId = "A"): string {
  const deployments = JSON.parse(readFileSync(deploymentPath, "utf8")) as {
    anchors?: Record<string, { address?: string } | undefined>;
  };
  const address = deployments.anchors?.[institutionId]?.address;
  if (!address) {
    throw new Error(`deployment file ${deploymentPath} does not contain anchors.${institutionId}.address`);
  }
  return address;
}

export function readWalletPrivateKey(walletKeyPath: string): string {
  return readFileSync(walletKeyPath, "utf8").trim();
}

export function parsePositiveInteger(value: string | undefined, fallback: number): number {
  if (value === undefined || value === "") {
    return fallback;
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`expected positive integer, got ${value}`);
  }
  return parsed;
}
