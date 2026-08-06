// Checks that each gateway's local anchor history matches the anchors on chain.
//
// The two live in different places: the local history in data/inst-*/audit.db on the host, the
// anchors in the in-memory Hardhat chain. Restarting the chain or redeploying a contract on its
// own therefore desynchronises them silently, and the mismatch only surfaces much later, at the
// next anchoring, as "anchor batch N already exists with different values". Bootstrap runs this
// check up front so the operator is asked for an explicit -Reset instead.
import Database from "better-sqlite3";
import { existsSync } from "node:fs";
import { AnchorReader } from "../packages/verifier-cli/src/anchor.js";
import {
  defaultDeploymentPath,
  defaultInstitutionAuditDbPath,
  readAnchorAddress,
  repoRoot
} from "../packages/gateway/src/config.js";

interface LocalAnchor {
  batchId: number;
  rootHash: string;
  treeSize: number;
}

function rpcUrl(): string {
  return process.env.CHAIN_RPC_URL_HOST ?? process.env.CHAIN_RPC_URL ?? "http://127.0.0.1:8545";
}

function localAnchors(institutionId: string, rootDir: string): LocalAnchor[] {
  const path = defaultInstitutionAuditDbPath(institutionId, rootDir);
  if (!existsSync(path)) {
    return [];
  }
  const db = new Database(path, { readonly: true, fileMustExist: true });
  try {
    return db.prepare("SELECT batchId, rootHash, treeSize FROM anchor_history ORDER BY batchId").all() as LocalAnchor[];
  } catch {
    // A fresh database that has no schema yet.
    return [];
  } finally {
    db.close();
  }
}

async function checkInstitution(institutionId: "A" | "B", rootDir: string): Promise<string[]> {
  const problems: string[] = [];
  const local = localAnchors(institutionId, rootDir);
  const address = readAnchorAddress(defaultDeploymentPath(rootDir), institutionId);
  const reader = new AnchorReader(rpcUrl(), address, { apiCalls: 0, rpcCalls: 0, apiRequestBytes: 0, apiResponseBytes: 0 });
  const chain = await reader.anchors();

  if (local.length > chain.length) {
    problems.push(
      `institution ${institutionId}: ${local.length} local anchors > ${chain.length} on chain. ` +
      "The chain was restarted or redeployed and lost its history."
    );
  } else if (chain.length > local.length) {
    problems.push(
      `institution ${institutionId}: ${chain.length} anchors on chain > ${local.length} local. ` +
      "Anchors the gateway does not know about will block its next anchoring."
    );
  } else {
    const lastLocal = local.at(-1);
    const lastChain = chain.at(-1);
    if (lastLocal && lastChain) {
      if (lastLocal.rootHash !== lastChain.rootHash || Number(lastLocal.treeSize) !== Number(lastChain.treeSize)) {
        problems.push(
          `institution ${institutionId}: latest anchor differs ` +
          `(local treeSize=${lastLocal.treeSize} root=${lastLocal.rootHash.slice(0, 12)}…, ` +
          `chain treeSize=${lastChain.treeSize} root=${String(lastChain.rootHash).slice(0, 12)}…).`
        );
      }
    }
  }

  console.log(`  institution ${institutionId}: ${local.length} local / ${chain.length} on chain`);
  return problems;
}

async function main(): Promise<void> {
  const rootDir = repoRoot();
  const problems = [
    ...await checkInstitution("A", rootDir),
    ...await checkInstitution("B", rootDir)
  ];

  if (problems.length > 0) {
    console.error("");
    console.error("Local anchor history and on-chain state disagree:");
    for (const problem of problems) {
      console.error(`  - ${problem}`);
    }
    console.error("");
    console.error("Fix: .\\reproduce.cmd -Reset  (backs up and clears the audit databases, then rebuilds chain and contracts)");
    process.exitCode = 1;
    return;
  }
  console.log("  state consistent");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
