import Database from "better-sqlite3";
import { Contract, JsonRpcProvider } from "ethers";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Rfc6962LogTree, verifyConsistency } from "@vadrex/merkle";
import { repoRoot } from "../packages/gateway/src/config.js";
import { makeAuditEntries } from "./audit-events.js";

const ANCHOR_ABI = [
  "function anchorCount() view returns (uint64)",
  "function getAnchor(uint64 batchId) view returns (tuple(uint64 batchId, bytes32 rootHash, uint64 treeSize, bytes32 mapRoot, uint64 anchoredAt))"
] as const;

interface GatewayTreeStatus {
  treeSize: number;
  rootHash: string;
}

interface ChainAnchor {
  batchId: number;
  rootHash: `0x${string}`;
  treeSize: number;
}

interface AuditRow {
  leafIndex: number;
  canonicalBytes: Buffer;
}

function readAnchorAddress(rootDir: string): string {
  const deploymentPath = join(rootDir, "data", "deployments.local.json");
  const deployments = JSON.parse(readFileSync(deploymentPath, "utf8")) as {
    anchors?: { A?: { address?: string } };
  };
  const address = deployments.anchors?.A?.address;
  if (!address) {
    throw new Error(`missing anchors.A.address in ${deploymentPath}`);
  }
  return address;
}

function normalizeGatewayUrl(): string {
  return (process.env.GATEWAY_A_URL ?? "http://localhost:7001").replace(/\/$/, "");
}

async function getJson<T>(url: string): Promise<T> {
  const response = await fetch(url);
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`${url} returned ${response.status}: ${text}`);
  }
  return JSON.parse(text) as T;
}

async function postJson<T>(url: string, body: unknown = {}): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`${url} returned ${response.status}: ${text}`);
  }
  return JSON.parse(text) as T;
}

async function anchorCount(contract: Contract): Promise<number> {
  return Number(await contract.anchorCount());
}

async function getAnchor(contract: Contract, batchId: number): Promise<ChainAnchor> {
  const record = await contract.getAnchor(BigInt(batchId));
  return {
    batchId: Number(record.batchId ?? record[0]),
    rootHash: `0x${String(record.rootHash ?? record[1]).slice(2).toLowerCase()}`,
    treeSize: Number(record.treeSize ?? record[2])
  };
}

async function ensureAnchorAfter(gatewayUrl: string, contract: Contract, previousCount: number): Promise<ChainAnchor> {
  await postJson(`${gatewayUrl}/dev/anchor-now`);
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const count = await anchorCount(contract);
    if (count > previousCount) {
      return getAnchor(contract, count);
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`anchor count did not increase after batch ${previousCount}`);
}

function treeFromOpenDb(db: Database.Database, treeSize: number, requireContiguousLeafIndex: boolean): Rfc6962LogTree {
  const rows = db
    .prepare("SELECT leafIndex, canonicalBytes FROM audit_entries WHERE leafIndex < ? ORDER BY leafIndex ASC")
    .all(treeSize) as AuditRow[];
  const tree = new Rfc6962LogTree();
  rows.forEach((row, expectedIndex) => {
    if (requireContiguousLeafIndex && row.leafIndex !== expectedIndex) {
      throw new Error(`audit_entries leafIndex gap: expected ${expectedIndex}, got ${row.leafIndex}`);
    }
    tree.appendLeaf(new Uint8Array(row.canonicalBytes));
  });
  return tree;
}

function readTreeFromDb(dbPath: string, treeSize: number): Rfc6962LogTree {
  const db = new Database(dbPath, { readonly: true, fileMustExist: true });
  try {
    return treeFromOpenDb(db, treeSize, true);
  } finally {
    db.close();
  }
}

async function readTreeAfterDeletingCopiedRow(dbPath: string, treeSize: number, deletedLeafIndex: number): Promise<Rfc6962LogTree> {
  const tempDir = mkdtempSync(join(tmpdir(), "vadrex-demo-"));
  const copiedDbPath = join(tempDir, "audit-tampered.db");
  const source = new Database(dbPath, { readonly: true, fileMustExist: true });
  try {
    await source.backup(copiedDbPath);
  } finally {
    source.close();
  }

  const tampered = new Database(copiedDbPath);
  try {
    const result = tampered.prepare("DELETE FROM audit_entries WHERE leafIndex = ?").run(deletedLeafIndex);
    if (result.changes !== 1) {
      throw new Error(`expected to delete one row at leafIndex ${deletedLeafIndex}, deleted ${result.changes}`);
    }
    return treeFromOpenDb(tampered, treeSize, false);
  } finally {
    tampered.close();
    rmSync(tempDir, { recursive: true, force: true });
  }
}

async function inject(gatewayUrl: string, count: number, offset: number): Promise<void> {
  await postJson(`${gatewayUrl}/dev/audit-entries`, { entries: makeAuditEntries(count, offset) });
}

async function main() {
  const rootDir = repoRoot();
  const gatewayUrl = normalizeGatewayUrl();
  const dbPath = process.env.AUDIT_DB_PATH ?? join(rootDir, "data", "inst-a", "audit.db");
  const rpcUrl = process.env.CHAIN_RPC_URL ?? "http://localhost:8545";
  const provider = new JsonRpcProvider(rpcUrl);
  const contract = new Contract(readAnchorAddress(rootDir), ANCHOR_ABI, provider);

  console.log("[1/4] Read the current state of gateway-a");
  const initialStatus = await getJson<GatewayTreeStatus>(`${gatewayUrl}/dev/tree`);
  let previousAnchorCount = await anchorCount(contract);
  console.log(`  treeSize=${initialStatus.treeSize}, chainAnchorCount=${previousAnchorCount}`);

  console.log("[2/4] Inject 50 events and register the first anchor");
  await inject(gatewayUrl, 50, initialStatus.treeSize);
  const firstAnchor = await ensureAnchorAfter(gatewayUrl, contract, previousAnchorCount);
  previousAnchorCount = firstAnchor.batchId;
  console.log(`  batch=${firstAnchor.batchId}, treeSize=${firstAnchor.treeSize}, root=${firstAnchor.rootHash}`);

  console.log("[3/4] Inject 50 more events and register the second anchor");
  await inject(gatewayUrl, 50, firstAnchor.treeSize);
  const secondAnchor = await ensureAnchorAfter(gatewayUrl, contract, previousAnchorCount);
  console.log(`  batch=${secondAnchor.batchId}, treeSize=${secondAnchor.treeSize}, root=${secondAnchor.rootHash}`);

  console.log("[4/4] Verify consistency on the honest and the attacked path");
  const honestTree = readTreeFromDb(dbPath, secondAnchor.treeSize);
  const honestProof = honestTree.consistencyProof(firstAnchor.treeSize, secondAnchor.treeSize);
  const honestOk = verifyConsistency(
    firstAnchor.rootHash,
    firstAnchor.treeSize,
    secondAnchor.rootHash,
    secondAnchor.treeSize,
    honestProof
  );
  console.log(`  honest path: consistency verification = ${honestOk ? "SUCCESS" : "FAIL"}`);

  const deletedLeafIndex = firstAnchor.treeSize + Math.floor((secondAnchor.treeSize - firstAnchor.treeSize) / 2);
  const tamperedTree = await readTreeAfterDeletingCopiedRow(dbPath, secondAnchor.treeSize, deletedLeafIndex);
  console.log(`  attacked path: rebuilt without leafIndex=${deletedLeafIndex}, treeSize=${tamperedTree.treeSize()}`);

  try {
    tamperedTree.consistencyProof(firstAnchor.treeSize, secondAnchor.treeSize);
    console.log("  attacked path: unexpectedly produced a proof for the anchored treeSize");
  } catch (error) {
    console.log(`  attacked path: cannot produce a proof for the anchored treeSize (${(error as Error).message})`);
  }

  const tamperedProof = tamperedTree.consistencyProof(firstAnchor.treeSize, tamperedTree.treeSize());
  const tamperedOk = verifyConsistency(
    firstAnchor.rootHash,
    firstAnchor.treeSize,
    secondAnchor.rootHash,
    secondAnchor.treeSize,
    tamperedProof
  );
  console.log(`  attacked path: verification against the anchored root = ${tamperedOk ? "UNEXPECTED SUCCESS" : "DETECTED"}`);

  if (!honestOk || tamperedOk) {
    throw new Error("demo-completeness produced an unexpected verification result");
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
