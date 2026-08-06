import Database from "better-sqlite3";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Rfc6962LogTree } from "@vadrex/merkle";
import { readPublicKey, verifyEntrySignature } from "../packages/gateway/src/signing.js";
import { defaultDeploymentPath, readAnchorAddress } from "../packages/gateway/src/config.js";
import { AnchorReader } from "../packages/verifier-cli/src/anchor.js";
import { verifyAnchoredInclusion } from "../packages/verifier-cli/src/proofs.js";
import { getGateway, patientTransferBody, postGateway, resolveStudyUid, rootDir } from "./scenario-client.js";
import { CONCEALMENT_ROOT_MISMATCH } from "./detection-markers.js";

interface ChainResponse {
  entries: { eventType: string; seq: number; entryHash: string; canonicalBytes: string; leafIndex: number }[];
}

interface AnchorsResponse {
  anchors: { batchId: number; rootHash: string; treeSize: number; mapRoot: string }[];
}

function canonicalEntry(entry: { canonicalBytes: string }): Record<string, unknown> {
  return JSON.parse(Buffer.from(entry.canonicalBytes.slice(2), "hex").toString("utf8")) as Record<string, unknown>;
}

function requireEntry(chain: ChainResponse, eventType: string): ChainResponse["entries"][number] {
  const entry = chain.entries.find((candidate) => candidate.eventType === eventType);
  if (!entry) {
    throw new Error(`missing ${eventType}`);
  }
  return entry;
}

function rebuildRoot(db: Database.Database, treeSize: number): { root: string; leafCount: number } {
  const rows = db
    .prepare("SELECT leafIndex, canonicalBytes FROM audit_entries WHERE leafIndex < ? ORDER BY leafIndex ASC")
    .all(treeSize) as { leafIndex: number; canonicalBytes: Buffer }[];
  const tree = new Rfc6962LogTree();
  for (const row of rows) {
    tree.appendLeaf(new Uint8Array(row.canonicalBytes));
  }
  return { root: tree.currentRoot(), leafCount: rows.length };
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
  console.log(`  studyInstanceUid=${studyInstanceUid}`);

  console.log("[1/5] Run a transfer to completion");
  const consent = await postGateway<{ consentId: string; secretC: string }>("A", "/consents", {
    receiverInstitutionId: "B",
    studyInstanceUids: [studyInstanceUid],
    purpose,
    validUntil: Math.floor(Date.now() / 1000) + 3600
  }, "b");
  const transfer = await postGateway<{ status: string }>("B", "/transfers",
    patientTransferBody(consent, studyInstanceUid, purpose), "a");
  console.log(`  transferStatus=${transfer.status}`);
  if (transfer.status !== "COMPLETED") {
    throw new Error("concealment demo needs a COMPLETED transfer; check that the Study is loaded in Orthanc A");
  }

  console.log("[2/5] Verify B's records independently prove the transfer (A signatures on B evidence)");
  const chainA = await getGateway<ChainResponse>("A", `/consents/${consent.consentId}/chain-entries`, "b");
  const chainB = await getGateway<ChainResponse>("B", `/consents/${consent.consentId}/chain-entries`, "a");
  const approved = requireEntry(chainA, "TRANSFER_APPROVED");
  const completed = requireEntry(chainA, "TRANSFER_COMPLETED");
  const received = requireEntry(chainB, "RECEIVE_COMPLETED");
  const approvedEntry = canonicalEntry(approved);
  const completedEntry = canonicalEntry(completed);
  const receivedEntry = canonicalEntry(received);
  const publicKeyA = readPublicKey(join(rootDir, "scripts", "out", "inst-a", "ed25519.pub"));
  const publicKeyB = readPublicKey(join(rootDir, "scripts", "out", "inst-b", "ed25519.pub"));
  if (!verifyEntrySignature(approvedEntry.peerEntryHash as string, approvedEntry.peerSignature as string, publicKeyB)) {
    throw new Error("TRANSFER_APPROVED does not carry B's valid request signature");
  }
  if (receivedEntry.peerEntryHash !== approved.entryHash ||
      !verifyEntrySignature(approved.entryHash, receivedEntry.peerSignature as string, publicKeyA)) {
    throw new Error("B's RECEIVE_COMPLETED does not carry A's valid approval signature");
  }
  if (completedEntry.peerEntryHash !== received.entryHash ||
      !verifyEntrySignature(received.entryHash, completedEntry.peerSignature as string, publicKeyB)) {
    throw new Error("TRANSFER_COMPLETED does not carry B's valid receipt signature");
  }
  console.log("  B holds RECEIVE_COMPLETED signed against A's approval hash — independent proof of the transfer.");

  // Checking the signature alone would not support the claim that the peer's own anchoring
  // detects concealment, so B's receive entry is shown to be in B's on-chain anchor by proof.
  console.log("[2b/5] Verify B's receive entry is anchored on B's own contract");
  await anchorUntilCovered("B", consent.consentId, "RECEIVE_COMPLETED", "a");
  const rpc = process.env.CHAIN_RPC_URL_HOST ?? process.env.CHAIN_RPC_URL ?? "http://127.0.0.1:8545";
  const bAnchorAddress = readAnchorAddress(defaultDeploymentPath(rootDir), "B");
  const bAnchors = await new AnchorReader(rpc, bAnchorAddress, { apiCalls: 0, rpcCalls: 0 }).anchors();
  let anchoredReceive: { batchId: number; treeSize: number } | null = null;
  for (const candidate of bAnchors) {
    if (candidate.treeSize <= received.leafIndex) {
      continue;
    }
    const proof = await getGateway<Parameters<typeof verifyAnchoredInclusion>[1]>(
      "B",
      `/proofs/inclusion?entryHash=${encodeURIComponent(received.entryHash)}&anchorBatchId=${candidate.batchId}`,
      "a"
    );
    const parsed = verifyAnchoredInclusion(candidate, proof);
    if (parsed.entry.entryHash !== received.entryHash) {
      throw new Error(`B inclusion proof preimage hashes to ${parsed.entry.entryHash}, expected ${received.entryHash}`);
    }
    anchoredReceive = { batchId: candidate.batchId, treeSize: candidate.treeSize };
    break;
  }
  if (!anchoredReceive) {
    throw new Error("B's RECEIVE_COMPLETED is not covered by any anchored root on B's contract");
  }
  console.log(`  B receive entry verified against B's on-chain anchor batch=${anchoredReceive.batchId} (treeSize=${anchoredReceive.treeSize})`);

  console.log("[3/5] Anchor gateway A and read the anchored root");
  // Under load a periodic anchor can leave the latest anchor short of the
  // TRANSFER_COMPLETED leaf, which would place the deletion outside the anchored
  // tree and look undetectable. Anchor until an anchor covers the
  // target leaf, and use that anchor.
  let anchor: AnchorsResponse["anchors"][number] | undefined;
  const anchorDeadline = Date.now() + 30_000;
  do {
    await postGateway("A", "/dev/anchor-now", {}, "b");
    const anchors = await getGateway<AnchorsResponse>("A", "/anchors", "b");
    anchor = anchors.anchors.filter((candidate) => candidate.treeSize > completed.leafIndex).at(-1);
    if (anchor) {
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  } while (Date.now() < anchorDeadline);
  if (!anchor) {
    throw new Error("gateway A has no anchor covering the TRANSFER_COMPLETED entry");
  }
  console.log(`  anchor batchId=${anchor.batchId} treeSize=${anchor.treeSize} rootHash=${anchor.rootHash}`);

  console.log("[4/5] Simulate concealment on a copy of A's audit DB and show it is detectable");
  // Editing the running gateway's database would desynchronise it from the in-memory tree, so
  // VACUUM INTO takes a consistent copy, the deletion happens there, and the result is compared
  // against the anchored value.
  const dbPath = process.env.AUDIT_DB_PATH ?? join(rootDir, "data", "inst-a", "audit.db");
  const tempDir = mkdtempSync(join(tmpdir(), "vadrex-concealment-"));
  const copyPath = join(tempDir, "audit-copy.db").replace(/\\/g, "/");
  const source = new Database(dbPath, { readonly: true, fileMustExist: true });
  try {
    source.exec(`VACUUM INTO '${copyPath.replace(/'/g, "''")}'`);
  } finally {
    source.close();
  }
  const copy = new Database(copyPath);
  try {
    const intact = rebuildRoot(copy, anchor.treeSize);
    if (intact.root !== anchor.rootHash) {
      throw new Error(`sanity check failed: intact copy root ${intact.root} != anchored root ${anchor.rootHash}`);
    }
    console.log(`  sanity: intact copy reproduces the anchored root over ${intact.leafCount} leaves`);

    const target = copy
      .prepare("SELECT leafIndex FROM audit_entries WHERE consentId = ? AND eventType = 'TRANSFER_COMPLETED' ORDER BY leafIndex DESC LIMIT 1")
      .get(consent.consentId) as { leafIndex: number } | undefined;
    if (!target) {
      throw new Error("no TRANSFER_COMPLETED row found to delete");
    }
    copy.prepare("DELETE FROM audit_entries WHERE leafIndex = ?").run(target.leafIndex);
    console.log(`  deleted TRANSFER_COMPLETED at leafIndex=${target.leafIndex} from the copy`);

    const tampered = rebuildRoot(copy, anchor.treeSize);
    if (tampered.leafCount >= anchor.treeSize || tampered.root === anchor.rootHash) {
      throw new Error("tamper was not detectable — this should never happen");
    }
    console.log(`  detection: only ${tampered.leafCount}/${anchor.treeSize} leaves remain and the recomputed root`);
    console.log(`  ${tampered.root} ${CONCEALMENT_ROOT_MISMATCH} ${anchor.rootHash}`);
    console.log("  -> A cannot serve a consistent tree for its own anchor: consistency/self-check fails.");
  } finally {
    copy.close();
    rmSync(tempDir, { recursive: true, force: true });
  }

  console.log("[5/5] Conclusion: even if A conceals its transfer log, the anchored root exposes the deletion,");
  console.log("  and B's signed RECEIVE_COMPLETED/receipt entries prove the transfer happened.");
  console.log("demo-concealment SUCCESS");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
