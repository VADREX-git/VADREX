import Database from "better-sqlite3";
import { ContractFactory, JsonRpcProvider, Wallet } from "ethers";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AnchorClient } from "../../packages/gateway/src/anchorClient.js";
import { defaultInstitutionWalletKeyPath, readWalletPrivateKey } from "../../packages/gateway/src/config.js";
import { Rfc6962LogTree, verifyConsistency } from "@vadrex/merkle";
import { VERIFIER_VERDICTS } from "../../packages/verifier-cli/src/verdicts.js";
import { CONCEALMENT_ROOT_MISMATCH, violationCaseMarker } from "../../scripts/detection-markers.js";
import type { HexString } from "@vadrex/shared";

const ZERO_MAP_ROOT = `0x${"00".repeat(32)}` as HexString;
import type { EvalConfig } from "./common.js";
import { numericMetricSummaries, rootDir, round, timed, writeCsv, writeJson } from "./common.js";
import { stowDicomToOrthancA, syntheticDicomPath, syntheticStudyUid, writeSyntheticDicom } from "./dicom.js";
import { addCheckpointAndAnchor, chainAnchors, isTransientError, pinnedAnchors, releasePeerHold, restoreGatewaysFromProcessEnv, restartGatewaysWithRuntimeEnv, retryTransientStep, rpcUrl } from "./live.js";

export interface AttackRow {
  mode: string;
  repeat: number;
  property: "S1" | "S2" | "S3";
  attackType: string;
  detected: boolean;
  detectionMs: number;
  anchorsRequired: number | null;
  command?: string;
  status: "ok" | "failed" | "skipped";
  error?: string;
  // Audit trail for an S1 injection: the anchors the detection compared and the leaf touched.
  anchorBatchIds?: string;
  injectedLeafIndex?: number;
}

export async function measureAttackInjection(config: EvalConfig): Promise<AttackRow[]> {
  const rows: AttackRow[] = [];

  if (config.skipDocker) {
    // Even the S1 injection needs anchored state and a live audit DB.
    rows.push(skippedRow(config.mode, "S1", "docker-s1-cases", "docker measurements skipped"));
    rows.push(skippedRow(config.mode, "S2", "docker-s2-cases", "docker measurements skipped"));
    rows.push(skippedRow(config.mode, "S3", "docker-s3-cases", "docker measurements skipped"));
    writeOutputs(config, rows);
    return rows;
  }

  for (let repeat = 1; repeat <= config.repeats; repeat += 1) {
    rows.push(...await measureS1Injected(config.mode, repeat));
    rows.push(await measureS1ContractRevert(config.mode, repeat));
    await ensureAttackStudy(repeat);
    rows.push(...await measureS2(config.mode, repeat));
    rows.push(...await measureS3(config.mode, repeat));
  }

  writeOutputs(config, rows);
  return rows;
}

function auditDbPathA(): string {
  return process.env.AUDIT_DB_PATH ?? join(rootDir, "data", "inst-a", "audit.db");
}

function snapshotAuditDb(label: string): { copyPath: string; tempDir: string } {
  // Editing the running gateway's database would desynchronise it from the in-memory tree,
  // so VACUUM INTO takes a consistent copy and the attack is injected into the copy.
  const tempDir = mkdtempSync(join(tmpdir(), `vadrex-${label}-`));
  const copyPath = join(tempDir, "audit-copy.db").replace(/\\/g, "/");
  const source = new Database(auditDbPathA(), { readonly: true, fileMustExist: true });
  try {
    source.exec(`VACUUM INTO '${copyPath.replace(/'/g, "''")}'`);
  } finally {
    source.close();
  }
  return { copyPath, tempDir };
}

export interface AnchoredLeaf {
  leafIndex: number;
  canonicalBytes: Buffer;
}

/** On-chain anchor values a detection compares against. */
export interface AnchorRef {
  batchId: number;
  treeSize: number;
  rootHash: string;
}

export interface S1InjectionOutcome {
  targetIndex: number;
  tamper: { detected: boolean; verifyMs: number };
  omission: { detected: boolean; verifyMs: number };
}

function anchoredLeaves(db: Database.Database, treeSize: number): AnchoredLeaf[] {
  return db
    .prepare("SELECT leafIndex, canonicalBytes FROM audit_entries WHERE leafIndex < ? ORDER BY leafIndex ASC")
    .all(treeSize) as AnchoredLeaf[];
}

function treeFrom(leaves: readonly AnchoredLeaf[]): Rfc6962LogTree {
  const tree = new Rfc6962LogTree();
  for (const leaf of leaves) {
    tree.appendLeaf(new Uint8Array(leaf.canonicalBytes));
  }
  return tree;
}

function flipLastByte(bytes: Buffer): Buffer {
  const mutated = Buffer.from(bytes);
  mutated[mutated.length - 1] ^= 0x01;
  return mutated;
}

async function latestAnchorOnA(repeat: number): Promise<AnchorRef> {
  const address = pinnedAnchors().a;
  let anchors = await chainAnchors(address);
  for (let attempt = 0; anchors.length === 0 && attempt < 3; attempt += 1) {
    await addCheckpointAndAnchor("A", `s1-inject-${repeat}-${attempt}`);
    anchors = await chainAnchors(address);
  }
  const latest = anchors.at(-1);
  if (!latest) {
    throw new Error("gateway A has no anchors; the S1 injection needs one");
  }
  return latest;
}

/**
 * Registers the root of a tampered log on chain and checks that a verifier catches it.
 *
 * A fresh `Anchor.sol` instance is deployed for each trial. Reusing an institution's contract
 * would leave a bogus anchor behind and poison every later measurement. The contract only
 * enforces a growing treeSize, so the tampered root is accepted; detection comes from the
 * consistency proof between the two anchors read back from the chain.
 */
export async function runS1OnchainTamper(
  leaves: readonly AnchoredLeaf[],
  targetIndex: number,
  followUpLeaves = 3
): Promise<{ detected: boolean; verifyMs: number; contractAddress: string; batchIds: string }> {
  const artifactPath = join(rootDir, "contracts", "artifacts", "contracts", "Anchor.sol", "Anchor.json");
  if (!existsSync(artifactPath)) {
    throw new Error(`Anchor artifact not found at ${artifactPath}; run "npm run contracts:compile" first`);
  }
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8")) as { abi: unknown[]; bytecode: string };
  const wallet = new Wallet(
    readWalletPrivateKey(defaultInstitutionWalletKeyPath("A", rootDir)),
    new JsonRpcProvider(rpcUrl())
  );
  // These transactions go out on institution A's wallet, which gateway A's anchor loop also
  // uses. When both signers pick the same nonce the send fails; that is a harness race, not a
  // detection failure, so it is retried rather than recorded.
  const contract = await retryTransientStep(async () => {
    const deployed = await new ContractFactory(artifact.abi as never, artifact.bytecode, wallet).deploy();
    await deployed.waitForDeployment();
    return deployed;
  });
  const address = await contract.getAddress();
  const client = new AnchorClient(rpcUrl(), address, readWalletPrivateKey(defaultInstitutionWalletKeyPath("A", rootDir)));

  const honest = treeFrom(leaves);
  const firstSize = leaves.length;
  const first = await retryTransientStep(() => client.registerAnchor(honest.currentRoot() as HexString, firstSize, ZERO_MAP_ROOT));

  const tamperedTree = treeFrom(leaves.map((leaf) => leaf.leafIndex === targetIndex
    ? { ...leaf, canonicalBytes: flipLastByte(leaf.canonicalBytes) }
    : leaf));
  for (let index = 0; index < followUpLeaves; index += 1) {
    tamperedTree.appendLeaf(new Uint8Array(Buffer.from(`{"eventType":"CROSS_CHECKPOINT","followUp":${index}}`)));
  }
  const secondSize = firstSize + followUpLeaves;
  const second = await retryTransientStep(() => client.registerAnchor(tamperedTree.currentRoot() as HexString, secondSize, ZERO_MAP_ROOT));

  // A verifier reads anchor values from the chain, not from the gateway.
  const onchain = await chainAnchors(address);
  const a1 = onchain.find((x) => x.batchId === first.batchId);
  const a2 = onchain.find((x) => x.batchId === second.batchId);
  if (!a1 || !a2) {
    throw new Error("registered anchors were not readable from chain");
  }
  const proof = tamperedTree.consistencyProof(a1.treeSize, a2.treeSize);
  const measured = await timed(() => !verifyConsistency(a1.rootHash, a1.treeSize, a2.rootHash, a2.treeSize, proof));
  return {
    detected: measured.value,
    verifyMs: measured.ms,
    contractAddress: address,
    batchIds: `${a1.batchId},${a2.batchId}`
  };
}

/**
 * Injects tampering and deletion into an anchored log and detects both against the anchor.
 * The two cases mirror the two paths a verifier actually takes.
 *
 * - Tampering: anchoring the *next* batch from the tampered log breaks the consistency proof
 *   that links the previous on-chain anchor to the new one. A proof between two anchors that
 *   already exist is not enough: it reuses the old root as given and only appends nodes to the
 *   right, so a tampered leaf inside a complete subtree never appears in it.
 * - Omission: with a leaf removed the log no longer reproduces the anchored root at the
 *   anchored treeSize.
 *
 * `verifyMs` covers only what the verifier pays (proof verification and root comparison).
 * Building proofs from the tampered tree is the attacker's cost and stays outside the timer.
 *
 * Kept a pure function so it can be unit-tested without docker.
 */
export async function runS1Injection(
  leaves: readonly AnchoredLeaf[],
  anchor: AnchorRef,
  followUpLeaves = 3
): Promise<S1InjectionOutcome> {
  const intact = treeFrom(leaves);
  if (leaves.length !== anchor.treeSize || intact.currentRoot() !== anchor.rootHash) {
    throw new Error(`intact snapshot does not reproduce anchor ${anchor.batchId}`);
  }
  const targetIndex = Math.floor(anchor.treeSize / 2);

  const tamperedTree = treeFrom(leaves.map((leaf) => leaf.leafIndex === targetIndex
    ? { ...leaf, canonicalBytes: flipLastByte(leaf.canonicalBytes) }
    : leaf));
  for (let index = 0; index < followUpLeaves; index += 1) {
    tamperedTree.appendLeaf(new Uint8Array(Buffer.from(`{"eventType":"CROSS_CHECKPOINT","followUp":${index}}`)));
  }
  const nextSize = anchor.treeSize + followUpLeaves;
  const nextRoot = tamperedTree.currentRoot();
  const tamperedProof = tamperedTree.consistencyProof(anchor.treeSize, nextSize);
  const tamper = await timed(() => !verifyConsistency(
    anchor.rootHash, anchor.treeSize, nextRoot, nextSize, tamperedProof
  ));

  const omittedLeaves = leaves.filter((leaf) => leaf.leafIndex !== targetIndex);
  const omittedTree = treeFrom(omittedLeaves);
  const omission = await timed(() =>
    omittedLeaves.length < anchor.treeSize && omittedTree.currentRoot() !== anchor.rootHash);

  return {
    targetIndex,
    tamper: { detected: tamper.value, verifyMs: tamper.ms },
    omission: { detected: omission.value, verifyMs: omission.ms }
  };
}

async function measureS1Injected(mode: string, repeat: number): Promise<AttackRow[]> {
  const base = { mode, repeat, property: "S1" as const };
  let snapshot: { copyPath: string; tempDir: string } | null = null;
  try {
    const anchor = await latestAnchorOnA(repeat);
    snapshot = snapshotAuditDb(`s1-${repeat}`);
    const copy = new Database(snapshot.copyPath);
    try {
      const leaves = anchoredLeaves(copy, anchor.treeSize);
      const outcome = await runS1Injection(leaves, anchor);
      // The tampering case registers its root on an isolated contract before detecting it.
      const onchain = await runS1OnchainTamper(leaves, outcome.targetIndex);
      return [
        {
          ...base,
          attackType: "past-log-tamper",
          detected: onchain.detected,
          detectionMs: round(onchain.verifyMs),
          // Two anchors registered on the isolated contract: honest, then tampered.
          anchorsRequired: 2,
          anchorBatchIds: `${onchain.batchIds}@${onchain.contractAddress}`,
          injectedLeafIndex: outcome.targetIndex,
          status: onchain.detected ? "ok" : "failed"
        },
        {
          ...base,
          attackType: "log-entry-omission",
          detected: outcome.omission.detected,
          detectionMs: round(outcome.omission.verifyMs),
          anchorsRequired: 1,
          anchorBatchIds: String(anchor.batchId),
          injectedLeafIndex: outcome.targetIndex,
          status: outcome.omission.detected ? "ok" : "failed"
        }
      ];
    } finally {
      copy.close();
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return ["past-log-tamper", "log-entry-omission"].map((attackType) => ({
      ...base,
      attackType,
      detected: false,
      detectionMs: 0,
      anchorsRequired: null,
      status: "failed" as const,
      error: message
    }));
  } finally {
    if (snapshot) {
      rmSync(snapshot.tempDir, { recursive: true, force: true });
    }
  }
}

async function measureS1ContractRevert(mode: string, repeat: number): Promise<AttackRow> {
  const measured = await timed(async () => {
    await addCheckpointAndAnchor("A", `s1-revert-${repeat}`);
    const anchors = pinnedAnchors();
    const latest = (await chainAnchors(anchors.a)).at(-1);
    if (!latest) {
      throw new Error("A has no anchors after checkpoint");
    }
    const client = new AnchorClient(rpcUrl(), anchors.a, readWalletPrivateKey(defaultInstitutionWalletKeyPath("A", rootDir)));
    // Detection must come from the contract's append-only revert. Counting every exception
    // would turn a transient failure such as a nonce race into a false positive.
    try {
      await retryTransientStep(() => client.registerAnchor(latest.rootHash, latest.treeSize, latest.mapRoot));
      return false;
    } catch (error) {
      return !isTransientError(error);
    }
  });
  return {
    mode,
    repeat,
    property: "S1",
    attackType: "tree-size-regression-revert",
    detected: measured.value,
    detectionMs: round(measured.ms),
    anchorsRequired: 1,
    status: measured.value ? "ok" : "failed"
  };
}

async function measureS2(mode: string, repeat: number): Promise<AttackRow[]> {
  await releasePeerHold().catch(() => undefined);
  const result = await timedCommandWithAnchors("e2e:violation");
  const output = result.value.output;
  const ok = result.value.status === 0;
  const cases = [
    { type: "seq-k-plus-one", marker: violationCaseMarker("k-plus-one") },
    { type: "seq-skip-k-plus-seven", marker: violationCaseMarker("skip-seq") },
    { type: "logtree-only-no-head-update", marker: violationCaseMarker("no-head-update") }
  ];
  return cases.map((entry) => ({
    mode,
    repeat,
    property: "S2" as const,
    attackType: entry.type,
    detected: ok && output.includes(entry.marker),
    detectionMs: round(result.ms),
    anchorsRequired: result.value.anchorDelta,
    command: "npm run e2e:violation",
    status: ok && output.includes(entry.marker) ? "ok" as const : "failed" as const,
    error: ok ? undefined : output.slice(-1000)
  }));
}

async function measureS3(mode: string, repeat: number): Promise<AttackRow[]> {
  await releasePeerHold().catch(() => undefined);
  const dispute = await timedCommandWithAnchors("e2e:dispute");
  await releasePeerHold().catch(() => undefined);
  const concealment = await timedCommandWithAnchors("demo:concealment");
  await releasePeerHold().catch(() => undefined);
  const receiptless = await (async () => {
    try {
      await restartGatewaysWithRuntimeEnv({ receiptTimeoutSec: 5, simulatedReceiptDelayMs: 10_000 });
      return await timedCommandWithAnchors("e2e:receiptless-claim");
    } finally {
      await restoreGatewaysFromProcessEnv();
      await releasePeerHold().catch(() => undefined);
    }
  })();

  return [
    {
      mode,
      repeat,
      property: "S3" as const,
      attackType: "receiver-denial",
      detected: dispute.value.status === 0 && dispute.value.output.includes(VERIFIER_VERDICTS.bDenialRejected),
      detectionMs: round(dispute.ms),
      anchorsRequired: dispute.value.anchorDelta,
      command: "npm run e2e:dispute",
      status: dispute.value.status === 0 ? "ok" as const : "failed" as const,
      error: dispute.value.status === 0 ? undefined : dispute.value.output.slice(-1000)
    },
    {
      mode,
      repeat,
      // Detection here is a root recomputation failure, so the case belongs to log
      // completeness (S1) rather than non-repudiation.
      property: "S1" as const,
      attackType: "post-anchor-completion-entry-deletion",
      detected: concealment.value.status === 0
        && concealment.value.output.includes(CONCEALMENT_ROOT_MISMATCH),
      detectionMs: round(concealment.ms),
      anchorsRequired: concealment.value.anchorDelta,
      command: "npm run demo:concealment",
      status: concealment.value.status === 0 ? "ok" as const : "failed" as const,
      error: concealment.value.status === 0 ? undefined : concealment.value.output.slice(-1000)
    },
    {
      mode,
      repeat,
      property: "S3" as const,
      // The receipt arrives after the timeout, so only RECEIPT_LATE remains and no completion
      // pair is formed. The receipt is not absent, hence the name is stated in those terms.
      attackType: "no-timely-anchored-completion-pair",
      detected: receiptless.value.status === 0
        && receiptless.value.output.includes(VERIFIER_VERDICTS.aClaimNotEstablished),
      detectionMs: round(receiptless.ms),
      anchorsRequired: receiptless.value.anchorDelta,
      command: "npm run e2e:receiptless-claim",
      status: receiptless.value.status === 0 ? "ok" as const : "failed" as const,
      error: receiptless.value.status === 0 ? undefined : receiptless.value.output.slice(-1000)
    }
  ];
}

async function ensureAttackStudy(repeat: number): Promise<void> {
  const uid = syntheticStudyUid("attack", repeat, "study");
  const path = syntheticDicomPath("attack", repeat, "study");
  writeSyntheticDicom({
    studyInstanceUid: uid,
    seriesInstanceUid: `${uid}.1`,
    sopInstanceUid: `${uid}.1.1`,
    targetPixelBytes: 512 * 512,
    outputPath: path
  });
  await retryTransientStep(() => stowDicomToOrthancA(path));
  process.env.SCENARIO_STUDY_UID = uid;
}

function runNpmScript(script: string): { status: number; output: string } {
  const result = spawnSync("npm", ["run", script], {
    cwd: rootDir,
    env: { ...process.env, ENABLE_DEV_ENDPOINTS: "true" },
    encoding: "utf8",
    shell: process.platform === "win32"
  });
  return {
    status: result.status ?? 1,
    output: `${result.stdout ?? ""}\n${result.stderr ?? ""}${result.error ? `\n${String(result.error)}` : ""}`
  };
}

async function timedCommandWithAnchors(script: string): Promise<{ value: { status: number; output: string; anchorDelta: number }; ms: number }> {
  const before = await totalAnchorCount();
  const measured = await timed(() => runNpmScript(script));
  const after = await totalAnchorCount();
  return {
    ms: measured.ms,
    value: {
      ...measured.value,
      anchorDelta: Math.max(0, after - before)
    }
  };
}

async function totalAnchorCount(): Promise<number> {
  const anchors = pinnedAnchors();
  const [a, b] = await Promise.all([chainAnchors(anchors.a), chainAnchors(anchors.b)]);
  return a.length + b.length;
}

function writeOutputs(config: EvalConfig, rows: AttackRow[]): void {
  writeCsv(join(config.outDir, "raw", "attack_injection.csv"), rows);
  writeJson(join(config.outDir, "raw", "attack_injection.json"), rows);
  const summary = Array.from(
    rows.reduce((map, row) => {
      const key = `${row.property}|${row.attackType}`;
      const current = map.get(key) ?? { property: row.property, attackType: row.attackType, attempts: 0, detections: 0, totalMs: 0 };
      if (row.status !== "skipped") {
        current.attempts += 1;
        current.detections += row.detected ? 1 : 0;
        current.totalMs += row.detectionMs;
      }
      map.set(key, current);
      return map;
    }, new Map<string, { property: string; attackType: string; attempts: number; detections: number; totalMs: number }>())
      .values()
  ).map((row) => ({
    property: row.property,
    attackType: row.attackType,
    attempts: row.attempts,
    detections: row.detections,
    detectionRate: row.attempts > 0 ? round(row.detections / row.attempts) : 0,
    meanDetectionMs: row.attempts > 0 ? round(row.totalMs / row.attempts) : 0
  }));
  writeCsv(join(config.outDir, "summary", "attack-injection-summary.csv"), summary);
  writeCsv(
    join(config.outDir, "summary", "attack-injection-numeric-summary.csv"),
    numericMetricSummaries(
      rows.filter((row) => row.status !== "skipped") as unknown as Record<string, unknown>[],
      ["property", "attackType"],
      ["detectionMs", "anchorsRequired"]
    )
  );
}

function skippedRow(mode: string, property: "S1" | "S2" | "S3", attackType: string, reason: string): AttackRow {
  return {
    mode,
    repeat: 0,
    property,
    attackType,
    detected: false,
    detectionMs: 0,
    anchorsRequired: null,
    status: "skipped",
    error: reason
  };
}
