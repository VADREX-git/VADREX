import { randomBytes } from "node:crypto";
import { join } from "node:path";
import {
  InMemorySmtStore,
  leafHash,
  Rfc6962LogTree,
  smtLeafKey,
  SparseMerkleTree,
  verifyConsistency,
  verifyInclusion,
  verifySmtNonInclusion
} from "@vadrex/merkle";
import { sha256 } from "@vadrex/shared";
import type { EvalConfig } from "./common.js";
import { groupStats, modeSizes, numericMetricSummaries, round, timed, writeCsv, writeJson } from "./common.js";

export interface ScalingRow {
  mode: string;
  repeat: number;
  logicalLeaves: number;
  proofType: "inclusion" | "consistency" | "smtNonInclusion";
  proofBytes: number;
  proofHashes: number;
  verifyMs: number;
  verified: boolean;
  smtInsertedKeys?: number;
  note?: string;
}

export async function measureScaling(config: EvalConfig): Promise<ScalingRow[]> {
  const rows: ScalingRow[] = [];
  const sizes = modeSizes(config.mode);
  const maxSize = Math.max(...sizes);
  const tree = new Rfc6962LogTree();
  const preimages: Buffer[] = [];

  const buildStarted = Date.now();
  for (let index = 0; index < maxSize; index += 1) {
    const preimage = deterministicPreimage(index);
    preimages.push(preimage);
    tree.appendLeaf(preimage);
  }
  const buildMs = Date.now() - buildStarted;

  const smt = new SparseMerkleTree(new InMemorySmtStore());
  const smtSecret = `0x${randomBytes(32).toString("hex")}`;
  const smtPresentKey = smtLeafKey(smtSecret, "eval-consent", 1);
  smt.set(smtPresentKey, sha256("eval-smt-present"));

  for (const size of sizes) {
    const leafIndex = Math.max(0, Math.floor(size / 2));
    const leafHashValue = leafHash(preimages[leafIndex]);
    const root = tree.rootAt(size);
    const inclusionProof = tree.inclusionProof(leafIndex, size);

    const firstSize = Math.max(1, Math.floor(size / 2));
    const oldRoot = tree.rootAt(firstSize);
    const consistencyProof = tree.consistencyProof(firstSize, size);

    const absentKey = smtLeafKey(smtSecret, `eval-absent-${size}`, 2);
    const smtProof = smt.nonInclusionProof(absentKey);
    const smtRoot = smt.mapRoot();

    for (let repeat = 1; repeat <= config.repeats; repeat += 1) {
      const inclusion = await timed(() => verifyInclusion(root, size, leafHashValue, inclusionProof));
      rows.push({
        mode: config.mode,
        repeat,
        logicalLeaves: size,
        proofType: "inclusion",
        proofBytes: Buffer.byteLength(JSON.stringify(inclusionProof), "utf8"),
        proofHashes: inclusionProof.hashes.length,
        verifyMs: round(inclusion.ms),
        verified: inclusion.value
      });

      const consistency = await timed(() => verifyConsistency(oldRoot, firstSize, root, size, consistencyProof));
      rows.push({
        mode: config.mode,
        repeat,
        logicalLeaves: size,
        proofType: "consistency",
        proofBytes: Buffer.byteLength(JSON.stringify(consistencyProof), "utf8"),
        proofHashes: consistencyProof.hashes.length,
        verifyMs: round(consistency.ms),
        verified: consistency.value
      });

      const smtNonInclusion = await timed(() => verifySmtNonInclusion(smtRoot, smtProof));
      rows.push({
        mode: config.mode,
        repeat,
        logicalLeaves: size,
        proofType: "smtNonInclusion",
        proofBytes: Buffer.byteLength(JSON.stringify(smtProof), "utf8"),
        proofHashes: smtProof.siblings.length,
        verifyMs: round(smtNonInclusion.ms),
        verified: smtNonInclusion.value,
        smtInsertedKeys: 1,
        note: "SMT depth is fixed at 256; logicalLeaves is used for side-by-side plotting."
      });
    }
  }

  writeCsv(join(config.outDir, "raw", "scaling.csv"), rows);
  writeJson(join(config.outDir, "raw", "scaling.json"), rows);
  writeCsv(join(config.outDir, "summary", "scaling-verify-ms.csv"), groupStats(rows, ["logicalLeaves", "proofType"], "verifyMs"));
  writeCsv(
    join(config.outDir, "summary", "scaling-numeric-summary.csv"),
    numericMetricSummaries(rows as unknown as Record<string, unknown>[], ["logicalLeaves", "proofType"], ["proofBytes", "proofHashes", "verifyMs"])
  );
  writeJson(join(config.outDir, "summary", "scaling-10m-estimate.json"), estimateTenMillion({
    sizes,
    maxSize,
    buildMs,
    averagePreimageBytes: preimages.reduce((sum, preimage) => sum + preimage.length, 0) / preimages.length
  }));
  return rows;
}

function deterministicPreimage(index: number): Buffer {
  return Buffer.from(JSON.stringify({ index, payload: sha256(`vadrex-eval-leaf-${index}`) }), "utf8");
}

function estimateTenMillion(input: {
  sizes: readonly number[];
  maxSize: number;
  buildMs: number;
  averagePreimageBytes: number;
}): Record<string, unknown> {
  const targetLeaves = 10_000_000;
  const includedInRun = input.sizes.includes(targetLeaves);
  const ratio = targetLeaves / input.maxSize;
  return {
    targetLeaves,
    includedInRun,
    explicitOptIn: process.env.EVAL_INCLUDE_10M === "true",
    maxMeasuredLeaves: input.maxSize,
    measuredTreeBuildMs: input.buildMs,
    estimatedTreeBuildMs: includedInRun ? input.buildMs : round(input.buildMs * ratio),
    estimatedPreimageBytes: Math.round(input.averagePreimageBytes * targetLeaves),
    estimatedLeafHashStringBytes: 66 * targetLeaves,
    note: includedInRun
      ? "10^7 leaves were included in this run."
      : "10^7 leaves were not executed; estimate is linear from the largest measured tree build and excludes JS object overhead."
  };
}
