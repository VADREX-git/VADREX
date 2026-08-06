import { describe, expect, it } from "vitest";
import { Rfc6962LogTree, verifyConsistency } from "@vadrex/merkle";
import { type AnchoredLeaf, type AnchorRef, runS1Injection } from "../src/measure-attack.js";

// Exercises the detection logic of the S1 injection without docker. The detection results only
// mean something if the honest log passes first, so the no-false-positive case is checked too.

function buildLog(size: number): AnchoredLeaf[] {
  return Array.from({ length: size }, (_, index) => ({
    leafIndex: index,
    canonicalBytes: Buffer.from(`{"eventType":"CROSS_CHECKPOINT","seq":${index}}`)
  }));
}

function treeOf(leaves: readonly AnchoredLeaf[]): Rfc6962LogTree {
  const tree = new Rfc6962LogTree();
  for (const leaf of leaves) {
    tree.appendLeaf(new Uint8Array(leaf.canonicalBytes));
  }
  return tree;
}

function anchorOf(leaves: readonly AnchoredLeaf[]): AnchorRef {
  return { batchId: 7, treeSize: leaves.length, rootHash: treeOf(leaves).currentRoot() };
}

// Powers of two must be covered: as the regression test below shows, those shapes are where a
// consistency proof can hide a tampered leaf.
const SIZES = [2, 4, 16, 23, 813];

describe("S1 injection detection", () => {
  it.each(SIZES)("an honest log reproduces the anchored root and proves consistent (no false positive, n=%i)", (size) => {
    const leaves = buildLog(size);
    const anchor = anchorOf(leaves);
    const tree = treeOf(leaves);
    tree.appendLeaf(new Uint8Array(Buffer.from("{\"eventType\":\"CROSS_CHECKPOINT\",\"followUp\":0}")));

    expect(treeOf(leaves).currentRoot()).toBe(anchor.rootHash);
    expect(verifyConsistency(
      anchor.rootHash, anchor.treeSize, tree.currentRoot(), size + 1,
      tree.consistencyProof(anchor.treeSize, size + 1)
    )).toBe(true);
  });

  it.each(SIZES)("tampering with and deleting a past leaf are both detected (n=%i)", async (size) => {
    const leaves = buildLog(size);
    const outcome = await runS1Injection(leaves, anchorOf(leaves));

    expect(outcome.targetIndex).toBeLessThan(size);
    expect(outcome.tamper.detected).toBe(true);
    expect(outcome.omission.detected).toBe(true);
  });

  // Regression guard: a consistency proof *between* two anchored points does not reveal
  // tampering, because it reuses the old root exactly as the verifier supplied it. This is why
  // the injection model anchors the next batch from the tampered log instead.
  it("a consistency proof between two already anchored points does not reveal tampering", () => {
    const leaves = buildLog(16);
    const honest = treeOf(leaves);
    const earlierRoot = honest.rootAt(4);
    const latestRoot = honest.currentRoot();

    const tampered = treeOf(leaves.map((leaf) => leaf.leafIndex === 2
      ? { ...leaf, canonicalBytes: Buffer.from("{\"eventType\":\"TAMPERED\"}") }
      : leaf));

    expect(tampered.currentRoot()).not.toBe(latestRoot);
    expect(verifyConsistency(
      earlierRoot, 4, latestRoot, 16, tampered.consistencyProof(4, 16)
    )).toBe(true);
  });

  it("fails without injecting when the intact snapshot does not reproduce the anchored root", async () => {
    const leaves = buildLog(16);
    const wrongAnchor: AnchorRef = { ...anchorOf(leaves), rootHash: `0x${"11".repeat(32)}` };

    await expect(runS1Injection(leaves, wrongAnchor)).rejects.toThrow(/does not reproduce anchor/);
  });

  it("fails when the leaf count differs from the anchored treeSize", async () => {
    const leaves = buildLog(16);

    await expect(runS1Injection(leaves.slice(0, 15), anchorOf(leaves))).rejects.toThrow(/does not reproduce anchor/);
  });

  // The relation the on-chain injection relies on: no consistency proof can link an anchor
  // registered from the honest log to the next one registered from the tampered log.
  it.each(SIZES)("an honest anchor and a tampered follow-up anchor cannot be proved consistent (n=%i)", (size) => {
    const leaves = buildLog(size);
    const honestRoot = treeOf(leaves).currentRoot();
    const targetIndex = Math.floor(size / 2);

    const tampered = treeOf(leaves.map((leaf) => leaf.leafIndex === targetIndex
      ? { ...leaf, canonicalBytes: Buffer.from("{\"eventType\":\"TAMPERED\"}") }
      : leaf));
    for (let i = 0; i < 3; i += 1) {
      tampered.appendLeaf(new Uint8Array(Buffer.from(`{"eventType":"CROSS_CHECKPOINT","followUp":${i}}`)));
    }
    const secondSize = size + 3;

    expect(verifyConsistency(
      honestRoot, size, tampered.currentRoot(), secondSize, tampered.consistencyProof(size, secondSize)
    )).toBe(false);
  });
});
