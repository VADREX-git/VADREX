import { describe, expect, it } from "vitest";
import { computeEntryHash, entryPreimage, type AuditEntry } from "@vadrex/shared";
import { EMPTY_TREE_HASH, leafHash, Rfc6962LogTree, verifyConsistency, verifyInclusion } from "../src/index.js";

const encoder = new TextEncoder();

function bytes(input: string): Uint8Array {
  return encoder.encode(input);
}

function rawHex(hex: string): Uint8Array {
  const normalized = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

function buildTree(leaves: readonly Uint8Array[]): Rfc6962LogTree {
  const tree = new Rfc6962LogTree();
  for (const leaf of leaves) {
    tree.appendLeaf(leaf);
  }
  return tree;
}

function numberedLeaves(count: number): Uint8Array[] {
  return Array.from({ length: count }, (_, index) => bytes(`leaf-${index.toString().padStart(4, "0")}`));
}

describe("RFC 6962 log tree", () => {
  it("matches public Certificate Transparency Merkle tree test vectors", () => {
    // Source: Google Certificate Transparency community vectors, mirrored in
    // certificate-transparency/src/python/ct/crypto/merkle_test.py and cited by
    // SUNET plop ht.erl tests:
    // https://git.sunet.se/plop.git/tree/src/ht.erl?h=plop-0.10.1&id=285c44c882a50cdd43d4734dce2dc7be70329afe
    // The construction is the RFC 6962 Merkle Tree Hash.
    const leaves = [
      rawHex(""),
      rawHex("00"),
      rawHex("10"),
      bytes(" !"),
      bytes("01"),
      bytes("@ABC"),
      bytes("PQRSTUVW"),
      bytes("`abcdefghijklmno")
    ];
    const expectedRoots = [
      "0x6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
      "0xfac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
      "0xaeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
      "0xd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
      "0x4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
      "0x76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
      "0xddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
      "0x5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"
    ];

    expect(new Rfc6962LogTree().currentRoot()).toBe(EMPTY_TREE_HASH);

    const tree = new Rfc6962LogTree();
    for (let index = 0; index < leaves.length; index += 1) {
      tree.appendLeaf(leaves[index]);
      expect(tree.currentRoot()).toBe(expectedRoots[index]);
    }
  });

  it("uses canonical AuditEntry preimage bytes rather than entryHash bytes as the leaf input", () => {
    const draft: Omit<AuditEntry, "entryHash"> = {
      eventType: "TRANSFER_APPROVED",
      timestamp: 1_725_000_000,
      institutionId: "A",
      consentId: "consent-1",
      seq: 2,
      prevHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
      requestContext: { purpose: "research", study: "CT" },
      peerEntryHash: null,
      peerSignature: null
    };
    const entry: AuditEntry = { ...draft, entryHash: "" };
    entry.entryHash = computeEntryHash(entry);

    const preimage = entryPreimage(entry);
    const tree = buildTree([preimage]);
    const proof = tree.inclusionProof(0, 1);

    expect(verifyInclusion(tree.currentRoot(), 1, leafHash(preimage), proof)).toBe(true);
    expect(verifyInclusion(tree.currentRoot(), 1, leafHash(rawHex(entry.entryHash)), proof)).toBe(false);
  });

  it("verifies valid inclusion proofs and rejects a tampered leaf", () => {
    const tree = buildTree(numberedLeaves(8));
    const proof = tree.inclusionProof(3, tree.treeSize());

    expect(verifyInclusion(tree.currentRoot(), tree.treeSize(), leafHash(bytes("leaf-0003")), proof)).toBe(true);
    expect(verifyInclusion(tree.currentRoot(), tree.treeSize(), leafHash(bytes("leaf-9999")), proof)).toBe(false);
  });

  it("rejects malformed non-integer inclusion proof indexes", () => {
    const tree = buildTree([bytes("single-leaf")]);
    const proof = { ...tree.inclusionProof(0, 1), leafIndex: 0.5 };

    expect(verifyInclusion(tree.currentRoot(), 1, leafHash(bytes("single-leaf")), proof)).toBe(false);
  });

  it("verifies valid consistency proofs", () => {
    const tree = buildTree(numberedLeaves(100));
    const proof = tree.consistencyProof(50, 100);

    expect(verifyConsistency(tree.rootAt(50), 50, tree.rootAt(100), 100, proof)).toBe(true);
  });

  it("detects middle-leaf deletion during consistency verification", () => {
    const originalLeaves = numberedLeaves(10);
    const original = buildTree(originalLeaves);
    const deleted = buildTree(originalLeaves.filter((_, index) => index !== 6));
    const deletedProof = deleted.consistencyProof(5, 9);

    expect(() => deleted.consistencyProof(5, 10)).toThrow();
    expect(verifyConsistency(original.rootAt(5), 5, original.rootAt(10), 10, deletedProof)).toBe(false);

    // Forging the metadata (secondSize) to match the anchor must still fail hash reconstruction
    const forged = { ...deletedProof, secondSize: 10 };
    expect(verifyConsistency(original.rootAt(5), 5, original.rootAt(10), 10, forged)).toBe(false);

    // Padding with a duplicate leaf to match the anchored treeSize yields a different root
    const padded = buildTree([...originalLeaves.filter((_, index) => index !== 6), originalLeaves[9]]);
    expect(verifyConsistency(original.rootAt(5), 5, original.rootAt(10), 10, padded.consistencyProof(5, 10))).toBe(false);
  });

  it("detects leaf reordering during consistency verification", () => {
    const originalLeaves = numberedLeaves(10);
    const original = buildTree(originalLeaves);
    const reorderedLeaves = [...originalLeaves];
    [reorderedLeaves[6], reorderedLeaves[7]] = [reorderedLeaves[7], reorderedLeaves[6]];
    const reordered = buildTree(reorderedLeaves);
    const reorderedProof = reordered.consistencyProof(5, 10);

    expect(verifyConsistency(original.rootAt(5), 5, original.rootAt(10), 10, reorderedProof)).toBe(false);
  });

  it("keeps the incremental currentRoot identical to the recomputed prefix root while appending", () => {
    const tree = new Rfc6962LogTree();
    for (let size = 1; size <= 130; size += 1) {
      tree.appendLeaf(bytes(`leaf-${size}`));
      // rootAt recomputes from the leaf array, giving a control independent of the incremental path
      expect(tree.currentRoot()).toBe(tree.rootAt(size));
    }
  });

  it("computes currentRoot without a full recomputation on a large tree", () => {
    const tree = buildTree(numberedLeaves(50_000));
    const started = performance.now();
    for (let call = 0; call < 100; call += 1) {
      tree.currentRoot();
    }
    const elapsed = performance.now() - started;
    // Full recomputation would take about 60s for 100 roots, the incremental path under 1ms;
    // this bound is loose and only catches a regression to full recomputation
    expect(elapsed).toBeLessThan(200);
  });

  it("verifies consistency proofs for sampled pairs across a 1000-leaf tree", () => {
    const tree = buildTree(numberedLeaves(1000));
    const sampledSizes = [1, 2, 3, 4, 5, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256, 511, 512, 999, 1000];

    for (let leftIndex = 0; leftIndex < sampledSizes.length; leftIndex += 1) {
      for (let rightIndex = leftIndex + 1; rightIndex < sampledSizes.length; rightIndex += 1) {
        const size1 = sampledSizes[leftIndex];
        const size2 = sampledSizes[rightIndex];
        const proof = tree.consistencyProof(size1, size2);
        expect(verifyConsistency(tree.rootAt(size1), size1, tree.rootAt(size2), size2, proof)).toBe(true);
      }
    }
  });
});
