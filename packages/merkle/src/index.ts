// RFC 6962 append-only log tree.
//
// The leaf input is the same preimage used for the entry hash, i.e. the canonical bytes of
// the audit entry without its entryHash field. So leafHash = sha256(0x00 || preimage) while
// entryHash = sha256(preimage): the entry hash is an identifier for lookup, never the input
// to the leaf hash. Producers and verifiers must recompute leaves by this rule.
//
// The verify* functions are deliberately free of tree state so a browser or CLI verifier can
// reuse them without holding the log.
import { sha256 } from "@noble/hashes/sha256";
import type { ConsistencyProof, HexString, InclusionProof } from "@vadrex/shared";

export {
  EMPTY_SMT_HASHES,
  EMPTY_SMT_ROOT,
  InMemorySmtStore,
  SparseMerkleTree,
  deriveReceiverSecret,
  smtHeadKey,
  smtLeafKey,
  verifySmtInclusion,
  verifySmtNonInclusion
} from "./smt.js";
export type { SmtNode, SmtNodeStore } from "./smt.js";

type BytesLike = Uint8Array;

const HASH_BYTES = 32;

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const length = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): HexString {
  return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function normalizeHex(hash: string): HexString {
  if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) {
    throw new Error(`expected 32-byte 0x-prefixed hex hash, got ${hash}`);
  }
  return `0x${hash.slice(2).toLowerCase()}`;
}

function hexToBytes(hash: string): Uint8Array {
  const normalized = normalizeHex(hash);
  const bytes = new Uint8Array(HASH_BYTES);
  for (let i = 0; i < HASH_BYTES; i += 1) {
    bytes[i] = Number.parseInt(normalized.slice(2 + i * 2, 4 + i * 2), 16);
  }
  return bytes;
}

function equalHex(left: string, right: string): boolean {
  return normalizeHex(left) === normalizeHex(right);
}

function largestPowerOfTwoLessThan(n: number): number {
  if (!Number.isInteger(n) || n <= 1) {
    throw new Error(`n must be an integer greater than 1, got ${n}`);
  }

  let power = 1;
  while (power * 2 < n) {
    power *= 2;
  }
  return power;
}

function assertTreeSize(size: number, name: string): void {
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new Error(`${name} must be a non-negative safe integer`);
  }
}

function assertLeafIndex(index: number): void {
  if (!Number.isSafeInteger(index) || index < 0) {
    throw new Error("leafIndex must be a non-negative safe integer");
  }
}

function sha256Hex(input: Uint8Array): HexString {
  return bytesToHex(sha256(input));
}

export const EMPTY_TREE_HASH: HexString = sha256Hex(new Uint8Array());

export function leafHash(preimage: BytesLike): HexString {
  return sha256Hex(concatBytes(new Uint8Array([0]), preimage));
}

export function nodeHash(left: string, right: string): HexString {
  return sha256Hex(concatBytes(new Uint8Array([1]), hexToBytes(left), hexToBytes(right)));
}

function treeHashFromLeaves(leafHashes: readonly HexString[], start: number, end: number): HexString {
  const size = end - start;
  if (size === 0) {
    return EMPTY_TREE_HASH;
  }
  if (size === 1) {
    return normalizeHex(leafHashes[start]);
  }

  const split = start + largestPowerOfTwoLessThan(size);
  return nodeHash(treeHashFromLeaves(leafHashes, start, split), treeHashFromLeaves(leafHashes, split, end));
}

function inclusionPath(
  leafHashes: readonly HexString[],
  leafIndex: number,
  start: number,
  size: number
): HexString[] {
  if (size === 1) {
    return [];
  }

  const splitSize = largestPowerOfTwoLessThan(size);
  if (leafIndex < splitSize) {
    return [
      ...inclusionPath(leafHashes, leafIndex, start, splitSize),
      treeHashFromLeaves(leafHashes, start + splitSize, start + size)
    ];
  }

  return [
    ...inclusionPath(leafHashes, leafIndex - splitSize, start + splitSize, size - splitSize),
    treeHashFromLeaves(leafHashes, start, start + splitSize)
  ];
}

function consistencyPath(
  leafHashes: readonly HexString[],
  firstSize: number,
  start: number,
  secondSize: number,
  subtreeRootAlreadyKnown: boolean
): HexString[] {
  if (firstSize === secondSize) {
    return subtreeRootAlreadyKnown ? [] : [treeHashFromLeaves(leafHashes, start, start + secondSize)];
  }

  const splitSize = largestPowerOfTwoLessThan(secondSize);
  if (firstSize <= splitSize) {
    return [
      ...consistencyPath(leafHashes, firstSize, start, splitSize, subtreeRootAlreadyKnown),
      treeHashFromLeaves(leafHashes, start + splitSize, start + secondSize)
    ];
  }

  return [
    ...consistencyPath(leafHashes, firstSize - splitSize, start + splitSize, secondSize - splitSize, false),
    treeHashFromLeaves(leafHashes, start, start + splitSize)
  ];
}

function calculateInclusionRoot(
  leafHashValue: HexString,
  leafIndex: number,
  treeSize: number,
  proofHashes: readonly HexString[],
  proofIndex: number
): { root: HexString; proofIndex: number } {
  if (treeSize === 1) {
    return { root: leafHashValue, proofIndex };
  }

  const splitSize = largestPowerOfTwoLessThan(treeSize);
  if (leafIndex < splitSize) {
    const child = calculateInclusionRoot(leafHashValue, leafIndex, splitSize, proofHashes, proofIndex);
    const sibling = proofHashes[child.proofIndex];
    if (sibling === undefined) {
      throw new Error("inclusion proof ended before root could be reconstructed");
    }
    return { root: nodeHash(child.root, sibling), proofIndex: child.proofIndex + 1 };
  }

  const child = calculateInclusionRoot(
    leafHashValue,
    leafIndex - splitSize,
    treeSize - splitSize,
    proofHashes,
    proofIndex
  );
  const sibling = proofHashes[child.proofIndex];
  if (sibling === undefined) {
    throw new Error("inclusion proof ended before root could be reconstructed");
  }
  return { root: nodeHash(sibling, child.root), proofIndex: child.proofIndex + 1 };
}

function calculateConsistencyRoots(
  oldRoot: HexString,
  firstSize: number,
  secondSize: number,
  subtreeRootAlreadyKnown: boolean,
  proofHashes: readonly HexString[],
  proofIndex: number
): { firstRoot: HexString; secondRoot: HexString; proofIndex: number } {
  if (firstSize === secondSize) {
    if (subtreeRootAlreadyKnown) {
      return { firstRoot: oldRoot, secondRoot: oldRoot, proofIndex };
    }

    const subtreeRoot = proofHashes[proofIndex];
    if (subtreeRoot === undefined) {
      throw new Error("consistency proof ended before old subtree root could be reconstructed");
    }
    return { firstRoot: subtreeRoot, secondRoot: subtreeRoot, proofIndex: proofIndex + 1 };
  }

  const splitSize = largestPowerOfTwoLessThan(secondSize);
  if (firstSize <= splitSize) {
    const child = calculateConsistencyRoots(
      oldRoot,
      firstSize,
      splitSize,
      subtreeRootAlreadyKnown,
      proofHashes,
      proofIndex
    );
    const rightRoot = proofHashes[child.proofIndex];
    if (rightRoot === undefined) {
      throw new Error("consistency proof ended before new root could be reconstructed");
    }
    return {
      firstRoot: child.firstRoot,
      secondRoot: nodeHash(child.secondRoot, rightRoot),
      proofIndex: child.proofIndex + 1
    };
  }

  const child = calculateConsistencyRoots(
    oldRoot,
    firstSize - splitSize,
    secondSize - splitSize,
    false,
    proofHashes,
    proofIndex
  );
  const leftRoot = proofHashes[child.proofIndex];
  if (leftRoot === undefined) {
    throw new Error("consistency proof ended before old root could be reconstructed");
  }
  return {
    firstRoot: nodeHash(leftRoot, child.firstRoot),
    secondRoot: nodeHash(leftRoot, child.secondRoot),
    proofIndex: child.proofIndex + 1
  };
}

export class Rfc6962LogTree {
  private readonly leafHashes: HexString[] = [];
  // Roots of the completed 2^k subtrees, largest first: the binary representation of the
  // tree size. Appending merges them like a binary counter, which keeps currentRoot at
  // O(log n); recomputing the whole tree would cost seconds once the log holds tens of
  // thousands of leaves, stalling the anchor loop.
  private readonly subtreeRoots: { size: number; hash: HexString }[] = [];

  constructor(preimages: readonly BytesLike[] = []) {
    for (const preimage of preimages) {
      this.appendLeaf(preimage);
    }
  }

  appendLeaf(preimage: BytesLike): number {
    const leafIndex = this.leafHashes.length;
    const hash = leafHash(preimage);
    this.leafHashes.push(hash);

    this.subtreeRoots.push({ size: 1, hash });
    while (
      this.subtreeRoots.length >= 2 &&
      this.subtreeRoots[this.subtreeRoots.length - 1].size === this.subtreeRoots[this.subtreeRoots.length - 2].size
    ) {
      const right = this.subtreeRoots.pop()!;
      const left = this.subtreeRoots.pop()!;
      this.subtreeRoots.push({ size: left.size * 2, hash: nodeHash(left.hash, right.hash) });
    }

    return leafIndex;
  }

  currentRoot(): HexString {
    if (this.subtreeRoots.length === 0) {
      return EMPTY_TREE_HASH;
    }
    // RFC 6962 MTH splits at the largest power of two below the size, so folding the
    // remaining subtree roots right to left reproduces the full root.
    let root = this.subtreeRoots[this.subtreeRoots.length - 1].hash;
    for (let index = this.subtreeRoots.length - 2; index >= 0; index -= 1) {
      root = nodeHash(this.subtreeRoots[index].hash, root);
    }
    return root;
  }

  rootAt(treeSize: number): HexString {
    assertTreeSize(treeSize, "treeSize");
    if (treeSize > this.leafHashes.length) {
      throw new Error(`treeSize ${treeSize} exceeds current tree size ${this.leafHashes.length}`);
    }
    return treeHashFromLeaves(this.leafHashes, 0, treeSize);
  }

  treeSize(): number {
    return this.leafHashes.length;
  }

  inclusionProof(leafIndex: number, treeSize: number = this.treeSize()): InclusionProof {
    assertLeafIndex(leafIndex);
    assertTreeSize(treeSize, "treeSize");
    if (treeSize > this.leafHashes.length) {
      throw new Error(`treeSize ${treeSize} exceeds current tree size ${this.leafHashes.length}`);
    }
    if (treeSize === 0 || leafIndex >= treeSize) {
      throw new Error(`leafIndex ${leafIndex} is outside tree size ${treeSize}`);
    }

    return {
      type: "inclusion",
      treeSize,
      leafIndex,
      hashes: inclusionPath(this.leafHashes, leafIndex, 0, treeSize)
    };
  }

  consistencyProof(firstSize: number, secondSize: number = this.treeSize()): ConsistencyProof {
    assertTreeSize(firstSize, "firstSize");
    assertTreeSize(secondSize, "secondSize");
    if (firstSize > secondSize) {
      throw new Error("firstSize must be less than or equal to secondSize");
    }
    if (secondSize > this.leafHashes.length) {
      throw new Error(`secondSize ${secondSize} exceeds current tree size ${this.leafHashes.length}`);
    }

    return {
      type: "consistency",
      firstSize,
      secondSize,
      hashes:
        firstSize === 0 || firstSize === secondSize
          ? []
          : consistencyPath(this.leafHashes, firstSize, 0, secondSize, true)
    };
  }
}

export function verifyInclusion(
  root: string,
  treeSize: number,
  leafHashValue: string,
  proof: InclusionProof
): boolean {
  try {
    if (
      proof.type !== "inclusion" ||
      proof.treeSize !== treeSize ||
      !Number.isSafeInteger(proof.leafIndex) ||
      proof.leafIndex < 0 ||
      proof.leafIndex >= treeSize ||
      !Array.isArray(proof.hashes)
    ) {
      return false;
    }
    if (!Number.isSafeInteger(treeSize) || treeSize <= 0) {
      return false;
    }

    const hashes = proof.hashes.map(normalizeHex);
    const calculated = calculateInclusionRoot(
      normalizeHex(leafHashValue),
      proof.leafIndex,
      treeSize,
      hashes,
      0
    );

    return calculated.proofIndex === hashes.length && equalHex(calculated.root, root);
  } catch {
    return false;
  }
}

export function verifyConsistency(
  root1: string,
  size1: number,
  root2: string,
  size2: number,
  proof: ConsistencyProof
): boolean {
  try {
    if (proof.type !== "consistency" || proof.firstSize !== size1 || proof.secondSize !== size2) {
      return false;
    }
    if (
      !Number.isSafeInteger(size1) ||
      !Number.isSafeInteger(size2) ||
      size1 < 0 ||
      size2 < 0 ||
      size1 > size2 ||
      !Array.isArray(proof.hashes)
    ) {
      return false;
    }

    const normalizedRoot1 = normalizeHex(root1);
    const normalizedRoot2 = normalizeHex(root2);
    const hashes = proof.hashes.map(normalizeHex);

    if (size1 === 0) {
      return hashes.length === 0 && equalHex(normalizedRoot1, EMPTY_TREE_HASH);
    }
    if (size1 === size2) {
      return hashes.length === 0 && equalHex(normalizedRoot1, normalizedRoot2);
    }

    const calculated = calculateConsistencyRoots(normalizedRoot1, size1, size2, true, hashes, 0);
    return (
      calculated.proofIndex === hashes.length &&
      equalHex(calculated.firstRoot, normalizedRoot1) &&
      equalHex(calculated.secondRoot, normalizedRoot2)
    );
  } catch {
    return false;
  }
}
