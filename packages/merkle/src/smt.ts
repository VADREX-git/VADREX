// Sparse Merkle Tree of depth 256, keyed by HMAC so that keys reveal nothing without the
// consent secret. Nodes are content-addressed and copy-on-write: set() only adds nodes along
// the path and never mutates or drops an existing one, so a proof can still be produced
// against any historical mapRoot. Verification of "no event after revocation" asks for proofs
// at every anchor since the revocation, which a current-state-only tree could not answer.
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import type { HexString, SmtProof } from "@vadrex/shared";

const HASH_BYTES = 32;
const SMT_DEPTH = 256;
const ZERO_VALUE = `0x${"00".repeat(32)}` as HexString;

export interface SmtNode {
  leftHash: HexString;
  rightHash: HexString;
}

export interface SmtNodeStore {
  getNode(hash: HexString): SmtNode | null;
  putNode(hash: HexString, node: SmtNode): void;
  getLeafValue(leafHash: HexString): HexString | null;
  putLeafValue(leafHash: HexString, value: HexString): void;
}

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

function hexToBytes(hash: string): Uint8Array {
  const normalized = normalizeHash(hash);
  const bytes = new Uint8Array(HASH_BYTES);
  for (let i = 0; i < HASH_BYTES; i += 1) {
    bytes[i] = Number.parseInt(normalized.slice(2 + i * 2, 4 + i * 2), 16);
  }
  return bytes;
}

function sha256Hex(input: Uint8Array): HexString {
  return bytesToHex(sha256(input));
}

function leafHash(value: string): HexString {
  return sha256Hex(concatBytes(new Uint8Array([0]), hexToBytes(value)));
}

function branchHash(left: string, right: string): HexString {
  return sha256Hex(concatBytes(new Uint8Array([1]), hexToBytes(left), hexToBytes(right)));
}

function normalizeHash(hash: string): HexString {
  if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) {
    throw new Error(`expected 32-byte 0x-prefixed hex hash, got ${hash}`);
  }
  return `0x${hash.slice(2).toLowerCase()}`;
}

function keyBit(key: HexString, bitIndex: number): 0 | 1 {
  const byte = Number.parseInt(key.slice(2 + Math.floor(bitIndex / 8) * 2, 4 + Math.floor(bitIndex / 8) * 2), 16);
  return ((byte >> (7 - (bitIndex % 8))) & 1) as 0 | 1;
}

export const EMPTY_SMT_HASHES: readonly HexString[] = (() => {
  const hashes: HexString[] = [leafHash(ZERO_VALUE)];
  for (let height = 1; height <= SMT_DEPTH; height += 1) {
    hashes.push(branchHash(hashes[height - 1], hashes[height - 1]));
  }
  return hashes;
})();

export const EMPTY_SMT_ROOT = EMPTY_SMT_HASHES[SMT_DEPTH];

export class InMemorySmtStore implements SmtNodeStore {
  private readonly nodes = new Map<HexString, SmtNode>();
  private readonly leaves = new Map<HexString, HexString>();

  getNode(hash: HexString): SmtNode | null {
    return this.nodes.get(hash) ?? null;
  }

  putNode(hash: HexString, node: SmtNode): void {
    this.nodes.set(hash, node);
  }

  getLeafValue(hash: HexString): HexString | null {
    return this.leaves.get(hash) ?? null;
  }

  putLeafValue(hash: HexString, value: HexString): void {
    this.leaves.set(hash, value);
  }
}

export class SparseMerkleTree {
  private root: HexString;

  constructor(
    private readonly store: SmtNodeStore = new InMemorySmtStore(),
    root: string = EMPTY_SMT_ROOT
  ) {
    this.root = normalizeHash(root);
  }

  mapRoot(): HexString {
    return this.root;
  }

  setRoot(root: string): void {
    this.root = normalizeHash(root);
  }

  set(key: string, value: string): HexString {
    const normalizedKey = normalizeHash(key);
    const normalizedValue = normalizeHash(value);
    // The 32-byte zero is reserved for empty leaves. Storing it would make an occupied leaf
    // hash identical to an empty one, breaking non-inclusion proofs for every absent key.
    if (normalizedValue === ZERO_VALUE) {
      throw new Error("SMT value must not be the 32-byte zero value (reserved for empty leaves)");
    }
    const nextRoot = this.setAt(this.root, normalizedKey, normalizedValue, 0);
    this.root = nextRoot;
    return nextRoot;
  }

  inclusionProof(key: string, atRoot: string = this.root): SmtProof {
    const normalizedKey = normalizeHash(key);
    const normalizedRoot = normalizeHash(atRoot);
    const { siblings, leaf } = this.path(normalizedKey, normalizedRoot);
    const value = this.store.getLeafValue(leaf);
    if (!value) {
      throw new Error(`key ${normalizedKey} is not present at root ${normalizedRoot}`);
    }
    return {
      type: "smtInclusion",
      key: normalizedKey,
      value,
      siblings
    };
  }

  nonInclusionProof(key: string, atRoot: string = this.root): SmtProof {
    const normalizedKey = normalizeHash(key);
    const normalizedRoot = normalizeHash(atRoot);
    const { siblings, leaf } = this.path(normalizedKey, normalizedRoot);
    const value = this.store.getLeafValue(leaf);
    if (value) {
      throw new Error(`key ${normalizedKey} is present at root ${normalizedRoot}`);
    }
    return {
      type: "smtNonInclusion",
      key: normalizedKey,
      value: null,
      siblings
    };
  }

  hasRoot(root: string): boolean {
    const normalizedRoot = normalizeHash(root);
    return normalizedRoot === EMPTY_SMT_ROOT || this.store.getNode(normalizedRoot) !== null || this.store.getLeafValue(normalizedRoot) !== null;
  }

  private setAt(nodeHash: HexString, key: HexString, value: HexString, bitIndex: number): HexString {
    if (bitIndex === SMT_DEPTH) {
      const hash = leafHash(value);
      this.store.putLeafValue(hash, value);
      return hash;
    }

    const remainingHeight = SMT_DEPTH - bitIndex;
    const emptyHash = EMPTY_SMT_HASHES[remainingHeight];
    const childEmptyHash = EMPTY_SMT_HASHES[remainingHeight - 1];
    const oldNode = nodeHash === emptyHash ? null : this.store.getNode(nodeHash);
    if (nodeHash !== emptyHash && !oldNode) {
      throw new Error(`SMT node ${nodeHash} is missing from the content-addressed store`);
    }

    const left = oldNode?.leftHash ?? childEmptyHash;
    const right = oldNode?.rightHash ?? childEmptyHash;
    const bit = keyBit(key, bitIndex);
    const nextLeft = bit === 0 ? this.setAt(left, key, value, bitIndex + 1) : left;
    const nextRight = bit === 1 ? this.setAt(right, key, value, bitIndex + 1) : right;
    const hash = branchHash(nextLeft, nextRight);
    this.store.putNode(hash, { leftHash: nextLeft, rightHash: nextRight });
    return hash;
  }

  private path(key: HexString, root: HexString): { siblings: HexString[]; leaf: HexString } {
    const topDownSiblings: HexString[] = [];
    let nodeHash = root;

    for (let bitIndex = 0; bitIndex < SMT_DEPTH; bitIndex += 1) {
      const remainingHeight = SMT_DEPTH - bitIndex;
      const emptyHash = EMPTY_SMT_HASHES[remainingHeight];
      const childEmptyHash = EMPTY_SMT_HASHES[remainingHeight - 1];
      const node = nodeHash === emptyHash ? null : this.store.getNode(nodeHash);
      if (nodeHash !== emptyHash && !node) {
        throw new Error(`SMT node ${nodeHash} is missing from the content-addressed store`);
      }

      const left = node?.leftHash ?? childEmptyHash;
      const right = node?.rightHash ?? childEmptyHash;
      const bit = keyBit(key, bitIndex);
      topDownSiblings.push(bit === 0 ? right : left);
      nodeHash = bit === 0 ? left : right;
    }

    return {
      siblings: topDownSiblings.reverse(),
      leaf: nodeHash
    };
  }
}

function calculateRootFromProof(proof: SmtProof): HexString {
  const key = normalizeHash(proof.key);
  if (!Array.isArray(proof.siblings) || proof.siblings.length !== SMT_DEPTH) {
    throw new Error(`SMT proof must contain ${SMT_DEPTH} siblings`);
  }
  let hash = proof.value === null ? EMPTY_SMT_HASHES[0] : leafHash(proof.value);
  for (let siblingIndex = 0; siblingIndex < SMT_DEPTH; siblingIndex += 1) {
    const bitIndex = SMT_DEPTH - 1 - siblingIndex;
    const sibling = normalizeHash(proof.siblings[siblingIndex]);
    hash = keyBit(key, bitIndex) === 0 ? branchHash(hash, sibling) : branchHash(sibling, hash);
  }
  return hash;
}

export function verifySmtInclusion(root: string, proof: SmtProof): boolean {
  try {
    if (proof.type !== "smtInclusion" || proof.value === null) {
      return false;
    }
    // A zero-valued leaf hashes the same as an empty one, so accepting it as "present"
    // would let absence be presented as an inclusion proof.
    if (normalizeHash(proof.value) === ZERO_VALUE) {
      return false;
    }
    return calculateRootFromProof(proof) === normalizeHash(root);
  } catch {
    return false;
  }
}

export function verifySmtNonInclusion(root: string, proof: SmtProof): boolean {
  try {
    if (proof.type !== "smtNonInclusion" || proof.value !== null) {
      return false;
    }
    return calculateRootFromProof(proof) === normalizeHash(root);
  } catch {
    return false;
  }
}

export function smtLeafKey(secret: Uint8Array | Buffer | string, consentId: string, seq: number): HexString {
  if (!Number.isSafeInteger(seq) || seq < 1) {
    throw new Error("seq must be an integer >= 1");
  }
  return hmacSha256(secret, `${consentId}:${seq}`);
}

export function smtHeadKey(secret: Uint8Array | Buffer | string, consentId: string): HexString {
  return hmacSha256(secret, `${consentId}:head`);
}

export function deriveReceiverSecret(secret: Uint8Array | Buffer | string): Uint8Array {
  return hkdfSha256(toBytes(secret), new Uint8Array(), new TextEncoder().encode("receiver"), 32);
}

function toBytes(input: Uint8Array | Buffer | string): Uint8Array {
  if (typeof input === "string") {
    if (/^0x[0-9a-fA-F]+$/.test(input)) {
      const hex = input.slice(2);
      if (hex.length % 2 !== 0) {
        throw new Error("hex input must have an even number of digits");
      }
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < bytes.length; i += 1) {
        bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
      }
      return bytes;
    }
    return new TextEncoder().encode(input);
  }
  return new Uint8Array(input);
}

function hmacSha256(key: Uint8Array | Buffer | string, message: string): HexString {
  return bytesToHex(hmac(sha256, toBytes(key), new TextEncoder().encode(message)));
}

function hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const prk = hmac(sha256, salt, ikm);
  const chunks: Uint8Array[] = [];
  let previous = new Uint8Array();
  let generated = 0;
  let counter = 1;
  while (generated < length) {
    const input = concatBytes(previous, info, new Uint8Array([counter]));
    previous = new Uint8Array(hmac(sha256, prk, input));
    chunks.push(previous);
    generated += previous.length;
    counter += 1;
  }
  return concatBytes(...chunks).slice(0, length);
}
