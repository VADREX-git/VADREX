import { hkdfSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import type { HexString } from "@vadrex/shared";
import {
  EMPTY_SMT_ROOT,
  SparseMerkleTree,
  deriveReceiverSecret,
  smtHeadKey,
  smtLeafKey,
  verifySmtInclusion,
  verifySmtNonInclusion
} from "../src/index.js";
import { SqliteSmtStore } from "../src/sqlite.js";

let tempDirs: string[] = [];

function tempDbPath(): string {
  const dir = mkdtempSync(join(tmpdir(), "vadrex-smt-"));
  tempDirs.push(dir);
  return join(dir, "smt.db");
}

function hash(byte: string): HexString {
  return `0x${byte.repeat(64)}` as HexString;
}

afterEach(() => {
  for (const dir of tempDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
  tempDirs = [];
});

describe("SparseMerkleTree", () => {
  it("creates inclusion proofs and rejects tampered values", () => {
    const tree = new SparseMerkleTree();
    const key = smtLeafKey("secret", "consent-a", 1);
    tree.set(key, hash("a"));

    const proof = tree.inclusionProof(key);
    expect(verifySmtInclusion(tree.mapRoot(), proof)).toBe(true);
    expect(verifySmtInclusion(tree.mapRoot(), { ...proof, value: hash("b") })).toBe(false);
  });

  it("creates non-inclusion proofs and refuses to prove absence for present keys", () => {
    const tree = new SparseMerkleTree();
    const present = smtLeafKey("secret", "consent-a", 1);
    const absent = smtLeafKey("secret", "consent-a", 2);
    tree.set(present, hash("a"));

    const proof = tree.nonInclusionProof(absent);
    expect(verifySmtNonInclusion(tree.mapRoot(), proof)).toBe(true);
    expect(() => tree.nonInclusionProof(present)).toThrow(/present/);
  });

  it("generates proofs for historical roots after later updates", () => {
    const tree = new SparseMerkleTree();
    const key1 = smtLeafKey("secret", "consent-a", 1);
    const key2 = smtLeafKey("secret", "consent-a", 2);
    const key3 = smtLeafKey("secret", "consent-a", 3);

    const root0 = tree.mapRoot();
    tree.set(key1, hash("1"));
    const root1 = tree.mapRoot();
    tree.set(key2, hash("2"));
    const root2 = tree.mapRoot();
    tree.set(key3, hash("3"));

    expect(root0).toBe(EMPTY_SMT_ROOT);
    expect(verifySmtInclusion(root1, tree.inclusionProof(key1, root1))).toBe(true);
    expect(verifySmtNonInclusion(root1, tree.nonInclusionProof(key2, root1))).toBe(true);
    expect(verifySmtInclusion(root2, tree.inclusionProof(key2, root2))).toBe(true);
  });

  it("keeps historical head values for each map root", () => {
    const tree = new SparseMerkleTree();
    const secret = "secret";
    const consentId = "consent-a";
    const head = smtHeadKey(secret, consentId);
    const roots: HexString[] = [];

    for (let seq = 1; seq <= 3; seq += 1) {
      const value = hash(String(seq));
      tree.set(smtLeafKey(secret, consentId, seq), value);
      tree.set(head, value);
      roots.push(tree.mapRoot());
    }

    for (let seq = 1; seq <= 3; seq += 1) {
      const proof = tree.inclusionProof(head, roots[seq - 1]);
      expect(proof.value).toBe(hash(String(seq)));
      expect(verifySmtInclusion(roots[seq - 1], proof)).toBe(true);
    }
  });

  it("persists content-addressed nodes and proves against a restored historical root", () => {
    const dbPath = tempDbPath();
    const db = new Database(dbPath);
    const store = new SqliteSmtStore(db);
    const first = new SparseMerkleTree(store);
    const key1 = smtLeafKey("secret", "consent-a", 1);
    const key2 = smtLeafKey("secret", "consent-a", 2);
    first.set(key1, hash("1"));
    const root1 = first.mapRoot();
    first.set(key2, hash("2"));
    db.close();

    const sameDb = new Database(dbPath);
    const restored = new SparseMerkleTree(new SqliteSmtStore(sameDb), root1);
    expect(verifySmtInclusion(root1, restored.inclusionProof(key1, root1))).toBe(true);
    expect(verifySmtNonInclusion(root1, restored.nonInclusionProof(key2, root1))).toBe(true);
    sameDb.close();
  });

  it("rejects the zero value on set and refuses zero-value inclusion proofs", () => {
    const tree = new SparseMerkleTree();
    const present = smtLeafKey("secret", "consent-a", 1);
    const absent = smtLeafKey("secret", "consent-a", 2);
    tree.set(present, hash("a"));

    // Producer side: storing the empty-leaf sentinel as a value would break every
    // non-inclusion proof, so it is rejected
    expect(() => tree.set(absent, hash("0"))).toThrow(/zero value/);

    // Verifier side: an absent key's siblings dressed up as an inclusion proof with a zero
    // value is rejected
    const nonInclusion = tree.nonInclusionProof(absent);
    expect(
      verifySmtInclusion(tree.mapRoot(), {
        type: "smtInclusion",
        key: absent,
        value: hash("0"),
        siblings: nonInclusion.siblings
      })
    ).toBe(false);
  });

  it("has deterministic roots regardless of insertion order", () => {
    const pairs = Array.from({ length: 128 }, (_, index) => ({
      key: smtLeafKey("secret", "bulk", index + 1),
      value: hash(((index % 15) + 1).toString(16))
    }));
    const forward = new SparseMerkleTree();
    const reverse = new SparseMerkleTree();

    for (const pair of pairs) {
      forward.set(pair.key, pair.value);
    }
    for (const pair of [...pairs].reverse()) {
      reverse.set(pair.key, pair.value);
    }

    expect(forward.mapRoot()).toBe(reverse.mapRoot());
  });

  it("inserts 10^4 keys, proves a sampled key, and remains insertion-order deterministic", () => {
    const tree = new SparseMerkleTree();
    const pairs = Array.from({ length: 10_000 }, (_, index) => ({
      key: smtLeafKey("bulk-secret", "bulk-consent", index + 1),
      value: hash((((index + 1) % 15) + 1).toString(16))
    }));
    const start = performance.now();
    for (const pair of pairs) {
      tree.set(pair.key, pair.value);
    }
    const insertMs = performance.now() - start;
    const key = smtLeafKey("bulk-secret", "bulk-consent", 9_999);
    const proofStart = performance.now();
    const proof = tree.inclusionProof(key);
    const proofMs = performance.now() - proofStart;
    const reverse = new SparseMerkleTree();
    const reverseStart = performance.now();
    for (const pair of [...pairs].reverse()) {
      reverse.set(pair.key, pair.value);
    }
    const reverseInsertMs = performance.now() - reverseStart;

    expect(verifySmtInclusion(tree.mapRoot(), proof)).toBe(true);
    expect(reverse.mapRoot()).toBe(tree.mapRoot());
    expect(insertMs).toBeLessThan(90_000);
    expect(reverseInsertMs).toBeLessThan(90_000);
    expect(proofMs).toBeLessThan(500);
  });

  it("derives receiver keys with fixed HKDF parameters independently from provider keys", () => {
    const secret = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    const receiverSecret1 = deriveReceiverSecret(secret);
    const receiverSecret2 = deriveReceiverSecret(secret);
    const providerKey = smtLeafKey(secret, "consent-a", 1);
    const receiverKey = smtLeafKey(receiverSecret1, "consent-a", 1);

    expect(Buffer.from(receiverSecret1).toString("hex")).toBe(Buffer.from(receiverSecret2).toString("hex"));
    expect(receiverKey).not.toBe(providerKey);

    // Self-consistency would not catch a departure from RFC 5869, so the derivation is compared
    // against Node's HKDF with the fixed parameters: empty salt, info = utf8("receiver"), 32 bytes
    const reference = hkdfSync(
      "sha256",
      Buffer.from(secret.slice(2), "hex"),
      Buffer.alloc(0),
      Buffer.from("receiver", "utf8"),
      32
    );
    expect(Buffer.from(receiverSecret1).toString("hex")).toBe(Buffer.from(reference).toString("hex"));

    const tree = new SparseMerkleTree();
    tree.set(receiverKey, hash("c"));
    expect(verifySmtInclusion(tree.mapRoot(), tree.inclusionProof(receiverKey))).toBe(true);
  });
});
