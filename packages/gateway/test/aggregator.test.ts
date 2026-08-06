import Database from "better-sqlite3";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { HexString } from "@vadrex/shared";
import { EMPTY_SMT_ROOT, smtHeadKey, smtLeafKey, verifySmtInclusion, verifySmtNonInclusion } from "@vadrex/merkle";
import type { AuditEntryInput } from "../src/aggregator.js";
import { AuditAggregator } from "../src/aggregator.js";
import { anchorPendingEntries, createAnchorRunner, type AnchorRegistrar } from "../src/anchoring.js";
import { createGatewayServer } from "../src/server.js";
import { EntryValidationError } from "../src/validation.js";

const ZERO = "0x0000000000000000000000000000000000000000000000000000000000000000";
const WRONG_ROOT = `0x${"ff".repeat(32)}` as HexString;

let tempDirs: string[] = [];

function tempDbPath(): string {
  const dir = mkdtempSync(join(tmpdir(), "vadrex-gateway-"));
  tempDirs.push(dir);
  return join(dir, "audit.db");
}

function entry(seq: number): AuditEntryInput {
  return {
    eventType: "TRANSFER_APPROVED",
    timestamp: 1_725_000_000 + seq,
    institutionId: "A",
    consentId: `consent-${seq}`,
    seq,
    prevHash: seq === 1 ? ZERO : "0x1111111111111111111111111111111111111111111111111111111111111111",
    requestContext: { seq },
    peerEntryHash: null,
    peerSignature: null
  };
}

async function closeServer(server: ReturnType<typeof createGatewayServer>): Promise<void> {
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve()))
  );
}

async function postJson<T>(url: string, body: unknown = {}): Promise<{ status: number; body: T }> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  return { status: response.status, body: (await response.json()) as T };
}

async function getJson<T>(url: string): Promise<{ status: number; body: T }> {
  const response = await fetch(url);
  return { status: response.status, body: (await response.json()) as T };
}

afterEach(() => {
  for (const dir of tempDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
  tempDirs = [];
});

describe("AuditAggregator", () => {
  it("persists entries, restores the tree, and self-checks the last anchored prefix", () => {
    const dbPath = tempDbPath();
    const first = new AuditAggregator(dbPath);
    const appended1 = first.appendEntry(entry(1));
    const anchoredRoot = first.currentRoot();
    first.recordAnchor({ batchId: 1, rootHash: anchoredRoot, treeSize: 1, mapRoot: EMPTY_SMT_ROOT, txHash: "0xtx1" });
    first.appendEntry(entry(2));
    const currentRoot = first.currentRoot();
    first.close();

    const restored = new AuditAggregator(dbPath);
    expect(restored.treeSize()).toBe(2);
    expect(restored.rootAt(1)).toBe(anchoredRoot);
    expect(restored.currentRoot()).toBe(currentRoot);
    expect(restored.latestAnchor()).toEqual({
      batchId: 1,
      rootHash: anchoredRoot,
      treeSize: 1,
      mapRoot: EMPTY_SMT_ROOT,
      txHash: "0xtx1"
    });
    expect(appended1.leafIndex).toBe(0);
    restored.close();
  });

  it("fails restore self-check when the stored anchor root does not match the restored prefix", () => {
    const dbPath = tempDbPath();
    const first = new AuditAggregator(dbPath);
    first.appendEntry(entry(1));
    first.recordAnchor({ batchId: 1, rootHash: WRONG_ROOT, treeSize: 1, mapRoot: EMPTY_SMT_ROOT, txHash: "0xtx1" });
    first.close();

    expect(() => new AuditAggregator(dbPath)).toThrow(/does not match last anchor root/);
  });

  it("refuses to open a legacy DB whose anchor history predates mapRoot, but migrates an empty one", () => {
    const legacyPath = tempDbPath();
    const legacy = new Database(legacyPath);
    legacy.exec(`
      CREATE TABLE audit_entries (
        leafIndex INTEGER PRIMARY KEY,
        canonicalBytes BLOB NOT NULL,
        entryHash TEXT NOT NULL,
        timestamp INTEGER NOT NULL
      );
      CREATE TABLE anchor_history (
        batchId INTEGER PRIMARY KEY,
        rootHash TEXT NOT NULL,
        treeSize INTEGER NOT NULL,
        txHash TEXT NOT NULL
      );
    `);
    legacy.prepare("INSERT INTO anchor_history (batchId, rootHash, treeSize, txHash) VALUES (1, ?, 1, '0xtx1')").run(WRONG_ROOT);
    legacy.close();

    // Detection: an old database that already has anchor history cannot have its mapRoot filled
    // in honestly, so migration is refused and a reset demanded
    expect(() => new AuditAggregator(legacyPath)).toThrow(/legacy rows without mapRoot/);

    // Success: an old schema without anchor history migrates by adding the column
    const emptyLegacyPath = tempDbPath();
    const emptyLegacy = new Database(emptyLegacyPath);
    emptyLegacy.exec(`
      CREATE TABLE audit_entries (
        leafIndex INTEGER PRIMARY KEY,
        canonicalBytes BLOB NOT NULL,
        entryHash TEXT NOT NULL,
        timestamp INTEGER NOT NULL
      );
      CREATE TABLE anchor_history (
        batchId INTEGER PRIMARY KEY,
        rootHash TEXT NOT NULL,
        treeSize INTEGER NOT NULL,
        txHash TEXT NOT NULL
      );
    `);
    emptyLegacy.close();
    const migrated = new AuditAggregator(emptyLegacyPath);
    expect(migrated.latestAnchor()).toBeNull();
    migrated.close();
  });

  it("rejects conflicting anchor history for an existing batchId", () => {
    const dbPath = tempDbPath();
    const aggregator = new AuditAggregator(dbPath);
    aggregator.appendEntry(entry(1));
    const rootHash = aggregator.currentRoot();
    aggregator.recordAnchor({ batchId: 1, rootHash, treeSize: 1, mapRoot: EMPTY_SMT_ROOT, txHash: "0xtx1" });

    expect(() =>
      aggregator.recordAnchor({ batchId: 1, rootHash: WRONG_ROOT, treeSize: 1, mapRoot: EMPTY_SMT_ROOT, txHash: "0xtx2" })
    ).toThrow(/already exists with different values/);
    expect(() =>
      aggregator.recordAnchor({ batchId: 1, rootHash, treeSize: 1, mapRoot: EMPTY_SMT_ROOT, txHash: "0xtx1" })
    ).not.toThrow();
    aggregator.close();
  });

  it("does not partially append a batch when preimage canonicalization fails", () => {
    const dbPath = tempDbPath();
    const aggregator = new AuditAggregator(dbPath);
    const invalid = {
      ...entry(2),
      requestContext: { unsupported: undefined }
    };

    expect(() => aggregator.appendEntries([entry(1), invalid])).toThrow(/cannot encode field unsupported/);
    expect(aggregator.treeSize()).toBe(0);
    aggregator.close();
  });

  it("rejects entries with unknown fields, bogus event types, or malformed hashes", () => {
    const aggregator = new AuditAggregator(tempDbPath());

    expect(() => aggregator.appendEntries([{ ...entry(1), injectedField: "x" } as never])).toThrow(
      EntryValidationError
    );
    expect(() => aggregator.appendEntries([{ ...entry(1), eventType: "NOT_A_REAL_EVENT" as never }])).toThrow(
      /eventType/
    );
    const { timestamp: _timestamp, ...missingTimestamp } = entry(1);
    expect(() => aggregator.appendEntries([missingTimestamp as never])).toThrow(/missing field timestamp/);
    expect(() =>
      aggregator.appendEntries([{ ...entry(2), prevHash: `0x${"FF".repeat(32)}` }])
    ).toThrow(/prevHash/);
    expect(() => aggregator.appendEntries([{ ...entry(1), seq: 0 }])).toThrow(/seq/);

    expect(aggregator.treeSize()).toBe(0);
    expect(() => aggregator.appendEntries([entry(1)])).not.toThrow();
    aggregator.close();
  });

  it("returns 400 with the failing entry index for invalid injected entries", async () => {
    const aggregator = new AuditAggregator(tempDbPath());
    const server = createGatewayServer(aggregator, undefined, { enableDevEndpoints: true });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    const url = `http://127.0.0.1:${port}/dev/audit-entries`;

    try {
      const bad = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ entries: [entry(1), { ...entry(2), injectedField: "x" }] })
      });
      expect(bad.status).toBe(400);
      expect(await bad.json()).toMatchObject({ entryIndex: 1 });
      expect(aggregator.treeSize()).toBe(0);

      const ok = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ entries: [entry(1)] })
      });
      expect(ok.status).toBe(200);
      expect(aggregator.treeSize()).toBe(1);
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve()))
      );
      aggregator.close();
    }
  });

  it("anchors only when new leaves exist", async () => {
    const dbPath = tempDbPath();
    const aggregator = new AuditAggregator(dbPath);
    const registrar: AnchorRegistrar = {
      async latestAnchor() {
        return null;
      },
      async registerAnchor(rootHash, treeSize, mapRoot) {
        return { batchId: 1, rootHash, treeSize, mapRoot, txHash: "0xtx1" };
      }
    };

    expect(await anchorPendingEntries(aggregator, registrar)).toBeNull();
    aggregator.appendEntry(entry(1));
    const anchor = await anchorPendingEntries(aggregator, registrar);
    expect(anchor).toEqual({
      batchId: 1,
      rootHash: aggregator.currentRoot(),
      treeSize: 1,
      mapRoot: aggregator.mapRoot(),
      txHash: "0xtx1"
    });
    expect(await anchorPendingEntries(aggregator, registrar)).toBeNull();
    aggregator.close();
  });

  it("reconciles a chain anchor that was mined before local DB history was recorded", async () => {
    const dbPath = tempDbPath();
    const aggregator = new AuditAggregator(dbPath);
    aggregator.appendEntry(entry(1));
    const rootHash = aggregator.currentRoot();
    const registrar: AnchorRegistrar = {
      async latestAnchor() {
        return { batchId: 1, rootHash, treeSize: 1, mapRoot: EMPTY_SMT_ROOT, txHash: "0xtx1" };
      },
      async registerAnchor() {
        throw new Error("registerAnchor should not be called after reconciliation");
      }
    };

    expect(await anchorPendingEntries(aggregator, registrar)).toBeNull();
    expect(aggregator.latestAnchor()).toEqual({ batchId: 1, rootHash, treeSize: 1, mapRoot: EMPTY_SMT_ROOT, txHash: "0xtx1" });
    aggregator.close();
  });

  it("rejects reconciliation when the chain mapRoot is unavailable locally", async () => {
    const dbPath = tempDbPath();
    const aggregator = new AuditAggregator(dbPath);
    aggregator.appendEntry(entry(1));
    const rootHash = aggregator.currentRoot();
    const registrar: AnchorRegistrar = {
      async latestAnchor() {
        return { batchId: 1, rootHash, treeSize: 1, mapRoot: WRONG_ROOT, txHash: "0xtx1" };
      },
      async registerAnchor() {
        throw new Error("registerAnchor should not be called after reconciliation failure");
      }
    };

    await expect(anchorPendingEntries(aggregator, registrar)).rejects.toThrow(/mapRoot/);
    aggregator.close();
  });

  it("shares one in-flight anchoring promise across overlapping calls", async () => {
    const dbPath = tempDbPath();
    const aggregator = new AuditAggregator(dbPath);
    aggregator.appendEntry(entry(1));
    let releaseRegister!: () => void;
    let registerCalls = 0;
    const registrar: AnchorRegistrar = {
      async latestAnchor() {
        return null;
      },
      async registerAnchor(rootHash, treeSize, mapRoot) {
        registerCalls += 1;
        await new Promise<void>((resolve) => {
          releaseRegister = resolve;
        });
        return { batchId: 1, rootHash, treeSize, mapRoot, txHash: "0xtx1" };
      }
    };
    const runner = createAnchorRunner(aggregator, registrar);

    const first = runner();
    const second = runner();
    expect(first).toBe(second);
    while (!releaseRegister) {
      await Promise.resolve();
    }
    releaseRegister();
    await expect(first).resolves.toEqual({
      batchId: 1,
      rootHash: aggregator.currentRoot(),
      treeSize: 1,
      mapRoot: aggregator.mapRoot(),
      txHash: "0xtx1"
    });
    expect(registerCalls).toBe(1);
    aggregator.close();
  });

  it("creates consent chains, updates SMT head, and revokes with a terminal event", () => {
    const aggregator = new AuditAggregator(tempDbPath());
    const created = aggregator.createConsent({
      receiverInstitutionId: "B",
      studyInstanceUids: ["1.2.840.10008.1"],
      purpose: "research",
      validUntil: 1_800_000_000
    });
    const approved = aggregator.appendDemoChainEvent(created.consentId, "TRANSFER_APPROVED", { demo: true });
    const completed = aggregator.appendDemoChainEvent(created.consentId, "TRANSFER_COMPLETED", { demo: true });
    const revoked = aggregator.revokeConsent(created.consentId);

    const entries = aggregator.chainEntries(created.consentId);
    expect(entries.map((item) => [item.eventType, item.seq])).toEqual([
      ["CONSENT_CREATED", 1],
      ["TRANSFER_APPROVED", 2],
      ["TRANSFER_COMPLETED", 3],
      ["CONSENT_REVOKED", 4]
    ]);
    expect(approved.seq).toBe(2);
    expect(completed.seq).toBe(3);
    expect(revoked.seq).toBe(4);

    const headProof = aggregator.smtInclusionProof(smtHeadKey(created.secretC, created.consentId));
    expect(headProof.value).toBe(revoked.entryHash);
    expect(verifySmtInclusion(aggregator.mapRoot(), headProof)).toBe(true);
    expect(() => aggregator.appendDemoChainEvent(created.consentId, "TRANSFER_APPROVED")).toThrow(/revoked/);
    aggregator.close();
  });

  it("logs non-chain consent events without polluting chain entries or SMT k+1 absence", () => {
    const aggregator = new AuditAggregator(tempDbPath());
    const created = aggregator.createConsent({
      receiverInstitutionId: "B",
      studyInstanceUids: ["1.2.840.10008.2"],
      purpose: "research",
      validUntil: 1_800_000_000
    });
    const revoked = aggregator.revokeConsent(created.consentId);
    const beforeDeniedRoot = aggregator.mapRoot();

    aggregator.appendNonChainConsentEvent(created.consentId, "TRANSFER_DENIED", { reason: "revoked" });

    expect(aggregator.mapRoot()).toBe(beforeDeniedRoot);
    expect(aggregator.chainEntries(created.consentId).map((item) => item.eventType)).toEqual([
      "CONSENT_CREATED",
      "CONSENT_REVOKED"
    ]);
    const kPlusOne = smtLeafKey(created.secretC, created.consentId, revoked.seq + 1);
    const proof = aggregator.smtNonInclusionProof(kPlusOne);
    expect(verifySmtNonInclusion(aggregator.mapRoot(), proof)).toBe(true);
    aggregator.close();
  });

  it("records anchors with the current mapRoot", async () => {
    const aggregator = new AuditAggregator(tempDbPath());
    aggregator.createConsent({
      receiverInstitutionId: "B",
      studyInstanceUids: ["1.2.840.10008.3"],
      purpose: "research",
      validUntil: 1_800_000_000
    });
    const registrar: AnchorRegistrar = {
      async latestAnchor() {
        return null;
      },
      async registerAnchor(rootHash, treeSize, mapRoot) {
        return { batchId: 1, rootHash, treeSize, mapRoot, txHash: "0xtx1" };
      }
    };

    const anchor = await anchorPendingEntries(aggregator, registrar);
    expect(anchor?.mapRoot).toBe(aggregator.mapRoot());
    expect(aggregator.latestAnchor()?.mapRoot).toBe(aggregator.mapRoot());
    aggregator.close();
  });

  it("serves the regular consent, chain-entry, SMT proof, and anchor APIs over HTTP", async () => {
    const aggregator = new AuditAggregator(tempDbPath());
    const server = createGatewayServer(aggregator, undefined, {
      anchorContractAddress: "0x00000000000000000000000000000000000000aa",
      signingPublicKeyPem: "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----\n"
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      const created = await postJson<{ consentId: string; secretC: HexString }>(`${baseUrl}/consents`, {
        receiverInstitutionId: "B",
        studyInstanceUids: ["1.2.840.10008.4"],
        purpose: "research",
        validUntil: 1_800_000_000
      });
      expect(created.status).toBe(200);

      const revoked = await postJson<{ seq: number; entryHash: HexString }>(
        `${baseUrl}/consents/${created.body.consentId}/revoke`
      );
      expect(revoked.status).toBe(200);
      expect(revoked.body.seq).toBe(2);

      const anchor = {
        batchId: 1,
        rootHash: aggregator.currentRoot(),
        treeSize: aggregator.treeSize(),
        mapRoot: aggregator.mapRoot(),
        txHash: "0xtx1"
      };
      aggregator.recordAnchor(anchor);

      const audit = await getJson<{
        rootHash: HexString;
        treeSize: number;
        entries: { leafIndex: number; entryHash: HexString; eventType: string; consentId: string; seq: number; canonicalBytes: HexString }[];
      }>(`${baseUrl}/audit-entries?anchorBatchId=1`);
      expect(audit.status).toBe(200);
      expect(audit.body.rootHash).toBe(anchor.rootHash);
      expect(audit.body.treeSize).toBe(anchor.treeSize);
      expect(audit.body.entries.map((item) => [item.leafIndex, item.eventType, item.seq])).toEqual([
        [0, "CONSENT_CREATED", 1],
        [1, "CONSENT_REVOKED", 2]
      ]);
      expect(audit.body.entries.every((item) => item.canonicalBytes.startsWith("0x"))).toBe(true);

      const chain = await getJson<{ entries: { eventType: string; seq: number }[] }>(
        `${baseUrl}/consents/${created.body.consentId}/chain-entries`
      );
      expect(chain.status).toBe(200);
      expect(chain.body.entries.map((item) => [item.eventType, item.seq])).toEqual([
        ["CONSENT_CREATED", 1],
        ["CONSENT_REVOKED", 2]
      ]);

      const smt = await getJson<{ mapRoot: HexString; proof: { value: HexString | null } }>(
        `${baseUrl}/proofs/smt?key=${encodeURIComponent(smtHeadKey(created.body.secretC, created.body.consentId))}&anchorBatchId=1`
      );
      expect(smt.status).toBe(200);
      expect(smt.body.mapRoot).toBe(anchor.mapRoot);
      expect(smt.body.proof.value).toBe(revoked.body.entryHash);

      const anchors = await getJson<{ contractAddress: string; anchors: unknown[] }>(`${baseUrl}/anchors`);
      expect(anchors.status).toBe(200);
      expect(anchors.body.contractAddress).toBe("0x00000000000000000000000000000000000000aa");
      expect(anchors.body.anchors).toHaveLength(1);

      const key = await getJson<{ institutionId: string; algorithm: string; publicKeyPem: string }>(`${baseUrl}/public-key`);
      expect(key.status).toBe(200);
      expect(key.body).toMatchObject({
        institutionId: "A",
        algorithm: "Ed25519",
        publicKeyPem: "-----BEGIN PUBLIC KEY-----\nTEST\n-----END PUBLIC KEY-----\n"
      });

      const dev = await fetch(`${baseUrl}/dev/tree`);
      expect(dev.status).toBe(404);
    } finally {
      await closeServer(server);
      aggregator.close();
    }
  });

  it("returns 500 for internal SMT store inconsistencies instead of reporting them as client errors", async () => {
    const aggregator = new AuditAggregator(tempDbPath());
    aggregator.createConsent({
      receiverInstitutionId: "B",
      studyInstanceUids: ["1.2.840.10008.5"],
      purpose: "research",
      validUntil: 1_800_000_000
    });
    aggregator.recordAnchor({
      batchId: 1,
      rootHash: aggregator.currentRoot(),
      treeSize: aggregator.treeSize(),
      mapRoot: WRONG_ROOT,
      txHash: "0xtx1"
    });
    const server = createGatewayServer(aggregator);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;

    try {
      const response = await fetch(
        `http://127.0.0.1:${port}/proofs/smt?key=${encodeURIComponent(smtLeafKey("secret", "consent", 1))}&anchorBatchId=1`
      );
      expect(response.status).toBe(500);
    } finally {
      await closeServer(server);
      aggregator.close();
    }
  });
});
