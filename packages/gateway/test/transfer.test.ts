import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import type { AddressInfo } from "node:net";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { deriveReceiverSecret, smtHeadKey } from "@vadrex/merkle";
import { AuditAggregator } from "../src/aggregator.js";
import { createGatewayHttpsServer, createGatewayServer } from "../src/server.js";
import { EntrySigner, verifyEntrySignature } from "../src/signing.js";
import { TransferService, type TransferServiceOptions } from "../src/transfer.js";
import { requestBuffer } from "../src/httpClient.js";
import { createTransferToken, verifyTransferToken } from "../src/token.js";
import Database from "better-sqlite3";

let tempDirs: string[] = [];

function tempDbPath(name: string): string {
  const dir = mkdtempSync(join(tmpdir(), `vadrex-${name}-`));
  tempDirs.push(dir);
  return join(dir, "audit.db");
}

function keyPair() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    signer: new EntrySigner(privateKey.export({ format: "pem", type: "pkcs8" }).toString()),
    publicKey
  };
}

function canonicalEntry(entry: { canonicalBytes: string }): Record<string, unknown> {
  return JSON.parse(Buffer.from(entry.canonicalBytes.slice(2), "hex").toString("utf8")) as Record<string, unknown>;
}

function opensslAvailable(): boolean {
  try {
    execFileSync("openssl", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const repoRootDir = resolve(fileURLToPath(new URL("../../..", import.meta.url)));
const mtlsFixtures = {
  cert: join(repoRootDir, "scripts", "out", "inst-a", "cert.pem"),
  key: join(repoRootDir, "scripts", "out", "inst-a", "key.pem"),
  ca: join(repoRootDir, "scripts", "out", "inst-a", "ca.cert.pem"),
  clientCert: join(repoRootDir, "scripts", "out", "inst-b", "cert.pem"),
  clientKey: join(repoRootDir, "scripts", "out", "inst-b", "key.pem")
};
const mtlsFixturesAvailable = Object.values(mtlsFixtures).every(existsSync);
const opensslPresent = opensslAvailable();

async function startMtlsServer(): Promise<{
  agg: AuditAggregator;
  server: ReturnType<typeof createGatewayHttpsServer>;
  url: string;
}> {
  const agg = new AuditAggregator(tempDbPath("mtls"), { institutionId: "A" });
  const server = createGatewayHttpsServer(
    {
      cert: readFileSync(mtlsFixtures.cert),
      key: readFileSync(mtlsFixtures.key),
      ca: readFileSync(mtlsFixtures.ca),
      requestCert: true,
      rejectUnauthorized: false
    },
    agg,
    undefined,
    {
      requireMtlsForInstitutionEndpoints: true,
      peerCertificateCommonName: "orthanc-b"
    }
  );
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    agg,
    server,
    url: `https://localhost:${(server.address() as AddressInfo).port}/transfer/receipt`
  };
}

function receiverSecret(secretC: string): string {
  return `0x${Buffer.from(deriveReceiverSecret(secretC)).toString("hex")}`;
}

function ensureReceiverReference(
  aggregator: AuditAggregator,
  created: { consentId: string; secretC: string },
  studyInstanceUid: string
): void {
  aggregator.ensureReceiverReferenceConsent({
    consentId: created.consentId,
    receiverSecret: receiverSecret(created.secretC),
    providerInstitutionId: "A",
    studyInstanceUid,
    purpose: "research"
  });
}

// Patient role: B receives the derived key and a signed token, never the raw secretC.
function patientBody(
  created: { consentId: string; secretC: string },
  studyInstanceUid: string,
  purpose = "research"
): Record<string, unknown> {
  return {
    consentId: created.consentId,
    receiverSecret: receiverSecret(created.secretC),
    authorizationToken: createTransferToken(
      created.secretC,
      { consentId: created.consentId, studyInstanceUid, purpose },
      60
    ).token,
    studyInstanceUid,
    purpose
  };
}

async function until(condition: () => boolean, timeoutMs = 3_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) {
      throw new Error("condition not met in time");
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

interface ServicePair {
  aggA: AuditAggregator;
  aggB: AuditAggregator;
  serviceA: TransferService;
  serviceB: TransferService;
  dbPathA: string;
  close(): Promise<void>;
}

async function servicePair(config: {
  name: string;
  receiptTimeoutMsA: number;
  simulatedReceiptDelayMsB?: number;
}): Promise<ServicePair> {
  const keysA = keyPair();
  const keysB = keyPair();
  const dbPathA = tempDbPath(`${config.name}-a`);
  const aggA = new AuditAggregator(dbPathA, { institutionId: "A" });
  const aggB = new AuditAggregator(tempDbPath(`${config.name}-b`), { institutionId: "B" });
  const optionsA: TransferServiceOptions = {
    institutionId: "A",
    peerInstitutionId: "B",
    peerBaseUrl: "http://127.0.0.1:0",
    signer: keysA.signer,
    peerPublicKey: keysB.publicKey,
    tokenTtlSeconds: 60,
    receiptTimeoutMs: config.receiptTimeoutMsA
  };
  const optionsB: TransferServiceOptions = {
    institutionId: "B",
    peerInstitutionId: "A",
    peerBaseUrl: "http://127.0.0.1:0",
    signer: keysB.signer,
    peerPublicKey: keysA.publicKey,
    tokenTtlSeconds: 60,
    receiptTimeoutMs: 2_000,
    simulatedReceiptDelayMs: config.simulatedReceiptDelayMsB
  };
  const serviceA = new TransferService(aggA, optionsA);
  const serviceB = new TransferService(aggB, optionsB);
  const serverA = createGatewayServer(aggA, undefined, { transferService: serviceA });
  const serverB = createGatewayServer(aggB, undefined, { transferService: serviceB });
  await new Promise<void>((resolve) => serverA.listen(0, "127.0.0.1", resolve));
  await new Promise<void>((resolve) => serverB.listen(0, "127.0.0.1", resolve));
  optionsA.peerBaseUrl = `http://127.0.0.1:${(serverB.address() as AddressInfo).port}`;
  optionsB.peerBaseUrl = `http://127.0.0.1:${(serverA.address() as AddressInfo).port}`;
  return {
    aggA,
    aggB,
    serviceA,
    serviceB,
    dbPathA,
    close: async () => {
      await closeServer(serverA);
      await closeServer(serverB);
      aggA.close();
      aggB.close();
    }
  };
}

async function closeServer(server: ReturnType<typeof createGatewayServer>): Promise<void> {
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve()))
  );
}

afterEach(() => {
  for (const dir of tempDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
  tempDirs = [];
});

describe("transfer handshake", () => {
  it("records mutual references across A and B without B allocating its own seq", async () => {
    const keysA = keyPair();
    const keysB = keyPair();
    const dbPathA = tempDbPath("a");
    const dbPathB = tempDbPath("b");
    const aggA = new AuditAggregator(dbPathA, { institutionId: "A" });
    const aggB = new AuditAggregator(dbPathB, { institutionId: "B" });
    const optionsA: TransferServiceOptions = {
      institutionId: "A",
      peerInstitutionId: "B",
      peerBaseUrl: "http://127.0.0.1:0",
      signer: keysA.signer,
      peerPublicKey: keysB.publicKey,
      tokenTtlSeconds: 60,
      receiptTimeoutMs: 2_000
    };
    const optionsB: TransferServiceOptions = {
      institutionId: "B",
      peerInstitutionId: "A",
      peerBaseUrl: "http://127.0.0.1:0",
      signer: keysB.signer,
      peerPublicKey: keysA.publicKey,
      tokenTtlSeconds: 60,
      receiptTimeoutMs: 2_000
    };
    const serviceA = new TransferService(aggA, optionsA);
    const serviceB = new TransferService(aggB, optionsB);
    const serverA = createGatewayServer(aggA, undefined, { transferService: serviceA });
    const serverB = createGatewayServer(aggB, undefined, { transferService: serviceB });
    await new Promise<void>((resolve) => serverA.listen(0, "127.0.0.1", resolve));
    await new Promise<void>((resolve) => serverB.listen(0, "127.0.0.1", resolve));
    optionsA.peerBaseUrl = `http://127.0.0.1:${(serverB.address() as AddressInfo).port}`;
    optionsB.peerBaseUrl = `http://127.0.0.1:${(serverA.address() as AddressInfo).port}`;

    try {
      const created = aggA.createConsent({
        receiverInstitutionId: "B",
        studyInstanceUids: ["1.2.3"],
        purpose: "research",
        validUntil: 1_900_000_000
      });

      const result = await serviceB.startTransfer(patientBody(created, "1.2.3")) as {
        status: string;
        receipt: { approvalEntryHash: string; receiveEntryHash: string; receiverSignature: string };
      };

      expect(result.status).toBe("COMPLETED");
      expect(aggA.chainEntries(created.consentId).map((entry) => [entry.eventType, entry.seq])).toEqual([
        ["CONSENT_CREATED", 1],
        ["TRANSFER_APPROVED", 2],
        ["TRANSFER_COMPLETED", 3]
      ]);
      expect(aggB.chainEntries(created.consentId).map((entry) => [entry.eventType, entry.seq])).toEqual([
        ["RECEIVE_COMPLETED", 2]
      ]);

      const aApproved = aggA.chainEntries(created.consentId)[1];
      const bReceive = aggB.chainEntries(created.consentId)[0];
      const aCompleted = aggA.chainEntries(created.consentId)[2];
      const approvedEntry = canonicalEntry(aApproved);
      const receiveEntry = canonicalEntry(bReceive);
      const completedEntry = canonicalEntry(aCompleted);
      const dbB = new Database(dbPathB, { readonly: true });
      const requestRow = dbB
        .prepare("SELECT entryHash FROM audit_entries WHERE eventType = 'TRANSFER_REQUESTED'")
        .get() as { entryHash: string };
      dbB.close();

      expect(aApproved.entryHash).not.toBe(bReceive.entryHash);
      expect(aCompleted.seq).toBe(3);
      expect(approvedEntry.peerEntryHash).toBe(requestRow.entryHash);
      expect(verifyEntrySignature(requestRow.entryHash, approvedEntry.peerSignature as string, keysB.publicKey)).toBe(true);
      expect(receiveEntry.peerEntryHash).toBe(aApproved.entryHash);
      expect(verifyEntrySignature(aApproved.entryHash, receiveEntry.peerSignature as string, keysA.publicKey)).toBe(true);
      expect(completedEntry.peerEntryHash).toBe(bReceive.entryHash);
      expect(verifyEntrySignature(bReceive.entryHash, completedEntry.peerSignature as string, keysB.publicKey)).toBe(true);
      expect(aggB.smtInclusionProof(smtHeadKey(aggB.consentSecret(created.consentId), created.consentId)).value)
        .toBe(bReceive.entryHash);

      // A duplicate receipt must not demote a completed transfer to RECEIPT_LATE or overwrite
      // the receipt evidence.
      expect(() => serviceA.handleReceipt(result.receipt)).toThrow(/already settled as COMPLETED/);
      const dbA = new Database(dbPathA, { readonly: true });
      const statusRow = dbA.prepare("SELECT status FROM transfers").get() as { status: string };
      dbA.close();
      expect(statusRow.status).toBe("COMPLETED");
    } finally {
      await closeServer(serverA);
      await closeServer(serverB);
      aggA.close();
      aggB.close();
    }
  });

  it("keeps denied post-revocation requests out of the consent chain", async () => {
    const agg = new AuditAggregator(tempDbPath("deny"), { institutionId: "A" });
    const created = agg.createConsent({
      receiverInstitutionId: "B",
      studyInstanceUids: ["1.2.4"],
      purpose: "research",
      validUntil: 1_900_000_000
    });
    const revoked = agg.revokeConsent(created.consentId);
    const root = agg.mapRoot();

    agg.recordTransferDenied({
      consentId: created.consentId,
      reason: "revoked_or_blocked",
      requestContext: { studyInstanceUid: "1.2.4" }
    });

    expect(agg.mapRoot()).toBe(root);
    expect(agg.chainEntries(created.consentId).map((entry) => [entry.eventType, entry.seq])).toEqual([
      ["CONSENT_CREATED", 1],
      ["CONSENT_REVOKED", revoked.seq]
    ]);
    agg.close();
  });

  it("rejects expired authorization tokens", () => {
    const { token } = createTransferToken(
      "0x1111111111111111111111111111111111111111111111111111111111111111",
      { consentId: "c", studyInstanceUid: "s", purpose: "research" },
      1,
      100
    );
    expect(() =>
      verifyTransferToken("0x1111111111111111111111111111111111111111111111111111111111111111", token, 102)
    ).toThrow(/expired/);
  });

  it("records REPLAY_BLOCKED when a valid nonce is reused", async () => {
    const keysA = keyPair();
    const keysB = keyPair();
    const dbPathA = tempDbPath("replay-a");
    const dbPathB = tempDbPath("replay-b");
    const aggA = new AuditAggregator(dbPathA, { institutionId: "A" });
    const aggB = new AuditAggregator(dbPathB, { institutionId: "B" });
    const serviceA = new TransferService(aggA, {
      institutionId: "A",
      peerInstitutionId: "B",
      peerBaseUrl: "http://127.0.0.1:9",
      signer: keysA.signer,
      peerPublicKey: keysB.publicKey,
      tokenTtlSeconds: 60,
      receiptTimeoutMs: 100
    });
    const created = aggA.createConsent({
      receiverInstitutionId: "B",
      studyInstanceUids: ["1.2.5"],
      purpose: "research",
      validUntil: 1_900_000_000
    });
    ensureReceiverReference(aggB, created, "1.2.5");
    const token = createTransferToken(
      created.secretC,
      { consentId: created.consentId, studyInstanceUid: "1.2.5", purpose: "research" },
      60
    );
    const requested = aggB.recordTransferRequested({
      consentId: created.consentId,
      studyInstanceUid: "1.2.5",
      purpose: "research",
      providerInstitutionId: "A",
      tokenNonce: token.payload.nonce
    });
    const body = {
      consentId: created.consentId,
      studyInstanceUid: "1.2.5",
      purpose: "research",
      requesterInstitutionId: "B",
      requesterEntryHash: requested.entryHash,
      requesterSignature: keysB.signer.signEntryHash(requested.entryHash),
      authorizationToken: token.token,
    };

    await expect(serviceA.handleTransferRequest(body)).resolves.toMatchObject({ status: "UNCONFIRMED" });
    await expect(serviceA.handleTransferRequest(body)).rejects.toThrow(/nonce/);

    const db = new Database(dbPathA, { readonly: true });
    const row = db.prepare("SELECT COUNT(*) AS count FROM audit_entries WHERE eventType = 'REPLAY_BLOCKED'").get() as { count: number };
    db.close();
    expect(row.count).toBe(1);
    aggA.close();
    aggB.close();
  });

  it("holds a peer after an unconfirmed transfer and blocks later approvals for that peer", async () => {
    const keysA = keyPair();
    const keysB = keyPair();
    const aggA = new AuditAggregator(tempDbPath("hold-a"), { institutionId: "A" });
    const aggB = new AuditAggregator(tempDbPath("hold-b"), { institutionId: "B" });
    const serviceA = new TransferService(aggA, {
      institutionId: "A",
      peerInstitutionId: "B",
      peerBaseUrl: "http://127.0.0.1:9",
      signer: keysA.signer,
      peerPublicKey: keysB.publicKey,
      tokenTtlSeconds: 60,
      receiptTimeoutMs: 50
    });

    const first = aggA.createConsent({
      receiverInstitutionId: "B",
      studyInstanceUids: ["1.2.hold.1"],
      purpose: "research",
      validUntil: 1_900_000_000
    });
    ensureReceiverReference(aggB, first, "1.2.hold.1");
    const firstToken = createTransferToken(
      first.secretC,
      { consentId: first.consentId, studyInstanceUid: "1.2.hold.1", purpose: "research" },
      60
    );
    const firstRequested = aggB.recordTransferRequested({
      consentId: first.consentId,
      studyInstanceUid: "1.2.hold.1",
      purpose: "research",
      providerInstitutionId: "A",
      tokenNonce: firstToken.payload.nonce
    });
    await expect(serviceA.handleTransferRequest({
      consentId: first.consentId,
      studyInstanceUid: "1.2.hold.1",
      purpose: "research",
      requesterInstitutionId: "B",
      requesterEntryHash: firstRequested.entryHash,
      requesterSignature: keysB.signer.signEntryHash(firstRequested.entryHash),
      authorizationToken: firstToken.token
    })).resolves.toMatchObject({ status: "UNCONFIRMED" });
    expect(aggA.isPeerHeld("B")).toBe(true);

    const second = aggA.createConsent({
      receiverInstitutionId: "B",
      studyInstanceUids: ["1.2.hold.2"],
      purpose: "research",
      validUntil: 1_900_000_000
    });
    ensureReceiverReference(aggB, second, "1.2.hold.2");
    const secondToken = createTransferToken(
      second.secretC,
      { consentId: second.consentId, studyInstanceUid: "1.2.hold.2", purpose: "research" },
      60
    );
    const secondRequested = aggB.recordTransferRequested({
      consentId: second.consentId,
      studyInstanceUid: "1.2.hold.2",
      purpose: "research",
      providerInstitutionId: "A",
      tokenNonce: secondToken.payload.nonce
    });

    await expect(serviceA.handleTransferRequest({
      consentId: second.consentId,
      studyInstanceUid: "1.2.hold.2",
      purpose: "research",
      requesterInstitutionId: "B",
      requesterEntryHash: secondRequested.entryHash,
      requesterSignature: keysB.signer.signEntryHash(secondRequested.entryHash),
      authorizationToken: secondToken.token
    })).rejects.toThrow(/held/);

    aggA.close();
    aggB.close();
  });

  it("records TRANSFER_FAILED when provider-side Orthanc retrieval fails before delivery", async () => {
    const keysA = keyPair();
    const keysB = keyPair();
    const dbPathA = tempDbPath("failed-a");
    const aggA = new AuditAggregator(dbPathA, { institutionId: "A" });
    const aggB = new AuditAggregator(tempDbPath("failed-b"), { institutionId: "B" });
    const serviceA = new TransferService(aggA, {
      institutionId: "A",
      peerInstitutionId: "B",
      peerBaseUrl: "http://127.0.0.1:9",
      orthancBaseUrl: "http://127.0.0.1:9",
      signer: keysA.signer,
      peerPublicKey: keysB.publicKey,
      tokenTtlSeconds: 60,
      receiptTimeoutMs: 50
    });
    const created = aggA.createConsent({
      receiverInstitutionId: "B",
      studyInstanceUids: ["1.2.failed"],
      purpose: "research",
      validUntil: 1_900_000_000
    });
    ensureReceiverReference(aggB, created, "1.2.failed");
    const token = createTransferToken(
      created.secretC,
      { consentId: created.consentId, studyInstanceUid: "1.2.failed", purpose: "research" },
      60
    );
    const requested = aggB.recordTransferRequested({
      consentId: created.consentId,
      studyInstanceUid: "1.2.failed",
      purpose: "research",
      providerInstitutionId: "A",
      tokenNonce: token.payload.nonce
    });

    await expect(serviceA.handleTransferRequest({
      consentId: created.consentId,
      studyInstanceUid: "1.2.failed",
      purpose: "research",
      requesterInstitutionId: "B",
      requesterEntryHash: requested.entryHash,
      requesterSignature: keysB.signer.signEntryHash(requested.entryHash),
      authorizationToken: token.token
    })).resolves.toMatchObject({ status: "FAILED" });

    const db = new Database(dbPathA, { readonly: true });
    const failedEvent = db
      .prepare("SELECT COUNT(*) AS count FROM audit_entries WHERE eventType = 'TRANSFER_FAILED'")
      .get() as { count: number };
    const failedTransfer = db
      .prepare("SELECT COUNT(*) AS count FROM transfers WHERE status = 'FAILED'")
      .get() as { count: number };
    db.close();
    expect(failedEvent.count).toBe(1);
    expect(failedTransfer.count).toBe(1);
    aggA.close();
    aggB.close();
  });

  it("records late receipts as non-chain RECEIPT_LATE after an unconfirmed settlement", async () => {
    const keysA = keyPair();
    const keysB = keyPair();
    const dbPathA = tempDbPath("late-a");
    const aggA = new AuditAggregator(dbPathA, { institutionId: "A" });
    const aggB = new AuditAggregator(tempDbPath("late-b"), { institutionId: "B" });
    const optionsA: TransferServiceOptions = {
      institutionId: "A",
      peerInstitutionId: "B",
      peerBaseUrl: "http://127.0.0.1:0",
      signer: keysA.signer,
      peerPublicKey: keysB.publicKey,
      tokenTtlSeconds: 60,
      receiptTimeoutMs: 75
    };
    const optionsB: TransferServiceOptions = {
      institutionId: "B",
      peerInstitutionId: "A",
      peerBaseUrl: "http://127.0.0.1:0",
      signer: keysB.signer,
      peerPublicKey: keysA.publicKey,
      tokenTtlSeconds: 60,
      receiptTimeoutMs: 2_000,
      simulatedReceiptDelayMs: 150
    };
    const serviceA = new TransferService(aggA, optionsA);
    const serviceB = new TransferService(aggB, optionsB);
    const serverA = createGatewayServer(aggA, undefined, { transferService: serviceA });
    const serverB = createGatewayServer(aggB, undefined, { transferService: serviceB });
    await new Promise<void>((resolve) => serverA.listen(0, "127.0.0.1", resolve));
    await new Promise<void>((resolve) => serverB.listen(0, "127.0.0.1", resolve));
    optionsA.peerBaseUrl = `http://127.0.0.1:${(serverB.address() as AddressInfo).port}`;
    optionsB.peerBaseUrl = `http://127.0.0.1:${(serverA.address() as AddressInfo).port}`;

    try {
      const created = aggA.createConsent({
        receiverInstitutionId: "B",
        studyInstanceUids: ["1.2.late"],
        purpose: "research",
        validUntil: 1_900_000_000
      });

      await expect(serviceB.startTransfer(patientBody(created, "1.2.late")))
        .resolves.toMatchObject({ status: "UNCONFIRMED" });

      await new Promise((resolve) => setTimeout(resolve, 400));
      const db = new Database(dbPathA, { readonly: true });
      const lateEvent = db
        .prepare("SELECT COUNT(*) AS count FROM audit_entries WHERE eventType = 'RECEIPT_LATE'")
        .get() as { count: number };
      const chainTypes = aggA.chainEntries(created.consentId).map((entry) => entry.eventType);
      db.close();
      expect(lateEvent.count).toBe(1);
      expect(chainTypes).toEqual(["CONSENT_CREATED", "TRANSFER_APPROVED"]);
    } finally {
      await closeServer(serverA);
      await closeServer(serverB);
      aggA.close();
      aggB.close();
    }
  });

  // Without the mTLS fixtures this is skipped explicitly rather than passing vacuously.
  it.skipIf(!mtlsFixturesAvailable)(
    "rejects institution endpoints without an mTLS client certificate and accepts the trusted peer",
    async () => {
      const { agg, server, url } = await startMtlsServer();
      try {
        const rejected = await requestBuffer(url, {
          method: "POST",
          tls: { ca: readFileSync(mtlsFixtures.ca), rejectUnauthorized: true },
          headers: { "content-type": "application/json" },
          body: "{}"
        });
        expect(rejected.statusCode).toBe(401);

        const acceptedMtls = await requestBuffer(url, {
          method: "POST",
          tls: {
            cert: readFileSync(mtlsFixtures.clientCert),
            key: readFileSync(mtlsFixtures.clientKey),
            ca: readFileSync(mtlsFixtures.ca),
            rejectUnauthorized: true
          },
          headers: { "content-type": "application/json" },
          body: "{}"
        });
        expect(acceptedMtls.statusCode).toBe(503);
      } finally {
        await closeServer(server);
        agg.close();
      }
    }
  );

  it.skipIf(!mtlsFixturesAvailable || !opensslPresent)(
    "rejects institution endpoint clients whose certificate is not signed by the trusted CA",
    async () => {
      const { agg, server, url } = await startMtlsServer();
      try {
        const untrustedDir = mkdtempSync(join(tmpdir(), "vadrex-untrusted-client-"));
        tempDirs.push(untrustedDir);
        const untrustedCert = join(untrustedDir, "client.cert.pem");
        const untrustedKey = join(untrustedDir, "client.key.pem");
        execFileSync("openssl", [
          "req",
          "-x509",
          "-newkey",
          "rsa:2048",
          "-nodes",
          "-subj",
          "/CN=orthanc-b",
          "-keyout",
          untrustedKey,
          "-out",
          untrustedCert,
          "-days",
          "1"
        ], { stdio: "ignore" });
        const rejectedUntrustedCa = await requestBuffer(url, {
          method: "POST",
          tls: {
            cert: readFileSync(untrustedCert),
            key: readFileSync(untrustedKey),
            ca: readFileSync(mtlsFixtures.ca),
            rejectUnauthorized: true
          },
          headers: { "content-type": "application/json" },
          body: "{}"
        });
        expect(rejectedUntrustedCa.statusCode).toBe(401);
      } finally {
        await closeServer(server);
        agg.close();
      }
    }
  );

  it("rejects reused or non-monotonic receiver seq values", () => {
    const aggB = new AuditAggregator(tempDbPath("seq-b"), { institutionId: "B" });
    const secretC = `0x${"11".repeat(32)}`;
    ensureReceiverReference(aggB, { consentId: "consent-seq", secretC }, "1.2.9");
    const receiveOptions = (seq: number, approvalByte: string) => ({
      consentId: "consent-seq",
      receiverSecret: receiverSecret(secretC),
      seq,
      providerInstitutionId: "A",
      studyInstanceUid: "1.2.9",
      purpose: "research",
      approvalEntryHash: `0x${approvalByte.repeat(32)}`,
      approvalSignature: `0x${"33".repeat(64)}`
    });

    expect(aggB.recordReceiveCompleted(receiveOptions(2, "22")).seq).toBe(2);
    expect(() => aggB.recordReceiveCompleted(receiveOptions(2, "44"))).toThrow(/not greater/);
    expect(() => aggB.recordReceiveCompleted(receiveOptions(1, "55"))).toThrow(/not greater/);
    expect(aggB.recordReceiveCompleted(receiveOptions(4, "66")).seq).toBe(4);
    aggB.close();
  });

  it("waits for in-flight settlement before CONSENT_REVOKED and keeps head at the revocation", async () => {
    const pair = await servicePair({ name: "barrier1", receiptTimeoutMsA: 2_000, simulatedReceiptDelayMsB: 150 });
    try {
      const created = pair.aggA.createConsent({
        receiverInstitutionId: "B",
        studyInstanceUids: ["1.2.b1"],
        purpose: "research",
        validUntil: 1_900_000_000
      });
      const transferPromise = pair.serviceB.startTransfer(patientBody(created, "1.2.b1"));
      await until(() =>
        pair.aggA.chainEntries(created.consentId).some((entry) => entry.eventType === "TRANSFER_APPROVED")
      );
      const revoked = await pair.serviceA.revokeConsentWithBarrier(created.consentId);
      await expect(transferPromise).resolves.toMatchObject({ status: "COMPLETED" });

      expect(pair.aggA.chainEntries(created.consentId).map((entry) => entry.eventType)).toEqual([
        "CONSENT_CREATED",
        "TRANSFER_APPROVED",
        "TRANSFER_COMPLETED",
        "CONSENT_REVOKED"
      ]);
      const head = pair.aggA.smtInclusionProof(
        smtHeadKey(pair.aggA.consentSecret(created.consentId), created.consentId)
      );
      expect(head.value).toBe(revoked.entryHash);
    } finally {
      await pair.close();
    }
  });

  it("keeps REVOKED terminal when a blocked receipt arrives late after the barrier", async () => {
    const pair = await servicePair({ name: "barrier2", receiptTimeoutMsA: 75, simulatedReceiptDelayMsB: 300 });
    try {
      const created = pair.aggA.createConsent({
        receiverInstitutionId: "B",
        studyInstanceUids: ["1.2.b2"],
        purpose: "research",
        validUntil: 1_900_000_000
      });
      const transferPromise = pair.serviceB.startTransfer(patientBody(created, "1.2.b2"));
      await until(() =>
        pair.aggA.chainEntries(created.consentId).some((entry) => entry.eventType === "TRANSFER_APPROVED")
      );
      const revoked = await pair.serviceA.revokeConsentWithBarrier(created.consentId);
      await expect(transferPromise).resolves.toMatchObject({ status: "UNCONFIRMED" });

      // Wait for the late receipt to arrive and be recorded as RECEIPT_LATE
      await new Promise((resolve) => setTimeout(resolve, 500));
      const dbA = new Database(pair.dbPathA, { readonly: true });
      const lateEvent = dbA
        .prepare("SELECT COUNT(*) AS count FROM audit_entries WHERE eventType = 'RECEIPT_LATE'")
        .get() as { count: number };
      dbA.close();
      expect(lateEvent.count).toBe(1);
      expect(pair.aggA.chainEntries(created.consentId).map((entry) => entry.eventType)).toEqual([
        "CONSENT_CREATED",
        "TRANSFER_APPROVED",
        "CONSENT_REVOKED"
      ]);
      const head = pair.aggA.smtInclusionProof(
        smtHeadKey(pair.aggA.consentSecret(created.consentId), created.consentId)
      );
      expect(head.value).toBe(revoked.entryHash);

      expect(pair.aggA.isPeerHeld("B")).toBe(true);
      expect(pair.aggA.releasePeerHold("B")).toBe(true);
      expect(pair.aggA.isPeerHeld("B")).toBe(false);
      expect(pair.aggA.releasePeerHold("B")).toBe(false);
    } finally {
      await pair.close();
    }
  });

  it("rejects oversized dicom deliveries with 413 without crashing the gateway", async () => {
    const keysA = keyPair();
    const keysB = keyPair();
    const agg = new AuditAggregator(tempDbPath("dicom-limit"), { institutionId: "B" });
    const service = new TransferService(agg, {
      institutionId: "B",
      peerInstitutionId: "A",
      peerBaseUrl: "http://127.0.0.1:9",
      signer: keysB.signer,
      peerPublicKey: keysA.publicKey,
      tokenTtlSeconds: 60,
      receiptTimeoutMs: 100
    });
    const server = createGatewayServer(agg, undefined, { transferService: service, dicomBodyLimitBytes: 1024 });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    try {
      const oversized = await requestBuffer(`${baseUrl}/transfer/dicom`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ dicomBase64: "A".repeat(4096) })
      });
      expect(oversized.statusCode).toBe(413);

      const health = await requestBuffer(`${baseUrl}/health`);
      expect(health.statusCode).toBe(200);
    } finally {
      await closeServer(server);
      agg.close();
    }
  });

  it("refuses a legacy transfers table with rows but recreates an empty one", () => {
    const legacyDdl = `
      CREATE TABLE transfers (
        transferId TEXT PRIMARY KEY,
        consentId TEXT NOT NULL,
        peerInstitutionId TEXT NOT NULL,
        studyInstanceUid TEXT NOT NULL,
        purpose TEXT NOT NULL,
        seq INTEGER,
        approvedEntryHash TEXT UNIQUE,
        approvedSignature TEXT,
        requesterEntryHash TEXT,
        requesterSignature TEXT,
        receiveEntryHash TEXT,
        receiverSignature TEXT,
        status TEXT NOT NULL CHECK(status IN ('APPROVED', 'COMPLETED', 'UNCONFIRMED')),
        startedAt INTEGER NOT NULL,
        settledAt INTEGER
      );
    `;

    const withRowsPath = tempDbPath("legacy-transfers-rows");
    const withRows = new Database(withRowsPath);
    withRows.exec(legacyDdl);
    withRows
      .prepare(
        "INSERT INTO transfers (transferId, consentId, peerInstitutionId, studyInstanceUid, purpose, status, startedAt) VALUES ('t1', 'c1', 'B', '1.2', 'research', 'APPROVED', 1)"
      )
      .run();
    withRows.close();
    expect(() => new AuditAggregator(withRowsPath, { institutionId: "A" })).toThrow(/legacy status CHECK/);

    const emptyPath = tempDbPath("legacy-transfers-empty");
    const empty = new Database(emptyPath);
    empty.exec(legacyDdl);
    empty.close();
    const agg = new AuditAggregator(emptyPath, { institutionId: "A" });
    agg.close();
    const check = new Database(emptyPath, { readonly: true });
    const ddl = check.prepare("SELECT sql FROM sqlite_master WHERE name = 'transfers'").get() as { sql: string };
    check.close();
    expect(ddl.sql).toContain("'FAILED'");
    expect(ddl.sql).toContain("'RECEIPT_LATE'");
  });
});
