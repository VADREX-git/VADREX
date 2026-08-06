// Audit log for one institution: append-only log tree, sparse Merkle tree and SQLite state.
//
// Three rules from the protocol contract are enforced here and are easy to break by accident:
//
//   - Only transfer-establishing events join the consent chain and the SMT: CONSENT_CREATED,
//     TRANSFER_APPROVED, TRANSFER_COMPLETED, the receiver's RECEIVE_COMPLETED, and
//     CONSENT_REVOKED. Everything else is appended to the log tree with seq = null.
//   - seq belongs to the provider. The receiver reuses the seq handed to it in the handshake
//     rather than counting on its own.
//   - prevHash links the previous chain entry *within this institution's log*; the first such
//     entry is 32 zero bytes even when the seq it carries is greater than one.
//
// The SMT head key must be updated in the same transaction as the chain event it describes.
// A log tree that advances while the head stays behind is exactly the inconsistency the
// verifier's head-to-log cross-check is designed to catch.
import { mkdirSync } from "node:fs";
import { randomBytes, randomUUID } from "node:crypto";
import { dirname } from "node:path";
import Database from "better-sqlite3";
import { computeEntryHash, entryPreimage, type AuditEntry, type EventType, type HexString } from "@vadrex/shared";
import { EMPTY_SMT_ROOT, Rfc6962LogTree, SparseMerkleTree, smtHeadKey, smtLeafKey } from "@vadrex/merkle";
import { SqliteSmtStore } from "@vadrex/merkle/sqlite";
import { validateAuditEntryInput } from "./validation.js";

export type AuditEntryInput = Omit<AuditEntry, "entryHash"> & { entryHash?: string | null };

export interface AuditAggregatorOptions {
  institutionId?: string;
}

export interface AppendedAuditEntry {
  leafIndex: number;
  entryHash: HexString;
  canonicalBytes: HexString;
  timestamp: number;
}

export interface AnchorHistoryRecord {
  batchId: number;
  rootHash: HexString;
  treeSize: number;
  mapRoot: HexString;
  txHash: string;
}

export interface CreateConsentRequest {
  receiverInstitutionId: string;
  studyInstanceUids: string[];
  purpose: string;
  validUntil: number;
}

export interface CreatedConsent {
  consentId: string;
  secretC: HexString;
}

export interface RevokedConsent {
  seq: number;
  entryHash: HexString;
}

export interface ChainEntryRecord {
  leafIndex: number;
  entryHash: HexString;
  eventType: EventType;
  seq: number;
  canonicalBytes: HexString;
}

export interface AuditLogEntryRecord {
  leafIndex: number;
  entryHash: HexString;
  eventType: EventType | null;
  consentId: string | null;
  seq: number | null;
  canonicalBytes: HexString;
}

interface AuditEntryRow {
  leafIndex: number;
  canonicalBytes: Buffer;
  entryHash: string;
  timestamp: number;
}

interface ChainEntryRow {
  leafIndex: number;
  canonicalBytes: Buffer;
  entryHash: string;
  eventType: EventType;
  seq: number;
}

interface AuditLogEntryRow {
  leafIndex: number;
  canonicalBytes: Buffer;
  entryHash: string;
  eventType: EventType | null;
  consentId: string | null;
  seq: number | null;
}

interface AnchorHistoryRow {
  batchId: number;
  rootHash: string;
  treeSize: number;
  mapRoot: string;
  txHash: string;
}

interface ConsentRow {
  consentId: string;
  secretC: string;
  providerInstitutionId: string;
  receiverInstitutionId: string;
  studyInstanceUids: string;
  purpose: string;
  validUntil: number;
  status: "active" | "revoked";
  lastSeq: number;
  lastEntryHash: string | null;
}

export interface TransferRow {
  transferId: string;
  consentId: string;
  peerInstitutionId: string;
  studyInstanceUid: string;
  purpose: string;
  seq: number | null;
  approvedEntryHash: string | null;
  approvedSignature: string | null;
  requesterEntryHash: string | null;
  requesterSignature: string | null;
  receiveEntryHash: string | null;
  receiverSignature: string | null;
  status: "APPROVED" | "COMPLETED" | "UNCONFIRMED" | "RECEIPT_LATE" | "FAILED";
  startedAt: number;
  settledAt: number | null;
}

const ZERO_HASH = `0x${"00".repeat(32)}` as HexString;
const TRANSFERS_TABLE_DDL = `
  CREATE TABLE IF NOT EXISTS transfers (
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
    status TEXT NOT NULL CHECK(status IN ('APPROVED', 'COMPLETED', 'UNCONFIRMED', 'RECEIPT_LATE', 'FAILED')),
    startedAt INTEGER NOT NULL,
    settledAt INTEGER
  );
`;
const CHAIN_EVENT_TYPES: ReadonlySet<EventType> = new Set([
  "CONSENT_CREATED",
  "TRANSFER_APPROVED",
  "TRANSFER_COMPLETED",
  "RECEIVE_COMPLETED",
  "CONSENT_REVOKED"
]);

function bytesToHex(bytes: Uint8Array): HexString {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

function asUint8Array(bytes: Buffer | Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

function normalizeHash(hash: string): HexString {
  if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) {
    throw new Error(`expected 32-byte 0x-prefixed hex hash, got ${hash}`);
  }
  return `0x${hash.slice(2).toLowerCase()}`;
}

function normalizeHex(hex: string): HexString {
  if (!/^0x[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error(`expected 0x-prefixed hex, got ${hex}`);
  }
  return `0x${hex.slice(2).toLowerCase()}`;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function normalizeEntry(input: AuditEntryInput): AuditEntry {
  const entry: AuditEntry = { ...input, entryHash: "" };
  entry.entryHash = computeEntryHash(entry);
  return entry;
}

function parseJsonArray(value: string): string[] {
  const parsed = JSON.parse(value) as unknown;
  if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== "string")) {
    throw new Error("stored studyInstanceUids is not a string array");
  }
  return parsed;
}

function validateConsentRequest(input: unknown): CreateConsentRequest {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new Error("consent request body must be a JSON object");
  }
  const record = input as Record<string, unknown>;
  if (typeof record.receiverInstitutionId !== "string" || record.receiverInstitutionId.length === 0) {
    throw new Error("receiverInstitutionId must be a non-empty string");
  }
  if (
    !Array.isArray(record.studyInstanceUids) ||
    record.studyInstanceUids.length === 0 ||
    record.studyInstanceUids.some((uid) => typeof uid !== "string" || uid.length === 0)
  ) {
    throw new Error("studyInstanceUids must be a non-empty string array");
  }
  if (typeof record.purpose !== "string" || record.purpose.length === 0) {
    throw new Error("purpose must be a non-empty string");
  }
  if (typeof record.validUntil !== "number" || !Number.isSafeInteger(record.validUntil) || record.validUntil <= 0) {
    throw new Error("validUntil must be a positive integer unix epoch seconds value");
  }
  return {
    receiverInstitutionId: record.receiverInstitutionId,
    studyInstanceUids: record.studyInstanceUids,
    purpose: record.purpose,
    validUntil: record.validUntil
  };
}

function assertChainEvent(eventType: EventType): void {
  if (!CHAIN_EVENT_TYPES.has(eventType)) {
    throw new Error(`${eventType} is not a chain-participating event`);
  }
}

export class AuditAggregator {
  private readonly db: Database.Database;
  private readonly tree = new Rfc6962LogTree();
  private readonly smt: SparseMerkleTree;
  readonly institutionId: string;

  constructor(readonly dbPath: string, options: AuditAggregatorOptions = {}) {
    this.institutionId = options.institutionId ?? "A";
    mkdirSync(dirname(dbPath), { recursive: true });
    this.db = new Database(dbPath);
    try {
      this.db.pragma("journal_mode = WAL");
      this.db.pragma("foreign_keys = ON");
      this.initializeSchema();
      this.smt = new SparseMerkleTree(new SqliteSmtStore(this.db), this.readMapRoot());
      this.restoreTree();
      this.selfCheckLastAnchor();
    } catch (error) {
      this.db.close();
      throw error;
    }
  }

  close(): void {
    this.db.close();
  }

  appendEntry(input: AuditEntryInput): AppendedAuditEntry {
    return this.appendSingleEntry(input);
  }

  appendEntries(inputs: readonly AuditEntryInput[]): AppendedAuditEntry[] {
    inputs.forEach((input, offset) => validateAuditEntryInput(input, offset));

    const startingLeafIndex = this.treeSize();
    const prepared = inputs.map((input, offset) => {
      const entry = normalizeEntry(input);
      const canonicalBytes = entryPreimage(entry);
      return {
        leafIndex: startingLeafIndex + offset,
        entry,
        canonicalBytes
      };
    });

    const insert = this.db.prepare(`
      INSERT INTO audit_entries (leafIndex, canonicalBytes, entryHash, timestamp, eventType, consentId, seq)
      VALUES (@leafIndex, @canonicalBytes, @entryHash, @timestamp, @eventType, @consentId, @seq)
    `);

    this.db.transaction(() => {
      for (const item of prepared) {
        insert.run({
          leafIndex: item.leafIndex,
          canonicalBytes: item.canonicalBytes,
          entryHash: item.entry.entryHash,
          timestamp: item.entry.timestamp,
          eventType: item.entry.eventType,
          consentId: item.entry.consentId,
          seq: item.entry.seq
        });
      }
    })();

    for (const item of prepared) {
      this.tree.appendLeaf(asUint8Array(item.canonicalBytes));
    }

    return prepared.map((item) => ({
      leafIndex: item.leafIndex,
      entryHash: normalizeHash(item.entry.entryHash),
      canonicalBytes: bytesToHex(asUint8Array(item.canonicalBytes)),
      timestamp: item.entry.timestamp
    }));
  }

  createConsent(input: unknown): CreatedConsent {
    const request = validateConsentRequest(input);
    const consentId = randomUUID();
    const secretC = `0x${randomBytes(32).toString("hex")}` as HexString;

    const tx = this.db.transaction(() => {
      this.db
        .prepare(
          `INSERT INTO consents (
            consentId, secretC, providerInstitutionId, receiverInstitutionId,
            studyInstanceUids, purpose, validUntil, status, lastSeq, lastEntryHash
          ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', 0, NULL)`
        )
        .run(
          consentId,
          secretC,
          this.institutionId,
          request.receiverInstitutionId,
          JSON.stringify(request.studyInstanceUids),
          request.purpose,
          request.validUntil
        );
      this.appendConsentChainEvent(consentId, "CONSENT_CREATED", {
        providerInstitutionId: this.institutionId,
        receiverInstitutionId: request.receiverInstitutionId,
        studyInstanceUids: request.studyInstanceUids,
        purpose: request.purpose,
        validUntil: request.validUntil
      });
    });
    tx();

    return { consentId, secretC };
  }

  revokeConsent(consentId: string): RevokedConsent {
    this.beginRevocationBarrier(consentId);
    const pendingTransfersSettled = this.pendingTransferCount(consentId) === 0;
    if (!pendingTransfersSettled) {
      throw new Error(`consent ${consentId} has pending transfers`);
    }
    const appended = this.appendConsentChainEvent(consentId, "CONSENT_REVOKED", {
      revocationBarrier: {
        newApprovalsBlocked: true,
        pendingTransfersSettled
      }
    });
    return {
      seq: appended.seq,
      entryHash: appended.entryHash
    };
  }

  appendDemoChainEvent(consentId: string, eventType: EventType, requestContext: object = {}): ChainEntryRecord {
    return this.appendConsentChainEvent(consentId, eventType, requestContext);
  }

  appendNonChainConsentEvent(consentId: string, eventType: EventType, requestContext: object = {}): AppendedAuditEntry {
    if (CHAIN_EVENT_TYPES.has(eventType)) {
      throw new Error(`${eventType} is a chain event`);
    }
    const consent = this.getConsent(consentId);
    const entry: AuditEntryInput = {
      eventType,
      timestamp: nowSeconds(),
      institutionId: this.institutionId,
      consentId,
      seq: null,
      prevHash: null,
      requestContext,
      peerEntryHash: null,
      peerSignature: null
    };
    if (!consent) {
      throw new Error(`consent ${consentId} not found`);
    }
    return this.appendEntry(entry);
  }

  appendPeerNonChainConsentEvent(options: {
    consentId: string;
    eventType: EventType;
    requestContext?: object;
    peerEntryHash?: string | null;
    peerSignature?: string | null;
    afterAuditInsert?: (entry: AuditEntry, leafIndex: number) => void;
  }): AppendedAuditEntry {
    if (CHAIN_EVENT_TYPES.has(options.eventType)) {
      throw new Error(`${options.eventType} is a chain event`);
    }
    if (!this.getConsent(options.consentId)) {
      throw new Error(`consent ${options.consentId} not found`);
    }
    return this.appendSingleEntry({
      eventType: options.eventType,
      timestamp: nowSeconds(),
      institutionId: this.institutionId,
      consentId: options.consentId,
      seq: null,
      prevHash: null,
      requestContext: options.requestContext ?? {},
      peerEntryHash: options.peerEntryHash ? normalizeHash(options.peerEntryHash) : null,
      peerSignature: options.peerSignature ? normalizeHex(options.peerSignature) : null
    }, options.afterAuditInsert);
  }

  forceAppendChainEvent(options: {
    consentId: string;
    eventType: EventType;
    seq: number;
    requestContext?: object;
    updateSmt?: boolean;
    updateHead?: boolean;
  }): ChainEntryRecord {
    return this.appendConsentChainEvent(options.consentId, options.eventType, options.requestContext ?? {}, {
      force: true,
      seqOverride: options.seq,
      updateSmt: options.updateSmt ?? true,
      updateHead: options.updateHead ?? true
    });
  }

  recordTransferRequested(options: {
    consentId: string;
    studyInstanceUid: string;
    purpose: string;
    providerInstitutionId: string;
    tokenNonce: string;
  }): AppendedAuditEntry {
    return this.appendPeerNonChainConsentEvent({
      consentId: options.consentId,
      eventType: "TRANSFER_REQUESTED",
      requestContext: {
        providerInstitutionId: options.providerInstitutionId,
        studyInstanceUid: options.studyInstanceUid,
        purpose: options.purpose,
        tokenNonce: options.tokenNonce
      }
    });
  }

  recordTransferDenied(options: {
    consentId: string;
    reason: string;
    requesterEntryHash?: string | null;
    requesterSignature?: string | null;
    requestContext?: object;
  }): AppendedAuditEntry {
    return this.appendPeerNonChainConsentEvent({
      consentId: options.consentId,
      eventType: "TRANSFER_DENIED",
      requestContext: { reason: options.reason, ...(options.requestContext ?? {}) },
      peerEntryHash: options.requesterEntryHash ?? null,
      peerSignature: options.requesterSignature ?? null
    });
  }

  recordReplayBlocked(options: {
    consentId: string;
    nonce: string;
    requesterEntryHash?: string | null;
    requesterSignature?: string | null;
  }): AppendedAuditEntry {
    return this.appendPeerNonChainConsentEvent({
      consentId: options.consentId,
      eventType: "REPLAY_BLOCKED",
      requestContext: { nonce: options.nonce },
      peerEntryHash: options.requesterEntryHash ?? null,
      peerSignature: options.requesterSignature ?? null
    });
  }

  recordTransferApproved(options: {
    consentId: string;
    peerInstitutionId: string;
    studyInstanceUid: string;
    purpose: string;
    requesterEntryHash: string;
    requesterSignature: string;
  }): ChainEntryRecord {
    if (this.isPeerHeld(options.peerInstitutionId)) {
      throw new Error(`peer ${options.peerInstitutionId} is held after an unconfirmed transfer`);
    }
    if (this.isApprovalBlocked(options.consentId)) {
      throw new Error(`consent ${options.consentId} is blocked for new approvals`);
    }
    const appended = this.appendConsentChainEvent(
      options.consentId,
      "TRANSFER_APPROVED",
      {
        peerInstitutionId: options.peerInstitutionId,
        studyInstanceUid: options.studyInstanceUid,
        purpose: options.purpose
      },
      {
        peerEntryHash: normalizeHash(options.requesterEntryHash),
        peerSignature: normalizeHex(options.requesterSignature),
        afterAuditInsert: (entry, seq) => {
          this.db
            .prepare(
              `INSERT INTO transfers (
                transferId, consentId, peerInstitutionId, studyInstanceUid, purpose, seq,
                approvedEntryHash, requesterEntryHash, requesterSignature, status, startedAt
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'APPROVED', ?)`
            )
            .run(
              randomUUID(),
              options.consentId,
              options.peerInstitutionId,
              options.studyInstanceUid,
              options.purpose,
              seq,
              normalizeHash(entry.entryHash),
              normalizeHash(options.requesterEntryHash),
              normalizeHex(options.requesterSignature),
              nowSeconds()
            );
        }
      }
    );
    return appended;
  }

  attachApprovalSignature(approvedEntryHash: string, signature: string): void {
    this.db
      .prepare("UPDATE transfers SET approvedSignature = ? WHERE approvedEntryHash = ?")
      .run(normalizeHex(signature), normalizeHash(approvedEntryHash));
  }

  recordReceiveCompleted(options: {
    consentId: string;
    receiverSecret: string;
    seq: number;
    providerInstitutionId: string;
    studyInstanceUid: string;
    purpose: string;
    approvalEntryHash: string;
    approvalSignature: string;
  }): ChainEntryRecord {
    this.ensureReceiverConsent({
      consentId: options.consentId,
      receiverSecret: options.receiverSecret,
      providerInstitutionId: options.providerInstitutionId,
      studyInstanceUid: options.studyInstanceUid,
      purpose: options.purpose
    });
    const consent = this.getConsent(options.consentId);
    if (!consent) {
      throw new Error(`consent ${options.consentId} not found`);
    }
    if (options.seq <= consent.lastSeq) {
      throw new Error(`receiver seq ${options.seq} is not greater than last seq ${consent.lastSeq}`);
    }
    return this.appendConsentChainEvent(
      options.consentId,
      "RECEIVE_COMPLETED",
      {
        providerInstitutionId: options.providerInstitutionId,
        studyInstanceUid: options.studyInstanceUid,
        purpose: options.purpose
      },
      {
        seqOverride: options.seq,
        peerEntryHash: normalizeHash(options.approvalEntryHash),
        peerSignature: normalizeHex(options.approvalSignature)
      }
    );
  }

  recordTransferCompleted(options: {
    approvalEntryHash: string;
    receiveEntryHash: string;
    receiverSignature: string;
  }): ChainEntryRecord | AppendedAuditEntry {
    const approvalHash = normalizeHash(options.approvalEntryHash);
    const transfer = this.transferByApprovalHash(approvalHash);
    if (!transfer) {
      throw new Error(`transfer ${approvalHash} not found`);
    }
    // RECEIPT_LATE applies only to a receipt arriving after the transfer settled as
    // UNCONFIRMED. Letting a duplicate receipt through in any other state would demote a
    // completed transfer and overwrite the receipt evidence already recorded.
    if (transfer.status === "UNCONFIRMED") {
      const late = this.appendPeerNonChainConsentEvent({
        consentId: transfer.consentId,
        eventType: "RECEIPT_LATE",
        requestContext: {
          approvalEntryHash: approvalHash,
          priorStatus: transfer.status
        },
        peerEntryHash: options.receiveEntryHash,
        peerSignature: options.receiverSignature,
        afterAuditInsert: () => {
          this.db
            .prepare(
              `UPDATE transfers
               SET status = 'RECEIPT_LATE', receiveEntryHash = ?, receiverSignature = ?, settledAt = ?
               WHERE transferId = ?`
            )
            .run(normalizeHash(options.receiveEntryHash), normalizeHex(options.receiverSignature), nowSeconds(), transfer.transferId);
        }
      });
      return late;
    }
    if (transfer.status !== "APPROVED") {
      throw new Error(`transfer ${approvalHash} is already settled as ${transfer.status}`);
    }

    const completed = this.appendConsentChainEvent(
      transfer.consentId,
      "TRANSFER_COMPLETED",
      {
        peerInstitutionId: transfer.peerInstitutionId,
        studyInstanceUid: transfer.studyInstanceUid,
        purpose: transfer.purpose,
        approvalEntryHash: approvalHash
      },
      {
        peerEntryHash: normalizeHash(options.receiveEntryHash),
        peerSignature: normalizeHex(options.receiverSignature),
        afterAuditInsert: () => {
          this.db
            .prepare(
              `UPDATE transfers
               SET status = 'COMPLETED', receiveEntryHash = ?, receiverSignature = ?, settledAt = ?
               WHERE transferId = ?`
            )
            .run(normalizeHash(options.receiveEntryHash), normalizeHex(options.receiverSignature), nowSeconds(), transfer.transferId);
        }
      }
    );
    return completed;
  }

  recordTransferUnconfirmed(approvalEntryHash: string, reason: string): AppendedAuditEntry {
    const approvalHash = normalizeHash(approvalEntryHash);
    const transfer = this.transferByApprovalHash(approvalHash);
    if (!transfer) {
      throw new Error(`transfer ${approvalHash} not found`);
    }
    if (transfer.status !== "APPROVED") {
      throw new Error(`transfer ${approvalHash} is already settled as ${transfer.status}`);
    }
    const unconfirmed = this.appendPeerNonChainConsentEvent({
      consentId: transfer.consentId,
      eventType: "TRANSFER_UNCONFIRMED",
      requestContext: {
        reason,
        approvalEntryHash: approvalHash,
        peerInstitutionId: transfer.peerInstitutionId,
        studyInstanceUid: transfer.studyInstanceUid
      },
      afterAuditInsert: () => {
        this.db
          .prepare("UPDATE transfers SET status = 'UNCONFIRMED', settledAt = ? WHERE transferId = ?")
          .run(nowSeconds(), transfer.transferId);
        this.holdPeer(transfer.peerInstitutionId, reason);
      }
    });
    return unconfirmed;
  }

  recordTransferFailed(approvalEntryHash: string, reason: string): AppendedAuditEntry {
    const approvalHash = normalizeHash(approvalEntryHash);
    const transfer = this.transferByApprovalHash(approvalHash);
    if (!transfer) {
      throw new Error(`transfer ${approvalHash} not found`);
    }
    if (transfer.status !== "APPROVED") {
      throw new Error(`transfer ${approvalHash} is already settled as ${transfer.status}`);
    }
    const failed = this.appendPeerNonChainConsentEvent({
      consentId: transfer.consentId,
      eventType: "TRANSFER_FAILED",
      requestContext: {
        reason,
        approvalEntryHash: approvalHash,
        peerInstitutionId: transfer.peerInstitutionId,
        studyInstanceUid: transfer.studyInstanceUid
      },
      afterAuditInsert: () => {
        this.db
          .prepare("UPDATE transfers SET status = 'FAILED', settledAt = ? WHERE transferId = ?")
          .run(nowSeconds(), transfer.transferId);
      }
    });
    return failed;
  }

  beginRevocationBarrier(consentId: string): void {
    const consent = this.getConsent(consentId);
    if (!consent) {
      throw new Error(`consent ${consentId} not found`);
    }
    if (consent.status !== "active") {
      throw new Error(`consent ${consentId} is not active`);
    }
    this.db
      .prepare("INSERT OR IGNORE INTO revocation_barriers (consentId, requestedAt) VALUES (?, ?)")
      .run(consentId, nowSeconds());
  }

  pendingTransferCount(consentId: string): number {
    const row = this.db
      .prepare("SELECT COUNT(*) AS count FROM transfers WHERE consentId = ? AND status = 'APPROVED'")
      .get(consentId) as { count: number };
    return row.count;
  }

  pendingTransfers(consentId: string): TransferRow[] {
    return this.db
      .prepare(
        `SELECT transferId, consentId, peerInstitutionId, studyInstanceUid, purpose, seq,
                approvedEntryHash, approvedSignature, requesterEntryHash, requesterSignature,
                receiveEntryHash, receiverSignature, status, startedAt, settledAt
         FROM transfers
         WHERE consentId = ? AND status = 'APPROVED'
         ORDER BY startedAt ASC`
      )
      .all(consentId) as TransferRow[];
  }

  markPendingTransfersUnconfirmed(consentId: string, reason: string): AppendedAuditEntry[] {
    return this.pendingTransfers(consentId)
      .map((transfer) => {
        if (!transfer.approvedEntryHash) {
          throw new Error(`pending transfer ${transfer.transferId} has no approval entry hash`);
        }
        return this.recordTransferUnconfirmed(transfer.approvedEntryHash, reason);
      });
  }

  isApprovalBlocked(consentId: string): boolean {
    const consent = this.getConsent(consentId);
    if (!consent || consent.status !== "active") {
      return true;
    }
    const row = this.db
      .prepare("SELECT 1 AS present FROM revocation_barriers WHERE consentId = ?")
      .get(consentId) as { present: number } | undefined;
    return row !== undefined;
  }

  isPeerHeld(peerInstitutionId: string): boolean {
    const row = this.db
      .prepare("SELECT 1 AS present FROM peer_transfer_holds WHERE peerInstitutionId = ?")
      .get(peerInstitutionId) as { present: number } | undefined;
    return row !== undefined;
  }

  releasePeerHold(peerInstitutionId: string): boolean {
    const result = this.db
      .prepare("DELETE FROM peer_transfer_holds WHERE peerInstitutionId = ?")
      .run(peerInstitutionId);
    return result.changes > 0;
  }

  private holdPeer(peerInstitutionId: string, reason: string): void {
    this.db
      .prepare(
        `INSERT INTO peer_transfer_holds (peerInstitutionId, reason, heldAt)
         VALUES (?, ?, ?)
         ON CONFLICT(peerInstitutionId) DO UPDATE SET reason = excluded.reason, heldAt = excluded.heldAt`
      )
      .run(peerInstitutionId, reason, nowSeconds());
  }

  useNonce(nonce: string, consentId: string): boolean {
    try {
      this.db
        .prepare("INSERT INTO token_nonces (nonce, consentId, usedAt) VALUES (?, ?, ?)")
        .run(nonce, consentId, nowSeconds());
      return true;
    } catch (error) {
      // Only a primary-key collision means replay. Treating any other database error as
      // replay would silently accept a first-use token as already spent.
      const code = (error as { code?: unknown }).code;
      if (typeof code === "string" && code.startsWith("SQLITE_CONSTRAINT")) {
        return false;
      }
      throw error;
    }
  }

  consentDetails(consentId: string): {
    consentId: string;
    secretC: HexString;
    providerInstitutionId: string;
    receiverInstitutionId: string;
    studyInstanceUids: string[];
    purpose: string;
    validUntil: number;
    status: "active" | "revoked";
    approvalBlocked: boolean;
  } {
    const consent = this.getConsent(consentId);
    if (!consent) {
      throw new Error(`consent ${consentId} not found`);
    }
    return {
      consentId,
      secretC: normalizeHash(consent.secretC),
      providerInstitutionId: consent.providerInstitutionId,
      receiverInstitutionId: consent.receiverInstitutionId,
      studyInstanceUids: parseJsonArray(consent.studyInstanceUids),
      purpose: consent.purpose,
      validUntil: consent.validUntil,
      status: consent.status,
      approvalBlocked: this.isApprovalBlocked(consentId)
    };
  }

  currentRoot(): HexString {
    return this.tree.currentRoot();
  }

  rootAt(treeSize: number): HexString {
    return this.tree.rootAt(treeSize);
  }

  treeSize(): number {
    return this.tree.treeSize();
  }

  mapRoot(): HexString {
    return this.smt.mapRoot();
  }

  hasMapRoot(mapRoot: string): boolean {
    return this.smt.hasRoot(mapRoot);
  }

  smtInclusionProof(key: string, mapRoot: string = this.mapRoot()) {
    return this.smt.inclusionProof(key, mapRoot);
  }

  smtNonInclusionProof(key: string, mapRoot: string = this.mapRoot()) {
    return this.smt.nonInclusionProof(key, mapRoot);
  }

  smtProof(key: string, mapRoot: string = this.mapRoot()) {
    try {
      return this.smt.inclusionProof(key, mapRoot);
    } catch {
      return this.smt.nonInclusionProof(key, mapRoot);
    }
  }

  consistencyProof(firstSize: number, secondSize: number) {
    return this.tree.consistencyProof(firstSize, secondSize);
  }

  inclusionProofByEntryHash(entryHash: string, treeSize: number = this.treeSize()) {
    const normalized = normalizeHash(entryHash);
    const row = this.db
      .prepare("SELECT leafIndex, canonicalBytes, entryHash, timestamp FROM audit_entries WHERE entryHash = ?")
      .get(normalized) as AuditEntryRow | undefined;
    if (!row) {
      throw new Error(`entryHash ${normalized} not found`);
    }
    return {
      canonicalBytes: bytesToHex(asUint8Array(row.canonicalBytes)),
      leafHash: undefined,
      proof: this.tree.inclusionProof(row.leafIndex, treeSize)
    };
  }

  latestAnchor(): AnchorHistoryRecord | null {
    const row = this.db
      .prepare("SELECT batchId, rootHash, treeSize, mapRoot, txHash FROM anchor_history ORDER BY batchId DESC LIMIT 1")
      .get() as AnchorHistoryRow | undefined;
    if (!row) {
      return null;
    }
    return {
      batchId: row.batchId,
      rootHash: normalizeHash(row.rootHash),
      treeSize: row.treeSize,
      mapRoot: normalizeHash(row.mapRoot),
      txHash: row.txHash
    };
  }

  anchorByBatchId(batchId: number): AnchorHistoryRecord {
    const row = this.db
      .prepare("SELECT batchId, rootHash, treeSize, mapRoot, txHash FROM anchor_history WHERE batchId = ?")
      .get(batchId) as AnchorHistoryRow | undefined;
    if (!row) {
      throw new Error(`anchor batch ${batchId} not found`);
    }
    return {
      batchId: row.batchId,
      rootHash: normalizeHash(row.rootHash),
      treeSize: row.treeSize,
      mapRoot: normalizeHash(row.mapRoot),
      txHash: row.txHash
    };
  }

  listAnchors(): AnchorHistoryRecord[] {
    const rows = this.db
      .prepare("SELECT batchId, rootHash, treeSize, mapRoot, txHash FROM anchor_history ORDER BY batchId ASC")
      .all() as AnchorHistoryRow[];
    return rows.map((row) => ({
      batchId: row.batchId,
      rootHash: normalizeHash(row.rootHash),
      treeSize: row.treeSize,
      mapRoot: normalizeHash(row.mapRoot),
      txHash: row.txHash
    }));
  }

  recordAnchor(record: AnchorHistoryRecord): void {
    const normalizedRoot = normalizeHash(record.rootHash);
    const normalizedMapRoot = normalizeHash(record.mapRoot);
    const existing = this.db
      .prepare("SELECT batchId, rootHash, treeSize, mapRoot, txHash FROM anchor_history WHERE batchId = ?")
      .get(record.batchId) as AnchorHistoryRow | undefined;

    if (existing) {
      const sameRecord =
        normalizeHash(existing.rootHash) === normalizedRoot &&
        existing.treeSize === record.treeSize &&
        normalizeHash(existing.mapRoot) === normalizedMapRoot &&
        existing.txHash === record.txHash;
      if (sameRecord) {
        return;
      }
      throw new Error(
        `anchor batch ${record.batchId} already exists with different values`
      );
    }

    this.db
      .prepare(
        `INSERT INTO anchor_history (batchId, rootHash, treeSize, mapRoot, txHash)
         VALUES (@batchId, @rootHash, @treeSize, @mapRoot, @txHash)`
      )
      .run({
        batchId: record.batchId,
        rootHash: normalizedRoot,
        treeSize: record.treeSize,
        mapRoot: normalizedMapRoot,
        txHash: record.txHash
      });
  }

  chainEntries(consentId: string): ChainEntryRecord[] {
    const rows = this.db
      .prepare(
        `SELECT leafIndex, canonicalBytes, entryHash, eventType, seq
         FROM audit_entries
         WHERE consentId = ?
           AND seq IS NOT NULL
           AND eventType IN ('CONSENT_CREATED', 'TRANSFER_APPROVED', 'TRANSFER_COMPLETED', 'RECEIVE_COMPLETED', 'CONSENT_REVOKED')
         ORDER BY leafIndex ASC`
      )
      .all(consentId) as ChainEntryRow[];

    return rows.map((row) => ({
      leafIndex: row.leafIndex,
      entryHash: normalizeHash(row.entryHash),
      eventType: row.eventType,
      seq: row.seq,
      canonicalBytes: bytesToHex(asUint8Array(row.canonicalBytes))
    }));
  }

  auditEntries(treeSize: number = this.treeSize()): AuditLogEntryRecord[] {
    if (!Number.isSafeInteger(treeSize) || treeSize < 0 || treeSize > this.treeSize()) {
      throw new Error(`treeSize ${treeSize} is outside current tree size ${this.treeSize()}`);
    }
    const rows = this.db
      .prepare(
        `SELECT leafIndex, canonicalBytes, entryHash, eventType, consentId, seq
         FROM audit_entries
         WHERE leafIndex < ?
         ORDER BY leafIndex ASC`
      )
      .all(treeSize) as AuditLogEntryRow[];

    return rows.map((row) => ({
      leafIndex: row.leafIndex,
      entryHash: normalizeHash(row.entryHash),
      eventType: row.eventType,
      consentId: row.consentId,
      seq: row.seq,
      canonicalBytes: bytesToHex(asUint8Array(row.canonicalBytes))
    }));
  }

  consentSecret(consentId: string): HexString {
    const consent = this.getConsent(consentId);
    if (!consent) {
      throw new Error(`consent ${consentId} not found`);
    }
    return normalizeHash(consent.secretC);
  }

  ensureReceiverReferenceConsent(options: {
    consentId: string;
    receiverSecret: string;
    providerInstitutionId: string;
    studyInstanceUid: string;
    purpose: string;
  }): void {
    this.ensureReceiverConsent(options);
  }

  private ensureReceiverConsent(options: {
    consentId: string;
    receiverSecret: string;
    providerInstitutionId: string;
    studyInstanceUid: string;
    purpose: string;
  }): void {
    const secret = normalizeHash(options.receiverSecret);
    const existing = this.getConsent(options.consentId);
    if (existing) {
      if (normalizeHash(existing.secretC) !== secret) {
        throw new Error(`receiver consent ${options.consentId} exists with a different derived secret`);
      }
      return;
    }
    this.db
      .prepare(
        `INSERT INTO consents (
          consentId, secretC, providerInstitutionId, receiverInstitutionId,
          studyInstanceUids, purpose, validUntil, status, lastSeq, lastEntryHash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', 0, NULL)`
      )
      .run(
        options.consentId,
        secret,
        options.providerInstitutionId,
        this.institutionId,
        JSON.stringify([options.studyInstanceUid]),
        options.purpose,
        Number.MAX_SAFE_INTEGER
      );
  }

  transferStatusByApprovalHash(approvedEntryHash: string): TransferRow["status"] | null {
    return this.transferByApprovalHash(approvedEntryHash)?.status ?? null;
  }

  private transferByApprovalHash(approvedEntryHash: string): TransferRow | null {
    const row = this.db
      .prepare(
        `SELECT transferId, consentId, peerInstitutionId, studyInstanceUid, purpose, seq,
                approvedEntryHash, approvedSignature, requesterEntryHash, requesterSignature,
                receiveEntryHash, receiverSignature, status, startedAt, settledAt
         FROM transfers
         WHERE approvedEntryHash = ?`
      )
      .get(normalizeHash(approvedEntryHash)) as TransferRow | undefined;
    return row ?? null;
  }

  private appendSingleEntry(
    input: AuditEntryInput,
    afterAuditInsert?: (entry: AuditEntry, leafIndex: number) => void
  ): AppendedAuditEntry {
    validateAuditEntryInput(input, 0);
    const entry = normalizeEntry(input);
    const canonicalBytes = entryPreimage(entry);
    const leafIndex = this.treeSize();
    const tx = this.db.transaction(() => {
      this.db
        .prepare(
          `INSERT INTO audit_entries (leafIndex, canonicalBytes, entryHash, timestamp, eventType, consentId, seq)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        )
        .run(leafIndex, canonicalBytes, entry.entryHash, entry.timestamp, entry.eventType, entry.consentId, entry.seq);
      afterAuditInsert?.(entry, leafIndex);
    });
    tx();
    this.tree.appendLeaf(asUint8Array(canonicalBytes));
    return {
      leafIndex,
      entryHash: normalizeHash(entry.entryHash),
      canonicalBytes: bytesToHex(asUint8Array(canonicalBytes)),
      timestamp: entry.timestamp
    };
  }

  private appendConsentChainEvent(
    consentId: string,
    eventType: EventType,
    requestContext: object,
    options: {
      force?: boolean;
      seqOverride?: number;
      updateSmt?: boolean;
      updateHead?: boolean;
      peerEntryHash?: string | null;
      peerSignature?: string | null;
      afterAuditInsert?: (entry: AuditEntry, seq: number, leafIndex: number) => void;
    } = {}
  ): ChainEntryRecord {
    assertChainEvent(eventType);
    const consent = this.getConsent(consentId);
    if (!consent) {
      throw new Error(`consent ${consentId} not found`);
    }
    if (!options.force && consent.status === "revoked") {
      throw new Error(`consent ${consentId} is revoked`);
    }
    if (!options.force && eventType === "CONSENT_REVOKED" && consent.status !== "active") {
      throw new Error(`consent ${consentId} is not active`);
    }
    if (!options.force && eventType === "TRANSFER_APPROVED" && this.isApprovalBlocked(consentId)) {
      throw new Error(`consent ${consentId} is blocked for new approvals`);
    }

    const seq = options.seqOverride ?? consent.lastSeq + 1;
    if (!Number.isSafeInteger(seq) || seq < 1) {
      throw new Error("seq must be an integer >= 1");
    }
    const prevHash = seq === 1 ? ZERO_HASH : normalizeHash(consent.lastEntryHash ?? ZERO_HASH);
    const entry: AuditEntry = normalizeEntry({
      eventType,
      timestamp: nowSeconds(),
      institutionId: this.institutionId,
      consentId,
      seq,
      prevHash,
      requestContext,
      peerEntryHash: options.peerEntryHash ? normalizeHash(options.peerEntryHash) : null,
      peerSignature: options.peerSignature ? normalizeHex(options.peerSignature) : null
    });
    const canonicalBytes = entryPreimage(entry);
    const leafIndex = this.treeSize();
    const oldMapRoot = this.smt.mapRoot();
    let nextMapRoot = oldMapRoot;

    const updateSmt = options.updateSmt ?? true;
    const updateHead = options.updateHead ?? true;
    const tx = this.db.transaction(() => {
      if (updateSmt) {
        const secret = normalizeHash(consent.secretC);
        nextMapRoot = this.smt.set(smtLeafKey(secret, consentId, seq), normalizeHash(entry.entryHash));
        if (updateHead) {
          nextMapRoot = this.smt.set(smtHeadKey(secret, consentId), normalizeHash(entry.entryHash));
        }
        this.writeMapRoot(nextMapRoot);
      }

      this.db
        .prepare(
          `INSERT INTO audit_entries (leafIndex, canonicalBytes, entryHash, timestamp, eventType, consentId, seq)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        )
        .run(leafIndex, canonicalBytes, entry.entryHash, entry.timestamp, entry.eventType, consentId, seq);

      this.db
        .prepare(
          `UPDATE consents
           SET status = CASE WHEN ? = 'CONSENT_REVOKED' THEN 'revoked' ELSE status END,
               lastSeq = ?,
               lastEntryHash = ?
           WHERE consentId = ?`
        )
        .run(eventType, Math.max(consent.lastSeq, seq), entry.entryHash, consentId);
      options.afterAuditInsert?.(entry, seq, leafIndex);
    });

    try {
      tx();
    } catch (error) {
      this.smt.setRoot(oldMapRoot);
      throw error;
    }

    this.tree.appendLeaf(asUint8Array(canonicalBytes));
    return {
      leafIndex,
      entryHash: normalizeHash(entry.entryHash),
      eventType,
      seq,
      canonicalBytes: bytesToHex(asUint8Array(canonicalBytes))
    };
  }

  private getConsent(consentId: string): ConsentRow | null {
    const row = this.db
      .prepare(
        `SELECT consentId, secretC, providerInstitutionId, receiverInstitutionId,
                studyInstanceUids, purpose, validUntil, status, lastSeq, lastEntryHash
         FROM consents
         WHERE consentId = ?`
      )
      .get(consentId) as ConsentRow | undefined;
    if (row) {
      parseJsonArray(row.studyInstanceUids);
    }
    return row ?? null;
  }

  private initializeSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit_entries (
        leafIndex INTEGER PRIMARY KEY,
        canonicalBytes BLOB NOT NULL,
        entryHash TEXT NOT NULL,
        timestamp INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_audit_entries_entryHash
        ON audit_entries(entryHash);

      CREATE TABLE IF NOT EXISTS anchor_history (
        batchId INTEGER PRIMARY KEY,
        rootHash TEXT NOT NULL,
        treeSize INTEGER NOT NULL,
        txHash TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS consents (
        consentId TEXT PRIMARY KEY,
        secretC TEXT NOT NULL,
        providerInstitutionId TEXT NOT NULL,
        receiverInstitutionId TEXT NOT NULL,
        studyInstanceUids TEXT NOT NULL,
        purpose TEXT NOT NULL,
        validUntil INTEGER NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
        lastSeq INTEGER NOT NULL,
        lastEntryHash TEXT
      );

      CREATE TABLE IF NOT EXISTS smt_state (
        id INTEGER PRIMARY KEY CHECK(id = 1),
        mapRoot TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS token_nonces (
        nonce TEXT PRIMARY KEY,
        consentId TEXT NOT NULL,
        usedAt INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS revocation_barriers (
        consentId TEXT PRIMARY KEY,
        requestedAt INTEGER NOT NULL
      );

      ${TRANSFERS_TABLE_DDL}

      CREATE TABLE IF NOT EXISTS peer_transfer_holds (
        peerInstitutionId TEXT PRIMARY KEY,
        reason TEXT NOT NULL,
        heldAt INTEGER NOT NULL
      );
    `);
    // CREATE TABLE IF NOT EXISTS does not widen an existing status CHECK, so a database
    // created before FAILED/RECEIPT_LATE existed would fail with a bare "CHECK constraint
    // failed" at settlement time. Recreate it while empty; demand a reset once it has rows.
    const transfersDdl = this.db
      .prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'transfers'")
      .get() as { sql: string } | undefined;
    if (transfersDdl && (!transfersDdl.sql.includes("'FAILED'") || !transfersDdl.sql.includes("'RECEIPT_LATE'"))) {
      const { count } = this.db.prepare("SELECT COUNT(*) AS count FROM transfers").get() as { count: number };
      if (count > 0) {
        throw new Error(
          "transfers table has a legacy status CHECK without FAILED/RECEIPT_LATE and existing rows; reset the audit DB before running this version"
        );
      }
      this.db.exec("DROP TABLE transfers;");
      this.db.exec(TRANSFERS_TABLE_DDL);
    }
    this.addColumnIfMissing("audit_entries", "eventType", "TEXT");
    this.addColumnIfMissing("audit_entries", "consentId", "TEXT");
    this.addColumnIfMissing("audit_entries", "seq", "INTEGER");
    // anchor_history.mapRoot cannot be back-filled. Anchors registered before the SMT
    // existed carry mapRoot = 0x00…00 on chain: filling the local column with
    // EMPTY_SMT_ROOT diverges from the chain and deadlocks reconcileLatestAnchor, while
    // filling it with zeros fails the SMT self-check at startup. Such a database must be reset.
    const anchorColumns = this.db.prepare("PRAGMA table_info(anchor_history)").all() as { name: string }[];
    if (!anchorColumns.some((row) => row.name === "mapRoot")) {
      const { count } = this.db.prepare("SELECT COUNT(*) AS count FROM anchor_history").get() as { count: number };
      if (count > 0) {
        throw new Error(
          "anchor_history has legacy rows without mapRoot; anchored history cannot be migrated — reset the audit DB (and restart/redeploy the local chain) instead"
        );
      }
      this.db.exec(`ALTER TABLE anchor_history ADD COLUMN mapRoot TEXT NOT NULL DEFAULT '${EMPTY_SMT_ROOT}'`);
    }
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_audit_entries_consent_chain
        ON audit_entries(consentId, leafIndex)
        WHERE consentId IS NOT NULL AND seq IS NOT NULL;
    `);
    this.db
      .prepare("INSERT OR IGNORE INTO smt_state (id, mapRoot) VALUES (1, ?)")
      .run(EMPTY_SMT_ROOT);
  }

  private addColumnIfMissing(tableName: string, columnName: string, definition: string): void {
    const rows = this.db.prepare(`PRAGMA table_info(${tableName})`).all() as { name: string }[];
    if (!rows.some((row) => row.name === columnName)) {
      this.db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition}`);
    }
  }

  private readMapRoot(): HexString {
    const row = this.db.prepare("SELECT mapRoot FROM smt_state WHERE id = 1").get() as { mapRoot: string } | undefined;
    return row ? normalizeHash(row.mapRoot) : EMPTY_SMT_ROOT;
  }

  private writeMapRoot(mapRoot: HexString): void {
    this.db.prepare("UPDATE smt_state SET mapRoot = ? WHERE id = 1").run(normalizeHash(mapRoot));
  }

  private restoreTree(): void {
    const rows = this.db
      .prepare("SELECT leafIndex, canonicalBytes, entryHash, timestamp FROM audit_entries ORDER BY leafIndex ASC")
      .all() as AuditEntryRow[];

    rows.forEach((row, expectedIndex) => {
      if (row.leafIndex !== expectedIndex) {
        throw new Error(`audit_entries leafIndex gap: expected ${expectedIndex}, got ${row.leafIndex}`);
      }
      this.tree.appendLeaf(asUint8Array(row.canonicalBytes));
    });
  }

  private selfCheckLastAnchor(): void {
    const latest = this.latestAnchor();
    if (!latest) {
      return;
    }
    if (latest.treeSize > this.treeSize()) {
      throw new Error(
        `last anchor treeSize ${latest.treeSize} exceeds restored tree size ${this.treeSize()}`
      );
    }
    const restoredAnchoredRoot = this.rootAt(latest.treeSize);
    if (restoredAnchoredRoot !== latest.rootHash) {
      throw new Error(
        `restored prefix root ${restoredAnchoredRoot} does not match last anchor root ${latest.rootHash}`
      );
    }
    if (!this.smt.hasRoot(latest.mapRoot)) {
      throw new Error(`last anchor mapRoot ${latest.mapRoot} is not available in the SMT store`);
    }
  }
}
