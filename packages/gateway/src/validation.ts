import type { EventType } from "@vadrex/shared";
import type { AuditEntryInput } from "./aggregator.js";

export class EntryValidationError extends Error {
  constructor(readonly entryIndex: number, detail: string) {
    super(`entry[${entryIndex}]: ${detail}`);
    this.name = "EntryValidationError";
  }
}

const EVENT_TYPES: ReadonlySet<string> = new Set<EventType>([
  "CONSENT_CREATED",
  "CONSENT_REVOKED",
  "TRANSFER_REQUESTED",
  "TRANSFER_APPROVED",
  "TRANSFER_DENIED",
  "TRANSFER_COMPLETED",
  "RECEIVE_COMPLETED",
  "TRANSFER_FAILED",
  "TRANSFER_UNCONFIRMED",
  "RECEIPT_LATE",
  "REPLAY_BLOCKED",
  "CROSS_CHECKPOINT"
]);

const REQUIRED_KEYS = [
  "eventType",
  "timestamp",
  "institutionId",
  "consentId",
  "seq",
  "prevHash",
  "requestContext",
  "peerEntryHash",
  "peerSignature"
] as const;

const ALLOWED_KEYS: ReadonlySet<string> = new Set([...REQUIRED_KEYS, "entryHash"]);

// Hashes are lowercase hex, 0x-prefixed, 66 characters. Accepting uppercase would let the
// same logical entry persist under two different canonical byte strings.
const HASH_PATTERN = /^0x[0-9a-f]{64}$/;
const SIGNATURE_PATTERN = /^0x(?:[0-9a-f]{2})+$/;

function fail(index: number, detail: string): never {
  throw new EntryValidationError(index, detail);
}

export function validateAuditEntryInput(value: unknown, index: number): asserts value is AuditEntryInput {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(index, "entry must be a JSON object");
  }
  const record = value as Record<string, unknown>;

  for (const key of Object.keys(record)) {
    if (!ALLOWED_KEYS.has(key)) {
      fail(index, `unknown field ${key}`);
    }
  }
  for (const key of REQUIRED_KEYS) {
    if (!(key in record)) {
      fail(index, `missing field ${key}`);
    }
  }

  if (typeof record.eventType !== "string" || !EVENT_TYPES.has(record.eventType)) {
    fail(index, `eventType must be one of the AuditEntry event types, got ${String(record.eventType)}`);
  }
  if (typeof record.timestamp !== "number" || !Number.isSafeInteger(record.timestamp) || record.timestamp <= 0) {
    fail(index, "timestamp must be a positive integer (unix epoch seconds)");
  }
  if (typeof record.institutionId !== "string" || record.institutionId.length === 0) {
    fail(index, "institutionId must be a non-empty string");
  }
  if (record.consentId !== null && (typeof record.consentId !== "string" || record.consentId.length === 0)) {
    fail(index, "consentId must be null or a non-empty string");
  }
  if (record.seq !== null && (typeof record.seq !== "number" || !Number.isSafeInteger(record.seq) || record.seq < 1)) {
    fail(index, "seq must be null or an integer >= 1");
  }
  if (record.prevHash !== null && (typeof record.prevHash !== "string" || !HASH_PATTERN.test(record.prevHash))) {
    fail(index, "prevHash must be null or a lowercase 0x-prefixed 32-byte hex string");
  }
  if (typeof record.requestContext !== "object" || record.requestContext === null || Array.isArray(record.requestContext)) {
    fail(index, "requestContext must be a JSON object");
  }
  if (record.peerEntryHash !== null && (typeof record.peerEntryHash !== "string" || !HASH_PATTERN.test(record.peerEntryHash))) {
    fail(index, "peerEntryHash must be null or a lowercase 0x-prefixed 32-byte hex string");
  }
  if (record.peerSignature !== null && (typeof record.peerSignature !== "string" || !SIGNATURE_PATTERN.test(record.peerSignature))) {
    fail(index, "peerSignature must be null or a lowercase 0x-prefixed hex string");
  }
  if ("entryHash" in record && record.entryHash !== null && typeof record.entryHash !== "string") {
    fail(index, "entryHash must be omitted, null, or a string (it is recomputed by the aggregator)");
  }
}
