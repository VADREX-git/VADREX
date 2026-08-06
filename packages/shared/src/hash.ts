// Hashing over audit entries. The preimage is always canonicalize(entry minus entryHash), and it
// is shared by two derivations: entryHash = sha256(preimage), while the log tree prefixes the
// same bytes with 0x00. Anything that computes an entryHash must go through entryPreimage, or the
// producer and the verifier will disagree about what was logged.
import { createHash, createHmac } from "node:crypto";
import { canonicalize } from "./canonical.js";
import type { AuditEntry } from "./types.js";

export type HexString = `0x${string}`;

function toBuffer(input: Buffer | Uint8Array | string): Buffer {
  if (Buffer.isBuffer(input)) {
    return input;
  }
  if (typeof input === "string") {
    return Buffer.from(input, "utf8");
  }
  return Buffer.from(input);
}

function toHex(buffer: Buffer): HexString {
  return `0x${buffer.toString("hex")}`;
}

export function sha256(input: Buffer | Uint8Array | string): HexString {
  return toHex(createHash("sha256").update(toBuffer(input)).digest());
}

export function hmacSha256(key: Buffer | Uint8Array | string, input: Buffer | Uint8Array | string): HexString {
  return toHex(createHmac("sha256", toBuffer(key)).update(toBuffer(input)).digest());
}

export function withoutEntryHash(entry: AuditEntry): Omit<AuditEntry, "entryHash"> {
  const { entryHash: _entryHash, ...preimage } = entry;
  return preimage;
}

export function entryPreimage(entry: AuditEntry): Buffer {
  return canonicalize(withoutEntryHash(entry));
}

export function computeEntryHash(entry: AuditEntry): HexString {
  return sha256(entryPreimage(entry));
}
