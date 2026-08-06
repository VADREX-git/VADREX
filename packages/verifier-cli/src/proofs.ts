// Where a gateway response is checked against a chain anchor.
//
// Every function that takes a ChainAnchor first requires the response to name the very root the
// chain holds, then re-derives the leaf from the canonical bytes the gateway supplied. A gateway
// therefore cannot answer with a proof against a root of its own choosing, and cannot hand over
// bytes that differ from the entry the proof is about.
import { createHash, createPublicKey, verify } from "node:crypto";
import type { AuditEntry, HexString, InclusionProof, SmtProof } from "@vadrex/shared";
import { verifyInclusion, verifySmtInclusion, verifySmtNonInclusion } from "@vadrex/merkle";

export interface InclusionResponse {
  rootHash: HexString;
  treeSize: number;
  canonicalBytes: HexString;
  proof: InclusionProof;
}

export interface ChainAnchor {
  batchId: number;
  rootHash: HexString;
  treeSize: number;
  mapRoot: HexString;
  anchoredAt: number;
}

export interface ParsedAnchoredEntry {
  entry: AuditEntry;
  leafHash: HexString;
  proof: InclusionProof;
}

export interface SmtResponse {
  mapRoot: HexString;
  proof: SmtProof;
}

function bytesToHex(bytes: Buffer): HexString {
  return `0x${bytes.toString("hex")}`;
}

export function normalizeHex(hex: string): HexString {
  if (!/^0x[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error(`expected 0x-prefixed even-length hex, got ${hex}`);
  }
  return `0x${hex.slice(2).toLowerCase()}`;
}

export function normalizeHash(hash: string): HexString {
  const normalized = normalizeHex(hash);
  if (normalized.length !== 66) {
    throw new Error(`expected 32-byte hash, got ${hash}`);
  }
  return normalized;
}

export function hexToBytes(hex: string): Buffer {
  const normalized = normalizeHex(hex);
  return Buffer.from(normalized.slice(2), "hex");
}

export function sha256Hex(bytes: Buffer): HexString {
  return bytesToHex(createHash("sha256").update(bytes).digest());
}

export function entryHashFromCanonicalBytes(canonicalBytes: string): HexString {
  return sha256Hex(hexToBytes(canonicalBytes));
}

// Same preimage, two hashes: entryHash identifies the entry, while the log tree hashes it with
// the 0x00 leaf prefix from RFC 6962. Producer and verifier must agree on this exactly.
export function rfc6962LeafHashFromCanonicalBytes(canonicalBytes: string): HexString {
  return sha256Hex(Buffer.concat([Buffer.from([0x00]), hexToBytes(canonicalBytes)]));
}

export function auditEntryFromCanonicalBytes(canonicalBytes: string): AuditEntry {
  const raw = hexToBytes(canonicalBytes).toString("utf8");
  const parsed = JSON.parse(raw) as Omit<AuditEntry, "entryHash">;
  return {
    ...parsed,
    entryHash: entryHashFromCanonicalBytes(canonicalBytes)
  };
}

export function verifyAnchoredInclusion(anchor: ChainAnchor, response: InclusionResponse): ParsedAnchoredEntry {
  if (normalizeHash(response.rootHash) !== normalizeHash(anchor.rootHash)) {
    throw new Error(`gateway proof root ${response.rootHash} does not match chain root ${anchor.rootHash}`);
  }
  if (response.treeSize !== anchor.treeSize) {
    throw new Error(`gateway proof treeSize ${response.treeSize} does not match chain treeSize ${anchor.treeSize}`);
  }
  const entry = auditEntryFromCanonicalBytes(response.canonicalBytes);
  const leafHash = rfc6962LeafHashFromCanonicalBytes(response.canonicalBytes);
  if (!verifyInclusion(anchor.rootHash, anchor.treeSize, leafHash, response.proof)) {
    throw new Error(`inclusion proof failed for entry ${entry.entryHash} at batch ${anchor.batchId}`);
  }
  return { entry, leafHash, proof: response.proof };
}

export function verifySmtProofAt(anchor: ChainAnchor, response: SmtResponse): SmtProof {
  if (normalizeHash(response.mapRoot) !== normalizeHash(anchor.mapRoot)) {
    throw new Error(`gateway SMT root ${response.mapRoot} does not match chain mapRoot ${anchor.mapRoot}`);
  }
  const proof = response.proof;
  const ok = proof.type === "smtInclusion"
    ? verifySmtInclusion(anchor.mapRoot, proof)
    : verifySmtNonInclusion(anchor.mapRoot, proof);
  if (!ok) {
    throw new Error(`SMT ${proof.type} proof failed at batch ${anchor.batchId}`);
  }
  return proof;
}

export function verifyEntrySignatureWithPem(entryHash: string, signatureHex: string, publicKeyPem: string): boolean {
  try {
    const hash = hexToBytes(normalizeHash(entryHash));
    const signature = hexToBytes(signatureHex);
    return verify(null, new Uint8Array(hash), createPublicKey(publicKeyPem), new Uint8Array(signature));
  } catch {
    return false;
  }
}

