// Ed25519 signatures over audit entries, the basis of the mutual references between institutions.
//
// The message is always the raw 32 bytes of an entryHash, never its hex text or the entry itself.
// Both sides of a handshake depend on that: a peer signs the hash of the other's entry, so the
// two must derive identical bytes from the same hash for the signature to carry any weight.
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import type { KeyObject } from "node:crypto";
import type { HexString } from "@vadrex/shared";

function normalizeHex(hex: string): HexString {
  if (!/^0x[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error(`expected 0x-prefixed hex, got ${hex}`);
  }
  return `0x${hex.slice(2).toLowerCase()}`;
}

function hashBytes(entryHash: string): Buffer {
  const normalized = normalizeHex(entryHash);
  if (normalized.length !== 66) {
    throw new Error(`entryHash must be 32 bytes, got ${entryHash}`);
  }
  return Buffer.from(normalized.slice(2), "hex");
}

export class EntrySigner {
  private readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;

  constructor(privateKeyPem: string) {
    this.privateKey = createPrivateKey(privateKeyPem);
    this.publicKey = createPublicKey(this.privateKey);
  }

  static fromFile(path: string): EntrySigner {
    return new EntrySigner(readFileSync(path, "utf8"));
  }

  signEntryHash(entryHash: string): HexString {
    return `0x${sign(null, new Uint8Array(hashBytes(entryHash)), this.privateKey).toString("hex")}`;
  }
}

export function readPublicKey(path: string): KeyObject {
  return createPublicKey(readFileSync(path, "utf8"));
}

export function verifyEntrySignature(entryHash: string, signatureHex: string, publicKey: KeyObject): boolean {
  try {
    return verify(
      null,
      new Uint8Array(hashBytes(entryHash)),
      publicKey,
      new Uint8Array(Buffer.from(normalizeHex(signatureHex).slice(2), "hex"))
    );
  } catch {
    return false;
  }
}
