import { generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { AuditEntry } from "@vadrex/shared";
import { entryPreimage } from "@vadrex/shared";
import { Rfc6962LogTree } from "@vadrex/merkle";
import {
  auditEntryFromCanonicalBytes,
  entryHashFromCanonicalBytes,
  rfc6962LeafHashFromCanonicalBytes,
  verifyAnchoredInclusion,
  verifyEntrySignatureWithPem
} from "../src/proofs.js";

function bytesToHex(bytes: Uint8Array): `0x${string}` {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

function entry(): AuditEntry {
  return {
    eventType: "CONSENT_REVOKED",
    timestamp: 1_725_000_000,
    institutionId: "A",
    consentId: "consent-1",
    seq: 2,
    prevHash: `0x${"11".repeat(32)}`,
    requestContext: { revocationBarrier: { newApprovalsBlocked: true, pendingTransfersSettled: true } },
    peerEntryHash: null,
    peerSignature: null,
    entryHash: ""
  };
}

describe("verifier proof helpers", () => {
  it("recomputes entryHash and RFC6962 leaf hash from canonicalBytes before verifying inclusion", () => {
    const base = entry();
    const canonicalBytes = bytesToHex(entryPreimage(base));
    const parsed = auditEntryFromCanonicalBytes(canonicalBytes);
    const tree = new Rfc6962LogTree();
    tree.appendLeaf(Buffer.from(canonicalBytes.slice(2), "hex"));
    const proof = tree.inclusionProof(0);

    expect(parsed.entryHash).toBe(entryHashFromCanonicalBytes(canonicalBytes));
    expect(
      verifyAnchoredInclusion(
        {
          batchId: 1,
          rootHash: tree.currentRoot(),
          treeSize: tree.treeSize(),
          mapRoot: `0x${"00".repeat(32)}`,
          anchoredAt: 1_725_000_030
        },
        {
          rootHash: tree.currentRoot(),
          treeSize: tree.treeSize(),
          canonicalBytes,
          proof
        }
      ).leafHash
    ).toBe(rfc6962LeafHashFromCanonicalBytes(canonicalBytes));
  });

  it("verifies Ed25519 signatures over raw entryHash bytes", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const entryHash = `0x${"ab".repeat(32)}`;
    const signature = bytesToHex(sign(null, Buffer.from(entryHash.slice(2), "hex"), privateKey));
    const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();

    expect(verifyEntrySignatureWithPem(entryHash, signature, publicKeyPem)).toBe(true);
    expect(verifyEntrySignatureWithPem(`0x${"cd".repeat(32)}`, signature, publicKeyPem)).toBe(false);
  });
});

