import { describe, expect, it } from "vitest";
import { canonicalize, computeEntryHash, hmacSha256, sha256 } from "../src/index.js";
import type { AuditEntry } from "../src/index.js";

describe("canonicalize", () => {
  it("emits identical bytes for objects with different insertion order", () => {
    const first = { b: 2, a: 1, nested: { z: true, y: null } };
    const second = { nested: { y: null, z: true }, a: 1, b: 2 };

    expect(canonicalize(first).toString("utf8")).toBe('{"a":1,"b":2,"nested":{"y":null,"z":true}}');
    expect(canonicalize(first)).toEqual(canonicalize(second));
  });

  it("sorts nested unicode keys by code point", () => {
    const value = {
      "한": 1,
      "가": 2,
      nested: {
        "😀": "face",
        "a": "latin",
        "💡": "light"
      }
    };

    expect(canonicalize(value).toString("utf8")).toBe(
      '{"nested":{"a":"latin","💡":"light","😀":"face"},"가":2,"한":1}'
    );
  });

  it("sorts by code point, not by UTF-16 code unit", () => {
    // By code point U+FFFF < U+1F600. A plain sort() compares code units (0xD83D < 0xFFFF) and
    // puts them the other way round.
    const value = { "😀": 2, "￿": 1 };

    expect(canonicalize(value).toString("utf8")).toBe('{"￿":1,"😀":2}');
  });
});

describe("hash helpers", () => {
  it("computes SHA-256 and HMAC-SHA-256 as lowercase 0x-prefixed hex", () => {
    expect(sha256("vadrex")).toBe("0x0bed5d982eccdf3ad589b97a935eb22670d8162aa05b299543c9ebf21816b220");
    expect(hmacSha256("secret", "consent:1")).toBe(
      "0x875a530552553b1639dfd17edc23b6496f758657ce17313cedd5666e24e0d54b"
    );
  });

  it("computes entryHash from the canonical preimage without the entryHash field", () => {
    const entry: AuditEntry = {
      eventType: "CONSENT_CREATED",
      timestamp: 1720000000,
      institutionId: "A",
      consentId: "consent-001",
      seq: 1,
      prevHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
      requestContext: { purpose: "research", study: { accession: "A-1", modalities: ["CT"] } },
      peerEntryHash: null,
      peerSignature: null,
      entryHash: "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    };

    expect(computeEntryHash(entry)).toBe("0x67fac87d6c682ed227fc69def6bc0c60937747170e7388404ed4a9b7d82551a5");
  });

  it("ignores the existing entryHash value when recomputing entryHash", () => {
    const entry: AuditEntry = {
      eventType: "CONSENT_CREATED",
      timestamp: 1720000000,
      institutionId: "A",
      consentId: "consent-001",
      seq: 1,
      prevHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
      requestContext: { purpose: "research", study: { accession: "A-1", modalities: ["CT"] } },
      peerEntryHash: null,
      peerSignature: null,
      entryHash: "0x1111111111111111111111111111111111111111111111111111111111111111"
    };

    const sameEntryWithDifferentHash: AuditEntry = {
      ...entry,
      entryHash: "0x2222222222222222222222222222222222222222222222222222222222222222"
    };

    expect(computeEntryHash(entry)).toBe(computeEntryHash(sameEntryWithDifferentHash));
  });
});
