import type { AuditEntry } from "@vadrex/shared";

export type AuditEntryDraft = Omit<AuditEntry, "entryHash">;

const ZERO_HASH = "0x0000000000000000000000000000000000000000000000000000000000000000";

export function makeAuditEntries(count: number, offset = 0, timestampBase = Math.floor(Date.now() / 1000)): AuditEntryDraft[] {
  return Array.from({ length: count }, (_, index) => {
    const ordinal = offset + index + 1;
    return {
      eventType: "CROSS_CHECKPOINT",
      timestamp: timestampBase + index,
      institutionId: "A",
      consentId: null,
      seq: null,
      prevHash: null,
      requestContext: {
        demo: "stage-3",
        ordinal,
        zeroHash: ZERO_HASH
      },
      peerEntryHash: null,
      peerSignature: null
    };
  });
}
