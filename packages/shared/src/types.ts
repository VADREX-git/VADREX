// The audit entry schema and the proof formats, shared by the gateways, the merkle package and
// the verifier so that all three agree on the bytes being hashed and proved.
//
// Only transfer-establishing events take part in a consent chain: CONSENT_CREATED,
// TRANSFER_APPROVED, TRANSFER_COMPLETED, the receiver's RECEIVE_COMPLETED and CONSENT_REVOKED.
// They carry a seq and a prevHash and are mirrored into the SMT. The rest may reference a
// consentId but are appended to the log tree with seq and prevHash null, so a denial or a blocked
// replay recorded after a revocation cannot disturb the non-transfer proof.
export type EventType =
  | "CONSENT_CREATED"
  | "CONSENT_REVOKED"
  | "TRANSFER_REQUESTED"
  | "TRANSFER_APPROVED"
  | "TRANSFER_DENIED"
  | "TRANSFER_COMPLETED"
  | "RECEIVE_COMPLETED"
  | "TRANSFER_FAILED"
  | "TRANSFER_UNCONFIRMED"
  | "RECEIPT_LATE"
  | "REPLAY_BLOCKED"
  | "CROSS_CHECKPOINT";

export interface AuditEntry {
  eventType: EventType;
  timestamp: number;
  institutionId: string;
  consentId: string | null;
  seq: number | null;
  /** Previous chain entry *within this institution's log*; 32 zero bytes for the first one. */
  prevHash: string | null;
  requestContext: object;
  /** The peer's entry hash and its signature over it: the link across an institution boundary. */
  peerEntryHash: string | null;
  peerSignature: string | null;
  entryHash: string;
}

export interface InclusionProof {
  type: "inclusion";
  treeSize: number;
  leafIndex: number;
  hashes: string[];
}

export interface ConsistencyProof {
  type: "consistency";
  firstSize: number;
  secondSize: number;
  hashes: string[];
}

export interface SmtProof {
  type: "smtInclusion" | "smtNonInclusion";
  key: string;
  value: string | null;
  siblings: string[];
}
