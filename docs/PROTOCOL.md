# Protocol contract

The interface contract every component implements. Generation (gateway) and verification
(verifier-cli, and any third-party verifier) must agree on all of it, byte for byte.

## 1. Encoding

- **Bytes** are lowercase hex with a `0x` prefix. A 32-byte hash is therefore always a 66-character
  string.
- **Time** is Unix epoch seconds as an integer, in the field `timestamp`.
- **Canonical JSON** (`packages/shared/src/canonical.ts`, `canonicalize(obj): Buffer`): object keys
  sorted ascending by Unicode code point, no whitespace, UTF-8. Every hash input goes through this
  one function.
- **Entry hash**: `entryHash = sha256(canonicalize(entry without the entryHash field))`.
- **Signatures**: Ed25519 over the raw 32 bytes of `entryHash`; the signature value is hex.

## 2. Audit entry

```typescript
interface AuditEntry {
  eventType: EventType;
  timestamp: number;
  institutionId: string;        // "A" | "B"
  consentId: string | null;
  seq: number | null;           // consent chain position, from 1
  prevHash: string | null;      // previous chain entry hash in this institution's own log
  requestContext: object;       // purpose, study scope summary — off-chain only
  peerEntryHash: string | null; // cross-institution reference
  peerSignature: string | null;
  entryHash: string;
}

type EventType =
  | "CONSENT_CREATED" | "CONSENT_REVOKED"
  | "TRANSFER_REQUESTED" | "TRANSFER_APPROVED" | "TRANSFER_DENIED"
  | "TRANSFER_COMPLETED" | "RECEIVE_COMPLETED"
  | "TRANSFER_FAILED" | "TRANSFER_UNCONFIRMED" | "RECEIPT_LATE"
  | "REPLAY_BLOCKED" | "CROSS_CHECKPOINT";
```

### 2.1 Chain-participating events

Only transfer-establishing events receive a `seq`, join the consent chain, and are written to the
SMT: `CONSENT_CREATED`, `TRANSFER_APPROVED`, `TRANSFER_COMPLETED`, the receiver's
`RECEIVE_COMPLETED`, and `CONSENT_REVOKED`.

All other event types may reference a `consentId` but carry `seq=null` and `prevHash=null` and are
**not** written to the SMT. They are still appended to the log tree. Consequently the subject of
"non-transfer after revocation" is approval, transfer, and receipt — a denial or a blocked replay
recorded after revocation does not pollute the verification.

### 2.2 Ownership of `seq`

A consent's home is the provider institution. Only the provider assigns and increments `seq`. The
receiver's `TRANSFER_REQUESTED` references the consent but carries `seq=null`. The receiver's
`RECEIVE_COMPLETED` reuses the `seq` the provider transmitted during the handshake (the `seq` of
`TRANSFER_APPROVED`) — it never uses a counter of its own.

### 2.3 `prevHash` is institution-local

`prevHash` points at the previous chain entry **for the same consent within the same institution's
log**. The first chain entry in each institution's log is 32 zero bytes: the provider's
`CONSENT_CREATED` (`seq=1`), and the receiver's first `RECEIVE_COMPLETED` even when the transmitted
`seq` is 2 or greater. Links across the institution boundary are carried by
`peerEntryHash`/`peerSignature`, not by `prevHash`.

A verifier therefore tests "is this the first chain entry in this log?", not "is `seq` equal to 1?".

### 2.4 Revocation is terminal, and the barrier makes it so

`CONSENT_REVOKED` at `seq=k` closes the chain: creating any event with `seq > k` for that consent is
forbidden, and the provider gateway blocks it. Detecting this violation is the point of the
verification protocol.

On a revocation request the provider gateway performs the **revocation barrier**:

1. immediately block new approvals for that consent,
2. wait for any approved-but-unsettled transfer to settle as `TRANSFER_COMPLETED` or
   `TRANSFER_UNCONFIRMED`,
3. then record `CONSENT_REVOKED`.

This is what guarantees, in an honest system, that the revocation is the consent's last chain event
— the premise of the head check. A receipt arriving after settlement is recorded as **`RECEIPT_LATE`
(non-chain)**, preserving the evidence without polluting the terminator or the head.

### 2.5 Storage contract

Log entries are indexed by `consentId` so that a consent's chain-participating events can be
retrieved in ascending `leafIndex` (log-tree append) order, each with its canonical bytes. This is
the prerequisite for the head–log-tree cross-check (§3.3).

## 3. Merkle contracts

### 3.1 RFC 6962 log tree

- **Leaf preimage**: the same bytes used for the entry hash, i.e. `canonicalize(entry without
  entryHash)`. Therefore `leafHash = sha256(0x00 ‖ preimage)` while
  `entryHash = sha256(preimage)`. `entryHash` is a lookup identifier, never the input to the leaf
  hash. Producers and verifiers must recompute leaf hashes by this same rule.
- **Internal node**: `sha256(0x01 ‖ left ‖ right)`.
- API: `appendLeaf`, `currentRoot()`, `treeSize()`, `inclusionProof(index, treeSize)`,
  `consistencyProof(size1, size2)`, plus stateless verifiers `verifyInclusion`, `verifyConsistency`
  that carry no tree state so browsers and CLIs can share them.

### 3.2 Sparse Merkle Tree

- Depth 256. Key: `hmacSha256(secret, utf8(consentId + ":" + seq))` — the separator is a colon.
- Value: `entryHash`. Empty leaf: 32 zero bytes. Per-level empty-subtree hashes are precomputed.
- **Versioned storage is mandatory.** Nodes are content-addressed (key = node hash, value = child
  hash pair) and copy-on-write: `set()` only adds nodes along the path and never modifies or deletes
  an existing node. Proofs must therefore be derivable from *any* historical `mapRoot` (the `atRoot`
  argument), because verification asks for proofs at every anchor since the revocation. A
  current-state-only SMT violates this contract.
- **Head key.** Each consent has a representative key
  `hmacSha256(secret, utf8(consentId + ":head"))` whose value is the `entryHash` of that consent's
  most recent chain event, updated in the same transaction as the chain event.
  This is the primary check: rather than testing "`k+1` is absent", the verifier tests that at every
  anchor after the revocation the head still equals the revocation's `entryHash`. A seq-skipping
  attacker who writes any chain event at any `seq` moves the head and is detected. The `k+1`
  non-inclusion check runs as a secondary signal.
- **Receiver-derived key**: HKDF-SHA256 over `secret_c`, salt = empty, info = `utf8("receiver")`,
  32-byte output, used as the HMAC key under the same rules. Both institutions must use identical
  parameters for the keys to agree.

### 3.3 Head–log-tree atomicity cross-check

Checking the head value alone does not detect a gateway that appends a chain event to the log tree
while leaving the SMT head unchanged. The verifier therefore also fetches the actual log entry the
head points at and confirms (a) it is `CONSENT_REVOKED` at `seq=k`, and (b) it is the last
chain-participating event for that consent in the log tree. A log tree containing a chain event with
`seq > k` while the head still points at the revocation is an inconsistency.

This cross-check is a required step of the revocation verification and is implemented in
verifier-cli. It is implemented for the provider side; see
[LIMITATIONS.md](LIMITATIONS.md) for the receiver side.

### 3.4 Proof formats

```typescript
interface InclusionProof   { type: "inclusion";   treeSize: number; leafIndex: number; hashes: string[]; }
interface ConsistencyProof { type: "consistency"; firstSize: number; secondSize: number; hashes: string[]; }
interface SmtProof         { type: "smtInclusion" | "smtNonInclusion"; key: string; value: string | null; siblings: string[]; }
```

## 4. On-chain record

One `Anchor` contract instance per institution, owned by that institution's anchoring wallet.

```solidity
struct Anchor {
  uint64  batchId;     // from 1, assigned by the contract
  bytes32 rootHash;    // cumulative log tree root
  uint64  treeSize;    // cumulative leaf count
  bytes32 mapRoot;     // SMT root
  uint64  anchoredAt;  // block.timestamp, assigned by the contract
}

function registerAnchor(bytes32 rootHash, uint64 treeSize, bytes32 mapRoot) external onlyOwner;
function getAnchor(uint64 batchId) external view returns (Anchor memory);
function latestAnchor() external view returns (Anchor memory);
function anchorCount() external view returns (uint64);
event AnchorRegistered(uint64 indexed batchId, bytes32 rootHash, uint64 treeSize, bytes32 mapRoot, uint64 anchoredAt);
```

`registerAnchor` requires `treeSize > lastTreeSize`, which blocks append-only violations. **No
information beyond these six fields is written on-chain** — no image data, patient identifier,
`consentId`, consent secret, individual consent record, DICOM UID, or file hash.

Note that the contract cannot judge whether a root is honest: it only enforces monotonic
`treeSize`. A tampered root registers successfully and is detected off-chain, by a consistency proof
between two anchors read from the chain.

## 5. Gateway API

Patient and verifier endpoints:

- `POST /consents` → `{ consentId, secretC }`; the secret is disclosed only in this response.
- `POST /consents/:id/revoke` → performs the barrier (§2.4), then returns `{ seq, entryHash }`. The
  patient keeps these values. The response can block for up to the receipt timeout.
- `GET /proofs/smt?key=&anchorBatchId=` → inclusion or non-inclusion, chosen automatically.
- `GET /proofs/inclusion?entryHash=&anchorBatchId=`
- `GET /proofs/consistency?fromBatchId=&toBatchId=`
- `GET /consents/:id/chain-entries` → that consent's chain-participating events in ascending
  `leafIndex`, each with `{ leafIndex, entryHash, eventType, seq, canonicalBytes }`.
- `GET /anchors`, `GET /anchors/:batchId` → contract address and batch list.

Institution-to-institution endpoints (mTLS required):

- `POST /transfer/request` → `{ consent reference token, studyRef, requesterEntryHash, requesterSignature }`
- `POST /transfer/receipt` → `{ receiveEntryHash, receiverSignature }`

### 5.1 Handshake order (fixed)

1. **B** records `TRANSFER_REQUESTED` (`seq=null`) and sends its hash with a signature.
2. **A** verifies, records `TRANSFER_APPROVED` (`peerEntryHash` = B's hash, `seq` = next in the
   provider chain), and transmits that `seq` and the derived key to B.
3. **A** transfers the DICOM over mTLS with its approval hash and signature.
4. **B** records `RECEIVE_COMPLETED` (`peerEntryHash` = A's approval hash, `seq` = the transmitted
   value), updates its own SMT under the derived key, and returns a signed receipt.
5. **A** records `TRANSFER_COMPLETED` (`peerEntryHash` = the receipt hash).

On receipt timeout A records `TRANSFER_UNCONFIRMED`. A receipt arriving after settlement — whether
by timeout or by the revocation barrier — is recorded as `RECEIPT_LATE` (non-chain).

## 6. Verifier trust boundary

A verifier — patient or auditor — trusts **no** gateway response on its own. The gateway's role is
limited to supplying proofs, entry preimages, and listings. Trust rests only on:

1. anchor values read directly from the chain over RPC, and
2. the verifier's own recomputation using the pure functions in `packages/merkle`.

Concretely: proofs from `/proofs/*` are re-verified against the `rootHash`/`mapRoot` read from the
chain; every item from `/consents/:id/chain-entries` has its leaf hash recomputed from
`canonicalBytes` and matched against an inclusion proof; the listing's completeness is judged
against the head value and consistency proofs. A gateway that omits or alters an item is exposed by
this cross-verification.

The contract addresses are pinned from a local deployment file, not taken from the untrusted
gateway's `/anchors` response. The verifier never touches the gateway's database or internal state —
only its API and the chain RPC.

## 7. Local environment

- Ports: Orthanc A 8042, Orthanc B 8043, Gateway A 7001, Gateway B 7002, chain 8545 (host,
  loopback-bound).
- Keys and certificates: `scripts/out/ca/`, `scripts/out/inst-a/`, `scripts/out/inst-b/`.
- SQLite: `data/inst-a/audit.db`, `data/inst-b/audit.db`.
- `ANCHOR_INTERVAL_SEC` (default 30) is the anchoring period and an independent variable of the
  evaluation; it is never hard-coded.
- `ANCHOR_MAX_INTERVAL_SEC` (Δ_max, default = `ANCHOR_INTERVAL_SEC`) is the policy ceiling on the
  receiver's anchoring period. The grace window used in receiver-side head verification is defined
  as Δ_max, which keeps it bounded: an actual interval exceeding Δ_max is itself an operational
  violation and surfaces in the consistency-proof-based completeness check.
