// The two verifications a third party can run: non-transfer after revocation, and dispute
// resolution between the two institutions.
//
// Nothing a gateway returns is trusted on its own. A gateway supplies proofs, entry preimages
// and listings; the trust comes from anchor values read straight off the chain and from the pure
// verification functions in the merkle package, which recompute everything locally. That is why,
// for instance, a listing from /consents/:id/chain-entries is never believed: every item is
// re-hashed from its canonical bytes and matched against an inclusion proof, and its
// completeness is cross-checked against the log the anchor commits to.
import type { AuditEntry, ConsistencyProof, EventType, HexString } from "@vadrex/shared";
import { deriveReceiverSecret, Rfc6962LogTree, smtHeadKey, smtLeafKey, verifyConsistency } from "@vadrex/merkle";
import { AnchorReader } from "./anchor.js";
import { type CallCounter, GatewayClient } from "./http.js";
import { VERIFIER_VERDICTS } from "./verdicts.js";
import {
  type ChainAnchor,
  type InclusionResponse,
  type SmtResponse,
  auditEntryFromCanonicalBytes,
  hexToBytes,
  normalizeHash,
  verifyAnchoredInclusion,
  verifyEntrySignatureWithPem,
  verifySmtProofAt
} from "./proofs.js";

const ZERO_HASH = `0x${"00".repeat(32)}` as HexString;

interface AnchorsApiResponse {
  contractAddress: string | null;
}

interface ChainEntriesResponse {
  entries: {
    leafIndex: number;
    entryHash: HexString;
    eventType: string;
    seq: number;
    canonicalBytes: HexString;
  }[];
}

interface AuditEntriesResponse {
  rootHash: HexString;
  treeSize: number;
  entries: {
    leafIndex: number;
    entryHash: HexString;
    eventType: string | null;
    consentId: string | null;
    seq: number | null;
    canonicalBytes: HexString;
  }[];
}

export interface CommonVerifyOptions {
  rpcUrl: string;
  tls?: {
    caPath?: string;
    certPath?: string;
    keyPath?: string;
    insecure?: boolean;
  };
  providerAnchorAddress?: string;
  receiverAnchorAddress?: string;
}

export interface VerifyNonTransferOptions extends CommonVerifyOptions {
  consentId: string;
  secretC: string;
  revocationSeq: number;
  revocationEntryHash: string;
  providerGateway: string;
  receiverGateway: string;
  graceSeconds: number;
}

export interface ResolveDisputeOptions extends CommonVerifyOptions {
  transferRef: string;
  aGateway: string;
  bGateway: string;
  aPublicKeyPem: string;
  bPublicKeyPem: string;
  claim?: "b-denies";
}

export interface VerificationResult {
  ok: boolean;
  status: "success" | "failure" | "waiting";
  lines: string[];
  apiCalls: number;
  rpcCalls: number;
  apiRequestBytes: number;
  apiResponseBytes: number;
}

class VerificationFailure extends Error {
  constructor(readonly step: string, message: string) {
    super(message);
  }
}

function resultFromCounter(
  counter: CallCounter,
  ok: boolean,
  status: VerificationResult["status"],
  lines: string[]
): VerificationResult {
  return {
    ok,
    status,
    lines,
    apiCalls: counter.apiCalls,
    rpcCalls: counter.rpcCalls,
    apiRequestBytes: counter.apiRequestBytes ?? 0,
    apiResponseBytes: counter.apiResponseBytes ?? 0
  };
}

function bytesToHex(bytes: Uint8Array): HexString {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

function assert(condition: unknown, step: string, message: string): asserts condition {
  if (!condition) {
    throw new VerificationFailure(step, message);
  }
}

function requestContext(entry: AuditEntry): Record<string, unknown> {
  if (typeof entry.requestContext !== "object" || entry.requestContext === null || Array.isArray(entry.requestContext)) {
    return {};
  }
  return entry.requestContext as Record<string, unknown>;
}

const CHAIN_EVENT_TYPES = new Set<EventType>([
  "CONSENT_CREATED",
  "TRANSFER_APPROVED",
  "TRANSFER_COMPLETED",
  "RECEIVE_COMPLETED",
  "CONSENT_REVOKED"
]);

async function contractAddressFor(
  gateway: GatewayClient,
  override: string | undefined,
  role: string
): Promise<string> {
  if (override) {
    return override;
  }
  const response = await gateway.get<AnchorsApiResponse>("/anchors");
  if (!response.contractAddress) {
    throw new VerificationFailure(role, `${role} gateway did not report an anchor contract address`);
  }
  return response.contractAddress;
}

function anchorByBatch(anchors: ChainAnchor[], batchId: number): ChainAnchor {
  const anchor = anchors.find((candidate) => candidate.batchId === batchId);
  if (!anchor) {
    throw new Error(`chain anchor batch ${batchId} not found`);
  }
  return anchor;
}

async function fetchAnchors(
  gateway: GatewayClient,
  rpcUrl: string,
  overrideAddress: string | undefined,
  role: string,
  counter: CallCounter
): Promise<{ address: string; reader: AnchorReader; anchors: ChainAnchor[] }> {
  const address = await contractAddressFor(gateway, overrideAddress, role);
  const reader = new AnchorReader(rpcUrl, address, counter);
  const anchors = await reader.anchors();
  return { address, reader, anchors };
}

/**
 * Finds the earliest anchor that already covers an entry, returning the verified proof.
 *
 * The two tolerated errors mean "this anchor predates the entry", which is expected while
 * scanning from the oldest anchor forward. Any other error is a real failure and is raised:
 * treating every error as "not yet anchored" would let a gateway hide an entry by erroring.
 */
async function findAnchoredEntry(
  gateway: GatewayClient,
  anchors: ChainAnchor[],
  entryHash: string
): Promise<{ anchor: ChainAnchor; response: InclusionResponse; entry: AuditEntry } | null> {
  const normalized = normalizeHash(entryHash);
  for (const anchor of anchors) {
    const path = `/proofs/inclusion?entryHash=${encodeURIComponent(normalized)}&anchorBatchId=${anchor.batchId}`;
    const proof = await gateway.tryGet<InclusionResponse>(path);
    if (!proof.ok) {
      if (proof.body.includes("leafIndex ") && proof.body.includes(" outside tree size ")) {
        continue;
      }
      if (proof.statusCode === 400 && proof.body.includes("not found")) {
        continue;
      }
      throw new VerificationFailure("inclusion", `gateway returned HTTP ${proof.statusCode} for ${path}: ${proof.body}`);
    }
    const parsed = verifyAnchoredInclusion(anchor, proof.value);
    if (parsed.entry.entryHash !== normalized) {
      throw new VerificationFailure("inclusion", `proof preimage hashes to ${parsed.entry.entryHash}, expected ${normalized}`);
    }
    return { anchor, response: proof.value, entry: parsed.entry };
  }
  return null;
}

/**
 * Fetches every leaf the anchor commits to and rebuilds the log tree from it.
 *
 * The recomputed root must equal the root read from the chain. That single equality is what makes
 * the returned list trustworthy: a gateway cannot drop, reorder, duplicate or alter an entry
 * without changing the root, so from here on the list can be treated as the complete anchored log.
 */
async function completeAnchoredLog(gateway: GatewayClient, anchor: ChainAnchor): Promise<{ leafIndex: number; entry: AuditEntry }[]> {
  const response = await gateway.get<AuditEntriesResponse>(`/audit-entries?anchorBatchId=${anchor.batchId}`);
  if (normalizeHash(response.rootHash) !== normalizeHash(anchor.rootHash)) {
    throw new VerificationFailure("complete log", `audit-entries root ${response.rootHash} does not match chain root ${anchor.rootHash}`);
  }
  if (response.treeSize !== anchor.treeSize) {
    throw new VerificationFailure("complete log", `audit-entries treeSize ${response.treeSize} does not match chain treeSize ${anchor.treeSize}`);
  }
  if (response.entries.length !== anchor.treeSize) {
    throw new VerificationFailure("complete log", `gateway returned ${response.entries.length}/${anchor.treeSize} audit entries`);
  }

  const entries: { leafIndex: number; entry: AuditEntry }[] = [];
  const seen = new Set<number>();
  const ordered = [...response.entries].sort((left, right) => left.leafIndex - right.leafIndex);
  const tree = new Rfc6962LogTree();
  for (const listed of ordered) {
    if (!Number.isSafeInteger(listed.leafIndex) || listed.leafIndex < 0 || listed.leafIndex >= anchor.treeSize) {
      throw new VerificationFailure("complete log", `invalid leafIndex ${listed.leafIndex}`);
    }
    if (seen.has(listed.leafIndex)) {
      throw new VerificationFailure("complete log", `duplicate leafIndex ${listed.leafIndex}`);
    }
    seen.add(listed.leafIndex);

    const entry = auditEntryFromCanonicalBytes(listed.canonicalBytes);
    if (entry.entryHash !== listed.entryHash) {
      throw new VerificationFailure("complete log", `listed leaf ${listed.leafIndex} hashes to ${entry.entryHash}, expected ${listed.entryHash}`);
    }
    const appendedIndex = tree.appendLeaf(hexToBytes(listed.canonicalBytes));
    if (appendedIndex !== listed.leafIndex) {
      throw new VerificationFailure("complete log", `leafIndex gap before ${listed.leafIndex}`);
    }
    entries.push({ leafIndex: listed.leafIndex, entry });
  }
  if (tree.currentRoot() !== normalizeHash(anchor.rootHash)) {
    throw new VerificationFailure("complete log", `recomputed audit log root ${tree.currentRoot()} does not match chain root ${anchor.rootHash}`);
  }
  return entries;
}

async function anchoredEntryAt(
  gateway: GatewayClient,
  anchor: ChainAnchor,
  entryHash: string
): Promise<AuditEntry> {
  const normalized = normalizeHash(entryHash);
  const response = await gateway.get<InclusionResponse>(
    `/proofs/inclusion?entryHash=${encodeURIComponent(normalized)}&anchorBatchId=${anchor.batchId}`
  );
  const parsed = verifyAnchoredInclusion(anchor, response);
  if (parsed.entry.entryHash !== normalized) {
    throw new VerificationFailure("inclusion", `proof preimage hashes to ${parsed.entry.entryHash}, expected ${normalized}`);
  }
  return parsed.entry;
}

async function verifyConsistencyFrom(
  gateway: GatewayClient,
  anchors: ChainAnchor[],
  fromBatchId: number,
  lines: string[],
  label: string
): Promise<void> {
  for (let batchId = fromBatchId; batchId < anchors.length; batchId += 1) {
    const left = anchorByBatch(anchors, batchId);
    const right = anchorByBatch(anchors, batchId + 1);
    const response = await gateway.get<{ proof: ConsistencyProof }>(
      `/proofs/consistency?fromBatchId=${batchId}&toBatchId=${batchId + 1}`
    );
    assert(
      verifyConsistency(left.rootHash, left.treeSize, right.rootHash, right.treeSize, response.proof),
      `${label} consistency`,
      `consistency proof failed for ${label} batches ${batchId}->${batchId + 1}`
    );
  }
  lines.push(`  ${label} consistency: verified from batch ${fromBatchId} to ${anchors.length}`);
}

async function verifyHeadProof(
  gateway: GatewayClient,
  anchor: ChainAnchor,
  key: string
) {
  const response = await gateway.get<SmtResponse>(
    `/proofs/smt?key=${encodeURIComponent(key)}&anchorBatchId=${anchor.batchId}`
  );
  return verifySmtProofAt(anchor, response);
}

/**
 * The provider-side core of the non-transfer proof, in three layers.
 *
 * 1. head: at every anchor from the revocation onwards, the consent's SMT head key must still
 *    hold the revocation entryHash. Recording any chain event after the revocation moves head,
 *    whatever seq it carries, so this also closes the seq-skipping attack that a k+1 check alone
 *    would miss.
 * 2. k+1: non-inclusion of the key one past the revocation, kept as a secondary check.
 * 3. cross-check: head alone cannot catch a gateway that appends to the log tree but leaves the
 *    SMT head unchanged. So the entry head points at is fetched and shown to be the *last* chain
 *    entry of this consent in the anchored log, and to be CONSENT_REVOKED. The list from
 *    chain-entries is re-derived from the anchored log rather than believed.
 */
async function verifyProviderHeadAndCrossCheck(
  provider: GatewayClient,
  anchors: ChainAnchor[],
  fromBatchId: number,
  consentId: string,
  secretC: string,
  revocationSeq: number,
  revocationEntryHash: HexString,
  lines: string[]
): Promise<void> {
  const headKey = smtHeadKey(secretC, consentId);
  const kPlusOneKey = smtLeafKey(secretC, consentId, revocationSeq + 1);
  for (const anchor of anchors.filter((candidate) => candidate.batchId >= fromBatchId)) {
    const headProof = await verifyHeadProof(provider, anchor, headKey);
    assert(headProof.type === "smtInclusion", "provider head", `provider head is absent at batch ${anchor.batchId}`);
    assert(headProof.value === revocationEntryHash, "provider head", `provider head at batch ${anchor.batchId} is ${headProof.value}, expected ${revocationEntryHash}`);

    const kPlusOneProof = await verifyHeadProof(provider, anchor, kPlusOneKey);
    assert(kPlusOneProof.type === "smtNonInclusion", "provider k+1", `provider k+1 key is present at batch ${anchor.batchId}`);
  }
  lines.push(`  provider head: ${anchors.length - fromBatchId + 1} anchored roots keep head=${revocationEntryHash}`);
  lines.push("  provider k+1: non-inclusion verified as a secondary check");

  const latest = anchors.at(-1);
  assert(latest, "provider cross-check", "provider has no anchors");
  const chain = await provider.get<ChainEntriesResponse>(`/consents/${encodeURIComponent(consentId)}/chain-entries`);
  const fullLog = await completeAnchoredLog(provider, latest);
  const completeChain = fullLog
    .filter((item) => item.entry.consentId === consentId && item.entry.seq !== null && CHAIN_EVENT_TYPES.has(item.entry.eventType))
    .sort((left, right) => left.leafIndex - right.leafIndex);
  assert(completeChain.length > 0, "provider cross-check", "complete provider log contains no chain entries for consent");
  assert(chain.entries.length === completeChain.length, "provider cross-check", `chain-entries returned ${chain.entries.length}, complete log has ${completeChain.length}`);

  let previousHash: string | null = null;
  for (let index = 0; index < completeChain.length; index += 1) {
    const listed = chain.entries[index];
    const completeEntry = completeChain[index].entry;
    assert(listed?.entryHash === completeEntry.entryHash, "provider cross-check", `chain-entries diverges from complete log at position ${index}`);
    const entry = await anchoredEntryAt(provider, latest, listed.entryHash);
    const fromList = auditEntryFromCanonicalBytes(listed.canonicalBytes);
    assert(entry.entryHash === listed.entryHash, "provider cross-check", `listed entry ${listed.entryHash} inclusion preimage mismatch`);
    assert(fromList.entryHash === listed.entryHash, "provider cross-check", `listed canonicalBytes hash to ${fromList.entryHash}, expected ${listed.entryHash}`);
    assert(entry.consentId === consentId, "provider cross-check", `entry ${entry.entryHash} has consentId ${entry.consentId}`);
    assert(entry.eventType === listed.eventType, "provider cross-check", `entry ${entry.entryHash} eventType mismatch`);
    assert(entry.seq === listed.seq, "provider cross-check", `entry ${entry.entryHash} seq mismatch`);
    assert(entry.prevHash === (previousHash ?? ZERO_HASH), "provider cross-check", `entry ${entry.entryHash} prevHash ${entry.prevHash} does not match local chain predecessor`);
    previousHash = entry.entryHash;
    assert(typeof entry.seq === "number" && entry.seq <= revocationSeq, "provider cross-check", `chain entry ${entry.entryHash} has seq>${revocationSeq}`);
  }

  const last = chain.entries.at(-1);
  assert(last?.entryHash === revocationEntryHash, "provider cross-check", `last provider chain entry is ${last?.entryHash}, expected revocation ${revocationEntryHash}`);
  assert(last.eventType === "CONSENT_REVOKED", "provider cross-check", "last provider chain entry is not CONSENT_REVOKED");
  lines.push(`  provider head-log cross-check: ${chain.entries.length} chain entries and ${fullLog.length} anchored leaves reverified; revocation is terminal`);
}

/**
 * The receiver side, which only becomes conclusive after a bounded grace window.
 *
 * The receiver may not have anchored yet when the provider's revocation lands, so anchors older
 * than revocationAnchorTime + grace prove nothing and the result is "waiting" rather than a pass.
 * Across the eligible anchors the receiver head must be monotone: absent throughout, or present
 * with one unchanging value. A head that appears after absence, disappears after inclusion, or
 * changes value is a receive event recorded after the revocation. Where the head is present, the
 * entry it names must be a RECEIVE_COMPLETED of this consent with seq below the revocation.
 */
async function verifyReceiverHead(
  receiver: GatewayClient,
  anchors: ChainAnchor[],
  consentId: string,
  secretC: string,
  revocationSeq: number,
  revocationAnchorTime: number,
  graceSeconds: number,
  lines: string[]
): Promise<"ok" | "waiting"> {
  if (anchors.length === 0) {
    lines.push("  receiver head: waiting for receiver anchors");
    return "waiting";
  }
  if (anchors.length > 1) {
    await verifyConsistencyFrom(receiver, anchors, 1, lines, "receiver");
  }
  const threshold = revocationAnchorTime + graceSeconds;
  const eligible = anchors.filter((anchor) => anchor.anchoredAt >= threshold);
  if (eligible.length === 0) {
    const latest = anchors.at(-1);
    const nextExpected = latest ? latest.anchoredAt + graceSeconds : threshold;
    lines.push(`  receiver head: waiting for an anchor at or after ${threshold} (next expected around ${nextExpected})`);
    return "waiting";
  }

  const receiverSecret = bytesToHex(deriveReceiverSecret(secretC));
  const headKey = smtHeadKey(receiverSecret, consentId);
  let includedValue: string | null = null;
  let baseline: "absent" | "present" | null = null;
  for (const anchor of eligible) {
    const proof = await verifyHeadProof(receiver, anchor, headKey);
    if (proof.type === "smtNonInclusion") {
      if (baseline === null) {
        baseline = "absent";
      }
      assert(baseline === "absent", "receiver head", `receiver head disappears after inclusion by batch ${anchor.batchId}`);
      assert(includedValue === null, "receiver head", `receiver head disappears after inclusion by batch ${anchor.batchId}`);
      continue;
    }
    assert(proof.value !== null, "receiver head", `receiver inclusion at batch ${anchor.batchId} has null value`);
    if (baseline === null) {
      baseline = "present";
    }
    assert(baseline === "present", "receiver head", `receiver head appears after absence at batch ${anchor.batchId}`);
    if (includedValue === null) {
      includedValue = proof.value;
    } else {
      assert(proof.value === includedValue, "receiver head", `receiver head changed at batch ${anchor.batchId}`);
    }
    const entry = await anchoredEntryAt(receiver, anchor, proof.value);
    assert(entry.consentId === consentId, "receiver head", `receiver head entry consentId ${entry.consentId} does not match ${consentId}`);
    assert(entry.eventType === "RECEIVE_COMPLETED", "receiver head", `receiver head entry is ${entry.eventType}, expected RECEIVE_COMPLETED`);
    assert(typeof entry.seq === "number" && entry.seq < revocationSeq, "receiver head", `receiver entry seq ${entry.seq} is not < revocation seq ${revocationSeq}`);
  }
  lines.push(`  receiver head: ${eligible.length} anchors checked after grace=${graceSeconds}s; grace-window residual risk recorded`);
  return "ok";
}

export async function verifyNonTransfer(options: VerifyNonTransferOptions): Promise<VerificationResult> {
  const counter: CallCounter = { apiCalls: 0, rpcCalls: 0, apiRequestBytes: 0, apiResponseBytes: 0 };
  const lines: string[] = [];
  const provider = new GatewayClient(options.providerGateway, options.tls ?? {}, counter, "provider");
  const receiver = new GatewayClient(options.receiverGateway, options.tls ?? {}, counter, "receiver");
  const revocationEntryHash = normalizeHash(options.revocationEntryHash);

  try {
    lines.push("[1/5] Revocation inclusion");
    const providerAnchors = await fetchAnchors(provider, options.rpcUrl, options.providerAnchorAddress, "provider", counter);
    if (providerAnchors.anchors.length === 0) {
      lines.push("  anchor wait: provider has no anchors yet");
      return resultFromCounter(counter, false, "waiting", lines);
    }
    const revoked = await findAnchoredEntry(provider, providerAnchors.anchors, revocationEntryHash);
    if (!revoked) {
      const latest = providerAnchors.anchors.at(-1);
      lines.push(`  anchor wait: revocation entry is not anchored yet; latest provider batch=${latest?.batchId ?? 0}`);
      return resultFromCounter(counter, false, "waiting", lines);
    }
    assert(revoked.entry.eventType === "CONSENT_REVOKED", "revocation inclusion", `entry ${revocationEntryHash} is ${revoked.entry.eventType}, not CONSENT_REVOKED`);
    assert(revoked.entry.consentId === options.consentId, "revocation inclusion", `revocation consentId ${revoked.entry.consentId} does not match ${options.consentId}`);
    assert(revoked.entry.seq === options.revocationSeq, "revocation inclusion", `revocation seq ${revoked.entry.seq} does not match ${options.revocationSeq}`);
    lines.push(`  included at provider batch=${revoked.anchor.batchId}, anchoredAt=${revoked.anchor.anchoredAt}`);

    lines.push("[2/5] Provider anchor consistency");
    await verifyConsistencyFrom(provider, providerAnchors.anchors, revoked.anchor.batchId, lines, "provider");

    lines.push("[3/5] Provider SMT head and log cross-check");
    await verifyProviderHeadAndCrossCheck(
      provider,
      providerAnchors.anchors,
      revoked.anchor.batchId,
      options.consentId,
      options.secretC,
      options.revocationSeq,
      revocationEntryHash,
      lines
    );

    lines.push("[4/5] Receiver head after bounded grace");
    const receiverAnchors = await fetchAnchors(receiver, options.rpcUrl, options.receiverAnchorAddress, "receiver", counter);
    const receiverStatus = await verifyReceiverHead(
      receiver,
      receiverAnchors.anchors,
      options.consentId,
      options.secretC,
      options.revocationSeq,
      revoked.anchor.anchoredAt,
      options.graceSeconds,
      lines
    );
    if (receiverStatus === "waiting") {
      return resultFromCounter(counter, false, "waiting", lines);
    }

    lines.push("[5/5] Final verdict");
    lines.push("  non-transfer after revocation verified");
    return resultFromCounter(counter, true, "success", lines);
  } catch (error) {
    if (error instanceof VerificationFailure) {
      lines.push(`  FAILED at ${error.step}: ${error.message}`);
    } else {
      lines.push(`  FAILED: ${error instanceof Error ? error.message : String(error)}`);
    }
    return resultFromCounter(counter, false, "failure", lines);
  }
}

function chainEntriesFromCompleteLog(fullLog: { leafIndex: number; entry: AuditEntry }[], consentId: string): AuditEntry[] {
  return fullLog
    .filter((item) => item.entry.consentId === consentId && item.entry.seq !== null && CHAIN_EVENT_TYPES.has(item.entry.eventType))
    .sort((left, right) => left.leafIndex - right.leafIndex)
    .map((item) => item.entry);
}

function findEntry(entries: AuditEntry[], eventType: string, predicate: (entry: AuditEntry) => boolean): AuditEntry | null {
  return entries.find((entry) => entry.eventType === eventType && predicate(entry)) ?? null;
}

/**
 * Settles a "we sent it" / "we never received it" dispute from the two institutions' own anchors,
 * with no cross-institutional record on chain.
 *
 * The evidence is the pair of mutual references made during the handshake: A's approval carries
 * B's signature over the request, B's receive entry carries A's signature over the approval, and
 * A's completion carries B's signature over the receipt. Each of those entries must also be
 * anchored by the institution that wrote it. Verifying signatures against pinned public keys is
 * what makes the evidence non-repudiable, and requiring both sides to have anchored is what makes
 * unilateral concealment detectable.
 *
 * Without an anchored completion pair the transfer is simply not established: A's claim is
 * rejected rather than B's denial. That asymmetry is deliberate, since an approval on its own
 * says nothing about whether data reached B.
 */
export async function resolveDispute(options: ResolveDisputeOptions): Promise<VerificationResult> {
  const counter: CallCounter = { apiCalls: 0, rpcCalls: 0, apiRequestBytes: 0, apiResponseBytes: 0 };
  const lines: string[] = [];
  const gatewayA = new GatewayClient(options.aGateway, options.tls ?? {}, counter, "A");
  const gatewayB = new GatewayClient(options.bGateway, options.tls ?? {}, counter, "B");
  const transferRef = normalizeHash(options.transferRef);

  try {
    lines.push("[1/4] Collect anchored approval evidence");
    const anchorsA = await fetchAnchors(gatewayA, options.rpcUrl, options.providerAnchorAddress, "A", counter);
    const anchorsB = await fetchAnchors(gatewayB, options.rpcUrl, options.receiverAnchorAddress, "B", counter);
    const approved = await findAnchoredEntry(gatewayA, anchorsA.anchors, transferRef);
    assert(approved !== null, "approval", `A approval ${transferRef} is not anchored`);
    assert(approved.entry.eventType === "TRANSFER_APPROVED", "approval", `transfer-ref is ${approved.entry.eventType}, expected TRANSFER_APPROVED`);
    assert(typeof approved.entry.consentId === "string", "approval", "approval has no consentId");
    lines.push(`  approval anchored at A batch=${approved.anchor.batchId}`);

    lines.push("[2/4] Verify anchor continuity and public keys");
    if (approved.anchor.batchId < anchorsA.anchors.length) {
      await verifyConsistencyFrom(gatewayA, anchorsA.anchors, approved.anchor.batchId, lines, "A");
    }
    if (anchorsB.anchors.length > 1) {
      await verifyConsistencyFrom(gatewayB, anchorsB.anchors, 1, lines, "B");
    }
    const keyA = options.aPublicKeyPem;
    const keyB = options.bPublicKeyPem;

    const requesterHash = approved.entry.peerEntryHash;
    const requesterSignature = approved.entry.peerSignature;
    assert(requesterHash && requesterSignature, "approval signature", "approval lacks B requester peer reference");
    assert(
      verifyEntrySignatureWithPem(requesterHash, requesterSignature, keyB),
      "approval signature",
      "B requester signature on approval peer hash is invalid"
    );
    lines.push("  approval carries a valid B requester signature");

    lines.push("[3/4] Verify receive/completion cross references");
    const consentId = approved.entry.consentId;
    const latestA = anchorsA.anchors.at(-1);
    const latestB = anchorsB.anchors.at(-1);
    assert(latestA, "complete A log", "A has no anchors");
    assert(latestB, "complete B log", "B has no anchors");
    const chainA = chainEntriesFromCompleteLog(await completeAnchoredLog(gatewayA, latestA), consentId);
    const chainB = chainEntriesFromCompleteLog(await completeAnchoredLog(gatewayB, latestB), consentId);
    const receive = findEntry(chainB, "RECEIVE_COMPLETED", (entry) => entry.peerEntryHash === approved.entry.entryHash);
    let receiveAnchored = false;
    if (receive) {
      const receiveProof = await findAnchoredEntry(gatewayB, anchorsB.anchors, receive.entryHash);
      assert(receiveProof !== null, "receive inclusion", `B RECEIVE_COMPLETED ${receive.entryHash} is not anchored`);
      assert(
        receive.peerSignature && verifyEntrySignatureWithPem(approved.entry.entryHash, receive.peerSignature, keyA),
        "receive signature",
        "A approval signature on B receive entry is invalid"
      );
      receiveAnchored = true;
      lines.push(`  B receive anchored at batch=${receiveProof.anchor.batchId}`);
    } else {
      lines.push("  B receive entry not provided by B chain-entries");
    }

    const completed = findEntry(chainA, "TRANSFER_COMPLETED", (entry) => {
      const context = requestContext(entry);
      return context.approvalEntryHash === approved.entry.entryHash || (receive ? entry.peerEntryHash === receive.entryHash : false);
    });
    if (!completed || !receive) {
      lines.push("[4/4] Final verdict");
      lines.push(`  ${VERIFIER_VERDICTS.aClaimNotEstablished}`);
      return resultFromCounter(counter, false, "failure", lines);
    }
    const completedProof = await findAnchoredEntry(gatewayA, anchorsA.anchors, completed.entryHash);
    assert(completedProof !== null, "completion inclusion", `A completion ${completed.entryHash} is not anchored`);
    assert(completed.peerEntryHash, "completion", "A completion lacks B receipt hash");
    assert(completed.peerEntryHash === receive.entryHash, "completion", "A completion does not point to B RECEIVE_COMPLETED");
    assert(completed.peerSignature, "completion", "A completion lacks B receipt signature");
    assert(
      verifyEntrySignatureWithPem(completed.peerEntryHash, completed.peerSignature, keyB),
      "completion signature",
      "B receipt signature on A completion is invalid"
    );
    lines.push(`  A completion anchored at batch=${completedProof.anchor.batchId}`);

    lines.push("[4/4] Final verdict");
    if (options.claim === "b-denies") {
      lines.push(`  ${VERIFIER_VERDICTS.bDenialRejected}: A holds anchored B-signed receipt evidence`);
      return resultFromCounter(counter, true, "success", lines);
    }
    if (receiveAnchored) {
      lines.push("  transfer completed: both sides have anchored evidence");
      return resultFromCounter(counter, true, "success", lines);
    }
    lines.push(`  ${VERIFIER_VERDICTS.bDenialRejected}: A holds anchored B-signed receipt evidence`);
    return resultFromCounter(counter, true, "success", lines);
  } catch (error) {
    if (error instanceof VerificationFailure) {
      lines.push(`  log inconsistency detected: ${error.step}: ${error.message}`);
    } else {
      lines.push(`  log inconsistency detected: ${error instanceof Error ? error.message : String(error)}`);
    }
    return resultFromCounter(counter, false, "failure", lines);
  }
}
