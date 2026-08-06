import type { SmtProof } from "@vadrex/shared";
import { smtHeadKey, verifySmtInclusion } from "@vadrex/merkle";
import { getGateway, patientTransferBody, postGateway, resolveStudyUid } from "./scenario-client.js";

interface CreatedConsent {
  consentId: string;
  secretC: string;
}

interface ChainResponse {
  entries: { eventType: string; seq: number; entryHash: string }[];
}

interface SmtProofResponse {
  mapRoot: string;
  proof: SmtProof;
}

interface HealthResponse {
  treeSize: number;
  mapRoot: string;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function createConsent(studyInstanceUid: string, purpose: string): Promise<CreatedConsent> {
  return postGateway<CreatedConsent>("A", "/consents", {
    receiverInstitutionId: "B",
    studyInstanceUids: [studyInstanceUid],
    purpose,
    validUntil: Math.floor(Date.now() / 1000) + 3600
  }, "b");
}

async function chainOf(consentId: string): Promise<ChainResponse> {
  return getGateway<ChainResponse>("A", `/consents/${consentId}/chain-entries`, "b");
}

async function waitForApproval(consentId: string): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const chain = await chainOf(consentId);
    if (chain.entries.some((entry) => entry.eventType === "TRANSFER_APPROVED")) {
      return;
    }
    await sleep(25);
  }
  throw new Error("TRANSFER_APPROVED was not recorded in time");
}

// The head check uses an inclusion proof for the SMT head key, not the last item of
// chain-entries, and verifies it with the pure functions from the merkle package.
async function assertHeadIsRevocation(consent: CreatedConsent, revokedEntryHash: string, label: string): Promise<void> {
  const key = smtHeadKey(consent.secretC, consent.consentId);
  const response = await getGateway<SmtProofResponse>("A", `/proofs/smt?key=${encodeURIComponent(key)}`, "b");
  if (response.proof.type !== "smtInclusion" || response.proof.value !== revokedEntryHash) {
    throw new Error(`${label}: SMT head value ${response.proof.value} is not the revocation entryHash ${revokedEntryHash}`);
  }
  if (!verifySmtInclusion(response.mapRoot, response.proof)) {
    throw new Error(`${label}: SMT head inclusion proof failed verification`);
  }
  console.log(`  ${label}: head=${revokedEntryHash} (SMT inclusion verified)`);
}

async function runSettlementVariant(studyInstanceUid: string, purpose: string): Promise<void> {
  const consent = await createConsent(studyInstanceUid, purpose);
  const transferPromise = postGateway<{ status: string }>("B", "/transfers",
    patientTransferBody(consent, studyInstanceUid, purpose), "a");
  await waitForApproval(consent.consentId);
  const revokePromise = postGateway<{ seq: number; entryHash: string }>("A", `/consents/${consent.consentId}/revoke`, {}, "b");

  const transfer = await transferPromise;
  const revoked = await revokePromise;
  const chain = await chainOf(consent.consentId);
  const events = chain.entries.map((entry) => `${entry.eventType}:${entry.seq}`);
  console.log(`  case-1: transfer=${transfer.status}, revokeSeq=${revoked.seq}`);
  console.log(`  case-1: chain=${events.join(" -> ")}`);
  if (transfer.status !== "COMPLETED") {
    throw new Error(`case-1: expected COMPLETED settlement before revocation, got ${transfer.status}`);
  }
  const types = chain.entries.map((entry) => entry.eventType);
  const expected = ["CONSENT_CREATED", "TRANSFER_APPROVED", "TRANSFER_COMPLETED", "CONSENT_REVOKED"];
  if (types.join(",") !== expected.join(",")) {
    throw new Error(`case-1: chain order is ${types.join(",")}, expected ${expected.join(",")}`);
  }
  const last = chain.entries.at(-1);
  if (last?.entryHash !== revoked.entryHash) {
    throw new Error("case-1: REVOKED is not the terminal chain event");
  }
  await assertHeadIsRevocation(consent, revoked.entryHash, "case-1");
}

async function runReceiptTimeoutVariant(studyInstanceUid: string, purpose: string): Promise<void> {
  const consent = await createConsent(studyInstanceUid, purpose);
  const transferPromise = postGateway<{ status: string }>("B", "/transfers",
    patientTransferBody(consent, studyInstanceUid, purpose), "a");
  await waitForApproval(consent.consentId);
  const revokePromise = postGateway<{ seq: number; entryHash: string }>("A", `/consents/${consent.consentId}/revoke`, {}, "b");

  const transfer = await transferPromise;
  const revoked = await revokePromise;
  if (transfer.status !== "UNCONFIRMED") {
    throw new Error(
      `case-2: expected UNCONFIRMED settlement, got ${transfer.status}; start compose with SIMULATED_RECEIPT_DELAY_MS greater than RECEIPT_TIMEOUT_SEC * 1000`
    );
  }
  const chain = await chainOf(consent.consentId);
  const types = chain.entries.map((entry) => entry.eventType);
  const expected = ["CONSENT_CREATED", "TRANSFER_APPROVED", "CONSENT_REVOKED"];
  if (types.join(",") !== expected.join(",")) {
    throw new Error(`case-2: chain order is ${types.join(",")}, expected ${expected.join(",")} (UNCONFIRMED is non-chain)`);
  }
  console.log(`  case-2: transfer=${transfer.status}, chain=${types.join(" -> ")}`);
  await assertHeadIsRevocation(consent, revoked.entryHash, "case-2");

  console.log("  case-2: waiting for the delayed receipt to arrive as non-chain RECEIPT_LATE...");
  const before = await getGateway<HealthResponse>("A", "/health", "b");
  const waitLimitMs = Number(process.env.SCENARIO_LATE_RECEIPT_WAIT_MS ?? 120_000);
  const deadline = Date.now() + waitLimitMs;
  let after = before;
  while (after.treeSize <= before.treeSize && Date.now() < deadline) {
    await sleep(500);
    after = await getGateway<HealthResponse>("A", "/health", "b");
  }
  if (after.treeSize <= before.treeSize) {
    throw new Error("case-2: late receipt did not arrive within the wait limit");
  }
  if (after.mapRoot !== before.mapRoot) {
    throw new Error("case-2: mapRoot changed after the late receipt — it must be recorded as non-chain");
  }
  const chainAfter = await chainOf(consent.consentId);
  if (chainAfter.entries.map((entry) => entry.eventType).join(",") !== expected.join(",")) {
    throw new Error("case-2: chain changed after the late receipt");
  }
  await assertHeadIsRevocation(consent, revoked.entryHash, "case-2 (after late receipt)");
  console.log("  case-2: late receipt appended to the log tree only (RECEIPT_LATE), head unchanged");

  const released = await postGateway<{ released: boolean }>("A", "/dev/release-peer-hold", { peerInstitutionId: "B" }, "b");
  console.log(`  case-2: peer hold released=${released.released}`);
}

async function main(): Promise<void> {
  const studyInstanceUid = await resolveStudyUid();
  const purpose = process.env.SCENARIO_PURPOSE ?? "research";
  console.log(`  studyInstanceUid=${studyInstanceUid}`);

  if (process.env.SCENARIO_BARRIER_VARIANT === "receipt-timeout") {
    console.log("[1/1] Barrier case 2: receipt blocked, then revoke, then late receipt");
    await runReceiptTimeoutVariant(studyInstanceUid, purpose);
  } else {
    console.log("[1/1] Barrier case 1: revoke while an approved transfer settles as COMPLETED");
    await runSettlementVariant(studyInstanceUid, purpose);
    console.log("  Run case 2 with SCENARIO_BARRIER_VARIANT=receipt-timeout after restarting compose");
    console.log("  with SIMULATED_RECEIPT_DELAY_MS > RECEIPT_TIMEOUT_SEC * 1000 (e.g. RECEIPT_TIMEOUT_SEC=5, SIMULATED_RECEIPT_DELAY_MS=10000).");
  }

  console.log("scenario-barrier SUCCESS");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
