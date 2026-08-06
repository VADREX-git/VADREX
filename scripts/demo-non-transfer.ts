import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { HexString } from "@vadrex/shared";
import { smtHeadKey, smtLeafKey, verifySmtInclusion, verifySmtNonInclusion } from "@vadrex/merkle";
import { AuditAggregator, type CreatedConsent, type RevokedConsent, type AnchorHistoryRecord } from "../packages/gateway/src/aggregator.js";
import { injectViolationIntoAggregator } from "./inject-violation.js";

interface Scenario {
  dir: string;
  aggregator: AuditAggregator;
  consent: CreatedConsent;
  revoked: RevokedConsent;
  revokeAnchor: AnchorHistoryRecord;
  nextBatchId: number;
}

function anchor(aggregator: AuditAggregator, batchId: number): AnchorHistoryRecord {
  const record = {
    batchId,
    rootHash: aggregator.currentRoot(),
    treeSize: aggregator.treeSize(),
    mapRoot: aggregator.mapRoot(),
    txHash: `local-demo-${batchId}`
  } satisfies AnchorHistoryRecord;
  aggregator.recordAnchor(record);
  return record;
}

function setupScenario(label: string): Scenario {
  const dir = mkdtempSync(join(tmpdir(), `vadrex-non-transfer-${label}-`));
  const aggregator = new AuditAggregator(join(dir, "audit.db"));
  const consent = aggregator.createConsent({
    receiverInstitutionId: "B",
    studyInstanceUids: ["1.2.840.10008.5.1.4.1.1.2"],
    purpose: "research-demo",
    validUntil: 1_900_000_000
  });
  aggregator.appendDemoChainEvent(consent.consentId, "TRANSFER_APPROVED", { demoEvent: 1 });
  aggregator.appendDemoChainEvent(consent.consentId, "TRANSFER_COMPLETED", { demoEvent: 2 });
  const revoked = aggregator.revokeConsent(consent.consentId);
  const revokeAnchor = anchor(aggregator, 1);
  return { dir, aggregator, consent, revoked, revokeAnchor, nextBatchId: 2 };
}

function cleanup(scenario: Scenario): void {
  scenario.aggregator.close();
  rmSync(scenario.dir, { recursive: true, force: true });
}

function verifyHeadAt(
  aggregator: AuditAggregator,
  consent: CreatedConsent,
  mapRoot: HexString,
  expectedEntryHash: HexString
): boolean {
  const proof = aggregator.smtInclusionProof(smtHeadKey(consent.secretC, consent.consentId), mapRoot);
  return proof.value === expectedEntryHash && verifySmtInclusion(mapRoot, proof);
}

function verifyKPlusOneAbsent(
  aggregator: AuditAggregator,
  consent: CreatedConsent,
  revoked: RevokedConsent,
  mapRoot: HexString
): boolean {
  const proof = aggregator.smtNonInclusionProof(smtLeafKey(consent.secretC, consent.consentId, revoked.seq + 1), mapRoot);
  return verifySmtNonInclusion(mapRoot, proof);
}

function normalDemo(): void {
  const scenario = setupScenario("normal");
  try {
    console.log("[1/4] Honest path: create consent -> two chain events -> revoke -> anchor");
    console.log(`  consentId=${scenario.consent.consentId}`);
    console.log(`  revokedSeq=${scenario.revoked.seq}, revokedEntryHash=${scenario.revoked.entryHash}`);
    console.log(`  anchor batch=${scenario.revokeAnchor.batchId}, treeSize=${scenario.revokeAnchor.treeSize}, mapRoot=${scenario.revokeAnchor.mapRoot}`);

    const headOk = verifyHeadAt(
      scenario.aggregator,
      scenario.consent,
      scenario.revokeAnchor.mapRoot,
      scenario.revoked.entryHash
    );
    const kPlusOneOk = verifyKPlusOneAbsent(
      scenario.aggregator,
      scenario.consent,
      scenario.revoked,
      scenario.revokeAnchor.mapRoot
    );
    console.log(`  head inclusion at revoke anchor = ${headOk ? "SUCCESS" : "FAIL"}`);
    console.log(`  k+1 non-inclusion at revoke anchor = ${kPlusOneOk ? "SUCCESS" : "FAIL"}`);

    scenario.aggregator.createConsent({
      receiverInstitutionId: "B",
      studyInstanceUids: ["9.9.9"],
      purpose: "unrelated",
      validUntil: 1_900_000_000
    });
    console.log(`  after unrelated consent mapRoot=${scenario.aggregator.mapRoot()}`);
    console.log(`  historical revoke-anchor head verification still = ${
      verifyHeadAt(scenario.aggregator, scenario.consent, scenario.revokeAnchor.mapRoot, scenario.revoked.entryHash)
        ? "SUCCESS"
        : "FAIL"
    }`);
  } finally {
    cleanup(scenario);
  }
}

function headViolationDemo(seqOffset: number, stepLabel: string): void {
  const scenario = setupScenario(`seq-${seqOffset}`);
  try {
    const injectedSeq = scenario.revoked.seq + seqOffset;
    console.log(`[${stepLabel}/4] Inject violation: seq=${injectedSeq} (${seqOffset === 1 ? "k+1" : "skipped seq"})`);
    const injected = injectViolationIntoAggregator(scenario.aggregator, {
      consentId: scenario.consent.consentId,
      seq: injectedSeq,
      noHeadUpdate: false
    });
    const violationAnchor = anchor(scenario.aggregator, scenario.nextBatchId);
    const headProof = scenario.aggregator.smtInclusionProof(
      smtHeadKey(scenario.consent.secretC, scenario.consent.consentId),
      violationAnchor.mapRoot
    );
    const headDetected = headProof.value !== scenario.revoked.entryHash;
    console.log(`  injectedEntryHash=${injected.entryHash}`);
    console.log(`  anchored head value=${headProof.value}`);
    console.log(`  head check result=${headDetected ? "DETECTED" : "UNEXPECTED PASS"}`);

    const kPlusOneKey = smtLeafKey(scenario.consent.secretC, scenario.consent.consentId, scenario.revoked.seq + 1);
    let kPlusOneOnlyDetected = false;
    try {
      const proof = scenario.aggregator.smtNonInclusionProof(kPlusOneKey, violationAnchor.mapRoot);
      kPlusOneOnlyDetected = !verifySmtNonInclusion(violationAnchor.mapRoot, proof);
    } catch {
      kPlusOneOnlyDetected = true;
    }
    console.log(`  k+1-only check=${kPlusOneOnlyDetected ? "DETECTED" : "MISSED"}${
      seqOffset === 7 ? " (a skipped seq is caught only by the head check)" : ""
    }`);
  } finally {
    cleanup(scenario);
  }
}

// Case B passes the head value check on its own, because head still points at the revocation
// entryHash. Catching it needs the head-to-log-tree cross-check: whether the log tree holds a
// chain event for the same consentId *after* the entry head points at.
function headLogCrossCheckDemo(): void {
  const scenario = setupScenario("no-head");
  try {
    console.log("[4/4] Case B: appended to the log tree, SMT head left unchanged");
    injectViolationIntoAggregator(scenario.aggregator, {
      consentId: scenario.consent.consentId,
      seq: scenario.revoked.seq + 1,
      noHeadUpdate: true
    });
    const violationAnchor = anchor(scenario.aggregator, scenario.nextBatchId);
    const headOnlyPasses = verifyHeadAt(
      scenario.aggregator,
      scenario.consent,
      violationAnchor.mapRoot,
      scenario.revoked.entryHash
    );
    const chainEntries = scenario.aggregator.chainEntries(scenario.consent.consentId);
    const lastEntry = chainEntries.at(-1);
    const crossCheckDetected = lastEntry?.entryHash !== scenario.revoked.entryHash;
    console.log(`  head-only check=${headOnlyPasses ? "PASS" : "FAIL"}`);
    console.log(`  chain last entry=${lastEntry?.eventType}/seq=${lastEntry?.seq}/entryHash=${lastEntry?.entryHash}`);
    console.log(`  head-log cross-check=${crossCheckDetected ? "DETECTED" : "UNEXPECTED PASS"}`);
  } finally {
    cleanup(scenario);
  }
}

function main(): void {
  normalDemo();
  headViolationDemo(1, "2");
  headViolationDemo(7, "3");
  headLogCrossCheckDemo();
}

try {
  main();
} catch (error) {
  console.error(error);
  process.exitCode = 1;
}
