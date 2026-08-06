import { join } from "node:path";
import { requestBuffer } from "../packages/gateway/src/httpClient.js";
import { EntrySigner, verifyEntrySignature } from "../packages/gateway/src/signing.js";
import { getGateway, patientTransferBody, postGateway, resolveStudyUid, rootDir, tlsForClient } from "./scenario-client.js";

interface CreatedConsent {
  consentId: string;
  secretC: string;
}

interface ChainResponse {
  entries: { eventType: string; seq: number; entryHash: string; canonicalBytes: string }[];
}

interface AnchorResponse {
  anchors: unknown[];
}

interface TransferResponse {
  status: string;
}

function canonicalEntry(entry: { canonicalBytes: string }): Record<string, unknown> {
  return JSON.parse(Buffer.from(entry.canonicalBytes.slice(2), "hex").toString("utf8")) as Record<string, unknown>;
}

function requireEntry(chain: ChainResponse, eventType: string): ChainResponse["entries"][number] {
  const entry = chain.entries.find((candidate) => candidate.eventType === eventType);
  if (!entry) {
    throw new Error(`missing ${eventType}`);
  }
  return entry;
}

async function assertStudyStoredInOrthancB(studyInstanceUid: string): Promise<void> {
  const orthancBUrl = (process.env.ORTHANC_B_URL ?? "https://localhost:8043").replace(/\/$/, "");
  const query = new URLSearchParams({ StudyInstanceUID: studyInstanceUid });
  const response = await requestBuffer(`${orthancBUrl}/dicom-web/studies?${query.toString()}`, {
    tls: tlsForClient("a"),
    headers: { accept: "application/dicom+json" },
    timeoutMs: 30_000
  });
  const text = response.body.toString("utf8");
  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw new Error(`Orthanc B QIDO returned HTTP ${response.statusCode}: ${text}`);
  }
  const studies = JSON.parse(text) as unknown[];
  if (!Array.isArray(studies) || studies.length === 0) {
    throw new Error("Orthanc B does not contain the transferred Study");
  }
}

async function main(): Promise<void> {
  const studyInstanceUid = await resolveStudyUid();
  const purpose = process.env.SCENARIO_PURPOSE ?? "research";
  console.log(`  studyInstanceUid=${studyInstanceUid}`);

  console.log("[1/6] Create consent at gateway A");
  const consent = await postGateway<CreatedConsent>("A", "/consents", {
    receiverInstitutionId: "B",
    studyInstanceUids: [studyInstanceUid],
    purpose,
    validUntil: Math.floor(Date.now() / 1000) + 3600
  }, "b");
  console.log(`  consentId=${consent.consentId}`);

  console.log("[2/6] Start B -> A transfer");
  const transfer = await postGateway<TransferResponse>("B", "/transfers",
    patientTransferBody(consent, studyInstanceUid, purpose), "a");
  console.log(`  transferStatus=${transfer.status}`);
  if (transfer.status !== "COMPLETED") {
    throw new Error("normal scenario expected COMPLETED; check that the Study is loaded in Orthanc A");
  }

  console.log("[3/6] Check chain entries and cross signatures");
  const chainA = await getGateway<ChainResponse>("A", `/consents/${consent.consentId}/chain-entries`, "b");
  const chainB = await getGateway<ChainResponse>("B", `/consents/${consent.consentId}/chain-entries`, "a");
  console.log(`  A=${chainA.entries.map((entry) => `${entry.eventType}:${entry.seq}`).join(" -> ")}`);
  console.log(`  B=${chainB.entries.map((entry) => `${entry.eventType}:${entry.seq}`).join(" -> ")}`);
  const approved = requireEntry(chainA, "TRANSFER_APPROVED");
  const completed = requireEntry(chainA, "TRANSFER_COMPLETED");
  const received = requireEntry(chainB, "RECEIVE_COMPLETED");
  const approvedEntry = canonicalEntry(approved);
  const completedEntry = canonicalEntry(completed);
  const receivedEntry = canonicalEntry(received);
  const signerA = EntrySigner.fromFile(join(rootDir, "scripts", "out", "inst-a", "ed25519.key"));
  const signerB = EntrySigner.fromFile(join(rootDir, "scripts", "out", "inst-b", "ed25519.key"));
  if (!verifyEntrySignature(approvedEntry.peerEntryHash as string, approvedEntry.peerSignature as string, signerB.publicKey)) {
    throw new Error("TRANSFER_APPROVED does not contain B's valid requester signature");
  }
  if (receivedEntry.peerEntryHash !== approved.entryHash) {
    throw new Error("RECEIVE_COMPLETED does not point to TRANSFER_APPROVED");
  }
  if (!verifyEntrySignature(approved.entryHash, receivedEntry.peerSignature as string, signerA.publicKey)) {
    throw new Error("RECEIVE_COMPLETED does not contain A's valid approval signature");
  }
  if (completedEntry.peerEntryHash !== received.entryHash) {
    throw new Error("TRANSFER_COMPLETED does not point to RECEIVE_COMPLETED");
  }
  if (!verifyEntrySignature(received.entryHash, completedEntry.peerSignature as string, signerB.publicKey)) {
    throw new Error("TRANSFER_COMPLETED does not contain B's valid receipt signature");
  }

  console.log("[4/6] Check Orthanc B storage");
  await assertStudyStoredInOrthancB(studyInstanceUid);
  console.log("  orthancBStored=true");

  console.log("[5/6] Anchor both gateways");
  await postGateway("A", "/dev/anchor-now", {}, "b");
  await postGateway("B", "/dev/anchor-now", {}, "a");
  const anchorsA = await getGateway<AnchorResponse>("A", "/anchors", "b");
  const anchorsB = await getGateway<AnchorResponse>("B", "/anchors", "a");
  console.log(`  anchorsA=${anchorsA.anchors.length}, anchorsB=${anchorsB.anchors.length}`);

  console.log("[6/6] scenario-normal SUCCESS");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
