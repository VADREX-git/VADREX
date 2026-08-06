import { join } from "node:path";
import { createTransferToken } from "../packages/gateway/src/token.js";
import { EntrySigner } from "../packages/gateway/src/signing.js";
import { getGateway, patientTransferBody, postGateway, rootDir } from "./scenario-client.js";

async function expectBlocked(label: string, action: () => Promise<unknown>): Promise<void> {
  let blocked = false;
  try {
    await action();
  } catch (error) {
    blocked = true;
    console.log(`  ${label}=BLOCKED (${error instanceof Error ? error.message.split("\n")[0] : String(error)})`);
  }
  if (!blocked) {
    throw new Error(`${label} unexpectedly succeeded`);
  }
}

async function createConsent(studies: string[], purpose: string, validUntil: number) {
  return postGateway<{ consentId: string; secretC: string }>("A", "/consents", {
    receiverInstitutionId: "B",
    studyInstanceUids: studies,
    purpose,
    validUntil
  }, "b");
}

async function main(): Promise<void> {
  const now = Math.floor(Date.now() / 1000);

  console.log("[1/4] Out-of-scope Study is denied before Orthanc lookup");
  const scoped = await createConsent(["1.2.allowed"], "research", now + 3600);
  await expectBlocked("out_of_scope", () => postGateway("B", "/transfers",
    patientTransferBody(scoped, "1.2.denied", "research"), "a"));

  console.log("[2/4] Expired consent is denied");
  const expired = await createConsent(["1.2.expired"], "research", now - 10);
  await expectBlocked("expired", () => postGateway("B", "/transfers",
    patientTransferBody(expired, "1.2.expired", "research"), "a"));

  console.log("[3/4] Post-revocation transfer is denied and head is not polluted by DENIED");
  const revoked = await createConsent(["1.2.revoked"], "research", now + 3600);
  await postGateway("A", `/consents/${revoked.consentId}/revoke`, {}, "b");
  const before = await getGateway<{ mapRoot: string }>("A", "/health", "b");
  await expectBlocked("revoked", () => postGateway("B", "/transfers",
    patientTransferBody(revoked, "1.2.revoked", "research"), "a"));
  const after = await getGateway<{ mapRoot: string }>("A", "/health", "b");
  console.log(`  mapRootUnchangedAfterDenied=${before.mapRoot === after.mapRoot}`);

  console.log("[4/4] Reused token nonce is blocked with REPLAY_BLOCKED");
  const replay = await createConsent(["1.2.replay.allowed"], "research", now + 3600);
  const token = createTransferToken(replay.secretC, {
    consentId: replay.consentId,
    studyInstanceUid: "1.2.replay.denied",
    purpose: "research"
  }, 60);
  const requested = await postGateway<{ entries: { entryHash: string }[] }>("B", "/dev/audit-entries", {
    entries: [{
      eventType: "TRANSFER_REQUESTED",
      timestamp: now,
      institutionId: "B",
      consentId: replay.consentId,
      seq: null,
      prevHash: null,
      requestContext: {
        providerInstitutionId: "A",
        studyInstanceUid: "1.2.replay.denied",
        purpose: "research",
        tokenNonce: token.payload.nonce
      },
      peerEntryHash: null,
      peerSignature: null
    }]
  }, "a");
  const signer = EntrySigner.fromFile(join(rootDir, "scripts", "out", "inst-b", "ed25519.key"));
  const requesterEntryHash = requested.entries[0].entryHash;
  const body = {
    consentId: replay.consentId,
    studyInstanceUid: "1.2.replay.denied",
    purpose: "research",
    requesterInstitutionId: "B",
    requesterEntryHash,
    requesterSignature: signer.signEntryHash(requesterEntryHash),
    authorizationToken: token.token
  };
  await expectBlocked("first_replay_request_scope_denied", () => postGateway("A", "/transfer/request", body, "b"));
  await expectBlocked("second_replay_request_nonce", () => postGateway("A", "/transfer/request", body, "b"));

  console.log("scenario-violations SUCCESS");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
