import { patientTransferBody, postGateway, resolveStudyUid } from "./scenario-client.js";

interface CreatedConsent {
  consentId: string;
  secretC: string;
}

async function createConsent(studyInstanceUid: string, purpose: string): Promise<CreatedConsent> {
  return postGateway<CreatedConsent>("A", "/consents", {
    receiverInstitutionId: "B",
    studyInstanceUids: [studyInstanceUid],
    purpose,
    validUntil: Math.floor(Date.now() / 1000) + 3600
  }, "b");
}

async function main(): Promise<void> {
  const studyInstanceUid = await resolveStudyUid();
  const purpose = process.env.SCENARIO_PURPOSE ?? "research";
  console.log(`  studyInstanceUid=${studyInstanceUid}`);

  console.log("[1/4] Create consent");
  const consent = await createConsent(studyInstanceUid, purpose);

  console.log("[2/4] Start transfer expected to timeout");
  const transfer = await postGateway<{ status: string }>("B", "/transfers",
    patientTransferBody(consent, studyInstanceUid, purpose), "a");
  console.log(`  transferStatus=${transfer.status}`);
  if (transfer.status !== "UNCONFIRMED") {
    throw new Error(
      `expected UNCONFIRMED, got ${transfer.status}; start compose with SIMULATED_RECEIPT_DELAY_MS greater than RECEIPT_TIMEOUT_SEC * 1000`
    );
  }

  console.log("[3/4] Verify the peer hold flag blocks the next approval");
  const second = await createConsent(studyInstanceUid, purpose);
  let heldMessage: string | null = null;
  try {
    await postGateway("B", "/transfers", patientTransferBody(second, studyInstanceUid, purpose), "a");
  } catch (error) {
    heldMessage = error instanceof Error ? error.message : String(error);
  }
  if (!heldMessage || !heldMessage.includes("held")) {
    throw new Error(`expected the follow-up approval to be blocked by the peer hold, got: ${heldMessage ?? "success"}`);
  }
  console.log(`  followUpBlocked=true (${heldMessage.split("\n")[0]})`);

  console.log("[4/4] Release the peer hold so later scenarios are not blocked");
  const released = await postGateway<{ released: boolean }>("A", "/dev/release-peer-hold", { peerInstitutionId: "B" }, "b");
  console.log(`  released=${released.released}`);
  console.log("  Note: the delayed receipt will still arrive later and be preserved as non-chain RECEIPT_LATE.");

  console.log("demo-timeout SUCCESS");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
