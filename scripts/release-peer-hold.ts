// Releases the peer hold provider A places after an unsettled transfer.
//
// Once a transfer settles as TRANSFER_UNCONFIRMED, A stops approving new transfers to that peer.
// A hold left behind by an earlier run would block every later transfer, so bootstrap and the
// scenarios clear it first. It uses a /dev/* endpoint and therefore only works on this stack.
import { postGateway } from "./scenario-client.js";

async function main(): Promise<void> {
  const peerInstitutionId = process.argv[2] ?? "B";
  await postGateway("A", "/dev/release-peer-hold", { peerInstitutionId }, "b");
  console.log(`peer hold released: ${peerInstitutionId}`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
