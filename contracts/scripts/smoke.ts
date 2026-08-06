import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { ethers } from "hardhat";

const ROOT = "0x9999999999999999999999999999999999999999999999999999999999999999";
const MAP = "0x8888888888888888888888888888888888888888888888888888888888888888";

/**
 * Rejects a throwaway instance that landed on an institution's anchor address.
 *
 * The collision is reachable: if the chain is recreated the deployer's nonce returns to zero,
 * so a fresh deployment gets exactly the address recorded for institution A. Left alone, the
 * smoke root would be registered on a live contract and block that gateway's anchoring for good.
 */
function assertNotInstitutionAnchor(address: string): void {
  const deploymentPath = join(process.cwd(), "..", "data", "deployments.local.json");
  if (!existsSync(deploymentPath)) {
    return;
  }
  const deployments = JSON.parse(readFileSync(deploymentPath, "utf8")) as {
    anchors?: Record<string, { address?: string } | undefined>;
  };
  for (const [institutionId, anchor] of Object.entries(deployments.anchors ?? {})) {
    if (anchor?.address && anchor.address.toLowerCase() === address.toLowerCase()) {
      throw new Error(
        `smoke instance collided with institution ${institutionId} anchor ${address}. ` +
        "The chain was recreated and the deployer nonce reset; redeploy the contracts and retry."
      );
    }
  }
}

async function main() {
  // This must not write to the institutions' live anchor contracts. The contract only enforces a
  // growing treeSize, so the fake root below would be accepted, and the gateway anchor loop would
  // then be stuck for good. A separate instance of the same bytecode gives the same round trip.
  const [signerA] = await ethers.getSigners();
  const anchor = await (await ethers.getContractFactory("Anchor", signerA)).deploy();
  await anchor.waitForDeployment();
  const address = await anchor.getAddress();
  assertNotInstitutionAnchor(address);

  const treeSize = 1n;
  const tx = await anchor.registerAnchor(ROOT, treeSize, MAP);
  await tx.wait();

  const latest = await anchor.latestAnchor();
  if (latest.rootHash !== ROOT || latest.mapRoot !== MAP || latest.treeSize !== treeSize) {
    throw new Error("smoke round trip returned unexpected anchor fields");
  }
  if ((await anchor.anchorCount()) !== 1n) {
    throw new Error("smoke expected exactly one anchor on the throwaway instance");
  }

  console.log(`Smoke registered batch ${latest.batchId} on throwaway Anchor ${address}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
