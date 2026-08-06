import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { ethers } from "hardhat";

const rootDir = join(process.cwd(), "..");
const deploymentPath = join(rootDir, "data", "deployments.local.json");

async function deployForSigner(label: "A" | "B", signerIndex: number) {
  const signers = await ethers.getSigners();
  const signer = signers[signerIndex];
  const Anchor = await ethers.getContractFactory("Anchor", signer);
  const anchor = await Anchor.deploy();
  await anchor.waitForDeployment();

  return {
    institutionId: label,
    owner: await signer.getAddress(),
    address: await anchor.getAddress()
  };
}

async function main() {
  const [institutionA, institutionB] = await Promise.all([
    deployForSigner("A", 0),
    deployForSigner("B", 1)
  ]);

  const network = await ethers.provider.getNetwork();
  const output = {
    network: "localhost",
    chainId: Number(network.chainId),
    deployedAt: new Date().toISOString(),
    anchors: {
      A: institutionA,
      B: institutionB
    }
  };

  mkdirSync(dirname(deploymentPath), { recursive: true });
  writeFileSync(deploymentPath, `${JSON.stringify(output, null, 2)}\n`);

  console.log(`Institution A Anchor: ${institutionA.address}`);
  console.log(`Institution B Anchor: ${institutionB.address}`);
  console.log(`Wrote ${deploymentPath}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
