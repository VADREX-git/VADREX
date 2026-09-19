import fs from 'node:fs';
import path from 'node:path';
import hre from 'hardhat';

async function main() {
  const artifact = await hre.artifacts.readArtifact('Anchor');
  const build = await hre.artifacts.getBuildInfo('contracts/Anchor.sol:Anchor');
  const rows = [];
  const [signer] = await hre.ethers.getSigners();
  const factory = await hre.ethers.getContractFactory('Anchor');
  for (let repeat=1;repeat<=10;repeat++) {
    const estimate = await signer.estimateGas(await factory.getDeployTransaction());
    const contract = await factory.deploy();
    const receipt = await contract.deploymentTransaction()!.wait();
    rows.push({repeat, operation:'deploy', estimatedGas:Number(estimate), gasUsed:Number(receipt!.gasUsed)});
    for (const [index,size] of [1,2].entries()) {
      const root = hre.ethers.sha256(hre.ethers.toUtf8Bytes(`revision-log-${size}`));
      const map = hre.ethers.sha256(hre.ethers.toUtf8Bytes(`revision-map-${size}`));
      const estimatedGas = await contract.registerAnchor.estimateGas(root,size,map);
      const tx = await contract.registerAnchor(root,size,map);
      const actual = await tx.wait();
      rows.push({repeat,operation:index===0?'first-anchor':'subsequent-anchor',treeSize:size,root,map,
        estimatedGas:Number(estimatedGas),gasUsed:Number(actual!.gasUsed)});
    }
  }
  const out=path.resolve(process.env.REVISION_OUTPUT ?? '../eval/out/revision-20260917'); fs.mkdirSync(out,{recursive:true});
  fs.writeFileSync(path.join(out,'gas.json'),JSON.stringify({node:process.version,hardhat:require('hardhat/package.json').version,
    network:hre.network.name,chainId:(await hre.ethers.provider.getNetwork()).chainId.toString(),
    compiler:build?.solcLongVersion,compilerSettings:build?.input.settings,artifactBytecodeLength:artifact.bytecode.length,
    rows},null,2));
  console.log(JSON.stringify(rows.slice(0,3)));
}
main().catch(error=>{console.error(error);process.exitCode=1;});
