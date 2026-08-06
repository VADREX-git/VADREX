import { expect } from "chai";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { ethers } from "hardhat";

const ROOT_1 = "0x1111111111111111111111111111111111111111111111111111111111111111";
const ROOT_2 = "0x2222222222222222222222222222222222222222222222222222222222222222";
const ROOT_3 = "0x3333333333333333333333333333333333333333333333333333333333333333";
const MAP_1 = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const MAP_2 = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const MAP_3 = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

describe("Anchor", () => {
  async function deployAnchor() {
    const [owner, other] = await ethers.getSigners();
    const Anchor = await ethers.getContractFactory("Anchor", owner);
    const anchor = await Anchor.deploy();
    await anchor.waitForDeployment();
    return { anchor, owner, other };
  }

  it("registers an anchor, increments batchId, stores fields, and emits AnchorRegistered", async () => {
    const { anchor } = await deployAnchor();

    const tx = await anchor.registerAnchor(ROOT_1, 10, MAP_1);
    const receipt = await tx.wait();
    const block = await ethers.provider.getBlock(receipt!.blockNumber);

    await expect(tx)
      .to.emit(anchor, "AnchorRegistered")
      .withArgs(1, ROOT_1, 10, MAP_1, block!.timestamp);

    const stored = await anchor.getAnchor(1);
    expect(stored.batchId).to.equal(1);
    expect(stored.rootHash).to.equal(ROOT_1);
    expect(stored.treeSize).to.equal(10);
    expect(stored.mapRoot).to.equal(MAP_1);
    expect(stored.anchoredAt).to.equal(block!.timestamp);
    expect(await anchor.anchorCount()).to.equal(1);
  });

  it("reverts when treeSize is less than or equal to the previous treeSize", async () => {
    const { anchor } = await deployAnchor();

    await anchor.registerAnchor(ROOT_1, 10, MAP_1);
    await expect(anchor.registerAnchor(ROOT_2, 10, MAP_2)).to.be.revertedWith("treeSize must increase");
    await expect(anchor.registerAnchor(ROOT_2, 9, MAP_2)).to.be.revertedWith("treeSize must increase");
  });

  it("reverts when a non-owner registers an anchor", async () => {
    const { anchor, other } = await deployAnchor();

    await expect(anchor.connect(other).registerAnchor(ROOT_1, 1, MAP_1))
      .to.be.revertedWithCustomError(anchor, "OwnableUnauthorizedAccount")
      .withArgs(await other.getAddress());
  });

  it("returns getAnchor, latestAnchor, and anchorCount consistently", async () => {
    const { anchor } = await deployAnchor();

    await expect(anchor.getAnchor(0)).to.be.revertedWith("anchor not found");
    await expect(anchor.getAnchor(1)).to.be.revertedWith("anchor not found");
    await expect(anchor.latestAnchor()).to.be.revertedWith("anchor not found");

    await anchor.registerAnchor(ROOT_1, 1, MAP_1);
    await anchor.registerAnchor(ROOT_2, 2, MAP_2);

    expect(await anchor.anchorCount()).to.equal(2);
    expect((await anchor.getAnchor(1)).rootHash).to.equal(ROOT_1);
    expect((await anchor.getAnchor(2)).rootHash).to.equal(ROOT_2);
    expect((await anchor.latestAnchor()).rootHash).to.equal(ROOT_2);
    await expect(anchor.getAnchor(3)).to.be.revertedWith("anchor not found");
  });

  it("records anchoredAt from block.timestamp as a uint64-compatible value", async () => {
    const { anchor } = await deployAnchor();
    const nextTimestamp = 1_900_000_000;

    await time.setNextBlockTimestamp(nextTimestamp);
    await anchor.registerAnchor(ROOT_1, 1, MAP_1);

    const stored = await anchor.latestAnchor();
    expect(stored.anchoredAt).to.equal(nextTimestamp);
    expect(stored.anchoredAt).to.be.lessThan(2n ** 64n);
  });

  it("preserves the full history after three consecutive registrations", async () => {
    const { anchor } = await deployAnchor();

    await anchor.registerAnchor(ROOT_1, 5, MAP_1);
    await anchor.registerAnchor(ROOT_2, 8, MAP_2);
    await anchor.registerAnchor(ROOT_3, 13, MAP_3);

    const first = await anchor.getAnchor(1);
    const second = await anchor.getAnchor(2);
    const third = await anchor.getAnchor(3);

    expect(await anchor.anchorCount()).to.equal(3);
    expect(first.batchId).to.equal(1);
    expect(first.treeSize).to.equal(5);
    expect(first.rootHash).to.equal(ROOT_1);
    expect(second.batchId).to.equal(2);
    expect(second.treeSize).to.equal(8);
    expect(second.rootHash).to.equal(ROOT_2);
    expect(third.batchId).to.equal(3);
    expect(third.treeSize).to.equal(13);
    expect(third.rootHash).to.equal(ROOT_3);
  });
});
