// Writing side of the anchor contract: the gateway publishes its accumulated roots here.
//
// Only the six anchor fields ever reach the chain. batchId and anchoredAt are assigned by the
// contract, which is why a successful registration is followed by a read-back rather than by
// trusting locally computed values.
import { Contract, JsonRpcProvider, Wallet } from "ethers";
import type { HexString } from "@vadrex/shared";

const ANCHOR_ABI = [
  "event AnchorRegistered(uint64 indexed batchId, bytes32 rootHash, uint64 treeSize, bytes32 mapRoot, uint64 anchoredAt)",
  "function registerAnchor(bytes32 rootHash, uint64 treeSize, bytes32 mapRoot) external",
  "function anchorCount() view returns (uint64)",
  "function latestAnchor() view returns (tuple(uint64 batchId, bytes32 rootHash, uint64 treeSize, bytes32 mapRoot, uint64 anchoredAt))"
] as const;

export interface RegisteredAnchor {
  batchId: number;
  rootHash: HexString;
  treeSize: number;
  mapRoot: HexString;
  txHash: string;
}

function normalizeHash(hash: string): HexString {
  if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) {
    throw new Error(`expected 32-byte 0x-prefixed hex hash, got ${hash}`);
  }
  return `0x${hash.slice(2).toLowerCase()}`;
}

export class AnchorClient {
  private readonly contract: Contract;

  constructor(rpcUrl: string, anchorAddress: string, walletPrivateKey: string) {
    const provider = new JsonRpcProvider(rpcUrl);
    const wallet = new Wallet(walletPrivateKey, provider);
    this.contract = new Contract(anchorAddress, ANCHOR_ABI, wallet);
  }

  async registerAnchor(rootHash: HexString, treeSize: number, mapRoot: HexString): Promise<RegisteredAnchor> {
    const normalizedRoot = normalizeHash(rootHash);
    const normalizedMapRoot = normalizeHash(mapRoot);
    const tx = await this.contract.registerAnchor(normalizedRoot, BigInt(treeSize), normalizedMapRoot);
    const receipt = await tx.wait();
    if (!receipt) {
      throw new Error("anchor transaction was not mined");
    }

    const latest = await this.readLatestAnchor();
    return { ...latest, txHash: receipt.hash };
  }

  async latestAnchor(): Promise<RegisteredAnchor | null> {
    const count = Number(await this.contract.anchorCount());
    if (count === 0) {
      return null;
    }
    return this.readLatestAnchor();
  }

  private async readLatestAnchor(): Promise<RegisteredAnchor> {
    const latest = await this.contract.latestAnchor();
    const batchId = Number(latest.batchId ?? latest[0]);
    return {
      batchId,
      rootHash: normalizeHash(latest.rootHash ?? latest[1]),
      treeSize: Number(latest.treeSize ?? latest[2]),
      mapRoot: normalizeHash(latest.mapRoot ?? latest[3]),
      txHash: await this.findAnchorTxHash(batchId)
    };
  }

  private async findAnchorTxHash(batchId: number): Promise<string> {
    const filter = this.contract.filters.AnchorRegistered(BigInt(batchId));
    const logs = await this.contract.queryFilter(filter, 0, "latest");
    const latestLog = logs.at(-1);
    if (!latestLog) {
      throw new Error(`AnchorRegistered event not found for batch ${batchId}`);
    }
    return latestLog.transactionHash;
  }
}
