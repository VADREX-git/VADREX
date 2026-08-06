// Reading side of the anchor contract, and the verifier's root of trust: these values come from
// the chain over RPC, never from a gateway. Reads are counted so the evaluation can report the
// verification cost a patient pays.
import { Contract, JsonRpcProvider } from "ethers";
import type { CallCounter } from "./http.js";
import type { ChainAnchor } from "./proofs.js";
import { normalizeHash } from "./proofs.js";

const ANCHOR_ABI = [
  "function anchorCount() view returns (uint64)",
  "function getAnchor(uint64 batchId) view returns (tuple(uint64 batchId, bytes32 rootHash, uint64 treeSize, bytes32 mapRoot, uint64 anchoredAt))",
  "function latestAnchor() view returns (tuple(uint64 batchId, bytes32 rootHash, uint64 treeSize, bytes32 mapRoot, uint64 anchoredAt))"
];

function toSafeNumber(value: bigint | number, name: string): number {
  const numberValue = typeof value === "bigint" ? Number(value) : value;
  if (!Number.isSafeInteger(numberValue) || numberValue < 0) {
    throw new Error(`${name} is outside safe integer range`);
  }
  return numberValue;
}

function normalizeAnchor(raw: {
  batchId: bigint | number;
  rootHash: string;
  treeSize: bigint | number;
  mapRoot: string;
  anchoredAt: bigint | number;
}): ChainAnchor {
  return {
    batchId: toSafeNumber(raw.batchId, "batchId"),
    rootHash: normalizeHash(raw.rootHash),
    treeSize: toSafeNumber(raw.treeSize, "treeSize"),
    mapRoot: normalizeHash(raw.mapRoot),
    anchoredAt: toSafeNumber(raw.anchoredAt, "anchoredAt")
  };
}

export class AnchorReader {
  private readonly contract: Contract;

  constructor(rpcUrl: string, address: string, private readonly counter: CallCounter) {
    this.contract = new Contract(address, ANCHOR_ABI, new JsonRpcProvider(rpcUrl));
  }

  async anchorCount(): Promise<number> {
    this.counter.rpcCalls += 1;
    return toSafeNumber(await this.contract.anchorCount() as bigint, "anchorCount");
  }

  async getAnchor(batchId: number): Promise<ChainAnchor> {
    this.counter.rpcCalls += 1;
    return normalizeAnchor(await this.contract.getAnchor(batchId) as {
      batchId: bigint;
      rootHash: string;
      treeSize: bigint;
      mapRoot: string;
      anchoredAt: bigint;
    });
  }

  async anchors(): Promise<ChainAnchor[]> {
    const count = await this.anchorCount();
    const anchors: ChainAnchor[] = [];
    for (let batchId = 1; batchId <= count; batchId += 1) {
      anchors.push(await this.getAnchor(batchId));
    }
    return anchors;
  }
}

