// Periodic anchoring: publish the current log root and SMT root, then record what the chain
// accepted.
//
// The chain is authoritative. Before anchoring, the local history is reconciled against the
// latest on-chain anchor, and anything that cannot be explained as "the chain is ahead by anchors
// we simply have not recorded yet" is an error rather than something to paper over: a local
// history ahead of the chain, differing values for the same batch, or an anchored root the local
// log can no longer reproduce all mean the two have diverged, and continuing would produce
// anchors that no verifier could check.
//
// registerAnchor failures are reconciled once before being rethrown, because a transaction can
// land while the response is lost.
import type { AuditAggregator, AnchorHistoryRecord } from "./aggregator.js";
import type { RegisteredAnchor } from "./anchorClient.js";
import type { HexString } from "@vadrex/shared";

export interface AnchorRegistrar {
  registerAnchor(rootHash: HexString, treeSize: number, mapRoot: HexString): Promise<RegisteredAnchor>;
  latestAnchor(): Promise<RegisteredAnchor | null>;
}

function anchorsEqual(left: AnchorHistoryRecord, right: RegisteredAnchor): boolean {
  return left.batchId === right.batchId &&
    left.rootHash === right.rootHash &&
    left.treeSize === right.treeSize &&
    left.mapRoot === right.mapRoot &&
    left.txHash === right.txHash;
}

export async function reconcileLatestAnchor(
  aggregator: AuditAggregator,
  anchorClient: AnchorRegistrar
): Promise<AnchorHistoryRecord | null> {
  const chainLatest = await anchorClient.latestAnchor();
  if (!chainLatest) {
    return null;
  }

  const localLatest = aggregator.latestAnchor();
  if (localLatest) {
    if (localLatest.batchId > chainLatest.batchId) {
      throw new Error(
        `local anchor batch ${localLatest.batchId} is ahead of chain batch ${chainLatest.batchId}`
      );
    }
    if (localLatest.batchId === chainLatest.batchId) {
      if (!anchorsEqual(localLatest, chainLatest)) {
        throw new Error(`local anchor batch ${localLatest.batchId} differs from chain latest anchor`);
      }
      return null;
    }
  }

  if (chainLatest.treeSize > aggregator.treeSize()) {
    throw new Error(
      `chain latest treeSize ${chainLatest.treeSize} exceeds local tree size ${aggregator.treeSize()}`
    );
  }

  const localRoot = aggregator.rootAt(chainLatest.treeSize);
  if (localRoot !== chainLatest.rootHash) {
    throw new Error(
      `chain latest root ${chainLatest.rootHash} does not match local root ${localRoot} at treeSize ${chainLatest.treeSize}`
    );
  }
  if (!aggregator.hasMapRoot(chainLatest.mapRoot)) {
    throw new Error(`chain latest mapRoot ${chainLatest.mapRoot} is not available in the local SMT store`);
  }
  aggregator.recordAnchor(chainLatest);
  return chainLatest;
}

export async function anchorPendingEntries(
  aggregator: AuditAggregator,
  anchorClient: AnchorRegistrar
): Promise<AnchorHistoryRecord | null> {
  await reconcileLatestAnchor(aggregator, anchorClient);

  const latest = aggregator.latestAnchor();
  const latestTreeSize = latest?.treeSize ?? 0;
  const currentTreeSize = aggregator.treeSize();

  if (currentTreeSize <= latestTreeSize) {
    return null;
  }

  const rootHash = aggregator.currentRoot();
  const mapRoot = aggregator.mapRoot();
  let registered: RegisteredAnchor;
  try {
    registered = await anchorClient.registerAnchor(rootHash, currentTreeSize, mapRoot);
  } catch (error) {
    const reconciled = await reconcileLatestAnchor(aggregator, anchorClient);
    if (reconciled && reconciled.treeSize >= currentTreeSize) {
      return reconciled;
    }
    throw error;
  }
  if (registered.rootHash !== rootHash || registered.treeSize !== currentTreeSize || registered.mapRoot !== mapRoot) {
    throw new Error(
      `chain anchor mismatch: expected ${rootHash}/${currentTreeSize}/${mapRoot}, got ${registered.rootHash}/${registered.treeSize}/${registered.mapRoot}`
    );
  }

  aggregator.recordAnchor(registered);
  return registered;
}

export function createAnchorRunner(
  aggregator: AuditAggregator,
  anchorClient: AnchorRegistrar
): () => Promise<AnchorHistoryRecord | null> {
  let inFlight: Promise<AnchorHistoryRecord | null> | null = null;

  return () => {
    if (!inFlight) {
      inFlight = anchorPendingEntries(aggregator, anchorClient).finally(() => {
        inFlight = null;
      });
    }
    return inFlight;
  };
}

export function startAnchorLoop(
  anchorNow: () => Promise<AnchorHistoryRecord | null>,
  intervalMs: number,
  onError: (error: unknown) => void,
  onAnchor: (record: AnchorHistoryRecord | null) => void
): NodeJS.Timeout {
  const run = async () => {
    try {
      onAnchor(await anchorNow());
    } catch (error) {
      onError(error);
    }
  };

  const timer = setInterval(() => {
    void run();
  }, intervalMs);
  void run();
  return timer;
}
