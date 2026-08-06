// Violation-injection utility for tests; never called from a production path.
//
// This is a second process opening audit.db directly, so it must not run while the gateway that
// owns the database is up: the gateway's in-memory tree would not know about the injected leaf
// and its next append would collide on leafIndex. Stop the gateway first.
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import type { EventType } from "@vadrex/shared";
import { AuditAggregator } from "../packages/gateway/src/aggregator.js";
import { repoRoot } from "../packages/gateway/src/config.js";

interface Args {
  dbPath: string;
  consentId: string;
  seq: number;
  eventType: EventType;
  noHeadUpdate: boolean;
}

export interface InjectViolationOptions {
  consentId: string;
  seq: number;
  eventType?: EventType;
  noHeadUpdate?: boolean;
}

function readArgs(): Args {
  const rootDir = repoRoot();
  const out: Partial<Args> = {
    dbPath: process.env.AUDIT_DB_PATH ?? join(rootDir, "data", "inst-a", "audit.db"),
    eventType: "TRANSFER_APPROVED",
    noHeadUpdate: false
  };
  const args = process.argv.slice(2);

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const value = args[index + 1];
    if (arg === "--dbPath" && value) {
      out.dbPath = value;
      index += 1;
    } else if (arg === "--consentId" && value) {
      out.consentId = value;
      index += 1;
    } else if (arg === "--seq" && value) {
      out.seq = Number(value);
      index += 1;
    } else if (arg === "--eventType" && value) {
      out.eventType = value as EventType;
      index += 1;
    } else if (arg === "--no-head-update") {
      out.noHeadUpdate = true;
    } else {
      throw new Error(`unknown or incomplete argument: ${arg}`);
    }
  }

  if (!out.consentId) {
    throw new Error("--consentId is required");
  }
  if (!Number.isSafeInteger(out.seq) || out.seq < 1) {
    throw new Error("--seq must be an integer >= 1");
  }
  return out as Args;
}

export function injectViolationIntoAggregator(aggregator: AuditAggregator, options: InjectViolationOptions) {
  const noHeadUpdate = options.noHeadUpdate ?? false;
  return aggregator.forceAppendChainEvent({
    consentId: options.consentId,
    eventType: options.eventType ?? "TRANSFER_APPROVED",
    seq: options.seq,
    requestContext: {
      injectedViolation: true,
      noHeadUpdate,
      productionPath: false
    },
    updateSmt: !noHeadUpdate,
    updateHead: !noHeadUpdate
  });
}

function main() {
  const args = readArgs();
  const aggregator = new AuditAggregator(args.dbPath);
  try {
    const appended = injectViolationIntoAggregator(aggregator, {
      consentId: args.consentId,
      eventType: args.eventType,
      seq: args.seq,
      noHeadUpdate: args.noHeadUpdate
    });
    console.log(JSON.stringify({
      warning: "test-only violation injected; do not call from production paths",
      noHeadUpdate: args.noHeadUpdate,
      appended,
      treeSize: aggregator.treeSize(),
      rootHash: aggregator.currentRoot(),
      mapRoot: aggregator.mapRoot()
    }, null, 2));
  } finally {
    aggregator.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    console.error(error);
    process.exitCode = 1;
  }
}
