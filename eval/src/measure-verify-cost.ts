import { join } from "node:path";
import { verifyNonTransfer } from "../../packages/verifier-cli/src/verifier.js";
import type { EvalConfig } from "./common.js";
import { groupStats, modeAnchorCounts, numericMetricSummaries, round, timed, writeCsv, writeJson } from "./common.js";
import {
  addCheckpointAndAnchor,
  anchorNow,
  chainAnchors,
  createAnchors,
  createConsent,
  pinnedAnchors,
  restartGatewaysWithRuntimeEnv,
  restoreGatewaysFromProcessEnv,
  revokeConsent,
  rpcUrl,
  verifierTlsOptions,
  waitForAnchoredEntry
} from "./live.js";

export interface VerifyCostRow {
  mode: string;
  repeat: number;
  targetElapsedAnchors: number;
  actualProviderAnchorsChecked: number | null;
  actualReceiverAnchors: number | null;
  verifyMs: number | null;
  apiCalls: number | null;
  rpcCalls: number | null;
  apiRequestBytes: number | null;
  apiResponseBytes: number | null;
  status: "success" | "failure" | "waiting" | "skipped";
  error?: string;
}

export async function measureVerifyCost(config: EvalConfig): Promise<VerifyCostRow[]> {
  const rows: VerifyCostRow[] = [];
  if (config.skipDocker) {
    rows.push(skippedRow(config.mode, "docker measurements skipped"));
    writeOutputs(config, rows);
    return rows;
  }

  const verifyCostAnchorIntervalSec = process.env.EVAL_VERIFY_COST_ANCHOR_INTERVAL_SEC
    ? Number(process.env.EVAL_VERIFY_COST_ANCHOR_INTERVAL_SEC)
    : 3600;
  await restartGatewaysWithRuntimeEnv({
    anchorIntervalSec: verifyCostAnchorIntervalSec,
    anchorMaxIntervalSec: verifyCostAnchorIntervalSec
  });
  try {
    const anchors = pinnedAnchors();
    await warmUpAnchoring(anchors.a, anchors.b);
    for (const target of modeAnchorCounts(config.mode)) {
      for (let repeat = 1; repeat <= config.repeats; repeat += 1) {
        try {
          const consent = await createConsent(`1.3.6.1.4.1.5962.8.verify.${Date.now()}.${target}.${repeat}`);
          const revoked = await revokeConsent(consent.consentId);
          await anchorNow("A");
          await addCheckpointAndAnchor("B", `verify-cost-receiver-base-${target}-${repeat}`);
          // Setup wait outside the timed section below; anchors have accumulated here, so the
          // budget is generous.
          const revokedAnchor = await waitForAnchoredEntry("A", anchors.a, revoked.entryHash, 120_000);
          if (target > 1) {
            await createAnchors("A", target - 1, `verify-cost-provider-${target}-${repeat}`);
            await createAnchors("B", target - 1, `verify-cost-receiver-${target}-${repeat}`);
          }

          const providerAnchors = await chainAnchors(anchors.a);
          const receiverAnchors = await chainAnchors(anchors.b);
          const measured = await timed(() => verifyNonTransfer({
            consentId: consent.consentId,
            secretC: consent.secretC,
            revocationSeq: revoked.seq,
            revocationEntryHash: revoked.entryHash,
            providerGateway: process.env.GATEWAY_A_URL ?? "https://localhost:7001",
            receiverGateway: process.env.GATEWAY_B_URL ?? "https://localhost:7002",
            rpcUrl: rpcUrl(),
            graceSeconds: 0,
            providerAnchorAddress: anchors.a,
            receiverAnchorAddress: anchors.b,
            tls: verifierTlsOptions()
          }));

          rows.push({
            mode: config.mode,
            repeat,
            targetElapsedAnchors: target,
            actualProviderAnchorsChecked: providerAnchors.filter((anchor) => anchor.batchId >= revokedAnchor.batchId).length,
            actualReceiverAnchors: receiverAnchors.length,
            verifyMs: round(measured.ms),
            apiCalls: measured.value.apiCalls,
            rpcCalls: measured.value.rpcCalls,
            apiRequestBytes: measured.value.apiRequestBytes,
            apiResponseBytes: measured.value.apiResponseBytes,
            status: measured.value.status,
            error: measured.value.ok ? undefined : measured.value.lines.at(-1)
          });
        } catch (error) {
          rows.push({
            mode: config.mode,
            repeat,
            targetElapsedAnchors: target,
            actualProviderAnchorsChecked: null,
            actualReceiverAnchors: null,
            verifyMs: null,
            apiCalls: null,
            rpcCalls: null,
            apiRequestBytes: null,
            apiResponseBytes: null,
            status: "failure",
            error: error instanceof Error ? error.message : String(error)
          });
        }
      }
    }
  } finally {
    await restoreGatewaysFromProcessEnv();
  }

  writeOutputs(config, rows);
  return rows;
}

async function warmUpAnchoring(providerAddress: string, receiverAddress: string): Promise<void> {
  // The first anchor after a gateway restart can take longer than the measured
  // 30s budget to land on-chain, which deterministically fails the first
  // iteration. Prime both anchor paths once, waiting until the
  // anchor is observed, so the measured loop starts warm.
  for (const [id, address] of [["A", providerAddress], ["B", receiverAddress]] as const) {
    const before = (await chainAnchors(address)).length;
    await addCheckpointAndAnchor(id, "verify-cost-warmup");
    const deadline = Date.now() + 60_000;
    while (Date.now() < deadline && (await chainAnchors(address)).length <= before) {
      await new Promise((resolve) => setTimeout(resolve, 1_000));
    }
  }
}

function writeOutputs(config: EvalConfig, rows: VerifyCostRow[]): void {
  writeCsv(join(config.outDir, "raw", "verify_cost.csv"), rows);
  writeJson(join(config.outDir, "raw", "verify_cost.json"), rows);
  writeCsv(
    join(config.outDir, "summary", "verify-cost-ms.csv"),
    groupStats(rows.filter((row) => row.status === "success") as unknown as Record<string, unknown>[], ["targetElapsedAnchors"], "verifyMs")
  );
  writeCsv(
    join(config.outDir, "summary", "verify-cost-numeric-summary.csv"),
    numericMetricSummaries(
      rows.filter((row) => row.status === "success") as unknown as Record<string, unknown>[],
      ["targetElapsedAnchors"],
      ["actualProviderAnchorsChecked", "actualReceiverAnchors", "verifyMs", "apiCalls", "rpcCalls", "apiRequestBytes", "apiResponseBytes"]
    )
  );
}

function skippedRow(mode: string, reason: string): VerifyCostRow {
  return {
    mode,
    repeat: 0,
    targetElapsedAnchors: 0,
    actualProviderAnchorsChecked: null,
    actualReceiverAnchors: null,
    verifyMs: null,
    apiCalls: null,
    rpcCalls: null,
    apiRequestBytes: null,
    apiResponseBytes: null,
    status: "skipped",
    error: reason
  };
}
