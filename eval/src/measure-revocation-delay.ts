import { join } from "node:path";
import type { EvalConfig } from "./common.js";
import { groupStats, modeAnchorIntervals, numericMetricSummaries, round, timed, writeCsv, writeJson } from "./common.js";
import { createConsent, pinnedAnchors, restartGatewaysWithAnchorInterval, revokeConsent, waitForAnchoredEntry } from "./live.js";

export interface RevocationDelayRow {
  mode: string;
  repeat: number;
  anchorIntervalSec: number;
  randomOffsetMs: number;
  consentId: string;
  revocationSeq: number | null;
  revocationEntryHash: string | null;
  apiMs: number;
  observedDelayMs: number | null;
  anchoredBatchId: number | null;
  anchoredAt: number | null;
  status: "ok" | "failed" | "skipped";
  error?: string;
}

export async function measureRevocationDelay(config: EvalConfig): Promise<RevocationDelayRow[]> {
  const rows: RevocationDelayRow[] = [];
  if (config.skipDocker) {
    rows.push(skippedRow(config.mode, "docker measurements skipped"));
    writeOutputs(config, rows);
    return rows;
  }

  const anchors = pinnedAnchors();
  // Opt-in: decouple revoke timing from the free-running anchor clock to measure
  // the average-case delay (~T/2) instead of the phase-locked upper bound (~T).
  // Default off keeps the upper-bound measurement.
  const randomOffset = process.env.EVAL_REVOCATION_RANDOM_OFFSET === "true";
  const restoreInterval = parsePositiveEnv(process.env.ANCHOR_INTERVAL_SEC, 30);
  const restoreMaxInterval = parsePositiveEnv(process.env.ANCHOR_MAX_INTERVAL_SEC, restoreInterval);
  try {
    for (const interval of modeAnchorIntervals(config.mode)) {
      await restartGatewaysWithAnchorInterval(interval);
      for (let repeat = 1; repeat <= config.repeats; repeat += 1) {
        const offsetMs = randomOffset ? Math.floor(Math.random() * interval * 1000) : 0;
        try {
        const consent = await createConsent(`1.3.6.1.4.1.5962.8.revocation.${Date.now()}.${repeat}`);
        // Sleep the random offset BEFORE t0 so it is outside the measured window;
        // this randomizes the revoke's phase against the anchor tick.
        if (offsetMs > 0) {
          await new Promise((resolve) => setTimeout(resolve, offsetMs));
        }
        const revocationRequestedAtMs = Date.now();
        const revoked = await timed(() => revokeConsent(consent.consentId));
        const anchored = await waitForAnchoredEntry("A", anchors.a, revoked.value.entryHash, Math.max(30_000, interval * 3_000 + 15_000));
        rows.push({
          mode: config.mode,
          repeat,
          anchorIntervalSec: interval,
          randomOffsetMs: offsetMs,
          consentId: consent.consentId,
          revocationSeq: revoked.value.seq,
          revocationEntryHash: revoked.value.entryHash,
          apiMs: round(revoked.ms),
          observedDelayMs: Date.now() - revocationRequestedAtMs,
          anchoredBatchId: anchored.batchId,
          anchoredAt: anchored.anchoredAt,
          status: "ok"
        });
      } catch (error) {
        rows.push({
          mode: config.mode,
          repeat,
          anchorIntervalSec: interval,
          randomOffsetMs: offsetMs,
          consentId: "",
          revocationSeq: null,
          revocationEntryHash: null,
          apiMs: 0,
          observedDelayMs: null,
          anchoredBatchId: null,
          anchoredAt: null,
          status: "failed",
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }
    }
  } finally {
    await restartGatewaysWithAnchorInterval(restoreInterval, restoreMaxInterval);
  }

  writeOutputs(config, rows);
  return rows;
}

function writeOutputs(config: EvalConfig, rows: RevocationDelayRow[]): void {
  writeCsv(join(config.outDir, "raw", "revocation_delay.csv"), rows);
  writeJson(join(config.outDir, "raw", "revocation_delay.json"), rows);
  writeCsv(
    join(config.outDir, "summary", "revocation-delay-ms.csv"),
    groupStats(rows.filter((row) => row.status === "ok") as unknown as Record<string, unknown>[], ["anchorIntervalSec"], "observedDelayMs")
  );
  writeCsv(
    join(config.outDir, "summary", "revocation-delay-numeric-summary.csv"),
    numericMetricSummaries(
      rows.filter((row) => row.status === "ok") as unknown as Record<string, unknown>[],
      ["anchorIntervalSec"],
      ["apiMs", "observedDelayMs"]
    )
  );
}

function parsePositiveEnv(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function skippedRow(mode: string, reason: string): RevocationDelayRow {
  return {
    mode,
    repeat: 0,
    anchorIntervalSec: 0,
    randomOffsetMs: 0,
    consentId: "",
    revocationSeq: null,
    revocationEntryHash: null,
    apiMs: 0,
    observedDelayMs: null,
    anchoredBatchId: null,
    anchoredAt: null,
    status: "skipped",
    error: reason
  };
}
