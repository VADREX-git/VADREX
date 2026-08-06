import { join } from "node:path";
import { verifyNonTransfer } from "../../packages/verifier-cli/src/verifier.js";
import type { EvalConfig } from "./common.js";
import { groupStats, modeAnchorIntervals, numericMetricSummaries, round, timed, writeCsv, writeJson } from "./common.js";
import type { CreatedConsent, PinnedAnchors, RevokedResponse } from "./live.js";
import {
  addCheckpointAndAnchor,
  anchorNow,
  chainAnchors,
  createConsent,
  pinnedAnchors,
  revokeConsent,
  rpcUrl,
  verifierTlsOptions,
  waitForAnchoredEntry
} from "./live.js";

export interface GraceRow {
  mode: string;
  repeat: number;
  deltaMaxSec: number;
  graceWindowSec: number;
  eligibleReceiverAnchors: number | null;
  receiverAnchorsTotal: number | null;
  verifyMs: number | null;
  status: "success" | "failure" | "waiting" | "skipped";
  apiCalls: number | null;
  rpcCalls: number | null;
  // Result of the verification run before the threshold. It shows the grace filter returning
  // waiting first and turning into success once the threshold has passed.
  preThresholdStatus?: "success" | "failure" | "waiting";
  preThresholdEligible?: number | null;
  preThresholdBeforeThreshold?: boolean;
  error?: string;
}

export async function measureGraceWindow(config: EvalConfig): Promise<GraceRow[]> {
  const rows: GraceRow[] = [];
  if (config.skipDocker) {
    rows.push(skippedRow(config.mode, "docker measurements skipped"));
    writeOutputs(config, rows);
    return rows;
  }

  const anchors = pinnedAnchors();
  for (const delta of modeAnchorIntervals(config.mode)) {
    for (let repeat = 1; repeat <= config.repeats; repeat += 1) {
      try {
        const consent = await createConsent(`1.3.6.1.4.1.5962.8.grace.${Date.now()}.${delta}.${repeat}`);
        const revoked = await revokeConsent(consent.consentId);
        await anchorNow("A");
        // Anchors have accumulated by this point, so the budget is generous. This wait is used
        // to compute the threshold and sits outside the measured section.
        const revokedAnchor = await waitForAnchoredEntry("A", anchors.a, revoked.entryHash, 120_000);
        const threshold = revokedAnchor.anchoredAt + delta;

        // Before the threshold the grace filter must return waiting: the anchor is not there yet.
        const preAnchors = await chainAnchors(anchors.b);
        const preEligible = preAnchors.filter((anchor) => anchor.anchoredAt >= threshold).length;
        const pre = await verifyNonTransfer(verifyOptions(consent, revoked, delta, anchors));
        const preBeforeThreshold = Math.floor(Date.now() / 1000) < threshold;

        await waitUntilEpochSecond(threshold);
        await addCheckpointAndAnchor("B", `grace-${delta}-${repeat}`);

        const receiverAnchors = await chainAnchors(anchors.b);
        const eligible = receiverAnchors.filter((anchor) => anchor.anchoredAt >= threshold);
        const measured = await timed(() => verifyNonTransfer(verifyOptions(consent, revoked, delta, anchors)));

        rows.push({
          preThresholdStatus: pre.status,
          preThresholdEligible: preEligible,
          preThresholdBeforeThreshold: preBeforeThreshold,
          mode: config.mode,
          repeat,
          deltaMaxSec: delta,
          graceWindowSec: delta,
          eligibleReceiverAnchors: eligible.length,
          receiverAnchorsTotal: receiverAnchors.length,
          verifyMs: round(measured.ms),
          status: measured.value.status,
          apiCalls: measured.value.apiCalls,
          rpcCalls: measured.value.rpcCalls,
          error: measured.value.ok ? undefined : measured.value.lines.at(-1)
        });
      } catch (error) {
        rows.push({
          mode: config.mode,
          repeat,
          deltaMaxSec: delta,
          graceWindowSec: delta,
          eligibleReceiverAnchors: null,
          receiverAnchorsTotal: null,
          verifyMs: null,
          status: "failure",
          apiCalls: null,
          rpcCalls: null,
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }
  }

  writeOutputs(config, rows);
  return rows;
}

function verifyOptions(
  consent: CreatedConsent,
  revoked: RevokedResponse,
  delta: number,
  anchors: PinnedAnchors
) {
  return {
    consentId: consent.consentId,
    secretC: consent.secretC,
    revocationSeq: revoked.seq,
    revocationEntryHash: revoked.entryHash,
    providerGateway: process.env.GATEWAY_A_URL ?? "https://localhost:7001",
    receiverGateway: process.env.GATEWAY_B_URL ?? "https://localhost:7002",
    rpcUrl: rpcUrl(),
    graceSeconds: delta,
    providerAnchorAddress: anchors.a,
    receiverAnchorAddress: anchors.b,
    tls: verifierTlsOptions()
  };
}

async function waitUntilEpochSecond(epochSecond: number): Promise<void> {
  while (Math.floor(Date.now() / 1000) < epochSecond) {
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
}

function writeOutputs(config: EvalConfig, rows: GraceRow[]): void {
  writeCsv(join(config.outDir, "raw", "grace_window.csv"), rows);
  writeJson(join(config.outDir, "raw", "grace_window.json"), rows);
  writeCsv(
    join(config.outDir, "summary", "grace-window-ms.csv"),
    groupStats(rows.filter((row) => row.status === "success") as unknown as Record<string, unknown>[], ["deltaMaxSec"], "verifyMs")
  );
  writeCsv(
    join(config.outDir, "summary", "grace-window-numeric-summary.csv"),
    numericMetricSummaries(
      rows.filter((row) => row.status === "success") as unknown as Record<string, unknown>[],
      ["deltaMaxSec"],
      ["graceWindowSec", "eligibleReceiverAnchors", "receiverAnchorsTotal", "verifyMs", "apiCalls", "rpcCalls"]
    )
  );
}

function skippedRow(mode: string, reason: string): GraceRow {
  return {
    mode,
    repeat: 0,
    deltaMaxSec: 0,
    graceWindowSec: 0,
    eligibleReceiverAnchors: null,
    receiverAnchorsTotal: null,
    verifyMs: null,
    status: "skipped",
    apiCalls: null,
    rpcCalls: null,
    error: reason
  };
}
