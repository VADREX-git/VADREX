import { join } from "node:path";
import type { EvalConfig } from "./common.js";
import { groupStats, modeStudySizes, numericMetricSummaries, round, timed, writeCsv, writeJson } from "./common.js";
import { deleteStudyFromOrthanc, directOrthancCopy, removeSyntheticDicom, stowDicomToOrthancA, syntheticDicomPath, syntheticStudyUid, writeSyntheticDicom } from "./dicom.js";
import type { CreatedConsent, TransferResponse } from "./live.js";
import { createConsent, isTransientError, releasePeerHold, restartGatewaysWithRuntimeEnv, restoreGatewaysFromProcessEnv, retryTransientStep, startTransfer, waitForGateway } from "./live.js";

export interface HandshakeRow {
  mode: string;
  repeat: number;
  studySizeLabel: string;
  targetBytes: number;
  actualPixelBytes: number;
  frames: number;
  baselineDirectMs: number | null;
  gatewayHandshakeMs: number | null;
  overheadMs: number | null;
  overheadRatio: number | null;
  transferStatus: string | null;
  directCopiedBytes: number | null;
  status: "ok" | "failed" | "skipped";
  error?: string;
}

export async function measureHandshakeOverhead(config: EvalConfig): Promise<HandshakeRow[]> {
  const rows: HandshakeRow[] = [];
  if (config.skipDocker) {
    rows.push(skippedRow(config.mode, "docker measurements skipped"));
    writeOutputs(config, rows);
    return rows;
  }

  // Lengthen the anchor interval during handshake so periodic anchoring does not
  // contend with large base64 transfers under load; handshake
  // does not verify anchors. Restored after the loop below.
  await restartGatewaysWithRuntimeEnv({ anchorIntervalSec: 3600, anchorMaxIntervalSec: 3600 });

  for (const size of modeStudySizes(config.mode)) {
    for (let repeat = 1; repeat <= config.repeats; repeat += 1) {
      // UID and path are chosen outside the try so finally can clean up even on failure.
      const baselineStudyUid = syntheticStudyUid(size.label, repeat, "baseline");
      const gatewayStudyUid = syntheticStudyUid(size.label, repeat, "gateway");
      const baselinePath = syntheticDicomPath(size.label, repeat, "baseline");
      const gatewayPath = syntheticDicomPath(size.label, repeat, "gateway");
      try {
        await releasePeerHold();
        const baselineDicom = writeSyntheticDicom({
          studyInstanceUid: baselineStudyUid,
          seriesInstanceUid: `${baselineStudyUid}.1`,
          sopInstanceUid: `${baselineStudyUid}.1.1`,
          targetPixelBytes: size.targetBytes,
          outputPath: baselinePath
        });
        await retryTransientStep(() => stowDicomToOrthancA(baselinePath));
        const direct = await retryTransientStep(() => timed(() => directOrthancCopy(baselineStudyUid)));

        const gatewayDicom = writeSyntheticDicom({
          studyInstanceUid: gatewayStudyUid,
          seriesInstanceUid: `${gatewayStudyUid}.1`,
          sopInstanceUid: `${gatewayStudyUid}.1.1`,
          targetPixelBytes: size.targetBytes,
          outputPath: gatewayPath
        });
        await retryTransientStep(() => stowDicomToOrthancA(gatewayPath));
        const consent = await createConsent(gatewayStudyUid);
        const gateway = await measureTransferWithRetry(consent, gatewayStudyUid);
        const overhead = gateway.ms - direct.ms;

        rows.push({
          mode: config.mode,
          repeat,
          studySizeLabel: size.label,
          targetBytes: size.targetBytes,
          actualPixelBytes: gatewayDicom.pixelBytes,
          frames: gatewayDicom.frames,
          baselineDirectMs: round(direct.ms),
          gatewayHandshakeMs: round(gateway.ms),
          overheadMs: round(overhead),
          overheadRatio: direct.ms > 0 ? round(gateway.ms / direct.ms) : null,
          transferStatus: gateway.value.status,
          directCopiedBytes: direct.value.bytes,
          status: gateway.value.status === "COMPLETED" ? "ok" : "failed",
          error: gateway.value.status === "COMPLETED" ? undefined : `transfer status ${gateway.value.status}`
        });
        if (gateway.value.status !== "COMPLETED") {
          await releasePeerHold();
        }

        if (baselineDicom.pixelBytes !== gatewayDicom.pixelBytes) {
          rows[rows.length - 1].error = `baseline/gateway synthetic pixel size mismatch ${baselineDicom.pixelBytes}/${gatewayDicom.pixelBytes}`;
        }
      } catch (error) {
        await releasePeerHold().catch(() => undefined);
        rows.push({
          mode: config.mode,
          repeat,
          studySizeLabel: size.label,
          targetBytes: size.targetBytes,
          actualPixelBytes: 0,
          frames: 0,
          baselineDirectMs: null,
          gatewayHandshakeMs: null,
          overheadMs: null,
          overheadRatio: null,
          transferStatus: null,
          directCopiedBytes: null,
          status: "failed",
          error: error instanceof Error ? error.message : String(error)
        });
      } finally {
        // Cleanup runs only after the measurement is recorded. Skipping it would leave about
        // 10 GB per run in Orthanc and eventually exhaust the disk. Errors are ignored so a
        // cleanup failure cannot turn a good measurement into a failed one.
        for (const [institution, studyUid] of [
          ["a", baselineStudyUid], ["b", baselineStudyUid],
          ["a", gatewayStudyUid], ["b", gatewayStudyUid]
        ] as const) {
          await deleteStudyFromOrthanc(institution, studyUid).catch(() => false);
        }
        for (const path of [baselinePath, gatewayPath]) {
          try {
            removeSyntheticDicom(path);
          } catch {
            // A failure removing the host file is equally irrelevant to the measurement.
          }
        }
      }
    }
  }

  await restoreGatewaysFromProcessEnv();
  writeOutputs(config, rows);
  return rows;
}

async function measureTransferWithRetry(
  consent: CreatedConsent,
  studyInstanceUid: string,
  attempts = 8
): Promise<{ value: TransferResponse; ms: number }> {
  // Some transfers (notably ~50MiB) hit a transient ECONNRESET that can persist
  // across a sustained window (~30-60s) on this local Docker stack, so a short
  // retry span is not enough. Retry transient failures
  // with a longer capped backoff; between attempts clear any peer hold and wait
  // for both gateways to be ready again so retries do not hammer a still
  // -recovering gateway. Only the successful attempt is timed.
  let lastError: unknown;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await timed(() => startTransfer(consent, studyInstanceUid));
    } catch (error) {
      lastError = error;
      if (attempt === attempts || !isTransientError(error)) {
        throw error;
      }
      await releasePeerHold().catch(() => undefined);
      await waitForGateway("A", 30_000).catch(() => undefined);
      await waitForGateway("B", 30_000).catch(() => undefined);
      await new Promise((resolve) => setTimeout(resolve, Math.min(10_000, 3_000 * attempt)));
    }
  }
  throw lastError;
}

function writeOutputs(config: EvalConfig, rows: HandshakeRow[]): void {
  writeCsv(join(config.outDir, "raw", "handshake_overhead.csv"), rows);
  writeJson(join(config.outDir, "raw", "handshake_overhead.json"), rows);
  writeCsv(
    join(config.outDir, "summary", "handshake-overhead-ms.csv"),
    groupStats(rows.filter((row) => row.status === "ok") as unknown as Record<string, unknown>[], ["studySizeLabel"], "overheadMs")
  );
  writeCsv(
    join(config.outDir, "summary", "handshake-numeric-summary.csv"),
    numericMetricSummaries(
      rows.filter((row) => row.status === "ok") as unknown as Record<string, unknown>[],
      ["studySizeLabel"],
      ["baselineDirectMs", "gatewayHandshakeMs", "overheadMs", "overheadRatio", "directCopiedBytes", "actualPixelBytes", "frames"]
    )
  );
}

function skippedRow(mode: string, reason: string): HandshakeRow {
  return {
    mode,
    repeat: 0,
    studySizeLabel: "",
    targetBytes: 0,
    actualPixelBytes: 0,
    frames: 0,
    baselineDirectMs: null,
    gatewayHandshakeMs: null,
    overheadMs: null,
    overheadRatio: null,
    transferStatus: null,
    directCopiedBytes: null,
    status: "skipped",
    error: reason
  };
}
