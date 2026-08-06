import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { groupStats, numericMetricSummaries, parseArgs } from "../src/common.js";
import { measureScaling } from "../src/measure-scaling.js";

const originalLogSizes = process.env.EVAL_LOG_SIZES;
const originalInclude10m = process.env.EVAL_INCLUDE_10M;

afterEach(() => {
  restoreEnv("EVAL_LOG_SIZES", originalLogSizes);
  restoreEnv("EVAL_INCLUDE_10M", originalInclude10m);
});

describe("eval common helpers", () => {
  it("parses quick/full options and comma-separated measures", () => {
    const config = parseArgs(["--mode", "full", "--measures", "scaling,attack", "--repeats", "3", "--skip-docker"]);

    expect(config.mode).toBe("full");
    expect(config.repeats).toBe(3);
    expect(config.skipDocker).toBe(true);
    expect(Array.from(config.measures).sort()).toEqual(["attack", "scaling"]);
  });

  it("summarizes metrics with mean, stddev, and median", () => {
    const rows = [
      { group: "a", value: 1, bytes: 10 },
      { group: "a", value: 3, bytes: 14 }
    ];

    expect(groupStats(rows, ["group"], "value")).toEqual([
      { group: "a", metric: "value", count: 2, mean: 2, stddev: 1, median: 2, min: 1, max: 3 }
    ]);
    expect(numericMetricSummaries(rows, ["group"], ["value", "bytes"]).map((row) => row.metric)).toEqual(["value", "bytes"]);
  });
});

describe("scaling measurement", () => {
  it("writes raw data, numeric summaries, and a 10M execution note without measuring 10M by default", async () => {
    process.env.EVAL_LOG_SIZES = "8";
    delete process.env.EVAL_INCLUDE_10M;
    const outDir = mkdtempSync(join(tmpdir(), "vadrex-eval-scaling-"));

    const rows = await measureScaling({
      mode: "quick",
      repeats: 1,
      outDir,
      skipDocker: true,
      measures: new Set(["scaling"])
    });

    expect(rows).toHaveLength(3);
    expect(rows.every((row) => row.verified)).toBe(true);

    const estimate = JSON.parse(readFileSync(join(outDir, "summary", "scaling-10m-estimate.json"), "utf8")) as {
      includedInRun: boolean;
      targetLeaves: number;
    };
    expect(estimate.targetLeaves).toBe(10_000_000);
    expect(estimate.includedInRun).toBe(false);

    const summary = readFileSync(join(outDir, "summary", "scaling-numeric-summary.csv"), "utf8");
    expect(summary).toContain("stddev");
    expect(summary).toContain("proofBytes");
  });
});

function restoreEnv(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}

