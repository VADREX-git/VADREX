import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { cpus, freemem, platform, release, totalmem } from "node:os";
import { dirname, join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";

export type EvalMode = "quick" | "full";

export interface EvalConfig {
  mode: EvalMode;
  repeats: number;
  outDir: string;
  skipDocker: boolean;
  measures: Set<string>;
}

export interface SummaryStats {
  count: number;
  mean: number;
  stddev: number;
  median: number;
  min: number;
  max: number;
}

export const rootDir = resolve(fileURLToPath(new URL("../..", import.meta.url)));

export function parseArgs(argv: string[] = process.argv.slice(2)): EvalConfig {
  let mode: EvalMode = (process.env.EVAL_MODE as EvalMode | undefined) ?? "quick";
  let outDir = process.env.EVAL_OUT_DIR ?? "";
  let skipDocker = process.env.EVAL_SKIP_DOCKER === "true";
  let measures = new Set<string>();
  let repeatsOverride: number | null = null;

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--mode") {
      const value = argv[++index];
      if (value !== "quick" && value !== "full") {
        throw new Error("--mode must be quick or full");
      }
      mode = value;
    } else if (arg === "--out") {
      outDir = argv[++index] ?? "";
    } else if (arg === "--skip-docker") {
      skipDocker = true;
    } else if (arg === "--measures") {
      measures = new Set((argv[++index] ?? "").split(",").map((value) => value.trim()).filter(Boolean));
    } else if (arg === "--repeats") {
      const parsed = Number(argv[++index]);
      if (!Number.isSafeInteger(parsed) || parsed < 1) {
        throw new Error("--repeats must be an integer >= 1");
      }
      repeatsOverride = parsed;
    } else {
      throw new Error(`unknown eval argument: ${arg}`);
    }
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const resolvedOutDir = outDir ? resolve(outDir) : join(rootDir, "eval", "out", `${timestamp}-${mode}`);
  const envRepeats = process.env.EVAL_REPEATS ? Number(process.env.EVAL_REPEATS) : undefined;
  const defaultRepeats = mode === "quick" ? 2 : 10;
  const repeats = repeatsOverride ?? (Number.isSafeInteger(envRepeats) && envRepeats! > 0 ? envRepeats! : defaultRepeats);

  if (measures.size === 0) {
    measures = new Set(["scaling", "revocation-delay", "handshake", "verify-cost", "grace", "attack"]);
  }

  return {
    mode,
    repeats,
    outDir: resolvedOutDir,
    skipDocker,
    measures
  };
}

export function ensureRunDirs(outDir: string): void {
  for (const subdir of ["raw", "summary", "figures", "logs"]) {
    mkdirSync(join(outDir, subdir), { recursive: true });
  }
}

export function writeJson(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

export function writeCsv(path: string, rows: readonly Record<string, unknown>[]): void {
  mkdirSync(dirname(path), { recursive: true });
  if (rows.length === 0) {
    writeFileSync(path, "", "utf8");
    return;
  }
  const headers = Array.from(rows.reduce((set, row) => {
    for (const key of Object.keys(row)) {
      set.add(key);
    }
    return set;
  }, new Set<string>()));
  const lines = [headers.join(",")];
  for (const row of rows) {
    lines.push(headers.map((header) => csvCell(row[header])).join(","));
  }
  writeFileSync(path, `${lines.join("\n")}\n`, "utf8");
}

export function appendMarkdown(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, "utf8");
}

export function stats(values: readonly number[]): SummaryStats {
  const finite = values.filter((value) => Number.isFinite(value)).sort((left, right) => left - right);
  if (finite.length === 0) {
    return { count: 0, mean: 0, stddev: 0, median: 0, min: 0, max: 0 };
  }
  const mean = finite.reduce((sum, value) => sum + value, 0) / finite.length;
  const variance = finite.reduce((sum, value) => sum + (value - mean) ** 2, 0) / finite.length;
  const mid = Math.floor(finite.length / 2);
  const median = finite.length % 2 === 0 ? (finite[mid - 1] + finite[mid]) / 2 : finite[mid];
  return {
    count: finite.length,
    mean,
    stddev: Math.sqrt(variance),
    median,
    min: finite[0],
    max: finite[finite.length - 1]
  };
}

export function groupStats(
  rows: readonly Record<string, unknown>[],
  groupKeys: readonly string[],
  metric: string
): Record<string, unknown>[] {
  const groups = new Map<string, Record<string, unknown>[]>();
  for (const row of rows) {
    const key = groupKeys.map((groupKey) => String(row[groupKey])).join("|");
    const current = groups.get(key) ?? [];
    current.push(row);
    groups.set(key, current);
  }
  return Array.from(groups.values()).map((groupRows) => {
    const first = groupRows[0];
    const summary = stats(groupRows.map((row) => Number(row[metric])));
    return {
      ...Object.fromEntries(groupKeys.map((key) => [key, first[key]])),
      metric,
      count: summary.count,
      mean: round(summary.mean),
      stddev: round(summary.stddev),
      median: round(summary.median),
      min: round(summary.min),
      max: round(summary.max)
    };
  });
}

export function numericMetricSummaries(
  rows: readonly Record<string, unknown>[],
  groupKeys: readonly string[],
  metrics: readonly string[]
): Record<string, unknown>[] {
  return metrics.flatMap((metric) => groupStats(rows, groupKeys, metric));
}

export async function timed<T>(fn: () => Promise<T> | T): Promise<{ value: T; ms: number }> {
  const start = performance.now();
  const value = await fn();
  return { value, ms: performance.now() - start };
}

export function repoPath(...parts: string[]): string {
  return join(rootDir, ...parts);
}

export function run(command: string, args: string[], options: { env?: NodeJS.ProcessEnv; quiet?: boolean } = {}): string {
  const result = spawnSync(command, args, {
    cwd: rootDir,
    env: options.env ?? process.env,
    encoding: "utf8",
    shell: process.platform === "win32"
  });
  if (!options.quiet && result.stdout) {
    process.stdout.write(result.stdout);
  }
  if (!options.quiet && result.stderr) {
    process.stderr.write(result.stderr);
  }
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed with exit ${result.status ?? "unknown"}\n${result.stdout}\n${result.stderr}`);
  }
  return result.stdout;
}

export function commandExists(command: string): boolean {
  const checker = process.platform === "win32" ? "where.exe" : "command";
  const args = process.platform === "win32" ? [command] : ["-v", command];
  const result = spawnSync(checker, args, { encoding: "utf8", shell: process.platform !== "win32" });
  return result.status === 0;
}

export function readTextIfExists(path: string): string | null {
  return existsSync(path) ? readFileSync(path, "utf8") : null;
}

export function environmentInfo(): Record<string, unknown> {
  return {
    capturedAt: new Date().toISOString(),
    platform: platform(),
    release: release(),
    cpuModel: cpus()[0]?.model ?? "unknown",
    cpuCount: cpus().length,
    totalMemoryBytes: totalmem(),
    freeMemoryBytes: freemem(),
    nodeVersion: process.version,
    npmVersion: safeExec("npm", ["--version"]),
    gitCommit: safeExec("git", ["rev-parse", "HEAD"]),
    gitStatusShort: safeExec("git", ["status", "--short"])
  };
}

export function modeSizes(mode: EvalMode): number[] {
  const explicit = process.env.EVAL_LOG_SIZES;
  if (explicit) {
    return explicit.split(",").map((value) => Number(value.trim())).filter((value) => Number.isSafeInteger(value) && value > 0);
  }
  const sizes = mode === "quick" ? [1_000, 10_000] : [1_000, 10_000, 100_000, 1_000_000];
  if (mode === "full" && process.env.EVAL_INCLUDE_10M === "true") {
    sizes.push(10_000_000);
  }
  return sizes;
}

export function modeAnchorIntervals(mode: EvalMode): number[] {
  const explicit = process.env.EVAL_ANCHOR_INTERVALS;
  if (explicit) {
    return explicit.split(",").map((value) => Number(value.trim())).filter((value) => Number.isSafeInteger(value) && value > 0);
  }
  return mode === "quick" ? [10] : [10, 30, 60, 300];
}

export function modeAnchorCounts(mode: EvalMode): number[] {
  const explicit = process.env.EVAL_ANCHOR_COUNTS;
  if (explicit) {
    return explicit.split(",").map((value) => Number(value.trim())).filter((value) => Number.isSafeInteger(value) && value > 0);
  }
  return mode === "quick" ? [1, 3] : [1, 10, 50, 100];
}

export function modeStudySizes(mode: EvalMode): { label: string; targetBytes: number }[] {
  const explicit = process.env.EVAL_STUDY_SIZES;
  if (explicit) {
    return explicit.split(",").map((part) => {
      const [label, bytes] = part.split(":");
      return { label: label.trim(), targetBytes: Number(bytes) };
    }).filter((item) => item.label && Number.isSafeInteger(item.targetBytes) && item.targetBytes > 0);
  }
  if (mode === "quick") {
    return [
      { label: "small", targetBytes: 1 * 1024 * 1024 },
      { label: "medium", targetBytes: 5 * 1024 * 1024 },
      { label: "large", targetBytes: 10 * 1024 * 1024 }
    ];
  }
  return [
    { label: "small", targetBytes: 5 * 1024 * 1024 },
    { label: "medium", targetBytes: 50 * 1024 * 1024 },
    { label: "large", targetBytes: 200 * 1024 * 1024 }
  ];
}

export function round(value: number, digits = 3): number {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function csvCell(value: unknown): string {
  if (value === null || value === undefined) {
    return "";
  }
  const text = typeof value === "string" ? value : JSON.stringify(value);
  if (/[",\n\r]/.test(text)) {
    return `"${text.replace(/"/g, "\"\"")}"`;
  }
  return text;
}

function safeExec(command: string, args: string[]): string | null {
  try {
    return execFileSync(command, args, { cwd: rootDir, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return null;
  }
}
