# VADREX Local Evaluation

This directory contains the local-only measurement harness and plotting pipeline.

The entry point is `evaluate.cmd` at the repository root. Run `reproduce.cmd` first so the stack is up.

```powershell
cd VADREX
.\evaluate.cmd quick
.\evaluate.cmd full
.\evaluate.cmd paper
```

## Profiles

Profiles are data, not code — see `eval/profiles/*.json`. Each one fixes the scale sets, the repeat
count, and the completion criteria, and its SHA-256 is recorded in every run's `run-manifest.json`.

| Profile | Purpose | Repeats | Rows | Runtime |
|---|---|---:|---:|---|
| `quick` | install / pipeline validation. **Not paper numbers.** | 2 | 44 | ~8 min |
| `full` | pre-paper regression check | 1 | 26 | ~15 min |
| `paper` | paper dataset regeneration | 10 | 360 | hours |

Runtimes are measured on the reference machine and are dominated by wall-clock waits (anchor
intervals, receipt timeouts), not CPU — expect them to be similar on slower hardware. The `full`
and `paper` figures are estimates carried over from the pre-container stack; they should drop now
that gateway restarts no longer reinstall dependencies. `paper` is re-timed when it is next run.

`full` keeps the full-only code paths that historically broke — the 200MiB handshake
(`DICOM_MAX_BODY_BYTES` / HTTP 413), the 50-anchor verify-cost (nonce isolation), and every
S1/S2/S3 attack case (peer hold, gateway restart, ECONNRESET). It drops only the wait-dominated
points (300s anchor intervals, 100-anchor verify-cost, 1M-leaf scaling), which change runtime but
not the executed code path.

`paper` runs the six measures in a fixed order and refuses to start on a dirty tree. Do not run the
measures in parallel: `verify-cost` and `grace` depend on the anchor state accumulated by earlier
measures.

## Reset before a paper run

```powershell
.\reproduce.cmd -Reset
```

`docker compose down -v` does **not** reset evaluation state — the accumulated anchors live in the
host files `data/inst-*/audit.db` and in the in-memory chain, so `-v` only wipes Orthanc storage and
the node_modules volumes. `reproduce.cmd -Reset` runs `scripts/reset-local.ps1`, which stops the
gateways, backs up and removes the audit DBs, recreates the chain from block 0, redeploys the
contracts, and restarts the gateways against the new addresses.

## Running unattended

A `paper` run takes hours, so there is no reason to watch it. The completion criteria are checked
by `scripts/verify-run.ps1`, not by reading CSVs.

```powershell
.\evaluate.cmd paper -Detach
```

`-Detach` starts a background worker, records the run directory in `eval/out/latest-run.txt`, and
returns immediately with the PID and path.

1. Start the run and leave it alone.
2. When it exits, read `status.json`. If `verdict == "pass"`, you are done — every completion
   condition (row counts, `S1 4 / S2 3 / S3 2`, zero failures, scaling `verified`, figures, clean
   tree) has already been checked, and the reasons are recorded in `verdictReasons`.
3. If `verdict != "pass"`, read `logs/failure-context.log`. It aggregates the failed, waiting and
   skipped counts, the diagnostic signals, and bounded tails of stdout and stderr.
4. Open the raw CSV and JSON only if that is still not enough.

## Outputs

Each run writes:

- `status.json`: watchdog state plus the **`verdict`** (`pass` / `fail`), `verdictReasons`, and the
  checked counts. This is the only file you need on the happy path.
- `config.resolved.json`: the profile, every resolved `EVAL_*` / runtime environment variable, the
  completion criteria, and the source commit/tree hash.
- `run-manifest.json`: verdict, timings, source state, and SHA-256 of the profile,
  `package-lock.json`, and `docker-compose.yml`, plus the anchor contract addresses.
- `PROVENANCE.md`: human-readable summary of the above.
- `SHA256SUMS`: SHA-256 of every published result file.
- `environment.json`: CPU, memory, Node/npm version, git status, mode, repeats.
- `raw/*.csv` and `raw/*.json`: raw measurement records.
- `summary/*.csv`, `summary/report.md`: summary statistics and the generated report.
- `figures/*.png`: six figures.
- `logs/failure-context.log`: written only when the run does not finish clean.

## Measures

- `scaling`: proof size and verification time for RFC6962 inclusion, RFC6962 consistency, and SMT non-inclusion.
- `revocation-delay`: consent revocation API call to anchored revocation inclusion.
- `handshake`: synthetic DICOM direct Orthanc WADO->STOW baseline versus full Gateway transfer.
- `verify-cost`: `verifyNonTransfer()` total time, API/RPC calls, and Gateway API bytes by elapsed anchor count.
- `grace`: `ANCHOR_MAX_INTERVAL_SEC` grace-window tradeoff.
- `attack`: S1/S2/S3 violation injection detection.

## Important Notes

- No external RPC, testnet, faucet, or paid service is used.
- Synthetic DICOM files are generated locally under `eval/out/synthetic-dicom/`.
- Contract addresses and Ed25519 public keys are pinned from local files, not trusted from Gateway responses.
- 10^7 leaves are not run by default. Set `EVAL_INCLUDE_10M=true` only after reviewing runtime and memory expectations.
- Docker-dependent measures require `ENABLE_DEV_ENDPOINTS=true` in the local compose stack because they use evaluation-only checkpoints and manual anchoring.

