# revision-20260917 — supplementary timing and gas run

The supplementary run the paper reports: it separates local verification **compute** time from
**end-to-end** scenario time for the nine violation conditions, measures the anchor contract's gas,
and re-aggregates the published handshake rows. It does not replace `paper-v1`, which remains the
source for the 360-row evaluation.

## 1. Provenance

| | |
|---|---|
| Run | 2026-09-17, one isolated stack, no reset between repeats |
| Repository state | `sourceTreeHash` `8e28c2b98d88dd1291a7ae6e2670fe301f3a8023d79759c157889cf4cfedfd1a` (113 files) |
| Harness | [`eval/revision`](../../revision/) — instrumented copies only, no change to `packages/`, `contracts/` or `scripts/` |
| Isolation | compose project `vadrex-revision-20260917`, ports 18545 / 17001 / 17002 / 18042 / 18043, its own database, chain and volumes |
| Conditions | 9 conditions × 10 repeats = 90 rows, plus one pilot repeat kept separately |
| Outcome | 90/90 matched the expected verdict; the 50 S2/S3 instrumented verifications replayed through the unmodified verifier agreed on verdict and printed lines |

`sourceTreeHash` does **not** cover `eval/revision`. `instrumentation.json` records the SHA-256 of
every tool file as it ran and of each instrumented workspace copy beside the repository file it came
from. `source-hashes.json` and `provenance-check.json` record that the 103 copied repository files
were unchanged during the run and that the gateway image's `shared`, `merkle` and `gateway` sources
and builds (32 files) matched the repository.

This run predates the published harness's `REVISION_RUN` parameters and `instrumentation.json`; both
were added on 2026-09-19. The measurement boundary code — `timing.ts`, `verify-timing-cli.ts`,
`gas.ts` and `timing.test.ts` — is byte-identical between the two versions; the changed files
(`prepare.ts`, `run.ts`, `summarize.ts`, `capture-state.ts`, `check-provenance.ts`, plus the new
`config.ts`) only resolve the run identity, paths, ports and image tags.
[`revision-20260919`](../revision-20260919/) is an independent repetition of the same procedure with
the published harness.

Machine: Intel Core i7-11700K, 32 GB RAM, Windows 11, Node v20.16.0, Docker 20.10.21.

## 2. Conditions and state

Synthetic study 0.25 MiB; anchor interval 30 s; receipt timeout 30 s, except the late-receipt case
which ran with a 5 s timeout and a 10 s simulated delay; `grace=0` for the S2 injections, which end
in the provider check. State accumulated across repeats: anchors A 13 → 123 and B 5 → 35, log leaves
A 26 → 235 and B 8 → 68 (`table1/manifest.json`, `table1/completed.json`,
`table1/anchors-final.json`, `table1/rows.jsonl`). An honest revocation was verified successfully
before the injections (`table1/positive-control.json`).

Compute time for log-entry omission, post-anchor deletion, the log-only append and both S3 cases
includes a full log reconstruction, so it scales with those leaf counts. The accumulated anchor
history here is far smaller than `paper-v1`'s (~1,650 receiver anchors), so these times are not
comparable with it as a speed improvement.

## 3. Results

Mean ± standard deviation over ten repeats, denominator `n`, as in `paper-v1`
(`summary/timing.json`, `summary/timing.csv`):

| Case | Correct | Compute (ms) | End-to-end (s) |
|---|---|---|---|
| Historical log tampering | 10/10 | 0.16 ± 0.06 | 9.55 ± 1.56 |
| Log-entry omission | 10/10 | 3.55 ± 1.89 | 1.26 ± 0.64 |
| Post-anchor completion deletion | 10/10 | 5.25 ± 2.33 | 10.54 ± 1.10 |
| Reused treeSize (contract revert) | 10/10 | N/A | 5.55 ± 0.62 |
| Append seq=k+1 | 10/10 | 20.54 ± 2.24 | 17.62 ± 0.96 |
| Skip to seq=k+7 | 10/10 | 20.83 ± 2.28 | 17.38 ± 0.81 |
| Log-only append, stale head | 10/10 | 36.31 ± 7.70 | 17.58 ± 1.08 |
| Receiver denial after anchoring | 10/10 | 27.01 ± 8.26 | 12.63 ± 2.19 |
| No timely completion pair | 10/10 | 26.75 ± 8.31 | 23.18 ± 1.22 |

`N/A` marks the contract rejecting the registration rather than a local verifier reaching a verdict.
Measurement boundaries are in [eval/revision/README.md](../../revision/README.md).

Gas (`gas.json`, `summary/gas.json`), ten fresh contracts, identical input hashes, Solidity
0.8.20+commit.a1b79de6, optimizer enabled with 200 runs, EVM target `paris`, Hardhat 2.28.6 on its
in-process network: deploy 444,021, first anchor 160,481, subsequent anchor 143,369 gas, with the
receipt `gasUsed` equal to the estimate in every case. This is on-chain computation only — no public
network fee, congestion or confirmation delay.

`summary/handshake.json` re-aggregates the 30 published handshake rows of
[`paper-v1`](../paper-v1/raw/handshake_overhead.csv) into absolute times and effective throughput
over the pixel payload. It measures nothing new.

## 4. What is published here

Row-level records (`table1/rows.jsonl`, `pilot1/rows.jsonl`) carry, per case and repeat, both times,
the anchor counts before and after, the tree size where applicable, the replay agreement and the
verifier's printed verdict lines. Per-case stdout logs and per-case timing shards are redundant with
those records and stay local. The synthetic DICOM file, SQLite databases, chain state, certificates,
keys and the workspace itself are not published: the workspace is rebuilt by `prepare.ts` and the
study is generated by the harness.

`SHA256SUMS` covers every file in this directory.
