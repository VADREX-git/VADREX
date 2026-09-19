# revision-20260919 — independent repetition of the supplementary run

The same nine violation conditions, gas measurement and handshake re-aggregation as
[`revision-20260917`](../revision-20260917/), repeated from a fresh clone of this repository with
the published harness. It exists to show that the supplementary procedure reproduces outside the
machine state it was first measured on. **The paper reports `revision-20260917`; nothing here
replaces those numbers.**

## 1. Provenance

| | |
|---|---|
| Run | 2026-09-19 07:41:01Z → 08:06:51Z, one isolated stack, no reset between repeats |
| Starting point | `git clone https://github.com/vadrex-git/VADREX.git` at `f5cecca9543fbc23bacae0ca10e73f03d81478d9`, then `npm ci`, `npm run build`, `scripts/ca-setup.ps1`, `npm run keygen` |
| Repository state | `sourceTreeHash` `8e28c2b98d88dd1291a7ae6e2670fe301f3a8023d79759c157889cf4cfedfd1a` (113 files), verified with `eval/reference/source-hash.ps1` on PowerShell 5.1 |
| `paper-v1` integrity | `SHA256SUMS` 44/44 verified in the same clone |
| Harness | published [`eval/revision`](../../revision/) with `REVISION_RUN=20260919`, `REVISION_PORT_OFFSET=20000` |
| Isolation | compose project `vadrex-revision-20260919`, ports 28545 / 27001 / 27002 / 28042 / 28043, images `vadrex-revision-20260919-{gateway,chain}:local` built in this run, its own database, chain and volumes |
| Conditions | 9 conditions × 10 repeats = 90 rows, plus one pilot repeat kept separately |
| Outcome | 90/90 matched the expected verdict; 50/50 instrumented S2/S3 verifications agreed with the unmodified verifier on replay; the honest-revocation control verified successfully |

Unlike the 2026-09-17 run, which reused the ordinary stack's prebuilt images and verified them by
hashing their contents, this run built its own images from the clone. `provenance-check.json`
records that the 104 copied repository files were unchanged during the run and that the gateway
image's `shared`, `merkle` and `gateway` sources and builds (32 files) match the repository.
`instrumentation.json` records the SHA-256 of every tool file and of each instrumented workspace
copy, beside the repository file it came from.

Machine: Intel Core i7-11700K, 32 GB RAM, Windows 11, Node v20.16.0, Docker 20.10.21.

## 2. Conditions and state

Identical to the 2026-09-17 run: synthetic study 0.25 MiB, anchor interval 30 s, receipt timeout
30 s except the late-receipt case (5 s timeout, 10 s simulated delay), `grace=0` for the S2
injections, state accumulating across repeats.

| | 2026-09-17 | 2026-09-19 |
|---|---|---|
| anchors A | 13 → 123 | 13 → 124 |
| anchors B | 5 → 35 | 5 → 35 |
| log leaves A | 26 → 235 | 26 → 235 |
| log leaves B | 8 → 68 | 8 → 68 |

The one extra provider anchor is an additional checkpoint registered while a case waited for its
anchor; it does not change any verdict.

## 3. What matched exactly

| Quantity | 2026-09-17 | 2026-09-19 |
|---|---|---|
| Expected verdicts | 90/90 | 90/90 |
| Replay agreement (S2, S3) | 50/50 | 50/50 |
| Cases with no local compute time | reused treeSize (contract revert) | same |
| Deploy gas (estimate = `gasUsed`) | 444,021 | 444,021 |
| First anchor gas | 160,481 | 160,481 |
| Subsequent anchor gas | 143,369 | 143,369 |
| Handshake re-aggregation (30 published rows) | identical | identical |

Gas was measured on ten fresh contracts with identical input hashes, Solidity 0.8.20, optimizer 200
runs, EVM target `paris`, Hardhat 2.28.6 in-process network. The handshake aggregate is computed
from [`paper-v1/raw/handshake_overhead.csv`](../paper-v1/raw/handshake_overhead.csv) and measures
nothing new, so equality there only confirms the aggregation path.

## 4. Times

Mean ± standard deviation over ten repeats, denominator `n`. Times are machine- and state-dependent
and are to be read statistically, not as a match:

| Case | Compute (ms) 09-17 → 09-19 | End-to-end (s) 09-17 → 09-19 |
|---|---|---|
| Historical log tampering | 0.16 ± 0.06 → 0.14 ± 0.05 | 9.55 ± 1.56 → 7.55 ± 2.15 |
| Log-entry omission | 3.55 ± 1.89 → 2.94 ± 1.64 | 1.26 ± 0.64 → 1.62 ± 0.81 |
| Post-anchor completion deletion | 5.25 ± 2.33 → 4.43 ± 1.96 | 10.54 ± 1.10 → 10.54 ± 1.32 |
| Reused treeSize (contract revert) | N/A | 5.55 ± 0.62 → 5.43 ± 1.39 |
| Append seq=k+1 | 20.54 ± 2.24 → 21.35 ± 2.51 | 17.62 ± 0.96 → 18.28 ± 1.14 |
| Skip to seq=k+7 | 20.83 ± 2.28 → 22.49 ± 2.94 | 17.38 ± 0.81 → 18.26 ± 1.32 |
| Log-only append, stale head | 36.31 ± 7.70 → 38.44 ± 8.27 | 17.58 ± 1.08 → 18.36 ± 1.25 |
| Receiver denial after anchoring | 27.01 ± 8.26 → 27.66 ± 9.57 | 12.63 ± 2.19 → 13.86 ± 1.79 |
| No timely completion pair | 26.75 ± 8.31 → 27.72 ± 8.65 | 23.18 ± 1.22 → 23.36 ± 2.07 |

Every pair overlaps within one standard deviation.

## 5. What is published here

The same selection as `revision-20260917`: row-level records, aggregates, manifests, the positive
control, the anchor snapshot and the provenance files. Per-case stdout logs and timing shards, the
synthetic DICOM file, the databases, chain state, certificates, keys and the workspace stay local;
`rows.jsonl` already carries both times, the anchor counts and the verdict lines per case.

`SHA256SUMS` covers every file in this directory.
