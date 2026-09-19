# Supplementary measurement harness

Evaluation-only tooling that separates two times the main harness reports as one: the local
verification **compute** time and the **end-to-end** scenario time of the same violation case. It
also measures the anchor contract's gas locally and re-aggregates the published handshake rows into
absolute times and throughput.

It adds no protocol, API, schema or verdict logic. `packages/`, `contracts/` and `scripts/` are
never edited in place: `prepare.ts` copies the tracked sources into an isolated workspace and
instruments only that copy. The verdicts come from the repository's own verifier, and every
instrumented run is replayed through the unmodified verifier to confirm the verdict and the printed
lines are identical.

`sourceTreeHash` (see [eval/reference/source-manifest.txt](../reference/source-manifest.txt)) does
not cover this directory. An unchanged `sourceTreeHash` therefore says nothing about this harness;
`instrumentation.json` in each run directory records the SHA-256 of every tool file and of each
instrumented workspace copy next to the repository file it came from.

## Outputs

A run writes to `eval/out/revision-<REVISION_RUN>/`:

| Path | Contents |
|---|---|
| `table1/rows.jsonl` | one record per case and repeat: compute ms, invocation ms, total ms, anchors before/after, tree size, replay agreement, verdict lines |
| `table1/manifest.json`, `completed.json` | run configuration, state policy, initial/final anchor counts |
| `table1/positive-control.json` | an honest revocation verified successfully before the injections |
| `table1/anchors-final.json` | on-chain anchor list read back after the timed trials |
| `pilot1/` | the pilot repeat; excluded from the reported aggregates, kept as run history |
| `gas.json` | deploy, first anchor and subsequent anchor gas (estimate and receipt `gasUsed`), with compiler settings |
| `summary/` | `timing.{json,csv}`, `gas.json`, `handshake.json` aggregates (standard deviation over denominator `n`, as in paper-v1) |
| `source-hashes.json`, `instrumentation.json`, `preparation.json` | provenance of the copied sources, the instrumented copies and the run configuration |
| `provenance-check.json` | repository files unchanged during the run, and the gateway image's `shared`/`merkle`/`gateway` sources and builds identical to the repository |

## Measurement boundaries

| Case | Local compute time | End-to-end time |
|---|---|---|
| Historical log tampering | the consistency check inside `runS1OnchainTamper` | anchor/log reads, isolated contract deployment, injection and verdict |
| Log-entry omission | tree recomputation over the anchored prefix and comparison | data reads, honest-root control and verdict |
| Post-anchor completion deletion | root recomputation and comparison after reading the tampered database copy | normal transfer, anchor wait, copy injection, comparison and script exit |
| Reused treeSize | N/A — the contract rejects it, not the local verifier | checkpoint and anchoring, the call, and the rejection |
| S2 (three cases) | the executed compute segments of the original verifier up to the first verdict | per case, from case preparation to the verdict, including the gateway restart inside the case |
| S3 (two cases) | the executed compute segments of the original dispute verifier up to the verdict | the evaluation script process, from start to clean exit |

Common environment setup, builds, and configuration changes made outside a case are excluded from
the end-to-end time, so these totals are not a baseline for deployment or operational latency. S2 is
timed inside the case while the other end-to-end scripts are timed at the process boundary, so
Node/tsx startup is included in the latter. The S2 and S3 totals also include the instrumented
verifier's tsx startup and the replay check. Compute time and end-to-end time are different scopes.

`ActiveTimer` stops for the duration of every API and RPC call. The excluded boundaries are
`GatewayClient.tryGet` and `AnchorReader.anchorCount/getAnchor`, which also covers TLS file reads and
response-envelope decoding. Canonical entry parsing, hashing, proof and signature verification, log
reconstruction and the verdict conditions actually executed are included. This is elapsed time over
the active segments, not operating-system CPU time. Proof generation is server side and excluded.
The S1 local checks are timed at their own boundaries. No fixed wait is ever subtracted afterwards
to estimate a compute time.

The instrumented verifier keeps its API and RPC responses in memory and, after the timer stops,
replays them through the unmodified verifier to confirm the verdict and the printed lines match. The
replay is outside the compute time and inside the script's end-to-end time.

Compute times for the omission, deletion, log-only-append and both S3 cases include a full log
reconstruction, so they scale with the log, not only with the anchor count. Record the leaf counts
of a run together with its anchor counts; the values of the published runs are in their
`PROVENANCE.md`.

## Isolation and configuration

A run owns its output directory, compose project, host ports and image tags, all derived from
`REVISION_RUN` ([config.ts](config.ts)):

| Variable | Default | Effect |
|---|---|---|
| `REVISION_RUN` | `20260917` | output `eval/out/revision-<id>`, compose project `vadrex-revision-<id>`, image tags `vadrex-revision-<id>-{gateway,chain}:local` |
| `REVISION_PORT_OFFSET` | `10000` | added to 8545, 7001, 7002, 8042, 8043 |
| `REVISION_PROJECT` | derived | compose project name, if the derived one is unsuitable |
| `REVISION_LABEL` | `table1` | subdirectory of the run for one invocation of `run.ts` |
| `REVISION_REPEATS` | `10` | repeats of the nine conditions |
| `REVISION_OUTPUT` | — | run directory for the gas script, which executes from `contracts/` |

The ordinary stack (project `vadrex`, ports 8545/7001/7002/8042/8043, images `vadrex-gateway:local`
and `vadrex-chain:local`) is never started, rebuilt or reset by this harness. `prepare.ts` refuses to
run when the workspace of that `REVISION_RUN` already exists, so an existing run is never
overwritten; choose a new `REVISION_RUN` instead. Repeats accumulate state inside a run and are not
reset between cases.

## Running it from a fresh clone

Windows 11 with PowerShell 5.1, Docker Desktop running, and Node.js 20 (see `.nvmrc`), as in
[REPRODUCIBILITY.md](../../REPRODUCIBILITY.md). About 40 minutes, most of it the ten repeats.

```powershell
git clone https://github.com/vadrex-git/VADREX.git
cd VADREX
npm ci
npm run build                                   # packages + contracts artifacts
.\scripts\ca-setup.ps1                          # research CA and institution certificates
npm run keygen                                  # Ed25519 and anchoring wallet keys

$env:REVISION_RUN = '20260919'                  # any new identifier
$env:REVISION_PORT_OFFSET = '20000'             # any free offset
node --import tsx eval/revision/timing.test.ts
node --import tsx eval/revision/prepare.ts      # prints the isolated workspace path

Set-Location eval\out\revision-20260919\workspace
docker compose build                            # this run's own image tags
docker compose up -d chain orthanc-a orthanc-b
Set-Location contracts
npm.cmd run deploy                              # writes data/deployments.local.json
Set-Location ..
docker compose up -d gateway-a gateway-b

$env:REVISION_LABEL='pilot1'; $env:REVISION_REPEATS='1'
node --import tsx eval/revision/run.ts
$env:REVISION_LABEL='table1'; $env:REVISION_REPEATS='10'
node --import tsx eval/revision/run.ts

Set-Location contracts                          # gas, on a separate in-process Hardhat network
$env:REVISION_OUTPUT="$PWD\..\..\..\..\eval\out\revision-20260919"
npx.cmd hardhat run scripts/revision-gas.ts --network hardhat

Set-Location ..\..\..\..\..                     # back to the repository root
node --import tsx eval/revision/summarize.ts
node --import tsx eval/revision/capture-state.ts
node --import tsx eval/revision/check-provenance.ts
docker compose -p vadrex-revision-20260919 -f eval\out\revision-20260919\workspace\docker-compose.yml down
```

`run.ts` asserts that it runs inside that run's workspace, and `capture-state.ts` and
`check-provenance.ts` read the same `REVISION_RUN`, so keep the variables set for the whole
sequence. Structural results — verdict counts, replay agreement, gas, proof and row counts — must
match exactly. Times depend on the machine and on the accumulated state, so compare them
statistically and alongside the anchor and leaf counts.

## Published runs

Results are published under `eval/reference/`, separate from `paper-v1`, with their own provenance
and checksums:

- [`eval/reference/revision-20260917/`](../reference/revision-20260917/) — the run the paper reports.
- [`eval/reference/revision-20260919/`](../reference/revision-20260919/) — an independent repetition
  of the same procedure from the published clone.

Each of those directories publishes the row-level records, aggregates, manifests and provenance.
Per-case stdout logs and per-case timing shards stay local: `rows.jsonl` already carries both times,
the anchor counts and the verdict lines of every case. The synthetic DICOM file, the SQLite
databases, the chain state, certificates, keys and the workspace itself are not published; the
workspace is reconstructed by `prepare.ts` and the study by the harness.
