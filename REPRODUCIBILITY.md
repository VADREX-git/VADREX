# Reproducibility

How to reproduce the system and the paper's measurements, what is checked automatically, and how to
compare your results against ours.

## 1. Supported environment

The reference environment is the machine the paper's numbers were measured on.

| | Reference |
|---|---|
| OS | Windows 11 Home 10.0.26200, PowerShell 5.1 |
| Node.js | 20.16.0 |
| npm | 10.8.2 |
| Docker | 20.10.21 |
| Docker Compose | v2.12.2 |

Windows is the only supported host. The entry points are PowerShell, the evaluation harness reads
the gateways' SQLite files directly from host paths, and the reset procedure manipulates them.
Nothing else is required on the host — Python, OpenSSL, and every service run in pinned containers.

**Resources.** At least **16 GB RAM** and **40 GB free disk on `C:`**. The `paper` profile builds a
1,000,000-leaf log tree with all leaf preimages in memory, and relays a 200 MiB study base64-encoded
through the gateway (`DICOM_MAX_BODY_BYTES` is raised to 512 MiB for full-mode runs). Disk is
consumed by the container images, Orthanc storage, synthetic DICOM, and run outputs.

**Check `C:`, not the drive holding the repository.** Docker's virtual disk lives under
`%LOCALAPPDATA%\Docker\wsl` wherever you cloned to, and it accounts for most of the space. Cloning
onto a roomy second drive does not help if `C:` is full.

Measured after one complete cycle — bootstrap, image builds, one `paper` run and one auxiliary run:

```
13.9 GB   %LOCALAPPDATA%\Docker\wsl\data\ext4.vhdx     (images, containers, Orthanc storage)
 1.1 GB   %LOCALAPPDATA%\Docker\wsl\distro\ext4.vhdx
 1.5 GB   the repository (node_modules 0.5, audit DBs and reset backups 0.7)
─────────
16.6 GB   total
```

40 GB is the recommended figure rather than the measured one, because the virtual disk grows but
never shrinks (see below) and each rebuild leaves reclaimable layers behind. `reproduce.cmd`
enforces a hard floor of 20 GB, which is enough to bootstrap but not to repeat a `paper` run;
`evaluate.cmd paper` checks for 25 GB before starting an eleven-hour measurement.

The handshake measure deletes each synthetic study from both Orthanc instances and from the host
once its row is recorded, so repeated runs do not accumulate. Before that cleanup existed, one
`paper` run left roughly 10 GB in Orthanc storage and 4 GB on the host permanently, and repeated
runs filled the disk and killed the Docker engine mid-measurement. If you interrupt a run, check
`docker system df` and `eval/out/synthetic-dicom` — an aborted run can still leave studies behind.

On Docker Desktop with the WSL2 backend, note that the backing virtual disk **grows but never
shrinks**: freeing space inside it does not return space to the host. `wsl --manage
docker-desktop-data --set-sparse true` returns only already-trimmed blocks. Reclaiming the rest
needs either administrator rights (`diskpart compact vdisk`) or a Docker data reset
(`wsl --unregister docker-desktop-data`, which deletes all images and volumes).

`docker image prune` will not shrink the virtual disk either, but it does stop it from growing
further when you rebuild images repeatedly.

## 2. Pinned images

Every base image is pinned by digest, not tag.

| Image | Digest | Used by |
|---|---|---|
| `node` | `sha256:8f693eaa7e0a8e71560c9a82b55fd54c2ae920a2ba5d2cde28bac7d1c01c9ba5` | `docker/Dockerfile.gateway` — chain and both gateways |
| `orthancteam/orthanc` | `sha256:83a1f988c9790a8ec018d00bad2d23d29703313e10ec59ecbeb827b5fa8e0aee` | Orthanc A and B |
| `alpine/openssl` | `sha256:0b22ba3ac61b6bcc56e34506f1b548281e46986d70e0e539c94a70452b283cff` | `scripts/ca-setup.ps1` |
| `python` | `sha256:6b3223eb4d93718828223966ad316909c39813dee3ee9395204940500792b740` | `docker/Dockerfile.plot` — figures |

Node dependencies come from `package-lock.json` via `npm ci`. The plotting stack is pinned to exact
versions in `eval/plot/requirements.txt` (matplotlib 3.11.0, pandas 3.0.3, numpy 2.5.1).

`ca-setup.ps1` uses the pinned OpenSSL container by default. `-UseHostOpenSsl` opts into the host
binary, which is **not** reproducible — different OpenSSL versions produce different certificate and
PKCS#12 defaults.

## 3. Bootstrapping

```powershell
.\reproduce.cmd
```

Steps, in a fixed order:

1. `prerequisites` — Node ≥ 20, npm, Docker engine reachable, free disk
2. `ports` — 7001, 7002, 8042, 8043, 8545 free, or already owned by this stack
3. `npm-install` — `npm ci` when `node_modules` is absent
4. `certificates` — CA and institution mTLS certificates when absent
5. `institution-keys` — Ed25519 signing keys and anchoring wallet keys when absent
6. `images` — `docker compose build`
7. `chain` — start the chain only, wait for JSON-RPC
8. `contracts` — deploy the two Anchor contracts unless code already exists at the recorded addresses
9. `state-consistency` — compare local anchor records against on-chain anchors
10. `services` — start Orthanc A/B and both gateways, wait for mTLS health
11. `sample-dicom` — generate a synthetic study and STOW it to Orthanc A
12. `contract-smoke` — register/query round-trip on a throwaway Anchor instance
13. `e2e-compliant` — consent, transfer, revocation, patient verification

The result is written to `reproduce-status.json` with a per-step breakdown and a `verdict`.

### Why the order is fixed

- **Image build precedes contract deployment.** If the image changes after deployment, Compose
  recreates the chain container; the Hardhat chain is in-memory, so it restarts at block 0 and the
  deployed contracts vanish. A subsequent smoke run would then deploy at nonce 0 — the same address
  as institution A's recorded anchor — and write a fake root into it.
- **Chain precedes contract deployment precedes the gateways.** A gateway reads its anchor contract
  address once at startup, so it must start after deployment.
- **The chain image contains only `contracts/`.** `docker/Dockerfile.gateway` has two targets: the
  `chain` target copies just the contracts workspace, while the `gateway` target copies the whole
  tree. Editing application source or documentation therefore rebuilds only the gateway image, and
  the chain container is left alone — otherwise every edit would discard the blockchain state.

If the chain is ever recreated while the audit databases survive, step 9 detects the divergence and
tells you to run `.\reproduce.cmd -Reset` rather than letting it surface much later as a failed
anchor registration.

## 4. Evaluation

```powershell
.\evaluate.cmd quick     # ~8 min   pipeline validation, not paper numbers
.\evaluate.cmd full      # ~15 min  26 rows, pre-paper regression check
.\evaluate.cmd paper     #          360 rows, the paper dataset
```

Profiles are data, not code: `eval/profiles/*.json` fixes the scale sets, the repeat count, and the
completion criteria, and each profile's SHA-256 is recorded in every run's manifest.

`full` deliberately keeps the full-only code paths that historically broke — the 200 MiB handshake
(`DICOM_MAX_BODY_BYTES` / HTTP 413), the 50-anchor verify-cost (nonce isolation), and every S1/S2/S3
attack case (peer hold, gateway restart, ECONNRESET). It drops only wait-dominated points (300 s
anchor intervals, 100-anchor verify-cost, 1M-leaf scaling), which change runtime but not the
executed code path.

### `paper` row contract

| Measure | Composition | Rows |
|---|---|---:|
| scaling | 4 log sizes × 3 proof types × 10 | 120 |
| revocation-delay | 4 anchor intervals × 10 | 40 |
| handshake | 3 study sizes × 10 | 30 |
| verify-cost | 4 anchor counts × 10 | 40 |
| grace | 4 Δ_max values × 10 | 40 |
| attack | 9 scenarios × 10 | 90 |
| **total** | | **360** |

Independent variables: log sizes 10³/10⁴/10⁵/10⁶; anchor intervals 10/30/60/300 s; inspected anchor
counts 1/10/50/100; study sizes ≈5/50/200 MiB; 10 repeats. 10⁷ leaves are excluded unless
`EVAL_INCLUDE_10M=true`.

**Run the six measures in the fixed order, never in parallel.** `verify-cost` and `grace` are
sensitive to the anchor state accumulated by earlier measures; running them in a different order or
from a different starting state produces numbers that are not comparable. The resolved order and
starting state are recorded in `config.resolved.json`.

`paper` refuses to start on a dirty working tree.

### Completion criteria

`scripts/verify-run.ps1` checks these and writes the result into `status.json`:

- every expected `raw/*.json` exists, with the expected row count
- `failed`, `waiting`, `skipped`, `undetected` are all zero
- every `scaling` row has `verified=true` — scaling rows carry no `status` field, so a check of the
  form `ok == rows` would always fail
- the attack label distribution is **S1 4 / S2 3 / S3 2** distinct scenarios
- all six figures exist
- no tracked file changed during the run

## 5. Artifacts

Each run directory contains:

```
status.json            verdict, verdictReasons, checked counts, watchdog state
config.resolved.json   profile, every resolved EVAL_*/runtime variable, criteria, source commit+tree
run-manifest.json      verdict, timings, SHA-256 of profile/package-lock/compose, contract addresses
PROVENANCE.md          human-readable summary
SHA256SUMS             SHA-256 of every result file
environment.json       CPU, memory, Node/npm versions, git state
raw/                   *.csv and *.json measurement records
summary/               summary statistics and report.md
figures/               six PNGs
logs/                  written only when the run does not finish clean
```

## 6. Unattended runs

Long runs must not be supervised by polling — that is what makes them expensive, whether the
supervisor is a person or a tool.

```powershell
.\evaluate.cmd paper -Detach
```

This starts a background worker, records the run directory in `eval/out/latest-run.txt`, and returns
immediately with the PID and paths.

1. Launch, then wait for the process to exit. Do not read intermediate state.
2. Read `status.json` **once**. `verdict == "pass"` means every completion criterion above was met.
3. Only when `verdict != "pass"`, read `logs/failure-context.log` once — it aggregates the
   failed/waiting/skipped counts, diagnostic signals, and bounded output tails.
4. Open raw CSV/JSON only if that is still not enough.

## 7. Resetting state

```powershell
.\reproduce.cmd -Reset
```

`docker compose down -v` does **not** reset evaluation state. The accumulated anchors live in the
host files `data/inst-*/audit.db` and in the in-memory chain; `-v` only removes Orthanc storage.

`-Reset` runs `scripts/reset-local.ps1`, which stops the gateways, backs up and removes the audit
databases into `data/reset-backup-<stamp>/`, recreates the chain from block 0, redeploys the
contracts (the addresses are reproduced, since they are deterministic in the deployer nonce),
restarts the gateways so they load the new addresses, and verifies contract code exists.

`-Reset` resets runtime state only. It does not regenerate dependencies or certificates:
regenerating certificates while Orthanc has them mounted would break mTLS.

The backups under `data/reset-backup-*` are never cleaned up automatically — each is about 90 MB
after a `paper` run. Delete the old ones by hand once you no longer need them.

## 8. Comparing your results with ours

Compare **exactly**: row counts, proof sizes, proof hash counts, API/RPC call counts, and every
detection verdict. These are structural and must match.

Compare **statistically**: latencies. They depend on hardware, on Docker Desktop's filesystem
behaviour, and on wall-clock waits. Report them alongside `environment.json`.

Do not compare across profiles or across different starting anchor states. In particular,
`grace` and `verify-cost` verification times scale with the number of accumulated receiver anchors —
the same code measured with ~40 accumulated anchors and with ~1,600 differs by two orders of
magnitude. `config.resolved.json` records the state each run started from.

Read [docs/LIMITATIONS.md](docs/LIMITATIONS.md) before citing any number.

## 9. Troubleshooting

**`state-consistency` fails with "N local anchors > M on chain".** The chain restarted or was
redeployed while the audit databases survived — typically after `docker compose stop` and a restart,
since the Hardhat chain is in-memory. Run `.\reproduce.cmd -Reset`.

**A transfer settles as `TRANSFER_UNCONFIRMED` and later transfers are rejected with "peer B is
held".** After an unconfirmed transfer the provider blocks further approvals for that peer.
`reproduce.cmd` releases the hold before its scenario; to clear it manually run
`npx tsx scripts/release-peer-hold.ts`.

**A transfer fails with HTTP 413.** A scenario picked a large study left in Orthanc A by an earlier
handshake measurement. Set `SCENARIO_STUDY_UID` explicitly, or use `reproduce.cmd`, which pins its
own synthetic study.

**`ports` fails.** Another process holds 7001/7002/8042/8043/8545. The check is skipped when this
stack is already running.

**A PowerShell script fails to parse with an unterminated-string error.** The file lost its UTF-8
BOM. PowerShell 5.1 reads BOM-less scripts in the system code page, which corrupts non-ASCII text
and can swallow a closing quote.
