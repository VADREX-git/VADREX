# paper-v1 — reference dataset

The measurements the paper reports. A single `paper` profile run plus one declared auxiliary run,
both produced from the source published in this repository.

## 1. Provenance

| | |
|---|---|
| **`sourceTreeHash`** | **`8e28c2b98d88dd1291a7ae6e2670fe301f3a8023d79759c157889cf4cfedfd1a`** (113 files) |
| Profile | `paper` (`eval/profiles/paper.json`, sha256 `f473792cf93bc19660388cbe8baf2776c680fab22accd4cc4a31147d11f8b761`) |
| `package-lock.json` | sha256 `09152b2e4c0a8f3cd0db92d744a7ad20a5db118c9e7c8d6a0dd2deaa15642e1c` |
| `docker-compose.yml` | sha256 `6f56c82aca87ab1bae6b3819506c0acc0a82216bb20f7a044a4c9f1219e49196` |
| Anchor contracts | A `0x5FbDB2315678afecb367f032d93F642f64180aa3`, B `0x8464135c8F25Da09e49BC8782676a84730C318bC` |
| Run window | 2026-08-06 02:19 → 2026-08-06 14:01 KST (11.71 h) |
| Verdict | **pass** |

**The `sourceTreeHash` above is the hash of the source published here.** Verify it:

```powershell
.\eval\reference\source-hash.ps1
```

It covers the files listed in `eval/reference/source-manifest.txt` — the code, scripts, configs,
container definitions, and lockfile that produce measurements. README, REPRODUCIBILITY, `docs/`,
LICENSE, CITATION, the plotting scripts, and this directory are outside it, so documentation,
licensing, and figure rendering can change without breaking the link between these results and the
code that produced them. A commit hash would not survive that, since it changes with the author,
timestamp, or parent.

The plotting scripts sit outside the scope deliberately: they read CSVs the run has already
produced and render PNGs, so they cannot change a single measured row, and every figure carries its
own SHA-256 in `SHA256SUMS`. That is why the hash covers 113 files rather than the whole tree.

Machine: Intel Core i7-11700K (16 logical cores), 32 GB RAM, Windows 11 10.0.26200,
Node v20.16.0, Docker 20.10.21 / Compose v2.12.2. Repository and Docker data both on an NVMe SSD.

Every completion criterion was checked by `scripts/verify-run.ps1`, not by hand:

```
360 rows        scaling 120 · revocation-delay 40 · handshake 30 · verify-cost 40 · grace 40 · attack 90
failed 0        waiting 0 · skipped 0 · undetected 0
scaling         120/120 verified
attack labels   S1 4 / S2 3 / S3 2
figures         6/6
tracked files   unchanged during the run
```

The run started from a clean reset (`reproduce.cmd -Reset`): audit databases removed, chain
recreated from block 0, contracts redeployed, gateways restarted against the new addresses.

## 2. Auxiliary run — revocation average case

`aux-revocation-avgcase/` holds a separate 40-row `revocation-delay` measurement with
`EVAL_REVOCATION_RANDOM_OFFSET=true`, run from the **same source** after its own clean reset
(required — with accumulated anchors the anchor scan swamps the signal). 71 minutes, 40/40 ok.

It exists because the default measurement is phase-locked and reports an upper bound of one full
anchor interval T rather than the average case; see `docs/LIMITATIONS.md` §5.

| T | corr(offset, delay) | mean delay / T |
|---:|---:|---:|
| 10 s | +0.610 | 1.016 |
| 30 s | −0.420 | 0.569 |
| 60 s | −0.140 | 0.722 |
| **300 s** | **−1.000** | 0.393 |

**Cite the T = 300 s correlation.** The relation `delay = T − offset` — and therefore
`E[delay] = T/2` for revocations arriving independently of the anchoring clock — holds exactly at
T = 300 s, and has now done so in four independent runs (−1.000 each time). At smaller intervals
the fixed per-repeat overhead (revoke API, anchor registration, 1 s polling granularity) is a large
fraction of T and the relation is lost.

Those smaller-interval correlations must not be cited, and repeated runs of the same measurement
show why: across three runs T = 30 s gave −0.959, −0.178 and −0.420, and T = 60 s gave −0.302,
−0.995 and −0.140, while T = 300 s stayed at −1.000 every time. The instability is a property of
the measurement at small T, not of the relation being measured.

The sample mean over ten repeats deviates from T/2 by the sampling error of the drawn offsets
themselves; the correlation, not the sample mean, is the evidence.

## 3. Reading the numbers

- Structural quantities — row counts, proof sizes, proof hash counts, API/RPC call counts, and every
  detection verdict — are exact and must match on any machine.
- Latencies depend on hardware and on wall-clock waits. Compare them statistically, alongside
  `environment.json`.
- `verify-cost` and `grace` are end-to-end costs under the anchor history accumulated by the
  measures that ran before them, in the fixed profile order. They are not per-operation costs and
  are not comparable across runs that started from different states.
- In this dataset `grace` verification time is essentially flat across Δ_max, because the cost is
  dominated by walking the accumulated anchor history rather than by the grace window itself.

Read `docs/LIMITATIONS.md` before citing any number.

## 4. Verifying this dataset

```powershell
# file integrity
sha256sum -c SHA256SUMS          # or Get-FileHash against the listed values

# source match: must print the sourceTreeHash in section 1
.\eval\reference\source-hash.ps1
```

Regenerating it end to end takes about 11.5 hours plus about 1.2 hours for the auxiliary run:

```powershell
.\reproduce.cmd -Reset
.\evaluate.cmd paper -Detach
```
