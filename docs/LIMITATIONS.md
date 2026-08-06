# Limitations

What the implementation and the measurements do and do not establish. Read this before citing a
number or restating a security claim.

None of the items below are defects in the Merkle constructions or the verifier logic. They are
scope boundaries and measurement-methodology limits.

## 1. Non-repudiation (S3) is bounded, and unrecorded concealment cannot be attributed

The receipt body carries `{approvalEntryHash, receiveEntryHash, receiverSignature}` — hashes and a
signature, **not the receiver's entry preimage**. If the receiver returns a receipt but never
records the receive entry, a verifier cannot find the preimage in the receiver's log and terminates
with "claim not established".

More fundamentally, the value the provider signs when transmitting is the `entryHash` of
`TRANSFER_APPROVED`, and that signature is produced *before* the study is fetched. The provider's
signature therefore binds the approval, not the execution of the transfer. As a result, "the
provider transferred and then omitted its completion record" and "the provider only approved while
the receiver fabricated a receive record" are **not distinguishable from anchored evidence alone**.

Therefore:

- S3 establishes non-repudiation **only when all three preimages** — the provider's
  `TRANSFER_APPROVED`, the receiver's `RECEIVE_COMPLETED`, and the provider's `TRANSFER_COMPLETED` —
  are anchored and their cross-references and signatures agree.
- Otherwise the verdict is "insufficient evidence". **The protocol does not identify which
  institution omitted a record**, and this state is reachable by a single institution acting alone —
  it does not require collusion.
- Claims of the form "single-sided concealment is detected" are not supported and must not be made.

Removing this limitation would require both directions: the receipt must carry the receive entry's
preimage, and the provider must sign a value produced *after* the DICOM transfer for the receiver to
retain. One direction alone is not symmetric.

## 2. Two measured scenarios were relabelled without re-running

| Old label | Current label |
|---|---|
| `S3` / `single-sided-concealment` | `S1` / `post-anchor-completion-entry-deletion` |
| `S3` / `receiptless-transfer-claim` | `S3` / `no-timely-anchored-completion-pair` |

The concealment demo completes and anchors a normal transfer, then deletes `TRANSFER_COMPLETED` from
a **copy** of the provider's audit database and detects the mismatch by recomputing the anchored
root. The evidence is root recomputation, which is log completeness (S1), not non-repudiation — and
it is not a measurement of "never recorded in the first place".

The receipt scenario produces a state where the receipt arrives after the timeout, leaving only
`RECEIPT_LATE` and no completion pair. It is not a case of "no receipt exists", so the name is now
stated in terms of the completion pair. It must not be used as evidence that physical receipt did
not occur.

Datasets produced before 2026-07-27 carry the old labels; their per-property counts under the
current naming are S1 4 / S2 3 / S3 2.

## 3. S2 detection is measured at scenario granularity

The three S2 rows are not independently adjudicated. Detection is
`(e2e:violation exit code is 0) AND (the case marker appears in the output)`, and the marker is
printed on the success path, so the effective decision is whether the scenario as a whole succeeded.

Coverage is also partial. The injected cases are seq-skip, its `k+1` variant, and
`no-head-update`. The case of a **delayed revocation entry** is not injected — the injection tool
supports only `--seq` and `--no-head-update`.

Correct statement: "for the seq-skip case (and its `k+1` variant) and the no-head-update case,
detection was confirmed for every run at scenario granularity." Describing S2 as "three independent
cases each detected 100% of the time" overstates the result.

## 4. `anchorsRequired` is a scenario-level delta

For S2 and S3 the value is the total change in on-chain anchor count across the whole scenario, not
the minimum number of anchors the verification logic required for that specific case. `e2e:violation`
runs three cases in one process, so all three rows can carry the same delta.

Only the two S1 injection rows report the number of anchors the detection actually referenced.

## 5. Revocation delay is measured as an upper bound, not an average

The anchoring loop is a fixed-period `setInterval` on a free-running clock, and the measurement is
serial and blocking (each repeat is "revoke → wait until anchored → next repeat"). Each revoke
therefore lands immediately after a tick, the phase is pinned near zero, and the observed delay is
≈ one full anchor interval T. Measured medians at 10/30/60/300 s intervals sit within a few percent
of T.

If revocations arrive independently of the anchoring clock, the expected delay is T/2 with a maximum
of T. Reporting the default numbers as "average delay" overstates them by roughly a factor of two.

`EVAL_REVOCATION_RANDOM_OFFSET=true` desynchronizes the phase by sleeping a random `[0, interval)`
before the measurement window, yielding E[delay] = T/2. Verified on a clean stack at T=60 s:
correlation between offset and observed delay −1.00. This must be run from a clean state — with many
accumulated anchors the O(n) anchor scan inflates observations enough to swallow the signal.

## 6. Verification cost and grace numbers depend on accumulated anchor state

`verify-cost` and `grace` measure an end-to-end scenario cost under whatever anchor history has
accumulated, not an isolated per-operation cost. The same code measured with ~40 accumulated
receiver anchors and with ~1,600 differs by about two orders of magnitude.

Consequences:

- Numbers from runs that started from different states are not comparable, even on the same machine.
- The six measures must run in the fixed order; `verify-cost` and `grace` follow measures that
  create anchors.
- Reductions observed after a state reset are **not** improvements in detection logic — they reflect
  a shorter anchor history for the verifier to walk.

`config.resolved.json` records the starting state and resolved variables for each run.

## 7. The handshake measure deletes its studies after each repeat

Each handshake repeat removes its two synthetic studies from both Orthanc instances — and the local
files — once the row has been recorded. Without this, a single `paper` run left about 10 GB in
Orthanc storage and 4 GB on the host permanently; repeated runs exhausted the disk and killed the
Docker engine mid-measurement.

The cleanup runs strictly after the measurement is recorded, so it cannot affect the repeat it
follows. It does mean each repeat sees an Orthanc instance holding fewer prior studies than it would
under unbounded accumulation. Datasets produced before this change were measured with studies
accumulating across the whole run. The expected effect is confined to Orthanc's index lookups and
should be small, but it is a change in conditions, not a null one.

## 8. The receiver-side head–log-tree atomicity cross-check is not implemented

The cross-check described in [PROTOCOL.md §3.3](PROTOCOL.md#33-headlog-tree-atomicity-cross-check)
is implemented for the provider. The equivalent check on the receiver's log is declared out of
scope.

## 9. 10⁷ leaves are an extrapolation

Runs stop at 10⁶ leaves by default. The 10⁷ figure in the summary output is a linear projection from
the largest measured tree build and excludes JavaScript object overhead. Set
`EVAL_INCLUDE_10M=true` only after reviewing runtime and memory expectations.

## 10. `quick` output is not paper data

The `quick` profile exists to validate that the pipeline runs. It uses reduced repeats, reduced log
sizes, smaller synthetic studies, and a short grace set. Its numbers must never appear as results.
