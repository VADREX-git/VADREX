/**
 * Verdict phrases printed by resolve-dispute.
 *
 * The end-to-end scenarios and the violation-injection measurement decide detection by looking
 * for these strings in the CLI output, so the emitting and the checking side must share the
 * constant. Rewording one in place silently turns a detection into a miss.
 */
export const VERIFIER_VERDICTS = {
  /** Receiver's denial rejected; the printed line starts with this. */
  bDenialRejected: "B denial rejected",
  /** Provider's claim rejected for want of anchored receipt evidence. */
  aClaimNotEstablished: "A claim not established: anchored receipt evidence is missing"
} as const;
