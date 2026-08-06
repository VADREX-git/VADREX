/**
 * Detection markers the scenario and demo scripts print on stdout.
 *
 * The violation-injection measurement decides detection by looking for these strings, so the
 * emitting and the checking side must share the constant: rewording one in place silently turns
 * a detection into detected=false. The verifier's own verdict phrases live in
 * packages/verifier-cli/src/verdicts.ts.
 */

/** demo-concealment: a copy with an anchored entry deleted no longer reproduces the root. */
export const CONCEALMENT_ROOT_MISMATCH = "no longer matches the anchored root";

/** e2e-violation: marks the section of output belonging to one violation case. */
export function violationCaseMarker(caseName: string): string {
  return `[case:${caseName}]`;
}
