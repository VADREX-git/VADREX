// Run identity for a supplementary measurement: where it writes, which compose project and
// ports it owns, and which image tags it builds.
//
// The 2026-09-17 run that the paper reports used the values below as fixed constants. They are
// resolved from the environment here so a later run can be made without touching the tool, and
// so two runs can never share an output directory, a compose project, a port or an image tag.
// REVISION_RUN alone is enough to isolate a run; the rest exists for unusual environments.
import { resolve } from 'node:path';

export const runId = process.env.REVISION_RUN ?? '20260917';
export const project = process.env.REVISION_PROJECT ?? `vadrex-revision-${runId}`;
// Added to the published host ports of the repository's compose file.
export const portOffset = Number(process.env.REVISION_PORT_OFFSET ?? 10000);

if (!/^[A-Za-z0-9._-]+$/.test(runId)) {
  throw new Error('REVISION_RUN must be a path- and compose-safe name');
}
if (!Number.isSafeInteger(portOffset) || portOffset <= 0) {
  throw new Error('REVISION_PORT_OFFSET must be a positive integer');
}

export const ports = {
  rpc: 8545 + portOffset,
  gatewayA: 7001 + portOffset,
  gatewayB: 7002 + portOffset,
  orthancA: 8042 + portOffset,
  orthancB: 8043 + portOffset
};

// Isolated image tags. The repository's shared vadrex-gateway:local and vadrex-chain:local are
// left untouched, so a supplementary run never rebuilds or replaces the images of the ordinary
// stack.
export const images = { gateway: `${project}-gateway:local`, chain: `${project}-chain:local` };

/** Output directory of this run, resolved against the repository root. */
export function outputDir(root: string = process.cwd()): string {
  return resolve(root, 'eval', 'out', `revision-${runId}`);
}

/** The isolated workspace the run executes in. */
export function workspaceDir(root: string = process.cwd()): string {
  return resolve(outputDir(root), 'workspace');
}

export function describe(): Record<string, unknown> {
  return { runId, project, portOffset, ports, images };
}
