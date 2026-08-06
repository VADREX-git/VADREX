// Synthetic DICOM generator for bootstrap and the demos.
//
// Generating in-repo removes the dependency on an upstream download. The study UID is fixed, so
// a re-run is deduplicated by Orthanc as the same SOP instance.
import { join } from "node:path";
import { stowDicomToOrthancA, writeSyntheticDicom } from "../eval/src/dicom.js";
import { repoRoot } from "../packages/gateway/src/config.js";

const SAMPLE_STUDY_UID = "1.3.6.1.4.1.5962.99.8.1";
const FRAME_BYTES = 512 * 512;

function outputPath(): string {
  return join(repoRoot(), "scripts", "out", "samples", "synthetic.dcm");
}

async function main(): Promise<void> {
  const skipStow = process.argv.includes("--no-stow");
  const path = outputPath();
  const written = writeSyntheticDicom({
    studyInstanceUid: SAMPLE_STUDY_UID,
    seriesInstanceUid: `${SAMPLE_STUDY_UID}.1`,
    sopInstanceUid: `${SAMPLE_STUDY_UID}.1.1`,
    targetPixelBytes: FRAME_BYTES,
    outputPath: path
  });
  console.log(`sample DICOM: ${path} (${written.frames} frame, ${written.pixelBytes} pixel bytes)`);

  if (skipStow) {
    console.log(`studyInstanceUid: ${SAMPLE_STUDY_UID}`);
    return;
  }

  const bytes = await stowDicomToOrthancA(path);
  console.log(`STOW to Orthanc A OK (${bytes} bytes)`);
  console.log(`studyInstanceUid: ${SAMPLE_STUDY_UID}`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
