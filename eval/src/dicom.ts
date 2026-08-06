import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { requestBuffer } from "../../packages/gateway/src/httpClient.js";
import { tlsForClient } from "../../scripts/scenario-client.js";
import { repoPath } from "./common.js";

interface SyntheticDicomOptions {
  studyInstanceUid: string;
  seriesInstanceUid: string;
  sopInstanceUid: string;
  targetPixelBytes: number;
  outputPath: string;
}

const EXPLICIT_VR_LITTLE_ENDIAN = "1.2.840.10008.1.2.1";
const CT_IMAGE_STORAGE = "1.2.840.10008.5.1.4.1.1.2";
const IMPLEMENTATION_CLASS_UID = "1.3.6.1.4.1.5962.99.8";
const FRAME_BYTES = 512 * 512;

export function syntheticStudyUid(label: string, repeat: number, variant: string): string {
  const safeLabel = label.replace(/[^0-9A-Za-z]/g, "");
  const suffix = Date.now() % 1_000_000_000;
  return `1.3.6.1.4.1.5962.8.${suffix}.${repeat}.${numericHash(`${safeLabel}:${variant}`)}`;
}

export function writeSyntheticDicom(options: SyntheticDicomOptions): { pixelBytes: number; frames: number } {
  const frames = Math.max(1, Math.ceil(options.targetPixelBytes / FRAME_BYTES));
  const pixelBytes = frames * FRAME_BYTES;
  const pixelData = Buffer.alloc(pixelBytes, 0x7f);

  const metaWithoutGroupLength = Buffer.concat([
    element(0x0002, 0x0001, "OB", Buffer.from([0x00, 0x01])),
    element(0x0002, 0x0002, "UI", ui(CT_IMAGE_STORAGE)),
    element(0x0002, 0x0003, "UI", ui(options.sopInstanceUid)),
    element(0x0002, 0x0010, "UI", ui(EXPLICIT_VR_LITTLE_ENDIAN)),
    element(0x0002, 0x0012, "UI", ui(IMPLEMENTATION_CLASS_UID))
  ]);
  const groupLength = Buffer.alloc(4);
  groupLength.writeUInt32LE(metaWithoutGroupLength.length, 0);

  const preamble = Buffer.concat([Buffer.alloc(128), Buffer.from("DICM", "ascii")]);
  const meta = Buffer.concat([element(0x0002, 0x0000, "UL", groupLength), metaWithoutGroupLength]);
  const dataset = Buffer.concat([
    element(0x0008, 0x0016, "UI", ui(CT_IMAGE_STORAGE)),
    element(0x0008, 0x0018, "UI", ui(options.sopInstanceUid)),
    element(0x0008, 0x0020, "DA", text("20260711")),
    element(0x0008, 0x0030, "TM", text("120000")),
    element(0x0008, 0x0060, "CS", text("OT")),
    element(0x0010, 0x0010, "PN", text("VADREX^Synthetic")),
    element(0x0010, 0x0020, "LO", text(`EVAL${numericHash(options.studyInstanceUid)}`)),
    element(0x0020, 0x000d, "UI", ui(options.studyInstanceUid)),
    element(0x0020, 0x000e, "UI", ui(options.seriesInstanceUid)),
    element(0x0020, 0x0010, "SH", text("8A")),
    element(0x0020, 0x0011, "IS", text("1")),
    element(0x0020, 0x0013, "IS", text("1")),
    element(0x0028, 0x0002, "US", uint16(1)),
    element(0x0028, 0x0004, "CS", text("MONOCHROME2")),
    element(0x0028, 0x0008, "IS", text(String(frames))),
    element(0x0028, 0x0010, "US", uint16(512)),
    element(0x0028, 0x0011, "US", uint16(512)),
    element(0x0028, 0x0100, "US", uint16(8)),
    element(0x0028, 0x0101, "US", uint16(8)),
    element(0x0028, 0x0102, "US", uint16(7)),
    element(0x0028, 0x0103, "US", uint16(0)),
    element(0x7fe0, 0x0010, "OB", pixelData)
  ]);

  mkdirSync(dirname(options.outputPath), { recursive: true });
  writeFileSync(options.outputPath, Buffer.concat([preamble, meta, dataset]));
  return { pixelBytes, frames };
}

export async function stowDicomToOrthancA(dicomPath: string, orthancUrl = orthancAUrl()): Promise<number> {
  const dicom = await import("node:fs").then((fs) => fs.readFileSync(dicomPath));
  const boundary = `vadrex-eval-${Date.now()}`;
  const body = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Type: application/dicom\r\n\r\n`, "ascii"),
    dicom,
    Buffer.from(`\r\n--${boundary}--\r\n`, "ascii")
  ]);
  const response = await requestBuffer(`${orthancUrl}/dicom-web/studies`, {
    method: "POST",
    tls: tlsForClient("a"),
    headers: {
      "content-type": `multipart/related; type="application/dicom"; boundary=${boundary}`
    },
    body,
    timeoutMs: 120_000
  });
  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw new Error(`Orthanc A STOW returned HTTP ${response.statusCode}: ${response.body.toString("utf8")}`);
  }
  return body.length;
}

export async function directOrthancCopy(studyInstanceUid: string): Promise<{ bytes: number; contentType: string }> {
  const query = new URLSearchParams({ StudyInstanceUID: studyInstanceUid });
  const qido = await requestBuffer(`${orthancAUrl()}/dicom-web/studies?${query.toString()}`, {
    tls: tlsForClient("a"),
    headers: { accept: "application/dicom+json" },
    timeoutMs: 30_000
  });
  if (qido.statusCode < 200 || qido.statusCode >= 300) {
    throw new Error(`Orthanc A QIDO returned HTTP ${qido.statusCode}: ${qido.body.toString("utf8")}`);
  }

  const wado = await requestBuffer(`${orthancAUrl()}/dicom-web/studies/${encodeURIComponent(studyInstanceUid)}`, {
    tls: tlsForClient("a"),
    headers: { accept: "multipart/related; type=\"application/dicom\"" },
    timeoutMs: 120_000
  });
  if (wado.statusCode < 200 || wado.statusCode >= 300) {
    throw new Error(`Orthanc A WADO returned HTTP ${wado.statusCode}: ${wado.body.toString("utf8")}`);
  }

  const contentType = String(wado.headers["content-type"] ?? "application/dicom");
  const stow = await requestBuffer(`${orthancBUrl()}/dicom-web/studies`, {
    method: "POST",
    tls: tlsForClient("b"),
    headers: { "content-type": contentType },
    body: wado.body,
    timeoutMs: 120_000
  });
  if (stow.statusCode < 200 || stow.statusCode >= 300) {
    throw new Error(`Orthanc B STOW returned HTTP ${stow.statusCode}: ${stow.body.toString("utf8")}`);
  }

  return { bytes: wado.body.length, contentType };
}

export function syntheticDicomPath(label: string, repeat: number, variant: string): string {
  return repoPath("eval", "out", "synthetic-dicom", `${label}-${repeat}-${variant}.dcm`);
}

/**
 * Removes a study a measurement created from Orthanc.
 *
 * Without this a single paper run leaves roughly 10 GB in Orthanc storage for good, and repeated
 * runs exhaust the disk and take the run down with it. Callers invoke it *after* recording their
 * measurement, so a failure here cannot affect the numbers.
 */
export async function deleteStudyFromOrthanc(institution: "a" | "b", studyInstanceUid: string): Promise<boolean> {
  const base = institution === "a" ? orthancAUrl() : orthancBUrl();
  const tls = tlsForClient(institution);
  const lookup = await requestBuffer(`${base}/tools/lookup`, {
    method: "POST",
    tls,
    body: Buffer.from(studyInstanceUid, "ascii"),
    timeoutMs: 30_000
  });
  if (lookup.statusCode < 200 || lookup.statusCode >= 300) {
    return false;
  }
  const matches = JSON.parse(lookup.body.toString("utf8")) as { Type: string; ID: string }[];
  const study = matches.find((entry) => entry.Type === "Study");
  if (!study) {
    return false;
  }
  const removed = await requestBuffer(`${base}/studies/${encodeURIComponent(study.ID)}`, {
    method: "DELETE",
    tls,
    timeoutMs: 120_000
  });
  return removed.statusCode >= 200 && removed.statusCode < 300;
}

/** Deletes a generated synthetic DICOM file, reclaiming host disk. */
export function removeSyntheticDicom(path: string): void {
  rmSync(path, { force: true });
}

function orthancAUrl(): string {
  return (process.env.ORTHANC_A_URL ?? "https://localhost:8042").replace(/\/$/, "");
}

function orthancBUrl(): string {
  return (process.env.ORTHANC_B_URL ?? "https://localhost:8043").replace(/\/$/, "");
}

function element(group: number, tag: number, vr: string, value: Buffer): Buffer {
  const padded = padValue(vr, value);
  const header = Buffer.alloc(longVr(vr) ? 12 : 8);
  header.writeUInt16LE(group, 0);
  header.writeUInt16LE(tag, 2);
  header.write(vr, 4, 2, "ascii");
  if (longVr(vr)) {
    header.writeUInt16LE(0, 6);
    header.writeUInt32LE(padded.length, 8);
  } else {
    header.writeUInt16LE(padded.length, 6);
  }
  return Buffer.concat([header, padded]);
}

function longVr(vr: string): boolean {
  return ["OB", "OD", "OF", "OL", "OW", "SQ", "UC", "UR", "UT", "UN"].includes(vr);
}

function padValue(vr: string, value: Buffer): Buffer {
  if (value.length % 2 === 0) {
    return value;
  }
  const pad = vr === "UI" || vr === "OB" ? 0x00 : 0x20;
  return Buffer.concat([value, Buffer.from([pad])]);
}

function ui(value: string): Buffer {
  return Buffer.from(value, "ascii");
}

function text(value: string): Buffer {
  return Buffer.from(value, "ascii");
}

function uint16(value: number): Buffer {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16LE(value, 0);
  return buffer;
}

function numericHash(value: string): number {
  let hash = 0;
  for (const char of value) {
    hash = (hash * 31 + char.charCodeAt(0)) % 1_000_000;
  }
  return hash;
}
