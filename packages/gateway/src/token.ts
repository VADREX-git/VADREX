import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export interface TransferTokenPayload {
  consentId: string;
  studyInstanceUid: string;
  purpose: string;
  nonce: string;
  exp: number;
}

function base64url(input: Buffer | string): string {
  return typeof input === "string" ? Buffer.from(input).toString("base64url") : input.toString("base64url");
}

function fromBase64url(input: string): Buffer {
  return Buffer.from(input, "base64url");
}

function keyBytes(secret: string): Buffer {
  if (/^0x[0-9a-fA-F]+$/.test(secret)) {
    return Buffer.from(secret.slice(2), "hex");
  }
  return Buffer.from(secret, "utf8");
}

function sign(secret: string, data: string): string {
  return base64url(createHmac("sha256", new Uint8Array(keyBytes(secret))).update(data).digest());
}

export function createTransferToken(
  secret: string,
  fields: Omit<TransferTokenPayload, "nonce" | "exp">,
  ttlSeconds: number,
  nowSeconds = Math.floor(Date.now() / 1000)
): { token: string; payload: TransferTokenPayload } {
  const payload: TransferTokenPayload = {
    ...fields,
    nonce: randomBytes(16).toString("hex"),
    exp: nowSeconds + ttlSeconds
  };
  const encoded = base64url(JSON.stringify(payload));
  return {
    token: `${encoded}.${sign(secret, encoded)}`,
    payload
  };
}

function parsePayload(encoded: string): TransferTokenPayload {
  const parsed = JSON.parse(fromBase64url(encoded).toString("utf8")) as unknown;
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("authorization token payload is invalid");
  }
  const payload = parsed as TransferTokenPayload;
  if (
    typeof payload.consentId !== "string" ||
    typeof payload.studyInstanceUid !== "string" ||
    typeof payload.purpose !== "string" ||
    typeof payload.nonce !== "string" ||
    typeof payload.exp !== "number" ||
    !Number.isSafeInteger(payload.exp)
  ) {
    throw new Error("authorization token payload is invalid");
  }
  return payload;
}

// Decodes the payload without verifying the signature. The receiver does not hold the consent
// secret and so cannot verify the token; it only needs the nonce to log TRANSFER_REQUESTED.
// Verification is the provider's job, in verifyTransferToken.
export function decodeTransferTokenPayload(token: string): TransferTokenPayload {
  const parts = token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error("authorization token is malformed");
  }
  return parsePayload(parts[0]);
}

export function verifyTransferToken(
  secret: string,
  token: string,
  nowSeconds = Math.floor(Date.now() / 1000)
): TransferTokenPayload {
  const parts = token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error("authorization token is malformed");
  }
  const expected = sign(secret, parts[0]);
  const left = Buffer.from(parts[1]);
  const right = Buffer.from(expected);
  if (left.length !== right.length || !timingSafeEqual(new Uint8Array(left), new Uint8Array(right))) {
    throw new Error("authorization token signature is invalid");
  }
  const payload = parsePayload(parts[0]);
  if (payload.exp < nowSeconds) {
    throw new Error("authorization token expired");
  }
  return payload;
}
