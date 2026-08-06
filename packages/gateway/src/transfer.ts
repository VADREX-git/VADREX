import { readFileSync } from "node:fs";
import type { KeyObject } from "node:crypto";
import type { HexString } from "@vadrex/shared";
import { deriveReceiverSecret } from "@vadrex/merkle";
import type { AuditAggregator, AppendedAuditEntry, ChainEntryRecord, RevokedConsent } from "./aggregator.js";
import { requestBuffer, requestJson, type TlsMaterial } from "./httpClient.js";
import { decodeTransferTokenPayload, verifyTransferToken } from "./token.js";
import { EntrySigner, verifyEntrySignature } from "./signing.js";

export interface TransferServiceOptions {
  institutionId: string;
  peerInstitutionId: string;
  peerBaseUrl: string;
  orthancBaseUrl?: string;
  tls?: TlsMaterial;
  signer: EntrySigner;
  peerPublicKey: KeyObject;
  tokenTtlSeconds: number;
  receiptTimeoutMs: number;
  simulatedReceiptDelayMs?: number;
}

// Transfer handshake. The order is fixed and each step records the peer's entry hash and
// signature in the local log:
//
//   B: TRANSFER_REQUESTED (seq = null)  →  A: TRANSFER_APPROVED (assigns seq, returns it)
//   →  A transfers the study over mTLS  →  B: RECEIVE_COMPLETED (reuses that seq)
//   →  A: TRANSFER_COMPLETED (peer = receipt hash)
//
// Note what the provider's signature binds: it is produced over the approval entry, before
// the study is fetched. It attests to the approval, not to the transfer having happened.
// A receipt arriving after settlement is recorded as RECEIPT_LATE, off the consent chain, so
// that late evidence is preserved without moving the chain head.

// The receiver never handles the raw consent secret. The patient issues a derived key
// (receiverSecret) and a signed authorization token, and only those cross the boundary.
export interface StartTransferRequest {
  consentId: string;
  receiverSecret: string;
  authorizationToken: string;
  studyInstanceUid: string;
  purpose: string;
}

export interface TransferRequestBody {
  consentId: string;
  studyInstanceUid: string;
  purpose: string;
  requesterInstitutionId: string;
  requesterEntryHash: string;
  requesterSignature: string;
  authorizationToken: string;
}

export interface DicomDeliveryBody {
  consentId: string;
  studyInstanceUid: string;
  purpose: string;
  providerInstitutionId: string;
  receiverSecret: string;
  seq: number;
  approvalEntryHash: string;
  approvalSignature: string;
  dicomBase64: string;
  dicomContentType: string;
}

export interface ReceiptBody {
  approvalEntryHash: string;
  receiveEntryHash: string;
  receiverSignature: string;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function bytesToHex(bytes: Uint8Array): HexString {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

function requireString(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${key} must be a non-empty string`);
  }
  return value;
}

function requireNumber(record: Record<string, unknown>, key: string): number {
  const value = record[key];
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new Error(`${key} must be an integer`);
  }
  return value;
}

function parseObject(input: unknown, name: string): Record<string, unknown> {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    throw new Error(`${name} must be a JSON object`);
  }
  return input as Record<string, unknown>;
}

export class TransferService {
  constructor(
    private readonly aggregator: AuditAggregator,
    private readonly options: TransferServiceOptions
  ) {}

  async startTransfer(input: unknown): Promise<unknown> {
    const body = parseObject(input, "transfer request body");
    const request: StartTransferRequest = {
      consentId: requireString(body, "consentId"),
      receiverSecret: requireString(body, "receiverSecret"),
      authorizationToken: requireString(body, "authorizationToken"),
      studyInstanceUid: requireString(body, "studyInstanceUid"),
      purpose: requireString(body, "purpose")
    };
    const tokenPayload = decodeTransferTokenPayload(request.authorizationToken);
    this.aggregator.ensureReceiverReferenceConsent({
      consentId: request.consentId,
      receiverSecret: request.receiverSecret,
      providerInstitutionId: this.options.peerInstitutionId,
      studyInstanceUid: request.studyInstanceUid,
      purpose: request.purpose
    });
    const requested = this.aggregator.recordTransferRequested({
      consentId: request.consentId,
      studyInstanceUid: request.studyInstanceUid,
      purpose: request.purpose,
      providerInstitutionId: this.options.peerInstitutionId,
      tokenNonce: tokenPayload.nonce
    });
    const requesterSignature = this.options.signer.signEntryHash(requested.entryHash);
    return requestJson(`${this.options.peerBaseUrl}/transfer/request`, {
      consentId: request.consentId,
      studyInstanceUid: request.studyInstanceUid,
      purpose: request.purpose,
      requesterInstitutionId: this.options.institutionId,
      requesterEntryHash: requested.entryHash,
      requesterSignature,
      authorizationToken: request.authorizationToken
    }, { tls: this.options.tls, timeoutMs: this.options.receiptTimeoutMs + 5_000 });
  }

  async handleTransferRequest(input: unknown): Promise<unknown> {
    const request = this.parseTransferRequest(input);
    if (!verifyEntrySignature(request.requesterEntryHash, request.requesterSignature, this.options.peerPublicKey)) {
      throw new Error("requester signature is invalid");
    }

    const details = this.aggregator.consentDetails(request.consentId);

    const tokenPayload = verifyTransferToken(details.secretC, request.authorizationToken);
    if (!this.aggregator.useNonce(tokenPayload.nonce, request.consentId)) {
      this.aggregator.recordReplayBlocked({
        consentId: request.consentId,
        nonce: tokenPayload.nonce,
        requesterEntryHash: request.requesterEntryHash,
        requesterSignature: request.requesterSignature
      });
      throw new Error("authorization token nonce was already used");
    }

    const denial = this.validateConsentGate(details, request, tokenPayload);
    if (denial) {
      this.aggregator.recordTransferDenied({
        consentId: request.consentId,
        reason: denial,
        requesterEntryHash: request.requesterEntryHash,
        requesterSignature: request.requesterSignature,
        requestContext: {
          studyInstanceUid: request.studyInstanceUid,
          purpose: request.purpose
        }
      });
      throw new Error(`transfer denied: ${denial}`);
    }

    const approved = this.aggregator.recordTransferApproved({
      consentId: request.consentId,
      peerInstitutionId: request.requesterInstitutionId,
      studyInstanceUid: request.studyInstanceUid,
      purpose: request.purpose,
      requesterEntryHash: request.requesterEntryHash,
      requesterSignature: request.requesterSignature
    });
    const approvalSignature = this.options.signer.signEntryHash(approved.entryHash);
    this.aggregator.attachApprovalSignature(approved.entryHash, approvalSignature);

    const receiverSecret = bytesToHex(deriveReceiverSecret(details.secretC));
    let dicom: { body: Buffer; contentType: string };
    try {
      dicom = await this.fetchStudy(request.studyInstanceUid);
    } catch (error) {
      this.aggregator.recordTransferFailed(approved.entryHash, error instanceof Error ? error.message : String(error));
      return {
        status: "FAILED",
        seq: approved.seq,
        receiverSecret,
        approvalEntryHash: approved.entryHash,
        approvalSignature,
        approved
      };
    }

    try {
      const receipt = await this.withReceiptTimeout(requestJson<ReceiptBody>(`${this.options.peerBaseUrl}/transfer/dicom`, {
        consentId: request.consentId,
        studyInstanceUid: request.studyInstanceUid,
        purpose: request.purpose,
        providerInstitutionId: this.options.institutionId,
        receiverSecret,
        seq: approved.seq,
        approvalEntryHash: approved.entryHash,
        approvalSignature,
        dicomBase64: dicom.body.toString("base64"),
        dicomContentType: dicom.contentType
      }, { tls: this.options.tls, timeoutMs: this.options.receiptTimeoutMs }));
      // The receiver normally settles the transfer through POST /transfer/receipt. Only if
      // that call never arrived do we settle from the receipt returned inline; the reported
      // status is always read back from the recorded state, never assumed.
      if (this.aggregator.transferStatusByApprovalHash(approved.entryHash) === "APPROVED") {
        this.handleReceipt(receipt);
      }
      return {
        status: this.aggregator.transferStatusByApprovalHash(approved.entryHash) ?? "COMPLETED",
        seq: approved.seq,
        receiverSecret,
        approvalEntryHash: approved.entryHash,
        approvalSignature,
        approved,
        receipt
      };
    } catch (error) {
      // A receipt, this timeout and the revocation barrier can all try to settle the same
      // transfer, so record UNCONFIRMED only while it is still unsettled.
      if (this.aggregator.transferStatusByApprovalHash(approved.entryHash) === "APPROVED") {
        this.aggregator.recordTransferUnconfirmed(approved.entryHash, error instanceof Error ? error.message : String(error));
      }
      return {
        status: this.aggregator.transferStatusByApprovalHash(approved.entryHash) ?? "UNCONFIRMED",
        seq: approved.seq,
        receiverSecret,
        approvalEntryHash: approved.entryHash,
        approvalSignature,
        approved
      };
    }
  }

  async handleDicomDelivery(input: unknown): Promise<ReceiptBody> {
    const delivery = this.parseDicomDelivery(input);
    if (!verifyEntrySignature(delivery.approvalEntryHash, delivery.approvalSignature, this.options.peerPublicKey)) {
      throw new Error("approval signature is invalid");
    }
    if (this.options.simulatedReceiptDelayMs && this.options.simulatedReceiptDelayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.options.simulatedReceiptDelayMs));
    }
    await this.storeStudy(Buffer.from(delivery.dicomBase64, "base64"), delivery.dicomContentType);
    const received = this.aggregator.recordReceiveCompleted({
      consentId: delivery.consentId,
      receiverSecret: delivery.receiverSecret,
      seq: delivery.seq,
      providerInstitutionId: delivery.providerInstitutionId,
      studyInstanceUid: delivery.studyInstanceUid,
      purpose: delivery.purpose,
      approvalEntryHash: delivery.approvalEntryHash,
      approvalSignature: delivery.approvalSignature
    });
    const receipt: ReceiptBody = {
      approvalEntryHash: delivery.approvalEntryHash,
      receiveEntryHash: received.entryHash,
      receiverSignature: this.options.signer.signEntryHash(received.entryHash)
    };
    await requestJson(`${this.options.peerBaseUrl}/transfer/receipt`, receipt, { tls: this.options.tls, timeoutMs: this.options.receiptTimeoutMs });
    return receipt;
  }

  handleReceipt(input: unknown): ChainEntryRecord | AppendedAuditEntry {
    const receipt = this.parseReceipt(input);
    if (!verifyEntrySignature(receipt.receiveEntryHash, receipt.receiverSignature, this.options.peerPublicKey)) {
      throw new Error("receiver signature is invalid");
    }
    return this.aggregator.recordTransferCompleted(receipt);
  }

  async revokeConsentWithBarrier(consentId: string): Promise<RevokedConsent> {
    this.aggregator.beginRevocationBarrier(consentId);
    const deadline = Date.now() + this.options.receiptTimeoutMs + 1_000;
    while (this.aggregator.pendingTransferCount(consentId) > 0 && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    if (this.aggregator.pendingTransferCount(consentId) > 0) {
      this.aggregator.markPendingTransfersUnconfirmed(consentId, "revocation barrier receipt timeout");
    }
    return this.aggregator.revokeConsent(consentId);
  }

  private parseTransferRequest(input: unknown): TransferRequestBody {
    const body = parseObject(input, "transfer request body");
    return {
      consentId: requireString(body, "consentId"),
      studyInstanceUid: requireString(body, "studyInstanceUid"),
      purpose: requireString(body, "purpose"),
      requesterInstitutionId: requireString(body, "requesterInstitutionId"),
      requesterEntryHash: requireString(body, "requesterEntryHash"),
      requesterSignature: requireString(body, "requesterSignature"),
      authorizationToken: requireString(body, "authorizationToken")
    };
  }

  private parseDicomDelivery(input: unknown): DicomDeliveryBody {
    const body = parseObject(input, "dicom delivery body");
    return {
      consentId: requireString(body, "consentId"),
      studyInstanceUid: requireString(body, "studyInstanceUid"),
      purpose: requireString(body, "purpose"),
      providerInstitutionId: requireString(body, "providerInstitutionId"),
      receiverSecret: requireString(body, "receiverSecret"),
      seq: requireNumber(body, "seq"),
      approvalEntryHash: requireString(body, "approvalEntryHash"),
      approvalSignature: requireString(body, "approvalSignature"),
      dicomBase64: requireString(body, "dicomBase64"),
      dicomContentType: requireString(body, "dicomContentType")
    };
  }

  private parseReceipt(input: unknown): ReceiptBody {
    const body = parseObject(input, "receipt body");
    return {
      approvalEntryHash: requireString(body, "approvalEntryHash"),
      receiveEntryHash: requireString(body, "receiveEntryHash"),
      receiverSignature: requireString(body, "receiverSignature")
    };
  }

  private validateConsentGate(
    details: ReturnType<AuditAggregator["consentDetails"]>,
    request: TransferRequestBody,
    token: { consentId: string; studyInstanceUid: string; purpose: string }
  ): string | null {
    if (details.status !== "active" || details.approvalBlocked) {
      return "revoked_or_blocked";
    }
    if (details.validUntil < nowSeconds()) {
      return "expired";
    }
    if (details.purpose !== request.purpose || token.purpose !== request.purpose) {
      return "purpose_mismatch";
    }
    if (token.consentId !== request.consentId || token.studyInstanceUid !== request.studyInstanceUid) {
      return "token_scope_mismatch";
    }
    if (!details.studyInstanceUids.includes(request.studyInstanceUid)) {
      return "study_out_of_scope";
    }
    if (details.receiverInstitutionId !== request.requesterInstitutionId) {
      return "receiver_mismatch";
    }
    return null;
  }

  private async fetchStudy(studyInstanceUid: string): Promise<{ body: Buffer; contentType: string }> {
    if (!this.options.orthancBaseUrl) {
      return { body: Buffer.from(`VADREX mock DICOM ${studyInstanceUid}`), contentType: "application/dicom" };
    }
    const query = new URLSearchParams({ StudyInstanceUID: studyInstanceUid });
    const qido = await requestBuffer(`${this.options.orthancBaseUrl}/dicom-web/studies?${query.toString()}`, {
      tls: this.options.tls,
      headers: { accept: "application/dicom+json" },
      timeoutMs: 10_000
    });
    if (qido.statusCode < 200 || qido.statusCode >= 300) {
      throw new Error(`Orthanc QIDO failed with HTTP ${qido.statusCode}`);
    }
    const wado = await requestBuffer(`${this.options.orthancBaseUrl}/dicom-web/studies/${encodeURIComponent(studyInstanceUid)}`, {
      tls: this.options.tls,
      headers: { accept: "multipart/related; type=\"application/dicom\"" },
      timeoutMs: 30_000
    });
    if (wado.statusCode < 200 || wado.statusCode >= 300) {
      throw new Error(`Orthanc WADO failed with HTTP ${wado.statusCode}`);
    }
    return {
      body: wado.body,
      contentType: String(wado.headers["content-type"] ?? "application/dicom")
    };
  }

  private async storeStudy(body: Buffer, contentType: string): Promise<void> {
    if (!this.options.orthancBaseUrl) {
      return;
    }
    const response = await requestBuffer(`${this.options.orthancBaseUrl}/dicom-web/studies`, {
      method: "POST",
      tls: this.options.tls,
      headers: { "content-type": contentType },
      body,
      timeoutMs: 30_000
    });
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw new Error(`Orthanc STOW failed with HTTP ${response.statusCode}: ${response.body.toString("utf8")}`);
    }
  }

  private async withReceiptTimeout<T>(promise: Promise<T>): Promise<T> {
    let timer: NodeJS.Timeout | undefined;
    try {
      return await Promise.race([
        promise,
        new Promise<T>((_, reject) => {
          timer = setTimeout(() => reject(new Error("receipt timeout")), this.options.receiptTimeoutMs);
        })
      ]);
    } finally {
      if (timer) {
        clearTimeout(timer);
      }
    }
  }
}

export function tlsMaterialFromFiles(certPath: string, keyPath: string, caPath: string): TlsMaterial {
  return {
    cert: readFileSync(certPath),
    key: readFileSync(keyPath),
    ca: readFileSync(caPath),
    rejectUnauthorized: true
  };
}
