import { existsSync, readFileSync } from "node:fs";
import { AnchorClient } from "./anchorClient.js";
import { createAnchorRunner, startAnchorLoop } from "./anchoring.js";
import { AuditAggregator } from "./aggregator.js";
import {
  defaultAuditDbPath,
  defaultDeploymentPath,
  defaultInstitutionAuditDbPath,
  defaultInstitutionCaCertPath,
  defaultInstitutionEd25519KeyPath,
  defaultInstitutionEd25519PublicKeyPath,
  defaultInstitutionTlsCertPath,
  defaultInstitutionTlsKeyPath,
  defaultInstitutionWalletKeyPath,
  defaultWalletKeyPath,
  parsePositiveInteger,
  readAnchorAddress,
  readWalletPrivateKey,
  repoRoot
} from "./config.js";
import { createGatewayHttpsServer, createGatewayServer } from "./server.js";
import { EntrySigner, readPublicKey } from "./signing.js";
import { tlsMaterialFromFiles, TransferService } from "./transfer.js";

const rootDir = repoRoot();
const port = parsePositiveInteger(process.env.PORT, 7001);
const anchorIntervalSec = parsePositiveInteger(process.env.ANCHOR_INTERVAL_SEC, 30);
const institutionId = process.env.INSTITUTION_ID ?? "A";
const peerInstitutionId = process.env.PEER_INSTITUTION_ID ?? (institutionId === "A" ? "B" : "A");
const dbPath = process.env.AUDIT_DB_PATH ?? (process.env.INSTITUTION_ID ? defaultInstitutionAuditDbPath(institutionId, rootDir) : defaultAuditDbPath(rootDir));
const deploymentPath = process.env.DEPLOYMENTS_LOCAL_PATH ?? defaultDeploymentPath(rootDir);
const walletKeyPath =
  process.env.WALLET_KEY_PATH ??
  process.env.INST_A_WALLET_KEY_PATH ??
  (process.env.INSTITUTION_ID ? defaultInstitutionWalletKeyPath(institutionId, rootDir) : defaultWalletKeyPath(rootDir));
const rpcUrl = process.env.CHAIN_RPC_URL ?? "http://127.0.0.1:8545";
const tokenTtlSec = parsePositiveInteger(process.env.AUTH_TOKEN_TTL_SEC, 60);
const receiptTimeoutSec = parsePositiveInteger(process.env.RECEIPT_TIMEOUT_SEC, 30);
const dicomMaxBodyBytes = parsePositiveInteger(process.env.DICOM_MAX_BODY_BYTES, 64 * 1024 * 1024);

const aggregator = new AuditAggregator(dbPath, { institutionId });
let anchorClient: AnchorClient | null = null;
const anchorContractAddress = existsSync(deploymentPath) ? readAnchorAddress(deploymentPath, institutionId) : undefined;

function getAnchorClient(): AnchorClient {
  if (anchorClient) {
    return anchorClient;
  }
  if (!existsSync(deploymentPath)) {
    throw new Error(`deployment file not found: ${deploymentPath}`);
  }
  if (!existsSync(walletKeyPath)) {
    throw new Error(`institution ${institutionId} wallet key not found: ${walletKeyPath}`);
  }

  anchorClient = new AnchorClient(rpcUrl, readAnchorAddress(deploymentPath, institutionId), readWalletPrivateKey(walletKeyPath));
  return anchorClient;
}

const anchorNow = createAnchorRunner(aggregator, {
  registerAnchor: (rootHash, treeSize, mapRoot) => getAnchorClient().registerAnchor(rootHash, treeSize, mapRoot),
  latestAnchor: () => getAnchorClient().latestAnchor()
});

const tlsEnabled = process.env.GATEWAY_TLS_ENABLED === "true";
const certPath = process.env.GATEWAY_TLS_CERT_PATH ?? defaultInstitutionTlsCertPath(institutionId, rootDir);
const keyPath = process.env.GATEWAY_TLS_KEY_PATH ?? defaultInstitutionTlsKeyPath(institutionId, rootDir);
const caPath = process.env.GATEWAY_CA_CERT_PATH ?? defaultInstitutionCaCertPath(institutionId, rootDir);
const ed25519KeyPath = process.env.ED25519_KEY_PATH ?? defaultInstitutionEd25519KeyPath(institutionId, rootDir);
const peerEd25519PublicKeyPath =
  process.env.PEER_ED25519_PUBLIC_KEY_PATH ?? defaultInstitutionEd25519PublicKeyPath(peerInstitutionId, rootDir);
const entrySigner = existsSync(ed25519KeyPath) ? EntrySigner.fromFile(ed25519KeyPath) : undefined;
const signingPublicKeyPem = entrySigner?.publicKey.export({ format: "pem", type: "spki" }).toString();

const transferService =
  entrySigner && existsSync(peerEd25519PublicKeyPath)
    ? new TransferService(aggregator, {
        institutionId,
        peerInstitutionId,
        peerBaseUrl: process.env.PEER_BASE_URL ?? `https://gateway-${peerInstitutionId.toLowerCase()}:700${peerInstitutionId === "A" ? "1" : "2"}`,
        orthancBaseUrl: process.env.ORTHANC_BASE_URL,
        tls: existsSync(certPath) && existsSync(keyPath) && existsSync(caPath)
          ? tlsMaterialFromFiles(certPath, keyPath, caPath)
          : undefined,
        signer: entrySigner,
        peerPublicKey: readPublicKey(peerEd25519PublicKeyPath),
        tokenTtlSeconds: tokenTtlSec,
        receiptTimeoutMs: receiptTimeoutSec * 1000,
        simulatedReceiptDelayMs: process.env.SIMULATED_RECEIPT_DELAY_MS
          ? Number(process.env.SIMULATED_RECEIPT_DELAY_MS)
          : undefined
      })
    : undefined;

const serverOptions = {
  enableDevEndpoints: process.env.ENABLE_DEV_ENDPOINTS === "true",
  anchorContractAddress,
  signingPublicKeyPem,
  transferService,
  requireMtlsForInstitutionEndpoints: tlsEnabled,
  peerCertificateCommonName: process.env.PEER_CERT_CN ?? `orthanc-${peerInstitutionId.toLowerCase()}`,
  dicomBodyLimitBytes: dicomMaxBodyBytes
};

const server = tlsEnabled
  ? createGatewayHttpsServer(
      {
        cert: readFileSync(certPath),
        key: readFileSync(keyPath),
        ca: readFileSync(caPath),
        requestCert: true,
        rejectUnauthorized: false
      },
      aggregator,
      anchorNow,
      serverOptions
    )
  : createGatewayServer(aggregator, anchorNow, serverOptions);

server.listen(port, "0.0.0.0", () => {
  console.log(`VADREX gateway-${institutionId.toLowerCase()} listening on 0.0.0.0:${port} (${tlsEnabled ? "https" : "http"})`);
  console.log(`Audit DB: ${dbPath}`);
  console.log(`Anchor interval: ${anchorIntervalSec}s`);
  console.log(`Transfer service: ${transferService ? "enabled" : "disabled"}`);
});

const anchorTimer = startAnchorLoop(
  anchorNow,
  anchorIntervalSec * 1000,
  (error) => {
    console.error(`Anchor loop skipped: ${error instanceof Error ? error.message : String(error)}`);
  },
  (record) => {
    if (record) {
      console.log(`Registered anchor batch ${record.batchId} treeSize=${record.treeSize} root=${record.rootHash} mapRoot=${record.mapRoot}`);
    }
  }
);

function shutdown(): void {
  clearInterval(anchorTimer);
  server.close(() => {
    aggregator.close();
    process.exit(0);
  });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
