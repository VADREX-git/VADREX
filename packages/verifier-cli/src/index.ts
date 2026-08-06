#!/usr/bin/env node

import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { resolveDispute, verifyNonTransfer } from "./verifier.js";

type Args = Record<string, string | boolean>;

function usage(): string {
  return `
VADREX verifier CLI

Commands:
  verify-non-transfer
    --consent-id <id>
    --secret-c <0x...>
    --revocation-seq <k>
    --revocation-entry-hash <0x...>
    --provider-gateway <url>
    --receiver-gateway <url>
    --rpc-url <url>
    [--grace-sec <seconds>]
    [--provider-anchor-address <address>]
    [--receiver-anchor-address <address>]
    [--tls-ca <path>] [--tls-cert <path>] [--tls-key <path>] [--insecure]

  resolve-dispute
    --transfer-ref <A TRANSFER_APPROVED entryHash>
    --a-gateway <url>
    --b-gateway <url>
    --rpc-url <url>
    --a-public-key <path>
    --b-public-key <path>
    [--a-anchor-address <address>]
    [--b-anchor-address <address>]
    [--claim b-denies]
    [--tls-ca <path>] [--tls-cert <path>] [--tls-key <path>] [--insecure]
`.trim();
}

function parseArgs(argv: string[]): { command: string; args: Args } {
  const [command, ...rest] = argv;
  if (!command || command === "--help" || command === "-h") {
    return { command: "help", args: {} };
  }
  const args: Args = {};
  for (let index = 0; index < rest.length; index += 1) {
    const key = rest[index];
    if (!key.startsWith("--")) {
      throw new Error(`unexpected positional argument: ${key}`);
    }
    const name = key.slice(2);
    if (name === "insecure") {
      args[name] = true;
      continue;
    }
    const value = rest[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`missing value for ${key}`);
    }
    args[name] = value;
    index += 1;
  }
  return { command, args };
}

function requiredString(args: Args, name: string): string {
  const value = args[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`--${name} is required`);
  }
  return value;
}

function optionalString(args: Args, name: string): string | undefined {
  const value = args[name];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function requiredInteger(args: Args, name: string): number {
  const value = Number(requiredString(args, name));
  if (!Number.isSafeInteger(value)) {
    throw new Error(`--${name} must be an integer`);
  }
  return value;
}

function defaultGraceSeconds(args: Args): number {
  if (typeof args["grace-sec"] === "string") {
    const parsed = Number(args["grace-sec"]);
    if (!Number.isSafeInteger(parsed) || parsed < 0) {
      throw new Error("--grace-sec must be an integer >= 0");
    }
    return parsed;
  }
  const env = process.env.ANCHOR_MAX_INTERVAL_SEC ?? process.env.ANCHOR_INTERVAL_SEC;
  if (env) {
    const parsed = Number(env);
    if (Number.isSafeInteger(parsed) && parsed >= 0) {
      return parsed;
    }
  }
  return 30;
}

function pathArg(args: Args, name: string): string | undefined {
  const value = optionalString(args, name);
  return value ? resolve(value) : undefined;
}

function requiredFileText(args: Args, name: string): string {
  return readFileSync(resolve(requiredString(args, name)), "utf8");
}

function claimArg(args: Args): "b-denies" | undefined {
  const claim = optionalString(args, "claim");
  if (claim === undefined) {
    return undefined;
  }
  if (claim !== "b-denies") {
    throw new Error("--claim must be b-denies");
  }
  return claim;
}

function tlsArgs(args: Args) {
  return {
    caPath: pathArg(args, "tls-ca"),
    certPath: pathArg(args, "tls-cert"),
    keyPath: pathArg(args, "tls-key"),
    insecure: args.insecure === true
  };
}

async function main(): Promise<number> {
  const { command, args } = parseArgs(process.argv.slice(2));
  if (command === "help") {
    console.log(usage());
    return 0;
  }

  if (command === "verify-non-transfer") {
    const result = await verifyNonTransfer({
      consentId: requiredString(args, "consent-id"),
      secretC: requiredString(args, "secret-c"),
      revocationSeq: requiredInteger(args, "revocation-seq"),
      revocationEntryHash: requiredString(args, "revocation-entry-hash"),
      providerGateway: requiredString(args, "provider-gateway"),
      receiverGateway: requiredString(args, "receiver-gateway"),
      rpcUrl: requiredString(args, "rpc-url"),
      graceSeconds: defaultGraceSeconds(args),
      providerAnchorAddress: optionalString(args, "provider-anchor-address"),
      receiverAnchorAddress: optionalString(args, "receiver-anchor-address"),
      tls: tlsArgs(args)
    });
    console.log(result.lines.join("\n"));
    console.log(`API calls: ${result.apiCalls}`);
    console.log(`RPC calls: ${result.rpcCalls}`);
    console.log(`API bytes: request=${result.apiRequestBytes}, response=${result.apiResponseBytes}`);
    return result.ok ? 0 : 1;
  }

  if (command === "resolve-dispute") {
    const result = await resolveDispute({
      transferRef: requiredString(args, "transfer-ref"),
      aGateway: requiredString(args, "a-gateway"),
      bGateway: requiredString(args, "b-gateway"),
      rpcUrl: requiredString(args, "rpc-url"),
      aPublicKeyPem: requiredFileText(args, "a-public-key"),
      bPublicKeyPem: requiredFileText(args, "b-public-key"),
      providerAnchorAddress: optionalString(args, "a-anchor-address"),
      receiverAnchorAddress: optionalString(args, "b-anchor-address"),
      claim: claimArg(args),
      tls: tlsArgs(args)
    });
    console.log(result.lines.join("\n"));
    console.log(`API calls: ${result.apiCalls}`);
    console.log(`RPC calls: ${result.rpcCalls}`);
    console.log(`API bytes: request=${result.apiRequestBytes}, response=${result.apiResponseBytes}`);
    return result.ok ? 0 : 1;
  }

  throw new Error(`unknown command: ${command}\n\n${usage()}`);
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
