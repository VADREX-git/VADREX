import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { HDNodeWallet, Mnemonic } from "ethers";

// Derives accounts 0 (institution A) and 1 (institution B) from Hardhat's default mnemonic.
// Deriving rather than hard-coding the private keys rules out transcription errors, and the
// address comparison below checks the derivation against the expected accounts.
const HARDHAT_MNEMONIC = "test test test test test test test test test test test junk";
const hardhatAccounts = {
  a: { index: 0, address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" },
  b: { index: 1, address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" }
} as const;

const mnemonic = Mnemonic.fromPhrase(HARDHAT_MNEMONIC);
const outDir = join(process.cwd(), "scripts", "out");

for (const institution of ["a", "b"] as const) {
  const dir = join(outDir, `inst-${institution}`);
  mkdirSync(dir, { recursive: true });

  const account = hardhatAccounts[institution];
  const wallet = HDNodeWallet.fromMnemonic(mnemonic, `m/44'/60'/0'/0/${account.index}`);
  if (wallet.address !== account.address) {
    throw new Error(
      `derived wallet ${wallet.address} for inst-${institution} does not match Hardhat account #${account.index} (${account.address})`
    );
  }

  // An existing Ed25519 key is kept: regenerating it would silently invalidate every signature
  // already in the log. wallet.key is derived deterministically, so rewriting it changes nothing.
  const ed25519KeyPath = join(dir, "ed25519.key");
  if (existsSync(ed25519KeyPath)) {
    console.log(`Preserved existing Ed25519 key: ${ed25519KeyPath}`);
  } else {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    writeFileSync(ed25519KeyPath, privateKey.export({ format: "pem", type: "pkcs8" }));
    writeFileSync(join(dir, "ed25519.pub"), publicKey.export({ format: "pem", type: "spki" }));
  }
  writeFileSync(join(dir, "wallet.key"), `${wallet.privateKey}\n`);
}

console.log(`Generated Ed25519 and Hardhat wallet keys under ${outDir}`);
