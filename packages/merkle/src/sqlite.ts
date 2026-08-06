// SQLite backing store for the sparse Merkle tree.
//
// Nodes are content-addressed - the key is the node hash, the value its two child hashes - so a
// write never overwrites an existing node. Together with copy-on-write in the tree itself this is
// what lets a proof be produced against any past mapRoot, which the verification protocol needs
// in order to check every anchor taken after a revocation.
import Database from "better-sqlite3";
import type { HexString } from "@vadrex/shared";
import type { SmtNode, SmtNodeStore } from "./smt.js";

interface NodeRow {
  leftHash: string;
  rightHash: string;
}

interface LeafRow {
  value: string;
}

function normalizeHash(hash: string): HexString {
  if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) {
    throw new Error(`expected 32-byte 0x-prefixed hex hash, got ${hash}`);
  }
  return `0x${hash.slice(2).toLowerCase()}`;
}

export class SqliteSmtStore implements SmtNodeStore {
  constructor(private readonly db: Database.Database) {
    this.initializeSchema();
  }

  getNode(hash: HexString): SmtNode | null {
    const row = this.db
      .prepare("SELECT leftHash, rightHash FROM smt_nodes WHERE nodeHash = ?")
      .get(normalizeHash(hash)) as NodeRow | undefined;
    if (!row) {
      return null;
    }
    return {
      leftHash: normalizeHash(row.leftHash),
      rightHash: normalizeHash(row.rightHash)
    };
  }

  putNode(hash: HexString, node: SmtNode): void {
    this.db
      .prepare(
        `INSERT OR IGNORE INTO smt_nodes (nodeHash, leftHash, rightHash)
         VALUES (?, ?, ?)`
      )
      .run(normalizeHash(hash), normalizeHash(node.leftHash), normalizeHash(node.rightHash));
  }

  getLeafValue(hash: HexString): HexString | null {
    const row = this.db
      .prepare("SELECT value FROM smt_leaves WHERE leafHash = ?")
      .get(normalizeHash(hash)) as LeafRow | undefined;
    return row ? normalizeHash(row.value) : null;
  }

  putLeafValue(hash: HexString, value: HexString): void {
    this.db
      .prepare(
        `INSERT OR IGNORE INTO smt_leaves (leafHash, value)
         VALUES (?, ?)`
      )
      .run(normalizeHash(hash), normalizeHash(value));
  }

  private initializeSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS smt_nodes (
        nodeHash TEXT PRIMARY KEY,
        leftHash TEXT NOT NULL,
        rightHash TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS smt_leaves (
        leafHash TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);
  }
}

