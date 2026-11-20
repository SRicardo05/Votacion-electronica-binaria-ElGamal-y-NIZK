import Database from 'better-sqlite3';

import type { BallotRepository, InsertBallotResult } from '../protocol/index.js';
import { OrProofSchema, type StoredBallot, canonicalJson } from '../schema/index.js';
import type { Db } from './database.js';

interface BallotRow {
  election_id: string;
  token_id: string;
  version: string;
  alpha: string;
  beta: string;
  proof_json: string;
  ballot_hash: string;
  received_at: string;
}

const toBallot = (r: BallotRow): StoredBallot => ({
  version: r.version,
  election_id: r.election_id,
  token_id: r.token_id,
  ciphertext: { alpha: r.alpha, beta: r.beta },
  proof: OrProofSchema.parse(JSON.parse(r.proof_json)),
  received_at: r.received_at,
  ballot_hash: r.ballot_hash,
});

export class SqliteBallotRepository implements BallotRepository {
  private readonly insertStmt;
  private readonly hashStmt;
  private readonly ctStmt;
  private readonly countStmt;
  private readonly listStmt;

  constructor(db: Db) {
    this.insertStmt = db.prepare<[string, string, string, string, string, string, string, string]>(
      `INSERT INTO ballots (election_id, token_id, version, alpha, beta, proof_json, ballot_hash, received_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    this.hashStmt = db.prepare<[string, string], { one: number }>(
      'SELECT 1 AS one FROM ballots WHERE election_id = ? AND ballot_hash = ?',
    );
    this.ctStmt = db.prepare<[string, string, string], { one: number }>(
      'SELECT 1 AS one FROM ballots WHERE election_id = ? AND alpha = ? AND beta = ?',
    );
    this.countStmt = db.prepare<[string], { n: number }>('SELECT count(*) AS n FROM ballots WHERE election_id = ?');
    this.listStmt = db.prepare<[string], BallotRow>(
      `SELECT election_id, token_id, version, alpha, beta, proof_json, ballot_hash, received_at
       FROM ballots WHERE election_id = ? ORDER BY seq`,
    );
  }

  insert(b: StoredBallot): InsertBallotResult {
    try {
      this.insertStmt.run(
        b.election_id,
        b.token_id,
        b.version,
        b.ciphertext.alpha,
        b.ciphertext.beta,
        canonicalJson(b.proof),
        b.ballot_hash,
        b.received_at,
      );
      return 'inserted';
    } catch (e) {
      if (e instanceof Database.SqliteError && e.code === 'SQLITE_CONSTRAINT_UNIQUE') return 'duplicate';
      throw e;
    }
  }

  hasBallotHash(electionId: string, ballotHash: string): boolean {
    return this.hashStmt.get(electionId, ballotHash) !== undefined;
  }

  hasCiphertext(electionId: string, alpha: string, beta: string): boolean {
    return this.ctStmt.get(electionId, alpha, beta) !== undefined;
  }

  count(electionId: string): number {
    return this.countStmt.get(electionId)?.n ?? 0;
  }

  listByElection(electionId: string): StoredBallot[] {
    return this.listStmt.all(electionId).map(toBallot);
  }
}
