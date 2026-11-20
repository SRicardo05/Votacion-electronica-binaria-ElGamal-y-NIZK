import type { TokenRecord, TokenRepository } from '../protocol/index.js';
import type { Db } from './database.js';

interface TokenRow {
  election_id: string;
  token_id: string;
  issued_at: string;
  consumed_at: string | null;
}

const toRecord = (r: TokenRow): TokenRecord => ({
  electionId: r.election_id,
  tokenId: r.token_id,
  issuedAt: r.issued_at,
  consumedAt: r.consumed_at,
});

export class SqliteTokenRepository implements TokenRepository {
  private readonly insertStmt;
  private readonly findStmt;
  private readonly consumeStmt;
  private readonly listStmt;

  constructor(db: Db) {
    this.insertStmt = db.prepare<[string, string, string]>(
      'INSERT INTO tokens (election_id, token_id, issued_at) VALUES (?, ?, ?)',
    );
    this.findStmt = db.prepare<[string, string], TokenRow>(
      'SELECT election_id, token_id, issued_at, consumed_at FROM tokens WHERE election_id = ? AND token_id = ?',
    );
    // Atómico: la condición `consumed_at IS NULL` y la escritura ocurren en una sola sentencia.
    this.consumeStmt = db.prepare<[string, string, string]>(
      'UPDATE tokens SET consumed_at = ? WHERE election_id = ? AND token_id = ? AND consumed_at IS NULL',
    );
    this.listStmt = db.prepare<[string], TokenRow>(
      'SELECT election_id, token_id, issued_at, consumed_at FROM tokens WHERE election_id = ? ORDER BY token_id',
    );
  }

  insertIssued(records: readonly Omit<TokenRecord, 'consumedAt'>[]): void {
    for (const r of records) this.insertStmt.run(r.electionId, r.tokenId, r.issuedAt);
  }

  find(electionId: string, tokenId: string): TokenRecord | undefined {
    const row = this.findStmt.get(electionId, tokenId);
    return row === undefined ? undefined : toRecord(row);
  }

  markConsumed(electionId: string, tokenId: string, consumedAt: string): boolean {
    return this.consumeStmt.run(consumedAt, electionId, tokenId).changes === 1;
  }

  listByElection(electionId: string): TokenRecord[] {
    return this.listStmt.all(electionId).map(toRecord);
  }
}
