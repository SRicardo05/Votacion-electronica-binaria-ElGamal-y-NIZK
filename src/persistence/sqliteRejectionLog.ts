import type { Rejection, RejectionLog } from '../protocol/index.js';
import type { Db } from './database.js';

export interface RejectionRow {
  election_id: string | null;
  step: string;
  code: string;
  reason: string;
  at: string;
}

export class SqliteRejectionLog implements RejectionLog {
  private readonly insertStmt;
  private readonly listStmt;

  constructor(db: Db) {
    this.insertStmt = db.prepare<[string | null, string, string, string, string]>(
      'INSERT INTO rejections (election_id, step, code, reason, at) VALUES (?, ?, ?, ?, ?)',
    );
    this.listStmt = db.prepare<[], RejectionRow>('SELECT election_id, step, code, reason, at FROM rejections ORDER BY id');
  }

  record(electionId: string | null, r: Rejection, at: string): void {
    this.insertStmt.run(electionId, r.step, r.code, r.reason, at);
  }

  list(): RejectionRow[] {
    return this.listStmt.all();
  }
}
