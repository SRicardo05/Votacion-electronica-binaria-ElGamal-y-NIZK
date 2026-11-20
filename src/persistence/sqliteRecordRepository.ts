import type { RecordRepository } from '../protocol/index.js';
import { type AuditRecord, AuditRecordSchema, canonicalJson } from '../schema/index.js';
import type { Db } from './database.js';

export class SqliteRecordRepository implements RecordRepository {
  private readonly insertStmt;
  private readonly findStmt;

  constructor(db: Db) {
    this.insertStmt = db.prepare<[string, string]>('INSERT INTO records (election_id, record_json) VALUES (?, ?)');
    this.findStmt = db.prepare<[string], { record_json: string }>(
      'SELECT record_json FROM records WHERE election_id = ?',
    );
  }

  save(record: AuditRecord): void {
    this.insertStmt.run(record.params.election_id, canonicalJson(record));
  }

  find(electionId: string): AuditRecord | undefined {
    const row = this.findStmt.get(electionId);
    return row === undefined ? undefined : AuditRecordSchema.parse(JSON.parse(row.record_json));
  }
}
