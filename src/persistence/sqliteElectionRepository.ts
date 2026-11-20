import type { AuthoritySecrets, ElectionRecord, ElectionRepository, ElectionState } from '../protocol/index.js';
import { type ElectionParams, ElectionParamsSchema, canonicalJson } from '../schema/index.js';
import type { Db } from './database.js';

interface ElectionRow {
  params_json: string;
  state: ElectionState;
  closed_at: string | null;
}

interface SecretsRow {
  election_id: string;
  secret_key: string;
  mac_key: string;
  sign_secret_key: string;
}

export class SqliteElectionRepository implements ElectionRepository {
  private readonly insertElection;
  private readonly insertSecrets;
  private readonly findStmt;
  private readonly findSecretsStmt;
  private readonly closeStmt;

  constructor(db: Db) {
    this.insertElection = db.prepare<[string, string]>('INSERT INTO elections (election_id, params_json) VALUES (?, ?)');
    this.insertSecrets = db.prepare<[string, string, string, string]>(
      'INSERT INTO authority_secrets (election_id, secret_key, mac_key, sign_secret_key) VALUES (?, ?, ?, ?)',
    );
    this.findStmt = db.prepare<[string], ElectionRow>(
      'SELECT params_json, state, closed_at FROM elections WHERE election_id = ?',
    );
    this.findSecretsStmt = db.prepare<[string], SecretsRow>(
      'SELECT election_id, secret_key, mac_key, sign_secret_key FROM authority_secrets WHERE election_id = ?',
    );
    this.closeStmt = db.prepare<[string, string]>(
      "UPDATE elections SET state = 'closed', closed_at = ? WHERE election_id = ? AND state = 'open'",
    );
  }

  insert(params: ElectionParams, secrets: AuthoritySecrets): void {
    this.insertElection.run(params.election_id, canonicalJson(params));
    this.insertSecrets.run(secrets.electionId, secrets.secretKey, secrets.macKey, secrets.signSecretKey);
  }

  find(electionId: string): ElectionRecord | undefined {
    const row = this.findStmt.get(electionId);
    if (row === undefined) return undefined;
    // Se revalida al leer: una base alterada a mano no debe colar parámetros malformados.
    const params = ElectionParamsSchema.parse(JSON.parse(row.params_json));
    return { params, state: row.state, closedAt: row.closed_at };
  }

  findSecrets(electionId: string): AuthoritySecrets | undefined {
    const row = this.findSecretsStmt.get(electionId);
    return row === undefined
      ? undefined
      : { electionId: row.election_id, secretKey: row.secret_key, macKey: row.mac_key, signSecretKey: row.sign_secret_key };
  }

  markClosed(electionId: string, closedAt: string): boolean {
    return this.closeStmt.run(closedAt, electionId).changes === 1;
  }
}
