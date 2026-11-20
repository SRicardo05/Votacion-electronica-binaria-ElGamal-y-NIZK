/**
 * Implementaciones en memoria de los puertos de protocol/, para probar la lógica de dominio
 * sin base de datos. Deben cumplir el mismo contrato que los adaptadores SQLite.
 */
import type {
  AuthoritySecrets,
  BallotRepository,
  ElectionRecord,
  ElectionRepository,
  InsertBallotResult,
  Rejection,
  RejectionLog,
  TokenRecord,
  TokenRepository,
  TransactionRunner,
} from '../../src/protocol/index.js';
import type { ElectionParams, StoredBallot } from '../../src/schema/index.js';

/** Repositorio cuyo estado se puede copiar y restaurar (para simular rollback). */
interface Snapshottable {
  snapshot(): unknown;
  restore(state: unknown): void;
}

const key = (...parts: string[]): string => parts.join('\u0000');

export class InMemoryTokenRepository implements TokenRepository, Snapshottable {
  rows = new Map<string, TokenRecord>();

  insertIssued(records: readonly Omit<TokenRecord, 'consumedAt'>[]): void {
    for (const r of records) {
      const k = key(r.electionId, r.tokenId);
      if (this.rows.has(k)) throw new Error('token duplicado');
      this.rows.set(k, { ...r, consumedAt: null });
    }
  }

  find(electionId: string, tokenId: string): TokenRecord | undefined {
    return this.rows.get(key(electionId, tokenId));
  }

  markConsumed(electionId: string, tokenId: string, consumedAt: string): boolean {
    const k = key(electionId, tokenId);
    const row = this.rows.get(k);
    if (row === undefined || row.consumedAt !== null) return false;
    this.rows.set(k, { ...row, consumedAt });
    return true;
  }

  listByElection(electionId: string): TokenRecord[] {
    return [...this.rows.values()]
      .filter((r) => r.electionId === electionId)
      .sort((a, b) => a.tokenId.localeCompare(b.tokenId));
  }

  snapshot(): unknown {
    return new Map(this.rows);
  }

  restore(state: unknown): void {
    this.rows = state as Map<string, TokenRecord>;
  }
}

export class InMemoryElectionRepository implements ElectionRepository, Snapshottable {
  elections = new Map<string, ElectionRecord>();
  secrets = new Map<string, AuthoritySecrets>();

  insert(params: ElectionParams, secrets: AuthoritySecrets): void {
    if (this.elections.has(params.election_id)) throw new Error('elección duplicada');
    this.elections.set(params.election_id, { params, state: 'open', closedAt: null });
    this.secrets.set(secrets.electionId, secrets);
  }

  find(electionId: string): ElectionRecord | undefined {
    return this.elections.get(electionId);
  }

  findSecrets(electionId: string): AuthoritySecrets | undefined {
    return this.secrets.get(electionId);
  }

  markClosed(electionId: string, closedAt: string): boolean {
    const e = this.elections.get(electionId);
    if (e?.state !== 'open') return false;
    this.elections.set(electionId, { ...e, state: 'closed', closedAt });
    return true;
  }

  snapshot(): unknown {
    return [new Map(this.elections), new Map(this.secrets)];
  }

  restore(state: unknown): void {
    [this.elections, this.secrets] = state as [Map<string, ElectionRecord>, Map<string, AuthoritySecrets>];
  }
}

export class InMemoryBallotRepository implements BallotRepository, Snapshottable {
  rows: StoredBallot[] = [];

  insert(b: StoredBallot): InsertBallotResult {
    const dup = this.rows.some(
      (r) =>
        r.election_id === b.election_id &&
        (r.token_id === b.token_id ||
          r.ballot_hash === b.ballot_hash ||
          (r.ciphertext.alpha === b.ciphertext.alpha && r.ciphertext.beta === b.ciphertext.beta)),
    );
    if (dup) return 'duplicate';
    this.rows.push(b);
    return 'inserted';
  }

  hasBallotHash(electionId: string, ballotHash: string): boolean {
    return this.rows.some((r) => r.election_id === electionId && r.ballot_hash === ballotHash);
  }

  hasCiphertext(electionId: string, alpha: string, beta: string): boolean {
    return this.rows.some((r) => r.election_id === electionId && r.ciphertext.alpha === alpha && r.ciphertext.beta === beta);
  }

  count(electionId: string): number {
    return this.listByElection(electionId).length;
  }

  listByElection(electionId: string): StoredBallot[] {
    return this.rows.filter((r) => r.election_id === electionId);
  }

  snapshot(): unknown {
    return [...this.rows];
  }

  restore(state: unknown): void {
    this.rows = state as StoredBallot[];
  }
}

export class InMemoryRejectionLog implements RejectionLog {
  entries: { electionId: string | null; rejection: Rejection; at: string }[] = [];

  record(electionId: string | null, rejection: Rejection, at: string): void {
    this.entries.push({ electionId, rejection, at });
  }
}

/** Transacción en memoria: si `work` lanza, restaura el estado previo de todos los repositorios. */
export class InMemoryTransactionRunner implements TransactionRunner {
  constructor(private readonly repos: readonly Snapshottable[]) {}

  runInTransaction<T>(work: () => T): T {
    const snapshots = this.repos.map((r) => r.snapshot());
    try {
      return work();
    } catch (e) {
      this.repos.forEach((r, i) => {
        r.restore(snapshots[i]);
      });
      throw e;
    }
  }
}

export function createInMemoryRepositories() {
  const elections = new InMemoryElectionRepository();
  const tokens = new InMemoryTokenRepository();
  const ballots = new InMemoryBallotRepository();
  const rejections = new InMemoryRejectionLog();
  return {
    elections,
    tokens,
    ballots,
    rejections,
    transactions: new InMemoryTransactionRunner([elections, tokens, ballots]),
  };
}
