/**
 * Implementaciones en memoria de los puertos de protocol/, para probar la lógica de dominio
 * sin base de datos. Deben cumplir el mismo contrato que los adaptadores SQLite
 * (ver test/helpers/tokenContract.ts).
 */
import type { TokenRecord, TokenRepository, TransactionRunner } from '../../src/protocol/index.js';

const key = (electionId: string, tokenId: string): string => `${electionId}\u0000${tokenId}`;

export class InMemoryTokenRepository implements TokenRepository {
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
}

/** Transacción en memoria: si `work` lanza, restaura la copia previa del repositorio. */
export class InMemoryTransactionRunner implements TransactionRunner {
  constructor(private readonly repos: readonly InMemoryTokenRepository[]) {}

  runInTransaction<T>(work: () => T): T {
    const snapshots = this.repos.map((r) => new Map(r.rows));
    try {
      return work();
    } catch (e) {
      this.repos.forEach((r, i) => (r.rows = snapshots[i] ?? r.rows));
      throw e;
    }
  }
}
