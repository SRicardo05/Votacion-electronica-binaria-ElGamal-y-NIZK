/** API pública de la capa de persistencia (adaptadores SQLite de los puertos de protocol/). */
import { type Db, SqliteTransactionRunner } from './database.js';
import { SqliteBallotRepository } from './sqliteBallotRepository.js';
import { SqliteElectionRepository } from './sqliteElectionRepository.js';
import { SqliteRejectionLog } from './sqliteRejectionLog.js';
import { SqliteTokenRepository } from './sqliteTokenRepository.js';

export * from './database.js';
export * from './sqliteTokenRepository.js';
export * from './sqliteElectionRepository.js';
export * from './sqliteBallotRepository.js';
export * from './sqliteRejectionLog.js';

/** Todos los adaptadores sobre una misma conexión (y, por tanto, las mismas transacciones). */
export function createSqliteRepositories(db: Db) {
  return {
    elections: new SqliteElectionRepository(db),
    tokens: new SqliteTokenRepository(db),
    ballots: new SqliteBallotRepository(db),
    rejections: new SqliteRejectionLog(db),
    transactions: new SqliteTransactionRunner(db),
  };
}
