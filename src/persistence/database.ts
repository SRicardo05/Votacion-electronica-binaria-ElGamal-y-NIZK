import Database from 'better-sqlite3';

import type { TransactionRunner } from '../protocol/index.js';
import { MIGRATIONS } from './migrations.js';

export type Db = Database.Database;

/**
 * Abre (o crea) la base SQLite y aplica las migraciones pendientes.
 * `path = ':memory:'` crea una base efímera (pruebas).
 */
export function openDatabase(path: string): Db {
  const db = new Database(path);
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
  if (path !== ':memory:') db.pragma('journal_mode = WAL');
  migrate(db);
  return db;
}

export function migrate(db: Db): void {
  const current = db.pragma('user_version', { simple: true }) as number;
  if (current > MIGRATIONS.length) {
    throw new Error(`la base está en la versión ${current}, más nueva que este software (${MIGRATIONS.length})`);
  }
  MIGRATIONS.slice(current).forEach((sql, i) => {
    db.transaction(() => {
      db.exec(sql);
      db.pragma(`user_version = ${current + i + 1}`);
    }).immediate();
  });
}

/** Transacciones SQLite. `immediate` toma el bloqueo de escritura al inicio: evita carreras entre conexiones. */
export class SqliteTransactionRunner implements TransactionRunner {
  constructor(private readonly db: Db) {}

  runInTransaction<T>(work: () => T): T {
    return this.db.transaction(work).immediate();
  }
}
