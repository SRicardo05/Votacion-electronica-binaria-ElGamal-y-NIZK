import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { generateMacKey } from '../../src/crypto/index.js';
import { RejectCode, TokenService, parseCredential } from '../../src/protocol/index.js';
import {
  type Db,
  SqliteTokenRepository,
  SqliteTransactionRunner,
  migrate,
  openDatabase,
} from '../../src/persistence/index.js';
import { MIGRATIONS } from '../../src/persistence/migrations.js';
import { describeTokenRepositoryContract, describeTokenService } from '../helpers/tokenContract.js';

const sqliteBackend = () => {
  const db = openDatabase(':memory:');
  return {
    tokens: new SqliteTokenRepository(db),
    transactions: new SqliteTransactionRunner(db),
    close: () => db.close(),
  };
};

describeTokenRepositoryContract('SQLite', sqliteBackend);
describeTokenService('SQLite', sqliteBackend);

const E = 'eleccion-1';
const T = '0123456789abcdef0123456789abcdef';
const AT = '2026-11-20T10:00:00.000Z';

describe('restricciones a nivel de base de datos', () => {
  let db: Db;
  beforeEach(() => {
    db = openDatabase(':memory:');
    new SqliteTokenRepository(db).insertIssued([{ electionId: E, tokenId: T, issuedAt: AT }]);
  });
  afterEach(() => db.close());

  it('un trigger impide volver a marcar un token consumido, incluso con SQL directo', () => {
    db.prepare('UPDATE tokens SET consumed_at = ? WHERE token_id = ?').run(AT, T);
    expect(() => db.prepare('UPDATE tokens SET consumed_at = ? WHERE token_id = ?').run('otra', T)).toThrow(/E_TOKEN_USED/);
    expect(() => db.prepare('UPDATE tokens SET consumed_at = NULL WHERE token_id = ?').run(T)).toThrow(/E_TOKEN_USED/);
  });

  it('los tokens emitidos no se pueden borrar', () => {
    expect(() => db.prepare('DELETE FROM tokens').run()).toThrow(/no se pueden borrar/);
  });

  it.each([
    ['token_id corto', 'abc'],
    ['token_id con mayúsculas', T.toUpperCase()],
  ])('CHECK rechaza %s', (_caso, tokenId) => {
    expect(() => db.prepare('INSERT INTO tokens (election_id, token_id, issued_at) VALUES (?, ?, ?)').run(E, tokenId, AT)).toThrow(
      /CHECK/,
    );
  });
});

describe('migraciones', () => {
  it('quedan registradas en user_version y re-aplicarlas no hace nada', () => {
    const db = openDatabase(':memory:');
    expect(db.pragma('user_version', { simple: true })).toBe(MIGRATIONS.length);
    expect(() => { migrate(db); }).not.toThrow();
    db.close();
  });

  it('se niega a abrir una base más nueva que el software', () => {
    const db = openDatabase(':memory:');
    db.pragma(`user_version = ${MIGRATIONS.length + 1}`);
    expect(() => { migrate(db); }).toThrow(/más nueva/);
    db.close();
  });
});

describe('carrera entre dos conexiones al mismo archivo', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'voto-test-'));
  });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it('dos urnas validan el mismo token, pero solo una lo consume → la otra recibe U5 / E_TOKEN_USED', () => {
    const path = join(dir, 'urna.db');
    const macKey = generateMacKey();
    const dbA = openDatabase(path);
    const dbB = openDatabase(path);
    const make = (db: Db) =>
      new TokenService({ tokens: new SqliteTokenRepository(db), transactions: new SqliteTransactionRunner(db), macKey });
    const urnA = make(dbA);
    const urnB = make(dbB);

    const [cred = ''] = urnA.issue(E, 1);
    const tokenId = parseCredential(cred)?.tokenId ?? '';

    // Ambas pasan U2 antes de que ninguna consuma.
    expect(urnA.check(E, cred).ok).toBe(true);
    expect(urnB.check(E, cred).ok).toBe(true);

    const a = new SqliteTransactionRunner(dbA).runInTransaction(() => urnA.consume(E, tokenId));
    const b = new SqliteTransactionRunner(dbB).runInTransaction(() => urnB.consume(E, tokenId));
    expect(a.ok).toBe(true);
    expect(b).toEqual({ ok: false, rejection: expect.objectContaining({ step: 'U5', code: RejectCode.TOKEN_USED }) as unknown });

    dbA.close();
    dbB.close();
  });
});
