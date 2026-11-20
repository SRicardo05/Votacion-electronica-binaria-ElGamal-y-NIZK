import { buildBallot } from '../../src/client/ballotBuilder.js';
import { ElectionService } from '../../src/protocol/index.js';
import { createSqliteRepositories, openDatabase } from '../../src/persistence/index.js';
import { describeBallotBox } from '../helpers/ballotBoxContract.js';
import { describeClosing } from '../helpers/closingContract.js';

describeBallotBox('SQLite', () => {
  const db = openDatabase(':memory:');
  const repos = createSqliteRepositories(db);
  return {
    repos,
    rejectionsLogged: () => repos.rejections.list().map(({ step, code }) => ({ step, code })),
    close: () => db.close(),
  };
});

describe('restricciones SQLite de elecciones y ballots', () => {
  const setup = () => {
    const db = openDatabase(':memory:');
    const repos = createSqliteRepositories(db);
    const service = new ElectionService(repos);
    const params = service.create({ question: '¿?', nMaxVoters: 5 });
    const creds = service.issueTokens(params.election_id, 2);
    return { db, repos, params, creds };
  };

  it('los parámetros publicados son inmutables y las elecciones no se borran', () => {
    const { db } = setup();
    expect(() => db.prepare("UPDATE elections SET params_json = '{}'").run()).toThrow(/inmutables/);
    expect(() => db.prepare('DELETE FROM elections').run()).toThrow(/no se pueden borrar/);
    db.close();
  });

  it('una elección cerrada no se reabre', () => {
    const { db, repos, params } = setup();
    expect(repos.elections.markClosed(params.election_id, 'ahora')).toBe(true);
    expect(repos.elections.markClosed(params.election_id, 'otra vez')).toBe(false);
    expect(() => db.prepare("UPDATE elections SET state = 'open', closed_at = NULL").run()).toThrow(/E_CLOSED/);
    db.close();
  });

  it('un ballot no puede insertarse si su token no fue consumido (aunque se salte la urna)', () => {
    const { db, repos, params, creds } = setup();
    const sub = buildBallot(params, creds[0] ?? '', 1);
    const tokenId = (creds[0] ?? '').split('.')[0] ?? '';
    expect(() =>
      repos.ballots.insert({
        version: 'v1',
        election_id: params.election_id,
        token_id: tokenId,
        ciphertext: sub.ciphertext,
        proof: sub.proof,
        received_at: 'ahora',
        ballot_hash: 'a'.repeat(64),
      }),
    ).toThrow(/E_TOKEN_UNKNOWN/);
    db.close();
  });

  it('los ballots aceptados no se modifican ni se borran; un hash repetido se reporta como duplicate', () => {
    const { db, repos, params, creds } = setup();
    const service = new ElectionService(repos);
    expect(service.status(params.election_id).n_ballots).toBe(0);
    const tokenA = (creds[0] ?? '').split('.')[0] ?? '';
    const tokenB = (creds[1] ?? '').split('.')[0] ?? '';
    repos.tokens.markConsumed(params.election_id, tokenA, 'ahora');
    repos.tokens.markConsumed(params.election_id, tokenB, 'ahora');
    const sub = buildBallot(params, creds[0] ?? '', 1);
    const base = {
      version: 'v1',
      election_id: params.election_id,
      ciphertext: sub.ciphertext,
      proof: sub.proof,
      received_at: 'ahora',
      ballot_hash: 'b'.repeat(64),
    };
    expect(repos.ballots.insert({ ...base, token_id: tokenA })).toBe('inserted');
    // Mismo hash (E_REPLAY a nivel de base) con otro token.
    const other = buildBallot(params, creds[1] ?? '', 0);
    expect(repos.ballots.insert({ ...base, token_id: tokenB, ciphertext: other.ciphertext })).toBe('duplicate');
    expect(() => db.prepare('UPDATE ballots SET beta = alpha').run()).toThrow(/no se pueden modificar/);
    expect(() => db.prepare('DELETE FROM ballots').run()).toThrow(/no se pueden borrar/);
    db.close();
  });

  it('los secretos de la autoridad viven en una tabla separada de los parámetros públicos', () => {
    const { db, repos, params } = setup();
    const row = db.prepare('SELECT params_json FROM elections').get() as { params_json: string };
    const secrets = repos.elections.findSecrets(params.election_id);
    expect(secrets).toBeDefined();
    expect(row.params_json).not.toContain(secrets?.secretKey);
    expect(row.params_json).not.toContain(secrets?.macKey);
    db.close();
  });
});

describeClosing('SQLite', () => {
  const db = openDatabase(':memory:');
  const repos = createSqliteRepositories(db);
  return {
    repos,
    rejectionsLogged: () => repos.rejections.list().map(({ step, code }) => ({ step, code })),
    close: () => db.close(),
  };
});

describe('restricciones SQLite del expediente', () => {
  it('el expediente es inmutable y solo se guarda con la elección cerrada', () => {
    const db = openDatabase(':memory:');
    const repos = createSqliteRepositories(db);
    const service = new ElectionService(repos);
    const params = service.create({ question: '¿?', nMaxVoters: 2 });
    const record = service.close(params.election_id);
    expect(() => db.prepare("UPDATE records SET record_json = '{}'").run()).toThrow(/no se puede modificar/);
    expect(() => db.prepare('DELETE FROM records').run()).toThrow(/no se puede borrar/);

    const open = service.create({ question: '¿?', nMaxVoters: 2 });
    const fake = { ...record, params: open };
    expect(() => { repos.records.save(fake); }).toThrow(/E_NOT_CLOSED/);
    db.close();
  });
});
