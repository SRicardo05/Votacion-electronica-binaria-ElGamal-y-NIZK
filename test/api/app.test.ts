import request from 'supertest';

import { createApp } from '../../src/api/app.js';
import { buildBallot } from '../../src/client/ballotBuilder.js';
import { createSqliteRepositories, openDatabase, type Db } from '../../src/persistence/index.js';
import { BallotBox, ElectionService } from '../../src/protocol/index.js';
import type { ElectionParams } from '../../src/schema/index.js';

const ADMIN_KEY = 'clave-admin-de-pruebas-123';
const auth = { Authorization: `Bearer ${ADMIN_KEY}` };

describe('API HTTP', () => {
  let db: Db;
  let app: ReturnType<typeof createApp>;

  beforeEach(() => {
    db = openDatabase(':memory:');
    const repos = createSqliteRepositories(db);
    app = createApp({ elections: new ElectionService(repos), ballotBox: new BallotBox(repos), adminApiKey: ADMIN_KEY });
  });
  afterEach(() => {
    db.close();
  });

  async function createElection(n = 5): Promise<ElectionParams> {
    const res = await request(app).post('/admin/elections').set(auth).send({ question: '¿Aprueba?', n_max_voters: n });
    expect(res.status).toBe(201);
    return res.body as ElectionParams;
  }

  async function issue(electionId: string, count: number): Promise<string[]> {
    const res = await request(app).post(`/admin/elections/${electionId}/tokens`).set(auth).send({ count });
    expect(res.status).toBe(201);
    return (res.body as { credentials: string[] }).credentials;
  }

  it('createApp exige una clave de administración larga', () => {
    const repos = createSqliteRepositories(db);
    expect(() => createApp({ elections: new ElectionService(repos), ballotBox: new BallotBox(repos), adminApiKey: 'corta' })).toThrow();
  });

  describe('administración', () => {
    it.each([
      ['sin cabecera', {}],
      ['clave incorrecta', { Authorization: 'Bearer otra-clave-incorrecta-xx' }],
      ['esquema distinto', { Authorization: `Basic ${ADMIN_KEY}` }],
    ])('rechaza %s con 401', async (_caso, headers) => {
      const res = await request(app).post('/admin/elections').set(headers).send({ question: 'x', n_max_voters: 3 });
      expect(res.status).toBe(401);
      expect(res.body).toEqual({ error: 'E_UNAUTHORIZED' });
    });

    it('crea una elección y devuelve solo parámetros públicos', async () => {
      const params = await createElection();
      expect(Object.keys(params).sort()).toEqual(
        ['authority_sign_pk', 'election_id', 'generator', 'n_max_voters', 'opened_at', 'options', 'public_key', 'question', 'suite_id', 'version'],
      );
    });

    it('valida la entrada al crear (400) y el límite de tokens (409)', async () => {
      expect((await request(app).post('/admin/elections').set(auth).send({ question: 'x', n_max_voters: 50 })).status).toBe(400);
      expect((await request(app).post('/admin/elections').set(auth).send({ question: 'x' })).status).toBe(400);
      const params = await createElection(2);
      const res = await request(app).post(`/admin/elections/${params.election_id}/tokens`).set(auth).send({ count: 3 });
      expect(res.status).toBe(409);
      expect(res.body).toEqual(expect.objectContaining({ error: 'E_TOKEN_LIMIT' }));
    });

    it('emitir tokens en una elección inexistente → 404', async () => {
      const res = await request(app).post(`/admin/elections/${'0'.repeat(32)}/tokens`).set(auth).send({ count: 1 });
      expect(res.status).toBe(404);
    });
  });

  describe('flujo de votación', () => {
    it('params → ballot → recibo → status', async () => {
      const created = await createElection();
      const [cred = ''] = await issue(created.election_id, 3);

      const paramsRes = await request(app).get(`/elections/${created.election_id}/params`);
      expect(paramsRes.status).toBe(200);
      const params = paramsRes.body as ElectionParams;
      expect(params).toEqual(created);

      const res = await request(app).post(`/elections/${params.election_id}/ballots`).send(buildBallot(params, cred, 1));
      expect(res.status).toBe(201);
      expect(res.body).toEqual({
        accepted: true,
        election_id: params.election_id,
        ballot_hash: expect.stringMatching(/^[0-9a-f]{64}$/) as unknown,
        received_at: expect.any(String) as unknown,
      });

      const status = await request(app).get(`/elections/${params.election_id}/status`);
      expect(status.body).toEqual({
        election_id: params.election_id,
        state: 'open',
        n_max_voters: 5,
        n_tokens_issued: 3,
        n_tokens_consumed: 1,
        n_ballots: 1,
      });
    });

    it('params/status de una elección inexistente → 404', async () => {
      expect((await request(app).get(`/elections/${'1'.repeat(32)}/params`)).status).toBe(404);
      expect((await request(app).get(`/elections/${'1'.repeat(32)}/status`)).status).toBe(404);
    });
  });

  describe('rechazos: paso, código y estado HTTP', () => {
    let params: ElectionParams;
    let creds: string[];
    beforeEach(async () => {
      params = await createElection();
      creds = await issue(params.election_id, 3);
    });

    const post = (body: unknown) =>
      request(app).post(`/elections/${params.election_id}/ballots`).send(body as object);

    it('JSON mal formado → 400 U0/E_FORMAT', async () => {
      const res = await request(app)
        .post(`/elections/${params.election_id}/ballots`)
        .set('Content-Type', 'application/json')
        .send('{"version": ');
      expect(res.status).toBe(400);
      expect(res.body).toEqual({ accepted: false, step: 'U0', code: 'E_FORMAT' });
    });

    it('cuerpo demasiado grande → 413', async () => {
      const res = await post({ ...buildBallot(params, creds[0] ?? '', 1), version: 'x'.repeat(20_000) });
      expect(res.status).toBe(413);
    });

    it('versión desconocida → 400 U0/E_VERSION', async () => {
      const res = await post({ ...buildBallot(params, creds[0] ?? '', 1), version: 'v2' });
      expect(res.status).toBe(400);
      expect(res.body).toEqual({ accepted: false, step: 'U0', code: 'E_VERSION' });
    });

    it('punto inválido → 422 U1/E_POINT_ENCODING', async () => {
      const b = buildBallot(params, creds[0] ?? '', 1);
      const res = await post({ ...b, ciphertext: { ...b.ciphertext, beta: 'ff'.repeat(32) } });
      expect(res.status).toBe(422);
      expect(res.body).toEqual({ accepted: false, step: 'U1', code: 'E_POINT_ENCODING' });
    });

    it('MAC inválido → 403 U2/E_TOKEN_MAC', async () => {
      const c = creds[0] ?? '';
      const res = await post(buildBallot(params, c.slice(0, -1) + (c.endsWith('0') ? '1' : '0'), 1));
      expect(res.status).toBe(403);
      expect(res.body).toEqual({ accepted: false, step: 'U2', code: 'E_TOKEN_MAC' });
    });

    it('token repetido → 409 U2/E_TOKEN_USED', async () => {
      expect((await post(buildBallot(params, creds[0] ?? '', 1))).status).toBe(201);
      const res = await post(buildBallot(params, creds[0] ?? '', 0));
      expect(res.status).toBe(409);
      expect(res.body).toEqual({ accepted: false, step: 'U2', code: 'E_TOKEN_USED' });
    });

    it('reto alterado → 422 U3/E_PROOF_CHALLENGE', async () => {
      const b = buildBallot(params, creds[0] ?? '', 1);
      const res = await post({ ...b, proof: { ...b.proof, c0: b.proof.c1 } });
      expect(res.status).toBe(422);
      expect(res.body).toEqual({ accepted: false, step: 'U3', code: 'E_PROOF_CHALLENGE' });
    });

    it('la respuesta de rechazo no incluye el motivo interno', async () => {
      const res = await post({ ...buildBallot(params, creds[0] ?? '', 1), version: 'v2' });
      expect(Object.keys(res.body as object).sort()).toEqual(['accepted', 'code', 'step']);
    });
  });

  it('rutas desconocidas → 404 JSON', async () => {
    const res = await request(app).get('/nada');
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'E_NOT_FOUND' });
  });

  it('no expone la cabecera X-Powered-By', async () => {
    const res = await request(app).get('/nada');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });
});
