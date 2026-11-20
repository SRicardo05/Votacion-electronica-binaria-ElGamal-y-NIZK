import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { createApp } from '../../src/api/app.js';
import { runVoterCli } from '../../src/client/index.js';
import { G, encodePointHex } from '../../src/crypto/index.js';
import { type Db, createSqliteRepositories, openDatabase } from '../../src/persistence/index.js';
import { BallotBox, ElectionService } from '../../src/protocol/index.js';
import { type ElectionParams, paramsFingerprint } from '../../src/schema/index.js';

const ADMIN = 'clave-admin-cli-pruebas-123';

describe('CLI de votación contra la urna real', () => {
  let db: Db;
  let server: Server;
  let base: string;
  let elections: ElectionService;
  let params: ElectionParams;
  let creds: string[];

  beforeAll(async () => {
    db = openDatabase(':memory:');
    const repos = createSqliteRepositories(db);
    elections = new ElectionService(repos);
    server = createApp({ elections, ballotBox: new BallotBox(repos), adminApiKey: ADMIN }).listen(0, '127.0.0.1');
    await new Promise<void>((ok) => server.once('listening', () => { ok(); }));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await new Promise<void>((ok) => server.close(() => { ok(); }));
    db.close();
  });

  beforeEach(() => {
    params = elections.create({ question: '¿Aprueba?', nMaxVoters: 5 });
    creds = elections.issueTokens(params.election_id, 3);
  });

  const run = async (extra: string[], fetchImpl: typeof fetch = fetch) => {
    const lines: string[] = [];
    const code = await runVoterCli(extra, { fetch: fetchImpl, out: (l) => lines.push(l) });
    return { code, text: lines.join('\n') };
  };
  const args = (cred: string, choice = 'si', more: string[] = []) => [
    '--server', base, '--election', params.election_id, '--credential', cred, '--choice', choice, ...more,
  ];

  it('vota, muestra el recibo y la urna guarda el ballot (código 0)', async () => {
    const { code, text } = await run(args(creds[0] ?? ''));
    expect(code).toBe(0);
    expect(text).toMatch(/Voto ACEPTADO/);
    expect(text).toMatch(/Recibo \(ballot_hash\): [0-9a-f]{64}/);
    expect(elections.status(params.election_id).n_ballots).toBe(1);
  });

  it('acepta "no" y "sí" (con tilde), y fija la huella correcta', async () => {
    expect((await run(args(creds[0] ?? '', 'no', ['--params-sha256', paramsFingerprint(params)]))).code).toBe(0);
    expect((await run(args(creds[1] ?? '', 'sí'))).code).toBe(0);
  });

  it('--json devuelve el recibo estructurado con la huella', async () => {
    const { code, text } = await run(args(creds[0] ?? '', 'si', ['--json']));
    expect(code).toBe(0);
    expect(JSON.parse(text)).toEqual(
      expect.objectContaining({ accepted: true, http_status: 201, params_sha256: paramsFingerprint(params) }),
    );
  });

  it('votar dos veces: la urna rechaza en U2 con E_TOKEN_USED (código 1)', async () => {
    await run(args(creds[0] ?? ''));
    const { code, text } = await run(args(creds[0] ?? '', 'no'));
    expect(code).toBe(1);
    expect(text).toContain('paso U2, código E_TOKEN_USED');
  });

  it('huella distinta: NO envía el voto (código 2) y el token sigue disponible', async () => {
    const { code, text } = await run(args(creds[0] ?? '', 'si', ['--params-sha256', 'a'.repeat(64)]));
    expect(code).toBe(2);
    expect(text).toMatch(/huella .* no coincide/);
    expect(elections.status(params.election_id).n_ballots).toBe(0);
  });

  it('elección inexistente → código 2', async () => {
    const res = await run(['--server', base, '--election', 'f'.repeat(32), '--credential', creds[0] ?? '', '--choice', 'si']);
    expect(res.code).toBe(2);
    expect(res.text).toContain('HTTP 404');
  });

  it.each([
    ['sin argumentos', []],
    ['opción desconocida', ['--foo']],
    ['elección inválida', ['--server', 'x', '--election', 'e', '--credential', `${'a'.repeat(32)}.${'b'.repeat(64)}`, '--choice', 'tal vez']],
    ['credencial mal formada', ['--server', 'x', '--election', 'e', '--credential', 'abc', '--choice', 'si']],
  ])('uso incorrecto (%s) → código 2', async (_caso, argv) => {
    expect((await run(argv)).code).toBe(2);
  });
});

describe('CLI de votación frente a un servidor malicioso o caído', () => {
  const cred = `${'a'.repeat(32)}.${'b'.repeat(64)}`;
  const electionId = '1'.repeat(32);
  const goodParams = {
    version: 'v1',
    suite_id: 'VOTE-BIN-v1:ristretto255:sha512:hmac-sha256:ed25519',
    election_id: electionId,
    question: '¿?',
    options: ['no', 'si'],
    n_max_voters: 5,
    generator: encodePointHex(G),
    public_key: encodePointHex(G.add(G)),
    authority_sign_pk: 'c'.repeat(64),
    opened_at: 'ahora',
  };

  /** fetch falso que sirve `paramsBody` y registra si se intentó enviar un ballot. */
  const fakeServer = (paramsBody: unknown) => {
    const posts: unknown[] = [];
    const impl = ((_url: string | URL | Request, init?: RequestInit) => {
      if (init?.method === 'POST') {
        posts.push(init.body);
        return Promise.resolve(new Response(JSON.stringify({ accepted: true, ballot_hash: 'x' }), { status: 201 }));
      }
      return Promise.resolve(new Response(JSON.stringify(paramsBody), { status: 200 }));
    }) as typeof fetch;
    return { impl, posts };
  };

  const run = async (fetchImpl: typeof fetch, extra: string[] = []) => {
    const lines: string[] = [];
    const code = await runVoterCli(
      ['--server', 'http://urna', '--election', electionId, '--credential', cred, '--choice', 'si', ...extra],
      { fetch: fetchImpl, out: (l) => lines.push(l) },
    );
    return { code, text: lines.join('\n') };
  };

  it('parámetros con otra versión de suite → no envía nada', async () => {
    const s = fakeServer({ ...goodParams, suite_id: 'otra' });
    expect((await run(s.impl)).code).toBe(2);
    expect(s.posts).toHaveLength(0);
  });

  it('parámetros de otra elección → no envía nada', async () => {
    const s = fakeServer({ ...goodParams, election_id: '2'.repeat(32) });
    const res = await run(s.impl);
    expect(res.code).toBe(2);
    expect(res.text).toContain('otra elección');
    expect(s.posts).toHaveLength(0);
  });

  it('clave pública sustituida por el servidor: la huella fijada lo detecta → no envía nada', async () => {
    const pinned = paramsFingerprint(goodParams as ElectionParams);
    const s = fakeServer({ ...goodParams, public_key: encodePointHex(G.add(G).add(G)) });
    expect((await run(s.impl, ['--params-sha256', pinned])).code).toBe(2);
    expect(s.posts).toHaveLength(0);
  });

  it('servidor caído → código 2', async () => {
    const down = (() => Promise.reject(new Error('ECONNREFUSED'))) as typeof fetch;
    const res = await run(down);
    expect(res.code).toBe(2);
    expect(res.text).toContain('ECONNREFUSED');
  });
});
