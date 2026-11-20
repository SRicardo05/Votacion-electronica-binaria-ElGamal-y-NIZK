/**
 * Comportamiento de ElectionService + BallotBox (pasos U0–U5), ejecutado contra cada backend.
 * Cada caso negativo afirma el PASO y el CÓDIGO de rechazo (PLAN §4).
 */
import { buildBallot } from '../../src/client/ballotBuilder.js';
import {
  CryptoErrorCode,
  IDENTITY,
  ProofErrorCode,
  type Vote,
  aggregateCiphertexts,
  decodeBallotCiphertextHex,
  decodeNonIdentityPointHex,
  decodeScalarHex,
  decryptSmall,
  encodeCiphertextHex,
  encodeOrProofHex,
  encodePointHex,
  encryptVote,
  proveVote,
} from '../../src/crypto/index.js';
import {
  AdminErrorCode,
  BallotBox,
  type BallotRepository,
  ElectionService,
  type ElectionRepository,
  type Outcome,
  type Receipt,
  RejectCode,
  type RejectionLog,
  type TokenRepository,
  type TransactionRunner,
} from '../../src/protocol/index.js';
import { type BallotSubmission, type ElectionParams, computeBallotHash } from '../../src/schema/index.js';
import { forgeBothSimulated, forgeOneForced } from './maliciousProver.js';

export interface Repos {
  readonly elections: ElectionRepository;
  readonly tokens: TokenRepository;
  readonly ballots: BallotRepository;
  readonly rejections: RejectionLog;
  readonly transactions: TransactionRunner;
}

export interface Backend {
  readonly repos: Repos;
  /** Rechazos registrados, en orden. */
  readonly rejectionsLogged: () => { step: string; code: string }[];
  readonly close?: () => void;
}

/** Afirma un rechazo con paso y código concretos. */
export function expectRejection(outcome: Outcome<Receipt>, step: string, code: string): void {
  expect(outcome).toEqual({ ok: false, rejection: expect.objectContaining({ step, code }) as unknown });
}

/** Ballot cuya prueba se generó con `forge` en lugar del probador honesto. */
function forgedSubmission(
  params: ElectionParams,
  credential: string,
  forge: typeof forgeBothSimulated,
): BallotSubmission {
  const tokenId = credential.split('.')[0] ?? '';
  const ctx = { electionId: params.election_id, tokenId, publicKey: decodeNonIdentityPointHex(params.public_key) };
  const forged = forge(ctx, 2n);
  return {
    version: 'v1',
    election_id: params.election_id,
    credential,
    ciphertext: encodeCiphertextHex(forged.ciphertext),
    proof: encodeOrProofHex(forged.proof),
  };
}

export function describeBallotBox(name: string, make: () => Backend): void {
  describe(`Urna U0–U5 (${name})`, () => {
    let backend: Backend;
    let elections: ElectionService;
    let box: BallotBox;
    let params: ElectionParams;
    let creds: string[];

    beforeEach(() => {
      backend = make();
      elections = new ElectionService(backend.repos);
      box = new BallotBox(backend.repos);
      params = elections.create({ question: '¿Aprueba la propuesta?', nMaxVoters: 20 });
      creds = elections.issueTokens(params.election_id, 5);
    });
    afterEach(() => backend.close?.());

    const id = () => params.election_id;
    const cred = (i: number) => creds[i] ?? '';
    const ballot = (i: number, vote: Vote = 1) => buildBallot(params, cred(i), vote);

    // ───────────────────────── Elección y tokens ─────────────────────────

    describe('administración', () => {
      it('crea parámetros públicos válidos y guarda los secretos aparte', () => {
        expect(params.version).toBe('v1');
        expect(params.n_max_voters).toBe(20);
        expect(JSON.stringify(params)).not.toContain(backend.repos.elections.findSecrets(id())?.secretKey);
        expect(elections.getParams(id())).toEqual(params);
      });

      it('rechaza n_max_voters fuera de [1, 20] y preguntas vacías', () => {
        expect(() => elections.create({ question: 'x', nMaxVoters: 21 })).toThrow(AdminErrorCode.INVALID_INPUT);
        expect(() => elections.create({ question: 'x', nMaxVoters: 0 })).toThrow(AdminErrorCode.INVALID_INPUT);
        expect(() => elections.create({ question: '   ', nMaxVoters: 5 })).toThrow(AdminErrorCode.INVALID_INPUT);
      });

      it('no permite emitir más tokens que n_max_voters (y no emite ninguno si se excede)', () => {
        expect(() => elections.issueTokens(id(), 16)).toThrow(AdminErrorCode.TOKEN_LIMIT);
        expect(elections.status(id()).n_tokens_issued).toBe(5);
        expect(elections.issueTokens(id(), 15)).toHaveLength(15);
      });

      it('emitir tokens en una elección inexistente o cerrada falla', () => {
        expect(() => elections.issueTokens('0'.repeat(32), 1)).toThrow(AdminErrorCode.ELECTION);
        backend.repos.elections.markClosed(id(), new Date().toISOString());
        expect(() => elections.issueTokens(id(), 1)).toThrow(AdminErrorCode.CLOSED);
      });
    });

    // ───────────────────────────── Aceptación ─────────────────────────────

    describe('ballots válidos', () => {
      it('acepta un ballot y devuelve un recibo con su ballot_hash', () => {
        const sub = ballot(0, 1);
        const outcome = box.submit(id(), sub);
        expect(outcome.ok).toBe(true);
        if (!outcome.ok) return;
        const stored = backend.repos.ballots.listByElection(id());
        expect(stored).toHaveLength(1);
        expect(outcome.value.ballot_hash).toBe(stored[0]?.ballot_hash);
        expect(computeBallotHash({ ...sub, token_id: stored[0]?.token_id ?? '' })).toBe(outcome.value.ballot_hash);
      });

      it('el ballot guardado no contiene la credencial ni el MAC', () => {
        box.submit(id(), ballot(0));
        const stored = JSON.stringify(backend.repos.ballots.listByElection(id()));
        expect(stored).not.toContain(cred(0).split('.')[1]);
        expect(stored).not.toContain('credential');
      });

      it('20 votantes con distribución conocida: el agregado de lo guardado descifra al total', () => {
        const all = [...creds, ...elections.issueTokens(id(), 15)];
        const votes: Vote[] = all.map((_, i) => (i < 13 ? 1 : 0));
        all.forEach((c, i) => {
          expect(box.submit(id(), buildBallot(params, c, votes[i] ?? 0)).ok).toBe(true);
        });
        const agg = aggregateCiphertexts(
          backend.repos.ballots.listByElection(id()).map((b) => decodeBallotCiphertextHex(b.ciphertext)),
        );
        const x = decodeScalarHex(backend.repos.elections.findSecrets(id())?.secretKey ?? '');
        expect(decryptSmall(x, agg, 20)).toBe(13);
        expect(elections.status(id())).toEqual(
          expect.objectContaining({ n_tokens_issued: 20, n_tokens_consumed: 20, n_ballots: 20 }),
        );
      });
    });

    // ──────────────────────────────── U0 ────────────────────────────────

    describe('U0 — formato y estado', () => {
      it.each([
        ['cuerpo no objeto', 'hola'],
        ['cuerpo nulo', null],
        ['objeto vacío', {}],
      ])('%s → E_FORMAT', (_caso, body) => {
        expectRejection(box.submit(id(), body), 'U0', RejectCode.FORMAT);
      });

      it('campo extra → E_FORMAT', () => {
        expectRejection(box.submit(id(), { ...ballot(0), extra: 1 }), 'U0', RejectCode.FORMAT);
      });

      it('campo de la prueba ausente → E_FORMAT', () => {
        const { s1: _omit, ...proof } = ballot(0).proof;
        expectRejection(box.submit(id(), { ...ballot(0), proof }), 'U0', RejectCode.FORMAT);
      });

      it('versión distinta → E_VERSION', () => {
        expectRejection(box.submit(id(), { ...ballot(0), version: 'v2' }), 'U0', RejectCode.VERSION);
      });

      it('election_id del cuerpo distinto al de la ruta → E_ELECTION', () => {
        expectRejection(box.submit(id(), { ...ballot(0), election_id: 'f'.repeat(32) }), 'U0', RejectCode.ELECTION);
      });

      it('elección inexistente → E_ELECTION', () => {
        const other = 'a'.repeat(32);
        expectRejection(box.submit(other, { ...ballot(0), election_id: other }), 'U0', RejectCode.ELECTION);
      });

      it('elección cerrada → E_CLOSED', () => {
        backend.repos.elections.markClosed(id(), new Date().toISOString());
        expectRejection(box.submit(id(), ballot(0)), 'U0', RejectCode.CLOSED);
      });
    });

    // ──────────────────────────────── U1 ────────────────────────────────

    describe('U1 — decodificación estricta', () => {
      it('α = identidad → E_IDENTITY', () => {
        const b = ballot(0);
        const sub = { ...b, ciphertext: { ...b.ciphertext, alpha: encodePointHex(IDENTITY) } };
        expectRejection(box.submit(id(), sub), 'U1', CryptoErrorCode.IDENTITY);
      });

      it('β que no es un punto del grupo → E_POINT_ENCODING', () => {
        const b = ballot(0);
        expectRejection(box.submit(id(), { ...b, ciphertext: { ...b.ciphertext, beta: 'ff'.repeat(32) } }), 'U1', CryptoErrorCode.POINT_ENCODING);
      });

      it('escalar ≥ q → E_SCALAR_RANGE', () => {
        const b = ballot(0);
        expectRejection(box.submit(id(), { ...b, proof: { ...b.proof, s0: 'ff'.repeat(32) } }), 'U1', CryptoErrorCode.SCALAR_RANGE);
      });

      it('un ballot inválido en U1 no consume el token', () => {
        const b = ballot(0);
        box.submit(id(), { ...b, ciphertext: { ...b.ciphertext, beta: 'ff'.repeat(32) } });
        expect(box.submit(id(), ballot(0)).ok).toBe(true);
      });
    });

    // ──────────────────────────────── U2 ────────────────────────────────

    describe('U2 — token', () => {
      it('credencial mal formada → E_TOKEN_FORMAT', () => {
        expectRejection(box.submit(id(), { ...ballot(0), credential: 'basura' }), 'U2', RejectCode.TOKEN_FORMAT);
      });

      it('MAC alterado → E_TOKEN_MAC', () => {
        const c = cred(0);
        const altered = c.slice(0, -1) + (c.endsWith('0') ? '1' : '0');
        expectRejection(box.submit(id(), buildBallot(params, altered, 1)), 'U2', RejectCode.TOKEN_MAC);
      });

      it('token repetido: el mismo votante intenta votar dos veces → E_TOKEN_USED', () => {
        expect(box.submit(id(), ballot(0, 1)).ok).toBe(true);
        expectRejection(box.submit(id(), ballot(0, 0)), 'U2', RejectCode.TOKEN_USED);
      });

      it('reenvío exacto de un ballot aceptado (replay) → U2 / E_TOKEN_USED', () => {
        const sub = ballot(0);
        expect(box.submit(id(), sub).ok).toBe(true);
        expectRejection(box.submit(id(), sub), 'U2', RejectCode.TOKEN_USED);
        expect(backend.repos.ballots.count(id())).toBe(1);
      });
    });

    // ──────────────────────────────── U3 ────────────────────────────────

    describe('U3 — prueba OR', () => {
      it('voto de valor 2, ramas simuladas → E_PROOF_CHALLENGE', () => {
        expectRejection(box.submit(id(), forgedSubmission(params, cred(0), forgeBothSimulated)), 'U3', ProofErrorCode.CHALLENGE);
      });

      it('voto de valor 2, rama 0 forzada → E_PROOF_EQ_0', () => {
        const forge: typeof forgeBothSimulated = (ctx, m) => forgeOneForced(ctx, m, 1);
        expectRejection(box.submit(id(), forgedSubmission(params, cred(0), forge)), 'U3', ProofErrorCode.EQ_0);
      });

      it('compromiso modificado → E_PROOF_CHALLENGE', () => {
        const b = ballot(0);
        const other = ballot(1);
        expectRejection(box.submit(id(), { ...b, proof: { ...b.proof, A1: other.proof.A1 } }), 'U3', ProofErrorCode.CHALLENGE);
      });

      it('reto alterado → E_PROOF_CHALLENGE', () => {
        const b = ballot(0);
        expectRejection(box.submit(id(), { ...b, proof: { ...b.proof, c0: b.proof.c1 } }), 'U3', ProofErrorCode.CHALLENGE);
      });

      it('(α, β, π) de otro votante enviados con un token propio → E_PROOF_CHALLENGE', () => {
        const victim = ballot(0, 1);
        expectRejection(box.submit(id(), { ...victim, credential: cred(1) }), 'U3', ProofErrorCode.CHALLENGE);
      });

      it('un ballot rechazado en U3 no consume el token', () => {
        box.submit(id(), forgedSubmission(params, cred(0), forgeBothSimulated));
        expect(box.submit(id(), ballot(0)).ok).toBe(true);
      });
    });

    // ──────────────────────────────── U4 ────────────────────────────────

    describe('U4 — duplicados', () => {
      it('el mismo (α, β) re-probado con otro token (quien conoce r) → E_DUP_CIPHERTEXT', () => {
        const publicKey = decodeNonIdentityPointHex(params.public_key);
        const enc = encryptVote(publicKey, 1);
        const submit = (c: string) => {
          const ctx = { electionId: id(), tokenId: c.split('.')[0] ?? '', publicKey };
          return box.submit(id(), {
            version: 'v1',
            election_id: id(),
            credential: c,
            ciphertext: encodeCiphertextHex(enc.ciphertext),
            proof: encodeOrProofHex(proveVote(ctx, enc, 1)),
          });
        };
        expect(submit(cred(0)).ok).toBe(true);
        expectRejection(submit(cred(1)), 'U4', RejectCode.DUP_CIPHERTEXT);
        // El token del intento rechazado sigue disponible.
        expect(box.submit(id(), ballot(1)).ok).toBe(true);
      });
    });

    // ──────────────────────────── Registro ────────────────────────────

    describe('registro de rechazos', () => {
      it('cada rechazo queda registrado con su paso y código, sin la credencial', () => {
        box.submit(id(), { ...ballot(0), version: 'v9' });
        box.submit(id(), { ...ballot(0), credential: 'basura' });
        expect(backend.rejectionsLogged()).toEqual([
          expect.objectContaining({ step: 'U0', code: RejectCode.VERSION }),
          expect.objectContaining({ step: 'U2', code: RejectCode.TOKEN_FORMAT }),
        ]);
        expect(JSON.stringify(backend.rejectionsLogged())).not.toContain(cred(0));
      });
    });
  });
}
