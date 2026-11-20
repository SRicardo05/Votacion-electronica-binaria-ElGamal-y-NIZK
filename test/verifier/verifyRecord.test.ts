/**
 * Verificador independiente: casos positivos, manipulaciones del expediente (cada una debe fallar en
 * comprobaciones concretas) y pruebas que DOCUMENTAN las limitaciones declaradas (PLAN §3 y §5.3).
 */
import { buildBallot } from '../../src/client/ballotBuilder.js';
import {
  G,
  type Vote,
  bytesToHex,
  decodePointHex,
  encodePointHex,
  generateSigningKeyPair,
} from '../../src/crypto/index.js';
import { BallotBox, ElectionService } from '../../src/protocol/index.js';
import { type AuditRecord, computeBallotHash } from '../../src/schema/index.js';
import { type VerificationReport, verifyRecord } from '../../src/verifier/index.js';
import { clone, resign, runElection } from '../helpers/electionFixtures.js';
import { createInMemoryRepositories } from '../helpers/inMemoryRepositories.js';

const failed = (r: VerificationReport): string[] => r.verified.checks.filter((c) => !c.ok).map((c) => c.id);

const VOTES: Vote[] = [...Array<Vote>(13).fill(1), ...Array<Vote>(7).fill(0)];

describe('verificador independiente', () => {
  const { record, receipts, signSecretKey } = runElection(VOTES);

  /** Aplica una manipulación y re-firma con la clave de la autoridad (autoridad deshonesta). */
  const tamperAndResign = (mutate: (r: AuditRecord) => void): AuditRecord => {
    const r = clone(record);
    mutate(r);
    return resign(r, signSecretKey);
  };

  const firstBallot = (r: AuditRecord) => {
    const b = r.ballots[0];
    if (b === undefined) throw new Error('el expediente de prueba no tiene ballots');
    return b;
  };

  const beta0Plus = (r: AuditRecord): string => encodePointHex(decodePointHex(r.ballots[0]?.ciphertext.beta ?? '').add(G));

  // ───────────────────────────── Positivos ─────────────────────────────

  describe('expediente honesto', () => {
    const report = verifyRecord(record);

    it('pasa todas las comprobaciones A1–A9', () => {
      expect(report.verified.checks.map((c) => c.id)).toEqual(['A1', 'A2', 'A3', 'A4', 'A5', 'A6', 'A7', 'A8', 'A9']);
      expect(failed(report)).toEqual([]);
      expect(report.ok).toBe(true);
    });

    it('reporta POR SEPARADO el agregado recalculado y el resultado anunciado', () => {
      expect(report.verified.recomputed_aggregate).toEqual(record.aggregate);
      expect(report.declared.result).toEqual({ yes: 13, no: 7, n_ballots: 20 });
      expect(report.declared.consistent).toBe(true);
    });

    it('declara las limitaciones en la sección B', () => {
      expect(report.declared.notes.join(' ')).toMatch(/Sin prueba de descifrado/);
      expect(report.declared.notes.join(' ')).toMatch(/elegibilidad no es verificable/);
    });

    it('confirma que el recibo de un votante está incluido', () => {
      expect(verifyRecord(record, { ballotHash: receipts[5] ?? '' }).receipt).toEqual({ ballot_hash: receipts[5], found: true });
      expect(verifyRecord(record, { ballotHash: 'f'.repeat(64) }).receipt?.found).toBe(false);
    });

    it('funciona tras serializar y volver a leer el JSON (descargable)', () => {
      expect(verifyRecord(JSON.parse(JSON.stringify(record))).ok).toBe(true);
    });
  });

  // ─────────────────────────── Estructura y firma ───────────────────────────

  describe('estructura y firma', () => {
    it.each([
      ['no es un objeto', 'hola'],
      ['falta un campo', (() => { const { aggregate: _a, ...rest } = clone(record); return rest; })()],
      ['campo extra', { ...clone(record), extra: 1 }],
    ])('A1 falla si %s, y no se evalúa nada más', (_caso, input) => {
      const report = verifyRecord(input);
      expect(failed(report)).toEqual(['A1']);
      expect(report.verified.checks).toHaveLength(1);
      expect(report.ok).toBe(false);
    });

    it('cualquier cambio sin re-firmar rompe la firma (A4)', () => {
      const r = clone(record);
      r.declared_result = { yes: 7, no: 13, n_ballots: 20 };
      expect(failed(verifyRecord(r))).toEqual(['A4']);
    });

    it('firmado con otra clave → A4', () => {
      const other = generateSigningKeyPair();
      expect(failed(verifyRecord(resign(record, bytesToHex(other.secretKey))))).toEqual(['A4']);
    });

    it('versión del expediente distinta → A2', () => {
      expect(failed(verifyRecord(tamperAndResign((r) => (r.version = 'v2'))))).toEqual(['A2']);
    });

    it('generador distinto del estándar → A3', () => {
      const twoG = encodePointHex(G.add(G));
      expect(failed(verifyRecord(tamperAndResign((r) => (r.params.generator = twoG))))).toEqual(['A3']);
    });
  });

  // ───────────── Manipulaciones re-firmadas (autoridad deshonesta) ─────────────

  describe('manipulaciones detectables aunque la autoridad re-firme', () => {
    it('borrar un ballot → A6 (consumidos ≠ ballots), A8 (agregado) y A9 (conteo)', () => {
      const report = verifyRecord(tamperAndResign((r) => r.ballots.pop()));
      expect(failed(report)).toEqual(['A6', 'A8', 'A9']);
    });

    it('cambiar el β de un ballot (sin rehacer su hash) → A6, A7 y A8', () => {
      const report = verifyRecord(tamperAndResign((r) => {
        const b = r.ballots[0];
        if (b) b.ciphertext.beta = beta0Plus(r);
      }));
      expect(failed(report)).toEqual(['A6', 'A7', 'A8']);
    });

    it('cambiar el voto de un ballot y rehacer su hash → la prueba OR lo delata (A7) y el agregado (A8)', () => {
      const report = verifyRecord(tamperAndResign((r) => {
        const b = r.ballots[0];
        if (!b) return;
        b.ciphertext.beta = beta0Plus(r);
        (b as { ballot_hash: string }).ballot_hash = computeBallotHash(b);
      }));
      expect(failed(report)).toEqual(['A7', 'A8']);
      expect(report.verified.checks.find((c) => c.id === 'A7')?.failures[0]).toMatch(/ballot #0: V3 E_PROOF_CHALLENGE/);
    });

    it('duplicar un ballot → A6, A8 y A9', () => {
      const report = verifyRecord(tamperAndResign((r) => r.ballots.push(clone(firstBallot(r)))));
      expect(failed(report)).toEqual(['A6', 'A8', 'A9']);
    });

    it('agregado publicado que no es la suma de los ballots → solo A8', () => {
      const report = verifyRecord(tamperAndResign((r) => {
        r.aggregate = clone(firstBallot(r).ciphertext);
      }));
      expect(failed(report)).toEqual(['A8']);
    });

    it('n_ballots declarado falso → A9 y resultado declarado inconsistente', () => {
      const report = verifyRecord(tamperAndResign((r) => (r.declared_result = { yes: 13, no: 7, n_ballots: 21 })));
      expect(failed(report)).toEqual(['A9']);
      expect(report.declared.consistent).toBe(false);
    });

    it('resultado declarado incoherente (sí + no ≠ total) → B inconsistente, aunque A pase', () => {
      const report = verifyRecord(tamperAndResign((r) => (r.declared_result = { yes: 20, no: 5, n_ballots: 20 })));
      expect(failed(report)).toEqual([]);
      expect(report.declared.consistent).toBe(false);
      expect(report.ok).toBe(false);
    });

    it('resultado con valores negativos → no cumple el esquema (A1)', () => {
      const report = verifyRecord(tamperAndResign((r) => (r.declared_result = { yes: 25, no: -5, n_ballots: 20 })));
      expect(failed(report)).toEqual(['A1']);
    });

    it('token consumido que no fue emitido → A5 y A6', () => {
      const report = verifyRecord(tamperAndResign((r) => {
        r.tokens.issued = r.tokens.issued.filter((t) => t !== r.ballots[0]?.token_id);
      }));
      expect(failed(report)).toEqual(['A5', 'A6']);
    });

    it('más tokens emitidos que n_max_voters → A5', () => {
      const report = verifyRecord(tamperAndResign((r) => {
        r.tokens.issued = [...r.tokens.issued, 'a'.repeat(32)].sort();
      }));
      expect(failed(report)).toEqual(['A5']);
    });
  });

  // ─────────────── Limitaciones declaradas (NO detectables) ───────────────

  describe('limitaciones declaradas: el verificador NO puede detectar…', () => {
    it('…un resultado anunciado falso pero consistente (sin prueba de descifrado)', () => {
      // La autoridad anuncia 7 sí / 13 no cuando el agregado cifra 13: todo lo verificable pasa.
      const report = verifyRecord(tamperAndResign((r) => (r.declared_result = { yes: 7, no: 13, n_ballots: 20 })));
      expect(report.ok).toBe(true);
      expect(report.verified.recomputed_aggregate).toEqual(record.aggregate);
    });

    it('…votos de relleno emitidos por la autoridad con tokens sobrantes (elegibilidad)', () => {
      const repos = createInMemoryRepositories();
      const service = new ElectionService(repos);
      const box = new BallotBox(repos);
      const params = service.create({ question: '¿?', nMaxVoters: 5 });
      const creds = service.issueTokens(params.election_id, 5);
      // 3 votantes reales votan "no"; la autoridad usa los 2 tokens que no entregó para votar "sí".
      for (const c of creds.slice(0, 3)) box.submit(params.election_id, buildBallot(params, c, 0));
      for (const c of creds.slice(3)) box.submit(params.election_id, buildBallot(params, c, 1));
      const stuffed = service.close(params.election_id);
      const report = verifyRecord(stuffed);
      expect(report.ok).toBe(true);
      expect(stuffed.declared_result).toEqual({ yes: 2, no: 3, n_ballots: 5 });
    });
  });
});
