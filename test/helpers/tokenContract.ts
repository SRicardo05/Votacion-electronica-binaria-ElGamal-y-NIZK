/**
 * Suites compartidas: se ejecutan contra cada implementación de los puertos
 * (memoria y SQLite) para garantizar que se comportan igual.
 */
import { bytesToHex, generateMacKey } from '../../src/crypto/index.js';
import {
  RejectCode,
  type TokenRepository,
  TokenService,
  type TransactionRunner,
  computeTokenMac,
  formatCredential,
  parseCredential,
} from '../../src/protocol/index.js';

export interface TokenBackend {
  readonly tokens: TokenRepository;
  readonly transactions: TransactionRunner;
  readonly close?: () => void;
}

const E1 = 'eleccion-1';
const E2 = 'eleccion-2';
const T1 = '0123456789abcdef0123456789abcdef';
const T2 = 'fedcba9876543210fedcba9876543210';
const AT = '2026-11-20T10:00:00.000Z';
const LATER = '2026-11-20T11:00:00.000Z';

/** Contrato del puerto TokenRepository. */
export function describeTokenRepositoryContract(name: string, make: () => TokenBackend): void {
  describe(`TokenRepository (${name})`, () => {
    let b: TokenBackend;
    beforeEach(() => {
      b = make();
    });
    afterEach(() => b.close?.());

    it('guarda y encuentra tokens emitidos, sin consumir', () => {
      b.tokens.insertIssued([{ electionId: E1, tokenId: T1, issuedAt: AT }]);
      expect(b.tokens.find(E1, T1)).toEqual({ electionId: E1, tokenId: T1, issuedAt: AT, consumedAt: null });
      expect(b.tokens.find(E1, T2)).toBeUndefined();
    });

    it('rechaza reemitir el mismo token', () => {
      b.tokens.insertIssued([{ electionId: E1, tokenId: T1, issuedAt: AT }]);
      expect(() => { b.tokens.insertIssued([{ electionId: E1, tokenId: T1, issuedAt: AT }]); }).toThrow();
    });

    it('el mismo token_id en otra elección es otro token', () => {
      b.tokens.insertIssued([{ electionId: E1, tokenId: T1, issuedAt: AT }]);
      b.tokens.insertIssued([{ electionId: E2, tokenId: T1, issuedAt: AT }]);
      expect(b.tokens.markConsumed(E1, T1, LATER)).toBe(true);
      expect(b.tokens.find(E2, T1)?.consumedAt).toBeNull();
    });

    it('markConsumed tiene éxito exactamente una vez', () => {
      b.tokens.insertIssued([{ electionId: E1, tokenId: T1, issuedAt: AT }]);
      expect(b.tokens.markConsumed(E1, T1, LATER)).toBe(true);
      expect(b.tokens.markConsumed(E1, T1, LATER)).toBe(false);
      expect(b.tokens.find(E1, T1)?.consumedAt).toBe(LATER);
    });

    it('markConsumed sobre un token inexistente devuelve false', () => {
      expect(b.tokens.markConsumed(E1, T2, LATER)).toBe(false);
    });

    it('listByElection devuelve solo esa elección, ordenada por token_id', () => {
      b.tokens.insertIssued([
        { electionId: E1, tokenId: T2, issuedAt: AT },
        { electionId: E1, tokenId: T1, issuedAt: AT },
        { electionId: E2, tokenId: T1, issuedAt: AT },
      ]);
      expect(b.tokens.listByElection(E1).map((r) => r.tokenId)).toEqual([T1, T2]);
    });

    it('una transacción que falla no deja efectos', () => {
      expect(() =>
        b.transactions.runInTransaction(() => {
          b.tokens.insertIssued([{ electionId: E1, tokenId: T1, issuedAt: AT }]);
          throw new Error('fallo a mitad de la transacción');
        }),
      ).toThrow('fallo a mitad');
      expect(b.tokens.find(E1, T1)).toBeUndefined();
    });
  });
}

/** Comportamiento del TokenService (paso U2 y consumo de U5) sobre un backend dado. */
export function describeTokenService(name: string, make: () => TokenBackend): void {
  describe(`TokenService (${name})`, () => {
    let b: TokenBackend;
    let service: TokenService;
    const macKey = generateMacKey();

    beforeEach(() => {
      b = make();
      service = new TokenService({ tokens: b.tokens, transactions: b.transactions, macKey, clock: () => new Date(AT) });
    });
    afterEach(() => b.close?.());

    it('emite credenciales únicas con formato <token_id>.<mac> y las registra', () => {
      const creds = service.issue(E1, 20);
      expect(new Set(creds).size).toBe(20);
      for (const c of creds) expect(c).toMatch(/^[0-9a-f]{32}\.[0-9a-f]{64}$/);
      expect(b.tokens.listByElection(E1)).toHaveLength(20);
    });

    it('no persiste el MAC: la base solo conoce token_id', () => {
      const [cred = ''] = service.issue(E1, 1);
      const parsed = parseCredential(cred);
      const stored = b.tokens.listByElection(E1)[0];
      expect(stored?.tokenId).toBe(parsed?.tokenId);
      expect(JSON.stringify(stored)).not.toContain(parsed?.mac);
    });

    it('rechaza count inválido', () => {
      expect(() => service.issue(E1, 0)).toThrow(RangeError);
      expect(() => service.issue(E1, 1.5)).toThrow(RangeError);
    });

    it('acepta una credencial emitida y no usada', () => {
      const [cred = ''] = service.issue(E1, 1);
      expect(service.check(E1, cred)).toEqual({ ok: true, value: parseCredential(cred)?.tokenId });
    });

    it.each([
      ['vacía', ''],
      ['sin separador', 'a'.repeat(96)],
      ['token_id corto', `${'a'.repeat(30)}.${'b'.repeat(64)}`],
      ['MAC en mayúsculas', `${'a'.repeat(32)}.${'B'.repeat(64)}`],
      ['dos separadores', `${'a'.repeat(32)}.${'b'.repeat(64)}.x`],
    ])('credencial mal formada (%s) → U2 / E_TOKEN_FORMAT', (_caso, cred) => {
      expect(service.check(E1, cred)).toEqual({
        ok: false,
        rejection: expect.objectContaining({ step: 'U2', code: RejectCode.TOKEN_FORMAT }) as unknown,
      });
    });

    it('MAC alterado → U2 / E_TOKEN_MAC', () => {
      const [cred = ''] = service.issue(E1, 1);
      const last = cred.slice(-1) === '0' ? '1' : '0';
      expect(service.check(E1, cred.slice(0, -1) + last)).toEqual({
        ok: false,
        rejection: expect.objectContaining({ step: 'U2', code: RejectCode.TOKEN_MAC }) as unknown,
      });
    });

    it('token inventado sin la clave de la autoridad → U2 / E_TOKEN_MAC', () => {
      const forged = formatCredential({ tokenId: T1, mac: bytesToHex(computeTokenMac(generateMacKey(), E1, T1)) });
      expect(service.check(E1, forged)).toEqual({
        ok: false,
        rejection: expect.objectContaining({ code: RejectCode.TOKEN_MAC }) as unknown,
      });
    });

    it('credencial de otra elección → U2 / E_TOKEN_MAC (el MAC ata election_id)', () => {
      const [cred = ''] = service.issue(E2, 1);
      expect(service.check(E1, cred)).toEqual({
        ok: false,
        rejection: expect.objectContaining({ code: RejectCode.TOKEN_MAC }) as unknown,
      });
    });

    it('token con MAC válido pero nunca emitido (no registrado) → U2 / E_TOKEN_UNKNOWN', () => {
      const unissued = formatCredential({ tokenId: T2, mac: bytesToHex(computeTokenMac(macKey, E1, T2)) });
      expect(service.check(E1, unissued)).toEqual({
        ok: false,
        rejection: expect.objectContaining({ step: 'U2', code: RejectCode.TOKEN_UNKNOWN }) as unknown,
      });
    });

    it('token repetido: tras consumirlo, check → U2 / E_TOKEN_USED', () => {
      const [cred = ''] = service.issue(E1, 1);
      const tokenId = parseCredential(cred)?.tokenId ?? '';
      expect(service.consume(E1, tokenId)).toEqual({ ok: true, value: tokenId });
      expect(service.check(E1, cred)).toEqual({
        ok: false,
        rejection: expect.objectContaining({ step: 'U2', code: RejectCode.TOKEN_USED }) as unknown,
      });
    });

    it('carrera: dos solicitudes pasan check, solo la primera consume → U5 / E_TOKEN_USED', () => {
      const [cred = ''] = service.issue(E1, 1);
      const first = service.check(E1, cred);
      const second = service.check(E1, cred);
      expect(first.ok && second.ok).toBe(true);
      const tokenId = parseCredential(cred)?.tokenId ?? '';
      expect(service.consume(E1, tokenId).ok).toBe(true);
      expect(service.consume(E1, tokenId)).toEqual({
        ok: false,
        rejection: expect.objectContaining({ step: 'U5', code: RejectCode.TOKEN_USED }) as unknown,
      });
    });
  });
}
