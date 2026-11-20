/**
 * Tokens de votación de un solo uso (PLAN §3).
 *
 *   token_id   = 16 bytes aleatorios (32 hex)
 *   mac        = HMAC-SHA256(k_tok, "VOTE-BIN-v1/token" || LP(election_id) || LP(token_id))
 *   credencial = "<token_id>.<mac>"  (se entrega al votante fuera de banda)
 *
 * La urna recalcula el MAC (sin base de identidades en el camino crítico), luego comprueba que el
 * token fue emitido y que no se ha consumido. No se guarda ninguna identidad de votante, y el MAC
 * no se persiste: el expediente publica solo `token_id`.
 */
import { randomBytes } from 'node:crypto';

import { bytesToHex, concatBytes, constantTimeEqual, hmacSha256, lengthPrefixed, strictHexToBytes } from '../crypto/index.js';
import { type Outcome, RejectCode, accept, reject } from './errors.js';
import { type Clock, type TokenRepository, type TransactionRunner, systemClock } from './ports.js';

export const TOKEN_ID_BYTES = 16;
export const TOKEN_DST = 'VOTE-BIN-v1/token';

export interface TokenCredential {
  readonly tokenId: string;
  readonly mac: string;
}

const utf8 = new TextEncoder();

export function computeTokenMac(macKey: Uint8Array, electionId: string, tokenId: string): Uint8Array {
  return hmacSha256(macKey, concatBytes(utf8.encode(TOKEN_DST), lengthPrefixed(electionId), lengthPrefixed(tokenId)));
}

export function formatCredential(c: TokenCredential): string {
  return `${c.tokenId}.${c.mac}`;
}

/** Interpreta una credencial con formato estricto; `null` si no lo cumple. */
export function parseCredential(credential: string): TokenCredential | null {
  const parts = credential.split('.');
  if (parts.length !== 2) return null;
  const [tokenId = '', mac = ''] = parts;
  if (strictHexToBytes(tokenId, TOKEN_ID_BYTES) === null || strictHexToBytes(mac, 32) === null) return null;
  return { tokenId, mac };
}

export interface TokenServiceDeps {
  readonly tokens: TokenRepository;
  readonly transactions: TransactionRunner;
  readonly macKey: Uint8Array;
  readonly clock?: Clock;
}

export class TokenService {
  private readonly tokens: TokenRepository;
  private readonly transactions: TransactionRunner;
  private readonly macKey: Uint8Array;
  private readonly clock: Clock;

  constructor(deps: TokenServiceDeps) {
    this.tokens = deps.tokens;
    this.transactions = deps.transactions;
    this.macKey = deps.macKey;
    this.clock = deps.clock ?? systemClock;
  }

  /**
   * Emite `count` tokens nuevos y devuelve sus credenciales (lo único que sale del servicio:
   * se entregan una vez y no se pueden recuperar después).
   */
  issue(electionId: string, count: number): string[] {
    if (!Number.isInteger(count) || count < 1) throw new RangeError('issue: count debe ser un entero ≥ 1');
    const issuedAt = this.clock().toISOString();
    const ids = new Set<string>();
    while (ids.size < count) ids.add(bytesToHex(randomBytes(TOKEN_ID_BYTES)));

    const tokenIds = [...ids];
    this.transactions.runInTransaction(() => {
      this.tokens.insertIssued(tokenIds.map((tokenId) => ({ electionId, tokenId, issuedAt })));
    });
    return tokenIds.map((tokenId) =>
      formatCredential({ tokenId, mac: bytesToHex(computeTokenMac(this.macKey, electionId, tokenId)) }),
    );
  }

  /**
   * Paso U2: formato → MAC → emitido → no consumido. NO consume el token: el consumo ocurre
   * en U5, en la misma transacción que guarda el ballot (`consume`).
   */
  check(electionId: string, credential: string): Outcome<string> {
    const parsed = parseCredential(credential);
    if (parsed === null) {
      return reject('U2', RejectCode.TOKEN_FORMAT, 'la credencial no tiene el formato <token_id>.<mac>');
    }
    const expected = computeTokenMac(this.macKey, electionId, parsed.tokenId);
    const given = strictHexToBytes(parsed.mac, 32) ?? new Uint8Array();
    if (!constantTimeEqual(expected, given)) {
      return reject('U2', RejectCode.TOKEN_MAC, 'el MAC del token no es válido para esta elección');
    }
    const record = this.tokens.find(electionId, parsed.tokenId);
    if (record === undefined) {
      return reject('U2', RejectCode.TOKEN_UNKNOWN, 'el token no fue emitido por la autoridad');
    }
    if (record.consumedAt !== null) {
      return reject('U2', RejectCode.TOKEN_USED, 'el token ya fue usado');
    }
    return accept(parsed.tokenId);
  }

  /**
   * Consume el token atómicamente. Debe llamarse dentro de la transacción que guarda el ballot.
   * Un `false` aquí tras un `check` exitoso significa que otro ballot ganó la carrera.
   */
  consume(electionId: string, tokenId: string): Outcome<string> {
    const ok = this.tokens.markConsumed(electionId, tokenId, this.clock().toISOString());
    return ok ? accept(tokenId) : reject('U5', RejectCode.TOKEN_USED, 'el token fue consumido por otra solicitud');
  }
}
