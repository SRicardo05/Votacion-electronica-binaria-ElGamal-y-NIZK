/**
 * Rechazos del protocolo. Cada rechazo indica el PASO de validación de la urna (PLAN §4)
 * y un código estable, para poder reportar exactamente dónde se rechazó cada caso negativo.
 *
 * En U1 y U3 se propagan tal cual los códigos de la capa criptográfica
 * (E_POINT_ENCODING, E_IDENTITY, E_SCALAR_RANGE, E_PROOF_CHALLENGE, E_PROOF_EQ_0, E_PROOF_EQ_1).
 */

/** Pasos de validación de la urna: U0 formato … U5 persistencia atómica. */
export type BallotBoxStep = 'U0' | 'U1' | 'U2' | 'U3' | 'U4' | 'U5';

export const RejectCode = {
  // U0 — formato y estado de la elección
  FORMAT: 'E_FORMAT',
  VERSION: 'E_VERSION',
  ELECTION: 'E_ELECTION',
  CLOSED: 'E_CLOSED',
  // U2 — token
  TOKEN_FORMAT: 'E_TOKEN_FORMAT',
  TOKEN_MAC: 'E_TOKEN_MAC',
  TOKEN_UNKNOWN: 'E_TOKEN_UNKNOWN',
  TOKEN_USED: 'E_TOKEN_USED',
  // U4 — duplicados
  REPLAY: 'E_REPLAY',
  DUP_CIPHERTEXT: 'E_DUP_CIPHERTEXT',
} as const;

export type RejectCode = (typeof RejectCode)[keyof typeof RejectCode];

export interface Rejection {
  readonly step: BallotBoxStep;
  readonly code: string;
  readonly reason: string;
}

export type Outcome<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly rejection: Rejection };

export const accept = <T>(value: T): Outcome<T> => ({ ok: true, value });

export const reject = <T = never>(step: BallotBoxStep, code: string, reason: string): Outcome<T> => ({
  ok: false,
  rejection: { step, code, reason },
});

/** Errores de operaciones de administración (crear elección, emitir tokens…), fuera del flujo de la urna. */
export const AdminErrorCode = {
  ELECTION: 'E_ELECTION',
  CLOSED: 'E_CLOSED',
  TOKEN_LIMIT: 'E_TOKEN_LIMIT',
  INVALID_INPUT: 'E_INVALID_INPUT',
} as const;

export type AdminErrorCode = (typeof AdminErrorCode)[keyof typeof AdminErrorCode];

export class AdminError extends Error {
  readonly code: AdminErrorCode;

  constructor(code: AdminErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.name = 'AdminError';
    this.code = code;
  }
}
