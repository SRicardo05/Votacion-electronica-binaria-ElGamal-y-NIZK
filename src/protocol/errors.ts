/**
 * Rechazos del protocolo. Cada rechazo indica el PASO de validación de la urna (PLAN §4)
 * y un código estable, para poder reportar exactamente dónde se rechazó cada caso negativo.
 */

/** Pasos de validación de la urna: U0 formato … U5 persistencia atómica. */
export type BallotBoxStep = 'U0' | 'U1' | 'U2' | 'U3' | 'U4' | 'U5';

export const RejectCode = {
  // U2 — token
  TOKEN_FORMAT: 'E_TOKEN_FORMAT',
  TOKEN_MAC: 'E_TOKEN_MAC',
  TOKEN_UNKNOWN: 'E_TOKEN_UNKNOWN',
  TOKEN_USED: 'E_TOKEN_USED',
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
