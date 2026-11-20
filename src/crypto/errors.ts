/**
 * Códigos de rechazo de la capa criptográfica (ver PLAN_IMPLEMENTACION.md §0.1).
 * Las capas superiores los propagan tal cual para poder reportar en qué paso se rechazó un mensaje.
 */
export const CryptoErrorCode = {
  /** Punto: longitud/hex inválido o codificación Ristretto255 no canónica. */
  POINT_ENCODING: 'E_POINT_ENCODING',
  /** Punto identidad donde no está permitido (p. ej. α = r·G con r = 0). */
  IDENTITY: 'E_IDENTITY',
  /** Escalar: longitud/hex inválido o valor ≥ q (no canónico). */
  SCALAR_RANGE: 'E_SCALAR_RANGE',
} as const;

export type CryptoErrorCode = (typeof CryptoErrorCode)[keyof typeof CryptoErrorCode];

export class CryptoError extends Error {
  readonly code: CryptoErrorCode;

  constructor(code: CryptoErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.name = 'CryptoError';
    this.code = code;
  }
}
