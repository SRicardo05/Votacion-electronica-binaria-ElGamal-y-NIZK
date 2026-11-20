/**
 * Envoltura del grupo de orden primo Ristretto255 (RFC 9496) provisto por @noble/curves.
 *
 * Es el ÚNICO módulo que usa Ristretto255 de la biblioteca de curva (sign.ts usa Ed25519, que es
 * otra primitiva): si se cambiara la biblioteca, solo este archivo cambia para el grupo.
 * El resto del proyecto usa `Point`, `Scalar` y estas funciones.
 *
 * Notación: el grupo es aditivo. g^r del informe ↔ `mulSecret(r, G)`; g^v·h^r ↔ v·G + r·H.
 */
import { ristretto255 } from '@noble/curves/ed25519.js';

import { bigIntToBytesLE, bytesToBigIntLE, bytesToHex, strictHexToBytes } from './encoding.js';
import { CryptoError, CryptoErrorCode } from './errors.js';

const RistrettoPoint = ristretto255.Point;

export type Point = InstanceType<typeof RistrettoPoint>;

/** Escalar de Z_q, siempre reducido: 0 ≤ s < q. El "brand" impide pasar un bigint arbitrario. */
export type Scalar = bigint & { readonly __brand: 'Scalar' };

export const GROUP_ID = 'ristretto255';
export const POINT_BYTES = 32;
export const SCALAR_BYTES = 32;

/** Orden del grupo: q = 2^252 + 27742317777372353535851937790883648493. */
export const ORDER: bigint = RistrettoPoint.Fn.ORDER;

/** Generador estándar G de Ristretto255. */
export const G: Point = RistrettoPoint.BASE;

/** Elemento neutro del grupo. */
export const IDENTITY: Point = RistrettoPoint.ZERO;

// ───────────────────────────── Escalares ─────────────────────────────

/** Reduce cualquier entero a un escalar canónico de Z_q. */
export function toScalar(n: bigint): Scalar {
  const r = n % ORDER;
  return (r < 0n ? r + ORDER : r) as Scalar;
}

export const scalarAdd = (a: Scalar, b: Scalar): Scalar => toScalar(a + b);
export const scalarSub = (a: Scalar, b: Scalar): Scalar => toScalar(a - b);
export const scalarMul = (a: Scalar, b: Scalar): Scalar => toScalar(a * b);

/** Decodifica 32 bytes little-endian; rechaza valores ≥ q (codificación no canónica). */
export function decodeScalar(bytes: Uint8Array): Scalar {
  if (bytes.length !== SCALAR_BYTES) {
    throw new CryptoError(CryptoErrorCode.SCALAR_RANGE, `se esperaban ${SCALAR_BYTES} bytes`);
  }
  const n = bytesToBigIntLE(bytes);
  if (n >= ORDER) throw new CryptoError(CryptoErrorCode.SCALAR_RANGE, 'escalar ≥ q (no canónico)');
  return n as Scalar;
}

export function encodeScalar(s: Scalar): Uint8Array {
  return bigIntToBytesLE(s, SCALAR_BYTES);
}

export function decodeScalarHex(hex: string): Scalar {
  const bytes = strictHexToBytes(hex, SCALAR_BYTES);
  if (bytes === null) {
    throw new CryptoError(CryptoErrorCode.SCALAR_RANGE, 'hex inválido (se esperan 64 caracteres [0-9a-f])');
  }
  return decodeScalar(bytes);
}

export const encodeScalarHex = (s: Scalar): string => bytesToHex(encodeScalar(s));

// ─────────────────────────────── Puntos ───────────────────────────────

/** Decodifica 32 bytes con la decodificación canónica de RFC 9496; rechaza cualquier otra. */
export function decodePoint(bytes: Uint8Array): Point {
  if (bytes.length !== POINT_BYTES) {
    throw new CryptoError(CryptoErrorCode.POINT_ENCODING, `se esperaban ${POINT_BYTES} bytes`);
  }
  try {
    return RistrettoPoint.fromBytes(bytes);
  } catch {
    throw new CryptoError(CryptoErrorCode.POINT_ENCODING, 'codificación Ristretto255 inválida o no canónica');
  }
}

export function encodePoint(p: Point): Uint8Array {
  return p.toBytes();
}

export function decodePointHex(hex: string): Point {
  const bytes = strictHexToBytes(hex, POINT_BYTES);
  if (bytes === null) {
    throw new CryptoError(CryptoErrorCode.POINT_ENCODING, 'hex inválido (se esperan 64 caracteres [0-9a-f])');
  }
  return decodePoint(bytes);
}

export const encodePointHex = (p: Point): string => bytesToHex(encodePoint(p));

/** Como `decodePointHex`, pero además rechaza la identidad (claves públicas, α de un ciphertext). */
export function decodeNonIdentityPointHex(hex: string): Point {
  const p = decodePointHex(hex);
  if (p.is0()) throw new CryptoError(CryptoErrorCode.IDENTITY, 'el punto identidad no está permitido aquí');
  return p;
}

// ──────────────────────── Multiplicación escalar ────────────────────────

/**
 * s·P en tiempo constante, para escalares SECRETOS (clave x, aleatoriedad r, w).
 * Requiere s ≠ 0: un secreto nulo es siempre un error del llamador.
 */
export function mulSecret(s: Scalar, p: Point): Point {
  if (s === 0n) throw new RangeError('mulSecret: escalar secreto nulo');
  return p.multiply(s);
}

/**
 * s·P en tiempo variable, solo para escalares PÚBLICOS (retos y respuestas de una prueba
 * que se está verificando). Admite s = 0, que un adversario puede enviar.
 */
export function mulPublic(s: Scalar, p: Point): Point {
  return p.multiplyUnsafe(s);
}
