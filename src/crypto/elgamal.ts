/**
 * ElGamal exponencial sobre Ristretto255 (Boneh–Shoup §11.5, en notación aditiva).
 *
 *   Claves:     x ← Z_q*,  H = x·G
 *   Cifrado:    Enc(v; r) = (α, β) = (r·G, v·G + r·H)
 *   Agregación: (α1, β1) + (α2, β2) = Enc(v1 + v2; r1 + r2)
 *   Descifrado: M = β − x·α = v·G  →  v por búsqueda acotada del logaritmo discreto
 *
 * Este módulo NO restringe el valor cifrado a {0, 1}: un cifrado de 2 es un ciphertext
 * perfectamente válido. Esa garantía la aporta la prueba OR (fase 3), no ElGamal.
 */
import { CryptoError, CryptoErrorCode } from './errors.js';
import {
  G,
  IDENTITY,
  type Point,
  type Scalar,
  decodeNonIdentityPointHex,
  decodePointHex,
  encodePointHex,
  mulSecret,
} from './group.js';
import { randomScalar } from './random.js';

/** Voto binario: 0 = "no", 1 = "sí". */
export type Vote = 0 | 1;

export interface KeyPair {
  readonly secretKey: Scalar;
  readonly publicKey: Point;
}

export interface Ciphertext {
  readonly alpha: Point;
  readonly beta: Point;
}

/** Resultado de cifrar un voto. `randomness` (r) es secreta y solo la usa el probador de la prueba OR. */
export interface VoteEncryption {
  readonly ciphertext: Ciphertext;
  readonly randomness: Scalar;
}

/** Forma serializada de un ciphertext (puntos en hex canónico). */
export interface CiphertextHex {
  readonly alpha: string;
  readonly beta: string;
}

/** Cota de seguridad para la búsqueda del logaritmo discreto (evita bucles enormes por error del llamador). */
export const MAX_DLOG_BOUND = 10_000;

// ───────────────────────────── Claves ─────────────────────────────

export function generateKeyPair(): KeyPair {
  const secretKey = randomScalar();
  return { secretKey, publicKey: mulSecret(secretKey, G) };
}

function assertValidPublicKey(publicKey: Point): void {
  if (publicKey.is0()) {
    throw new CryptoError(CryptoErrorCode.IDENTITY, 'la clave pública no puede ser la identidad');
  }
}

// ───────────────────────────── Cifrado ─────────────────────────────

/**
 * Cifra un punto arbitrario M: (r·G, M + r·H).
 * Primitiva genérica; el código de protocolo debe usar `encryptVote`.
 */
export function encryptPoint(publicKey: Point, message: Point, r: Scalar): Ciphertext {
  assertValidPublicKey(publicKey);
  return {
    alpha: mulSecret(r, G),
    beta: message.add(mulSecret(r, publicKey)),
  };
}

/** Codifica el voto en el exponente: 0 ↦ identidad, 1 ↦ G. */
export function encodeVote(vote: Vote): Point {
  return vote === 1 ? G : IDENTITY;
}

/**
 * Cifra un voto v ∈ {0, 1}. Si no se pasa `r`, se elige uniforme en Z_q*.
 * Pasar `r` explícito solo tiene sentido para vectores de prueba deterministas.
 */
export function encryptVote(publicKey: Point, vote: Vote, r: Scalar = randomScalar()): VoteEncryption {
  // Defensa en tiempo de ejecución para llamadores sin tipos (CLI, JSON): el tipo no basta.
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
  if (vote !== 0 && vote !== 1) throw new RangeError('encryptVote: el voto debe ser 0 o 1');
  return { ciphertext: encryptPoint(publicKey, encodeVote(vote), r), randomness: r };
}

// ──────────────────────── Agregación homomórfica ────────────────────────

/** Suma componente a componente: cifra la suma de los textos planos. */
export function addCiphertexts(a: Ciphertext, b: Ciphertext): Ciphertext {
  return { alpha: a.alpha.add(b.alpha), beta: a.beta.add(b.beta) };
}

/** Agrega una lista de ciphertexts. La lista vacía da (0, 0), un cifrado trivial de 0. */
export function aggregateCiphertexts(ciphertexts: readonly Ciphertext[]): Ciphertext {
  return ciphertexts.reduce(addCiphertexts, { alpha: IDENTITY, beta: IDENTITY });
}

// ───────────────────────────── Descifrado ─────────────────────────────

/**
 * Recupera m ∈ [0, maxPlaintext] tal que m·G = M, por búsqueda lineal.
 * Con maxPlaintext ≤ 20 votantes son a lo sumo 21 sumas de puntos.
 */
export function discreteLogSmall(target: Point, maxPlaintext: number): number {
  if (!Number.isInteger(maxPlaintext) || maxPlaintext < 0 || maxPlaintext > MAX_DLOG_BOUND) {
    throw new RangeError(`discreteLogSmall: la cota debe ser un entero en [0, ${MAX_DLOG_BOUND}]`);
  }
  let candidate = IDENTITY; // candidate = k·G
  for (let k = 0; k <= maxPlaintext; k++) {
    if (candidate.equals(target)) return k;
    candidate = candidate.add(G);
  }
  throw new CryptoError(
    CryptoErrorCode.TALLY_OUT_OF_RANGE,
    `el texto plano no está en [0, ${maxPlaintext}]`,
  );
}

/**
 * Descifra un ciphertext cuyo texto plano es un entero pequeño en [0, maxPlaintext].
 *
 * Protocolo: la autoridad solo invoca esta función sobre el AGREGADO al cerrar la elección,
 * nunca sobre ballots individuales (PLAN §5.1).
 */
export function decryptSmall(secretKey: Scalar, ciphertext: Ciphertext, maxPlaintext: number): number {
  const message = ciphertext.beta.subtract(mulSecret(secretKey, ciphertext.alpha));
  return discreteLogSmall(message, maxPlaintext);
}

// ──────────────────────────── Serialización ────────────────────────────

export function encodeCiphertextHex(ct: Ciphertext): CiphertextHex {
  return { alpha: encodePointHex(ct.alpha), beta: encodePointHex(ct.beta) };
}

/**
 * Decodifica un ciphertext recibido de un votante.
 * α = identidad implica r = 0 y dejaría el voto en claro (β = v·G): se rechaza con E_IDENTITY.
 */
export function decodeBallotCiphertextHex(ct: CiphertextHex): Ciphertext {
  return { alpha: decodeNonIdentityPointHex(ct.alpha), beta: decodePointHex(ct.beta) };
}
