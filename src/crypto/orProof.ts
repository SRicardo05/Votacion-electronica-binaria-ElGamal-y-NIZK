/**
 * Prueba OR no interactiva de Cramer–Damgård–Schoenmakers: "(α, β) cifra 0 o 1" (PLAN §2).
 *
 * Para la rama j ∈ {0, 1} sea β_j = β − j·G. "Cifra j" ⇔ log_G(α) = log_H(β_j) (Chaum–Pedersen).
 * El probador demuestra la rama real y simula la otra; el verificador no distingue cuál es cuál.
 * El reto global es c = SHA-512(T) mod q (Fiat–Shamir), con T definido en transcript.ts.
 *
 * Prueba publicada π = (A0, B0, A1, B1, c0, c1, s0, s1): 4 puntos + 4 escalares = 256 bytes.
 */
import { type Ciphertext, type CiphertextHex, type Vote, type VoteEncryption, decodeBallotCiphertextHex } from './elgamal.js';
import { CryptoError } from './errors.js';
import {
  G,
  type Point,
  type Scalar,
  decodePointHex,
  decodeScalarHex,
  encodePointHex,
  encodeScalarHex,
  mulPublic,
  mulSecret,
  scalarAdd,
  scalarMul,
  scalarSub,
} from './group.js';
import { hashToScalar } from './hashing.js';
import { randomScalar } from './random.js';
import { type OrCommitments, type ProofContext, buildOrProofTranscript } from './transcript.js';

export interface OrProof extends OrCommitments {
  readonly c0: Scalar;
  readonly c1: Scalar;
  readonly s0: Scalar;
  readonly s1: Scalar;
}

export interface OrProofHex {
  readonly A0: string;
  readonly B0: string;
  readonly A1: string;
  readonly B1: string;
  readonly c0: string;
  readonly c1: string;
  readonly s0: string;
  readonly s1: string;
}

/** Códigos de rechazo propios de la verificación de la prueba (pasos V3–V5). */
export const ProofErrorCode = {
  CHALLENGE: 'E_PROOF_CHALLENGE',
  EQ_0: 'E_PROOF_EQ_0',
  EQ_1: 'E_PROOF_EQ_1',
} as const;

/** Paso del verificador en que se rechazó (PLAN §2.2). */
export type VerificationStep = 'V1' | 'V2' | 'V3' | 'V4' | 'V5';

export type VerificationResult =
  | { readonly valid: true }
  | { readonly valid: false; readonly step: VerificationStep; readonly code: string; readonly reason: string };

/** Fuente de escalares aleatorios; inyectable solo para vectores de prueba deterministas. */
export type ScalarSource = () => Scalar;

/** β_j = β − j·G: el valor que debe ser r·H si el ciphertext cifra j. */
export function branchTarget(ct: Ciphertext, j: Vote): Point {
  return j === 0 ? ct.beta : ct.beta.subtract(G);
}

/** c = SHA-512(T) mod q. */
export function computeChallenge(ctx: ProofContext, ct: Ciphertext, commitments: OrCommitments): Scalar {
  return hashToScalar(buildOrProofTranscript(ctx, ct, commitments));
}

// ─────────────────────────────── Probador ───────────────────────────────

/**
 * Genera π para el voto `vote` cifrado en `encryption` (necesita la aleatoriedad r).
 *
 *   rama falsa f:  c_f, s_f ← Z_q;  A_f = s_f·G − c_f·α;  B_f = s_f·H − c_f·β_f
 *   rama real v:   w ← Z_q*;        A_v = w·G;            B_v = w·H
 *   c = H(T);  c_v = c − c_f;  s_v = w + c_v·r
 */
export function proveVote(
  ctx: ProofContext,
  encryption: VoteEncryption,
  vote: Vote,
  rand: ScalarSource = randomScalar,
): OrProof {
  const { ciphertext: ct, randomness: r } = encryption;
  const H = ctx.publicKey;

  // Defensa contra mal uso: el probador solo prueba afirmaciones verdaderas.
  if (!ct.alpha.equals(mulSecret(r, G)) || !branchTarget(ct, vote).equals(mulSecret(r, H))) {
    throw new RangeError('proveVote: el ciphertext no cifra el voto indicado con esa aleatoriedad');
  }

  const fake: Vote = vote === 0 ? 1 : 0;

  // Rama falsa: simulación (se elige primero el reto y la respuesta).
  const cFake = rand();
  const sFake = rand();
  const aFake = mulSecret(sFake, G).subtract(mulSecret(cFake, ct.alpha));
  const bFake = mulSecret(sFake, H).subtract(mulSecret(cFake, branchTarget(ct, fake)));

  // Rama real: compromiso honesto.
  const w = rand();
  const aReal = mulSecret(w, G);
  const bReal = mulSecret(w, H);

  const commitments: OrCommitments =
    vote === 0
      ? { A0: aReal, B0: bReal, A1: aFake, B1: bFake }
      : { A0: aFake, B0: bFake, A1: aReal, B1: bReal };

  const c = computeChallenge(ctx, ct, commitments);
  const cReal = scalarSub(c, cFake);
  const sReal = scalarAdd(w, scalarMul(cReal, r));

  return vote === 0
    ? { ...commitments, c0: cReal, c1: cFake, s0: sReal, s1: sFake }
    : { ...commitments, c0: cFake, c1: cReal, s0: sFake, s1: sReal };
}

// ────────────────────────────── Verificador ──────────────────────────────

const reject = (step: VerificationStep, code: string, reason: string): VerificationResult => ({
  valid: false,
  step,
  code,
  reason,
});

/** Comprueba una rama: s·G = A + c·α  y  s·H = B + c·β_j. Solo escalares públicos → mulPublic. */
function branchHolds(ct: Ciphertext, H: Point, j: Vote, A: Point, B: Point, c: Scalar, s: Scalar): boolean {
  const lhsG = mulPublic(s, G);
  const rhsG = A.add(mulPublic(c, ct.alpha));
  const lhsH = mulPublic(s, H);
  const rhsH = B.add(mulPublic(c, branchTarget(ct, j)));
  return lhsG.equals(rhsG) && lhsH.equals(rhsH);
}

/**
 * Pasos V3–V5 sobre objetos ya decodificados (V1–V2 los garantiza la decodificación).
 * Los pasos se evalúan en orden y se reporta el primero que falla (todo es público: no hay
 * nada que ocultar con tiempo constante).
 */
export function verifyVoteProof(ctx: ProofContext, ct: Ciphertext, proof: OrProof): VerificationResult {
  const c = computeChallenge(ctx, ct, proof);
  if (scalarAdd(proof.c0, proof.c1) !== c) {
    return reject('V3', ProofErrorCode.CHALLENGE, 'c0 + c1 ≠ H(T)');
  }
  if (!branchHolds(ct, ctx.publicKey, 0, proof.A0, proof.B0, proof.c0, proof.s0)) {
    return reject('V4', ProofErrorCode.EQ_0, 'falla la ecuación de la rama 0');
  }
  if (!branchHolds(ct, ctx.publicKey, 1, proof.A1, proof.B1, proof.c1, proof.s1)) {
    return reject('V5', ProofErrorCode.EQ_1, 'falla la ecuación de la rama 1');
  }
  return { valid: true };
}

export type DecodeResult =
  | { readonly ok: true; readonly ciphertext: Ciphertext; readonly proof: OrProof }
  | { readonly ok: false; readonly step: 'V1' | 'V2'; readonly code: string; readonly reason: string };

/**
 * Pasos V1–V2: decodificación estricta de un ballot serializado.
 *   V1: puntos canónicos (α, β, A0, B0, A1, B1) y α ≠ identidad
 *   V2: escalares canónicos < q (c0, c1, s0, s1)
 * La urna la usa en su paso U1, antes de validar el token.
 */
export function decodeBallotHex(ctHex: CiphertextHex, proofHex: OrProofHex): DecodeResult {
  let ciphertext: Ciphertext;
  let commitments: OrCommitments;
  try {
    ciphertext = decodeBallotCiphertextHex(ctHex);
    commitments = {
      A0: decodePointHex(proofHex.A0),
      B0: decodePointHex(proofHex.B0),
      A1: decodePointHex(proofHex.A1),
      B1: decodePointHex(proofHex.B1),
    };
  } catch (e) {
    if (e instanceof CryptoError) return { ok: false, step: 'V1', code: e.code, reason: e.message };
    throw e;
  }

  try {
    const proof: OrProof = {
      ...commitments,
      c0: decodeScalarHex(proofHex.c0),
      c1: decodeScalarHex(proofHex.c1),
      s0: decodeScalarHex(proofHex.s0),
      s1: decodeScalarHex(proofHex.s1),
    };
    return { ok: true, ciphertext, proof };
  } catch (e) {
    if (e instanceof CryptoError) return { ok: false, step: 'V2', code: e.code, reason: e.message };
    throw e;
  }
}

/** Verificación completa V1–V5 a partir de datos serializados (la usa el verificador independiente). */
export function verifyVoteProofHex(
  ctx: ProofContext,
  ctHex: CiphertextHex,
  proofHex: OrProofHex,
): VerificationResult {
  const decoded = decodeBallotHex(ctHex, proofHex);
  if (!decoded.ok) return reject(decoded.step, decoded.code, decoded.reason);
  return verifyVoteProof(ctx, decoded.ciphertext, decoded.proof);
}

// ──────────────────────────── Serialización ────────────────────────────

export function encodeOrProofHex(p: OrProof): OrProofHex {
  return {
    A0: encodePointHex(p.A0),
    B0: encodePointHex(p.B0),
    A1: encodePointHex(p.A1),
    B1: encodePointHex(p.B1),
    c0: encodeScalarHex(p.c0),
    c1: encodeScalarHex(p.c1),
    s0: encodeScalarHex(p.s0),
    s1: encodeScalarHex(p.s1),
  };
}
