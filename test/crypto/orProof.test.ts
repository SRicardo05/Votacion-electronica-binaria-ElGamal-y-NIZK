/**
 * Prueba OR CDS + Fiat–Shamir. Cada caso negativo afirma el PASO (V1–V5) y el CÓDIGO de rechazo,
 * como pide la evaluación de la Entrega 1 (PLAN §2.2 y Fase 3).
 */
import { readFileSync } from 'node:fs';

import {
  CryptoErrorCode,
  G,
  IDENTITY,
  type OrProofHex,
  type ProofContext,
  ProofErrorCode,
  type VerificationResult,
  type Vote,
  decodePointHex,
  decodeScalarHex,
  encodeCiphertextHex,
  encodeOrProofHex,
  encodePointHex,
  encodeScalarHex,
  encryptVote,
  generateKeyPair,
  mulSecret,
  proveVote,
  randomScalar,
  scalarAdd,
  scalarSub,
  toScalar,
  verifyVoteProof,
  verifyVoteProofHex,
} from '../../src/crypto/index.js';
import { forgeBothSimulated, forgeOneForced } from '../helpers/maliciousProver.js';
import type { OrProofVectors } from '../helpers/orProofVectors.js';

const keys = generateKeyPair();
const ctx: ProofContext = { electionId: 'eleccion-test', tokenId: 'token-a', publicKey: keys.publicKey };

/** Ballot honesto serializado. */
function honestBallot(vote: Vote, context: ProofContext = ctx) {
  const enc = encryptVote(context.publicKey, vote);
  return {
    ct: encodeCiphertextHex(enc.ciphertext),
    proof: encodeOrProofHex(proveVote(context, enc, vote)),
  };
}

function expectRejected(result: VerificationResult, step: string, code: string): void {
  expect(result).toEqual(expect.objectContaining({ valid: false, step, code }));
}

const ONE = toScalar(1n);
const plusOne = (hex: string): string => encodeScalarHex(scalarAdd(decodeScalarHex(hex), ONE));
const minusOne = (hex: string): string => encodeScalarHex(scalarSub(decodeScalarHex(hex), ONE));
const otherPoint = (): string => encodePointHex(mulSecret(randomScalar(), G));

/** Voltea el bit `bit` del byte `byteIndex` de un valor hex. */
function flipBit(hex: string, byteIndex: number, bit: number): string {
  const b = Number.parseInt(hex.slice(2 * byteIndex, 2 * byteIndex + 2), 16) ^ (1 << bit);
  return hex.slice(0, 2 * byteIndex) + b.toString(16).padStart(2, '0') + hex.slice(2 * byteIndex + 2);
}

// ───────────────────────────── Casos positivos ─────────────────────────────

describe('pruebas honestas', () => {
  it.each([0, 1] as const)('una prueba de voto %d verifica', (v) => {
    const b = honestBallot(v);
    expect(verifyVoteProofHex(ctx, b.ct, b.proof)).toEqual({ valid: true });
  });

  it('verifica 50 ballots aleatorios', () => {
    for (let i = 0; i < 50; i++) {
      const b = honestBallot(Math.random() < 0.5 ? 0 : 1);
      expect(verifyVoteProofHex(ctx, b.ct, b.proof).valid).toBe(true);
    }
  });

  it('los vectores versionados verifican', () => {
    const vectors = JSON.parse(
      readFileSync(new URL('../vectors/or-proof.json', import.meta.url), 'utf8'),
    ) as OrProofVectors;
    const publicKey = decodePointHex(vectors.public_key);
    for (const c of vectors.cases) {
      const vctx = { electionId: vectors.election_id, tokenId: c.token_id, publicKey };
      expect(verifyVoteProofHex(vctx, c.ciphertext, c.proof)).toEqual({ valid: true });
    }
  });

  it('el probador se niega a probar un voto que el ciphertext no cifra', () => {
    const enc = encryptVote(keys.publicKey, 0);
    expect(() => proveVote(ctx, enc, 1)).toThrow(RangeError);
  });

  it('la prueba ocupa 4 puntos + 4 escalares = 256 bytes', () => {
    const { proof } = honestBallot(1);
    const bytes = Object.values(proof).reduce<number>((acc, hex: string) => acc + hex.length / 2, 0);
    expect(bytes).toBe(256);
  });
});

// ───────────── Casos exigidos por la evaluación: voto 2, compromiso, reto, token ─────────────

describe('voto de valor 2 (probador malicioso)', () => {
  it('(a) simulando ambas ramas: las ecuaciones cuadran pero c0 + c1 ≠ H(T) → V3', () => {
    const forged = forgeBothSimulated(ctx, 2n);
    expectRejected(verifyVoteProof(ctx, forged.ciphertext, forged.proof), 'V3', ProofErrorCode.CHALLENGE);
  });

  it('(b) simulando la rama 1 y forzando la rama 0 → V4', () => {
    const forged = forgeOneForced(ctx, 2n, 1);
    expectRejected(verifyVoteProof(ctx, forged.ciphertext, forged.proof), 'V4', ProofErrorCode.EQ_0);
  });

  it('(b) simulando la rama 0 y forzando la rama 1 → V5', () => {
    const forged = forgeOneForced(ctx, 2n, 0);
    expectRejected(verifyVoteProof(ctx, forged.ciphertext, forged.proof), 'V5', ProofErrorCode.EQ_1);
  });

  it.each([-1n, 3n, 20n])('lo mismo ocurre con otros valores fuera de {0,1} (m = %d)', (m) => {
    const both = forgeBothSimulated(ctx, m);
    expectRejected(verifyVoteProof(ctx, both.ciphertext, both.proof), 'V3', ProofErrorCode.CHALLENGE);
    const forced0 = forgeOneForced(ctx, m, 1);
    expectRejected(verifyVoteProof(ctx, forced0.ciphertext, forced0.proof), 'V4', ProofErrorCode.EQ_0);
    const forced1 = forgeOneForced(ctx, m, 0);
    expectRejected(verifyVoteProof(ctx, forced1.ciphertext, forced1.proof), 'V5', ProofErrorCode.EQ_1);
  });

  it('control: el mismo probador "forzado" con m = 0 sí produce una prueba válida', () => {
    // Demuestra que el rechazo anterior se debe al valor 2 y no a un error del probador malicioso.
    const forged = forgeOneForced(ctx, 0n, 1);
    expect(verifyVoteProof(ctx, forged.ciphertext, forged.proof)).toEqual({ valid: true });
  });
});

describe('compromiso modificado', () => {
  it.each(['A0', 'B0', 'A1', 'B1'] as const)('%s reemplazado por otro punto válido → V3', (field) => {
    const b = honestBallot(1);
    const proof: OrProofHex = { ...b.proof, [field]: otherPoint() };
    expectRejected(verifyVoteProofHex(ctx, b.ct, proof), 'V3', ProofErrorCode.CHALLENGE);
  });

  it('A0 con el bit 0 volteado (elemento "negativo", codificación inválida) → V1', () => {
    const b = honestBallot(0);
    const proof = { ...b.proof, A0: flipBit(b.proof.A0, 0, 0) };
    expectRejected(verifyVoteProofHex(ctx, b.ct, proof), 'V1', CryptoErrorCode.POINT_ENCODING);
  });

  it('bit flip arbitrario en un compromiso → V1 o V3, nunca aceptado', () => {
    const b = honestBallot(1);
    for (let bit = 1; bit < 8; bit++) {
      const result = verifyVoteProofHex(ctx, b.ct, { ...b.proof, B1: flipBit(b.proof.B1, 5, bit) });
      expect(result.valid).toBe(false);
      if (!result.valid) expect(['V1', 'V3']).toContain(result.step);
    }
  });
});

describe('reto alterado', () => {
  it('c0 + 1 → V3 (la suma ya no es H(T))', () => {
    const b = honestBallot(0);
    expectRejected(verifyVoteProofHex(ctx, b.ct, { ...b.proof, c0: plusOne(b.proof.c0) }), 'V3', ProofErrorCode.CHALLENGE);
  });

  it('c1 + 1 → V3', () => {
    const b = honestBallot(1);
    expectRejected(verifyVoteProofHex(ctx, b.ct, { ...b.proof, c1: plusOne(b.proof.c1) }), 'V3', ProofErrorCode.CHALLENGE);
  });

  it('c0 + 1 y c1 − 1 (la suma se conserva) → V4', () => {
    const b = honestBallot(1);
    const proof = { ...b.proof, c0: plusOne(b.proof.c0), c1: minusOne(b.proof.c1) };
    expectRejected(verifyVoteProofHex(ctx, b.ct, proof), 'V4', ProofErrorCode.EQ_0);
  });

  it('c0 y c1 intercambiados → V4 (con probabilidad abrumadora)', () => {
    const b = honestBallot(0);
    const proof = { ...b.proof, c0: b.proof.c1, c1: b.proof.c0 };
    expectRejected(verifyVoteProofHex(ctx, b.ct, proof), 'V4', ProofErrorCode.EQ_0);
  });

  it('reto ≥ q (no canónico) → V2', () => {
    const b = honestBallot(0);
    const nonCanonical = 'ff'.repeat(32);
    expectRejected(verifyVoteProofHex(ctx, b.ct, { ...b.proof, c0: nonCanonical }), 'V2', CryptoErrorCode.SCALAR_RANGE);
  });
});

describe('respuesta alterada', () => {
  it('s0 + 1 → V4', () => {
    const b = honestBallot(0);
    expectRejected(verifyVoteProofHex(ctx, b.ct, { ...b.proof, s0: plusOne(b.proof.s0) }), 'V4', ProofErrorCode.EQ_0);
  });

  it('s1 + 1 → V5', () => {
    const b = honestBallot(0);
    expectRejected(verifyVoteProofHex(ctx, b.ct, { ...b.proof, s1: plusOne(b.proof.s1) }), 'V5', ProofErrorCode.EQ_1);
  });

  it('respuesta en mayúsculas (representación alternativa) → V2', () => {
    const b = honestBallot(1);
    const proof = { ...b.proof, s1: b.proof.s1.toUpperCase() };
    expectRejected(verifyVoteProofHex(ctx, b.ct, proof), 'V2', CryptoErrorCode.SCALAR_RANGE);
  });
});

// ─────────────────────── Atado del contexto (anti-copia) ───────────────────────

describe('la prueba está atada a su contexto', () => {
  it('(α, β, π) copiados y enviados con otro token → V3', () => {
    const b = honestBallot(1);
    expectRejected(verifyVoteProofHex({ ...ctx, tokenId: 'token-b' }, b.ct, b.proof), 'V3', ProofErrorCode.CHALLENGE);
  });

  it('prueba presentada en otra elección → V3', () => {
    const b = honestBallot(1);
    expectRejected(verifyVoteProofHex({ ...ctx, electionId: 'otra' }, b.ct, b.proof), 'V3', ProofErrorCode.CHALLENGE);
  });

  it('prueba verificada con otra clave pública → V3', () => {
    const b = honestBallot(0);
    const other = { ...ctx, publicKey: generateKeyPair().publicKey };
    expectRejected(verifyVoteProofHex(other, b.ct, b.proof), 'V3', ProofErrorCode.CHALLENGE);
  });

  it('pruebas intercambiadas entre dos ballots → V3', () => {
    const a = honestBallot(0);
    const b = honestBallot(1);
    expectRejected(verifyVoteProofHex(ctx, a.ct, b.proof), 'V3', ProofErrorCode.CHALLENGE);
  });

  it('β modificado para cambiar el voto (β + G) → V3', () => {
    const b = honestBallot(0);
    const beta = encodePointHex(decodePointHex(b.ct.beta).add(G));
    expectRejected(verifyVoteProofHex(ctx, { ...b.ct, beta }, b.proof), 'V3', ProofErrorCode.CHALLENGE);
  });
});

// ─────────────────────── Ciphertext mal formado (V1) ───────────────────────

describe('ciphertext mal formado', () => {
  it('α = identidad → V1 / E_IDENTITY', () => {
    const b = honestBallot(1);
    const ct = { ...b.ct, alpha: encodePointHex(IDENTITY) };
    expectRejected(verifyVoteProofHex(ctx, ct, b.proof), 'V1', CryptoErrorCode.IDENTITY);
  });

  it('β que no pertenece al grupo → V1 / E_POINT_ENCODING', () => {
    const b = honestBallot(1);
    expectRejected(verifyVoteProofHex(ctx, { ...b.ct, beta: 'ff'.repeat(32) }, b.proof), 'V1', CryptoErrorCode.POINT_ENCODING);
  });

  it('componente vacío → V1', () => {
    const b = honestBallot(0);
    expectRejected(verifyVoteProofHex(ctx, { ...b.ct, alpha: '' }, b.proof), 'V1', CryptoErrorCode.POINT_ENCODING);
  });
});
