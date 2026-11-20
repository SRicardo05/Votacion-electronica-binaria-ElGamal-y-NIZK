/**
 * Probadores DELIBERADAMENTE incorrectos, usados solo como prueba de concepto interna (PLAN §8.2):
 * intentan convencer a la urna de que un cifrado de 2 (u otro valor ∉ {0,1}) es válido.
 *
 * Con v = 2 ninguna rama es una tupla Diffie–Hellman válida, así que el probador solo puede:
 *   (a) simular ambas ramas → las ecuaciones V4/V5 cuadran, pero c0 + c1 ≠ H(T)  → falla V3
 *   (b) simular una rama y "forzar" la otra con c_j = c − c_f → V3 cuadra, pero la
 *       rama forzada no satisface su ecuación                                      → falla V4 o V5
 */
import {
  type Ciphertext,
  G,
  type OrCommitments,
  type OrProof,
  type Point,
  type ProofContext,
  type Scalar,
  type Vote,
  branchTarget,
  computeChallenge,
  encryptPoint,
  mulPublic,
  mulSecret,
  randomScalar,
  scalarAdd,
  scalarMul,
  scalarSub,
  toScalar,
} from '../../src/crypto/index.js';

export interface ForgedBallot {
  readonly ciphertext: Ciphertext;
  readonly proof: OrProof;
}

/** Cifra m·G con aleatoriedad r (m arbitrario, p. ej. 2). */
export function encryptValue(publicKey: Point, m: bigint, r: Scalar): Ciphertext {
  return encryptPoint(publicKey, mulPublic(toScalar(m), G), r);
}

function simulate(ctx: ProofContext, ct: Ciphertext, j: Vote): { A: Point; B: Point; c: Scalar; s: Scalar } {
  const c = randomScalar();
  const s = randomScalar();
  return {
    A: mulSecret(s, G).subtract(mulSecret(c, ct.alpha)),
    B: mulSecret(s, ctx.publicKey).subtract(mulSecret(c, branchTarget(ct, j))),
    c,
    s,
  };
}

/** Estrategia (a): ambas ramas simuladas con retos elegidos libremente. */
export function forgeBothSimulated(ctx: ProofContext, m: bigint): ForgedBallot {
  const ct = encryptValue(ctx.publicKey, m, randomScalar());
  const b0 = simulate(ctx, ct, 0);
  const b1 = simulate(ctx, ct, 1);
  return {
    ciphertext: ct,
    proof: { A0: b0.A, B0: b0.B, A1: b1.A, B1: b1.B, c0: b0.c, c1: b1.c, s0: b0.s, s1: b1.s },
  };
}

/**
 * Estrategia (b): simula la rama `simulated` y responde "honestamente" en la otra como si
 * el ciphertext la cumpliera (s = w + c·r), forzando c_forzada = c − c_simulada.
 */
export function forgeOneForced(ctx: ProofContext, m: bigint, simulated: Vote): ForgedBallot {
  const r = randomScalar();
  const ct = encryptValue(ctx.publicKey, m, r);
  const sim = simulate(ctx, ct, simulated);
  const w = randomScalar();
  const aForced = mulSecret(w, G);
  const bForced = mulSecret(w, ctx.publicKey);

  const commitments: OrCommitments =
    simulated === 1
      ? { A0: aForced, B0: bForced, A1: sim.A, B1: sim.B }
      : { A0: sim.A, B0: sim.B, A1: aForced, B1: bForced };
  const c = computeChallenge(ctx, ct, commitments);
  const cForced = scalarSub(c, sim.c);
  const sForced = scalarAdd(w, scalarMul(cForced, r));

  const proof: OrProof =
    simulated === 1
      ? { ...commitments, c0: cForced, c1: sim.c, s0: sForced, s1: sim.s }
      : { ...commitments, c0: sim.c, c1: cForced, s0: sim.s, s1: sForced };
  return { ciphertext: ct, proof };
}
