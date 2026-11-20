/**
 * Transcript de Fiat–Shamir de la prueba OR: bytes EXACTOS (PLAN §2.4).
 *
 *   T = DST || LP(version) || LP(suite_id) || LP(election_id) || LP(token_id)
 *          || G || H || α || β || A0 || B0 || A1 || B1
 *
 *   DST   = ASCII "VOTE-BIN-v1/cds-or-proof" (24 bytes, sin prefijo de longitud)
 *   LP(s) = uint32 big-endian con la longitud en bytes de UTF-8(s) || UTF-8(s)
 *   puntos = codificación canónica Ristretto255 de 32 bytes, en ese orden
 *
 * Usar prefijos de longitud (y no JSON) hace la codificación inyectiva: dos contextos
 * distintos nunca producen el mismo T. Atar `token_id` impide reutilizar (α, β, π) con otro token.
 */
import type { Ciphertext } from './elgamal.js';
import { concatBytes } from './encoding.js';
import { G, type Point, encodePoint } from './group.js';
import { OR_PROOF_DST, PROTOCOL_VERSION, SUITE_ID } from './suite.js';

/** Datos públicos a los que se ata cada prueba. */
export interface ProofContext {
  readonly electionId: string;
  readonly tokenId: string;
  readonly publicKey: Point;
}

/** Compromisos de las dos ramas de la prueba OR. */
export interface OrCommitments {
  readonly A0: Point;
  readonly B0: Point;
  readonly A1: Point;
  readonly B1: Point;
}

const utf8 = new TextEncoder();

/** LP(s): longitud uint32 big-endian seguida de los bytes UTF-8 de s. */
export function lengthPrefixed(s: string): Uint8Array {
  const body = utf8.encode(s);
  const out = new Uint8Array(4 + body.length);
  new DataView(out.buffer).setUint32(0, body.length, false);
  out.set(body, 4);
  return out;
}

export function buildOrProofTranscript(
  ctx: ProofContext,
  ct: Ciphertext,
  commitments: OrCommitments,
): Uint8Array {
  return concatBytes(
    utf8.encode(OR_PROOF_DST),
    lengthPrefixed(PROTOCOL_VERSION),
    lengthPrefixed(SUITE_ID),
    lengthPrefixed(ctx.electionId),
    lengthPrefixed(ctx.tokenId),
    encodePoint(G),
    encodePoint(ctx.publicKey),
    encodePoint(ct.alpha),
    encodePoint(ct.beta),
    encodePoint(commitments.A0),
    encodePoint(commitments.B0),
    encodePoint(commitments.A1),
    encodePoint(commitments.B1),
  );
}
