/**
 * Formatos del ballot.
 *
 * - `BallotSubmission`: lo que el cliente envía a la urna (incluye la credencial con el MAC).
 * - `StoredBallot`: lo que la urna guarda y publica en el expediente (solo `token_id`, nunca el MAC).
 *
 * El esquema solo valida ESTRUCTURA (campos exactos, tipos, longitudes máximas). La validez
 * criptográfica de cada valor (puntos canónicos, escalares < q) se comprueba después, en U1.
 */
import { z } from 'zod';

import { type CiphertextHex, type OrProofHex, sha256Hex } from '../crypto/index.js';
import { canonicalBytes } from './canonical.js';

/** Campo hex: tope de longitud para no procesar cadenas enormes; el formato exacto se valida en U1. */
const hexField = z.string().max(128);

export const CiphertextSchema = z.strictObject({ alpha: hexField, beta: hexField });

export const OrProofSchema = z.strictObject({
  A0: hexField,
  B0: hexField,
  A1: hexField,
  B1: hexField,
  c0: hexField,
  c1: hexField,
  s0: hexField,
  s1: hexField,
});

export const BallotSubmissionSchema = z.strictObject({
  version: z.string().max(16),
  election_id: z.string().max(64),
  credential: z.string().max(256),
  ciphertext: CiphertextSchema,
  proof: OrProofSchema,
});

export type BallotSubmission = z.infer<typeof BallotSubmissionSchema>;

/** Contenido del ballot que se hashea: todo lo que lo define, sin la marca de tiempo de la urna. */
export interface BallotCore {
  readonly version: string;
  readonly election_id: string;
  readonly token_id: string;
  readonly ciphertext: CiphertextHex;
  readonly proof: OrProofHex;
}

export interface StoredBallot extends BallotCore {
  /** Asignado por la urna (no por el cliente), ISO 8601. */
  readonly received_at: string;
  /** SHA-256(JCS(BallotCore)) en hex: recibo del votante y detección de reenvíos. */
  readonly ballot_hash: string;
}

export function computeBallotHash(core: BallotCore): string {
  const { version, election_id, token_id, ciphertext, proof } = core;
  return sha256Hex(canonicalBytes({ version, election_id, token_id, ciphertext, proof }));
}
