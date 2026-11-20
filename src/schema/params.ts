/**
 * Parámetros públicos de una elección (PLAN §5.2). Se publican antes de abrir la votación y son
 * inmutables: cliente, urna y verificador los usan como única fuente de la clave pública.
 */
import { z } from 'zod';

import { PROTOCOL_VERSION, SUITE_ID } from '../crypto/index.js';

/** Máximo de votantes por elección (enunciado del proyecto). */
export const MAX_VOTERS = 20;

export const OPTIONS = ['no', 'si'] as const;

/** Identificador de elección: 16 bytes aleatorios en hex. */
export const ELECTION_ID_RE = /^[0-9a-f]{32}$/;

const hex32Bytes = z.string().regex(/^[0-9a-f]{64}$/);

export const ElectionParamsSchema = z.strictObject({
  version: z.literal(PROTOCOL_VERSION),
  suite_id: z.literal(SUITE_ID),
  election_id: z.string().regex(ELECTION_ID_RE),
  question: z.string().min(1).max(500),
  options: z.tuple([z.literal(OPTIONS[0]), z.literal(OPTIONS[1])]),
  n_max_voters: z.number().int().min(1).max(MAX_VOTERS),
  generator: hex32Bytes,
  public_key: hex32Bytes,
  authority_sign_pk: hex32Bytes,
  opened_at: z.string().min(1),
});

export type ElectionParams = z.infer<typeof ElectionParamsSchema>;
