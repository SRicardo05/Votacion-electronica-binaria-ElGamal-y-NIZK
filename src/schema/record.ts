/**
 * Expediente público de la elección (PLAN §5.2): documento autocontenido que el verificador
 * independiente audita sin acceso a la urna.
 *
 * Firma: Ed25519 de la autoridad sobre
 *   m = ASCII "VOTE-BIN-v1/election-record" || SHA-256(JCS(expediente sin el campo "signature"))
 * con la clave cuya parte pública se publicó en `params.authority_sign_pk` antes de abrir.
 */
import { z } from 'zod';

import { concatBytes, sha256Bytes, strictHexToBytes } from '../crypto/index.js';
import { StoredBallotSchema } from './ballot.js';
import { canonicalBytes } from './canonical.js';
import { ElectionParamsSchema } from './params.js';

export const RECORD_SIGNATURE_DST = 'VOTE-BIN-v1/election-record';

const count = z.number().int().min(0);

export const AuditRecordSchema = z.strictObject({
  version: z.string().max(16),
  suite_id: z.string().max(128),
  params: ElectionParamsSchema,
  tokens: z.strictObject({
    /** token_id emitidos, en orden lexicográfico. */
    issued: z.array(z.string().max(64)).max(1000),
    /** token_id consumidos, en orden lexicográfico. */
    consumed: z.array(z.string().max(64)).max(1000),
  }),
  /** Ballots aceptados, en orden de recepción. */
  ballots: z.array(StoredBallotSchema).max(1000),
  /** Suma homomórfica de todos los ballots aceptados (la que la autoridad descifró). */
  aggregate: z.strictObject({ alpha: z.string().max(128), beta: z.string().max(128) }),
  /** Resultado ANUNCIADO por la autoridad (sin prueba de descifrado: no verificable). */
  declared_result: z.strictObject({ yes: count, no: count, n_ballots: count }),
  closing: z.strictObject({ closed_at: z.string().max(64), software_version: z.string().max(32) }),
  /** Firma Ed25519 (64 bytes, hex). */
  signature: z.string().max(256),
});

export type AuditRecord = z.infer<typeof AuditRecordSchema>;
export type UnsignedAuditRecord = Omit<AuditRecord, 'signature'>;

/** Bytes que firma la autoridad y comprueba el verificador. */
export function recordSigningMessage(record: UnsignedAuditRecord | AuditRecord): Uint8Array {
  const { signature: _ignored, ...unsigned } = record as AuditRecord;
  return concatBytes(new TextEncoder().encode(RECORD_SIGNATURE_DST), sha256Bytes(canonicalBytes(unsigned)));
}

/** Decodifica la firma hex del expediente (null si no tiene el formato exacto). */
export function recordSignatureBytes(record: AuditRecord): Uint8Array | null {
  return strictHexToBytes(record.signature, 64);
}
