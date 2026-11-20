/**
 * Escrutinio y construcción del expediente (PLAN §5.1–5.2).
 *
 *   1. A = Σ α_i,  B = Σ β_i  sobre los ballots aceptados
 *   2. M = B − x·A = (Σ v_i)·G
 *   3. k ∈ [0, n_ballots] con k·G = M  (logaritmo discreto acotado)
 *   4. sí = k,  no = n_ballots − k
 *
 * Solo se descifra el AGREGADO, nunca un ballot individual.
 */
import {
  PROTOCOL_VERSION,
  SUITE_ID,
  aggregateCiphertexts,
  bytesToHex,
  decodeBallotCiphertextHex,
  decodeScalarHex,
  decryptSmall,
  encodeCiphertextHex,
  signMessage,
  strictHexToBytes,
} from '../crypto/index.js';
import {
  type AuditRecord,
  type ElectionParams,
  type StoredBallot,
  type UnsignedAuditRecord,
  recordSigningMessage,
} from '../schema/index.js';
import type { AuthoritySecrets, TokenRecord } from './ports.js';

export const SOFTWARE_VERSION = '0.1.0';

export interface TallyInput {
  readonly params: ElectionParams;
  readonly secrets: AuthoritySecrets;
  readonly ballots: readonly StoredBallot[];
  readonly tokens: readonly TokenRecord[];
  readonly closedAt: string;
}

export function tallyAndSign(input: TallyInput): AuditRecord {
  const { params, secrets, ballots, tokens, closedAt } = input;

  const aggregate = aggregateCiphertexts(ballots.map((b) => decodeBallotCiphertextHex(b.ciphertext)));
  const yes = decryptSmall(decodeScalarHex(secrets.secretKey), aggregate, ballots.length);

  const sortedIds = (list: readonly TokenRecord[]) => list.map((t) => t.tokenId).sort();

  const unsigned: UnsignedAuditRecord = {
    version: PROTOCOL_VERSION,
    suite_id: SUITE_ID,
    params,
    tokens: {
      issued: sortedIds(tokens),
      consumed: sortedIds(tokens.filter((t) => t.consumedAt !== null)),
    },
    ballots: [...ballots],
    aggregate: encodeCiphertextHex(aggregate),
    declared_result: { yes, no: ballots.length - yes, n_ballots: ballots.length },
    closing: { closed_at: closedAt, software_version: SOFTWARE_VERSION },
  };

  const signKey = strictHexToBytes(secrets.signSecretKey, 32);
  if (signKey === null) throw new Error('clave de firma de la autoridad corrupta');
  return { ...unsigned, signature: bytesToHex(signMessage(signKey, recordSigningMessage(unsigned))) };
}
