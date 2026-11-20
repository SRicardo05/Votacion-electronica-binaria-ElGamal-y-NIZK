/**
 * Utilidades para pruebas de cierre y verificación: correr una elección completa y
 * re-firmar un expediente manipulado con la clave de la autoridad (simula una autoridad deshonesta).
 */
import { buildBallot } from '../../src/client/ballotBuilder.js';
import { type Vote, bytesToHex, signMessage, strictHexToBytes } from '../../src/crypto/index.js';
import { BallotBox, ElectionService } from '../../src/protocol/index.js';
import { type AuditRecord, type UnsignedAuditRecord, recordSigningMessage } from '../../src/schema/index.js';
import type { Repos } from './ballotBoxContract.js';
import { createInMemoryRepositories } from './inMemoryRepositories.js';

export interface RunElectionResult {
  readonly record: AuditRecord;
  readonly receipts: string[];
  /** Clave de firma de la autoridad (hex), para re-firmar expedientes manipulados. */
  readonly signSecretKey: string;
  /** Credenciales emitidas que no se usaron. */
  readonly unusedCredentials: string[];
  readonly repos: Repos;
}

/** Corre una elección con los votos dados (y `spare` tokens sin usar) y la cierra. */
export interface RunElectionOptions {
  /** Tokens extra que se emiten pero no se usan. */
  readonly spare?: number;
  readonly repos?: Repos;
}

export function runElection(votes: readonly Vote[], options: RunElectionOptions = {}): RunElectionResult {
  const spare = options.spare ?? 0;
  const repos = options.repos ?? createInMemoryRepositories();
  const elections = new ElectionService(repos);
  const box = new BallotBox(repos);
  const params = elections.create({ question: '¿Aprueba la propuesta?', nMaxVoters: 20 });
  const total = votes.length + spare;
  const creds = total > 0 ? elections.issueTokens(params.election_id, total) : [];
  const receipts = votes.map((v, i) => {
    const outcome = box.submit(params.election_id, buildBallot(params, creds[i] ?? '', v));
    if (!outcome.ok) throw new Error(`ballot rechazado en la preparación: ${outcome.rejection.code}`);
    return outcome.value.ballot_hash;
  });
  const record = elections.close(params.election_id);
  return {
    record,
    receipts,
    signSecretKey: repos.elections.findSecrets(params.election_id)?.signSecretKey ?? '',
    unusedCredentials: creds.slice(votes.length),
    repos,
  };
}

/** Re-firma un expediente (como haría una autoridad que manipula su propio expediente). */
export function resign(record: UnsignedAuditRecord | AuditRecord, signSecretKeyHex: string): AuditRecord {
  const { signature: _old, ...unsigned } = record as AuditRecord;
  const sk = strictHexToBytes(signSecretKeyHex, 32);
  if (sk === null) throw new Error('clave de firma inválida');
  return { ...unsigned, signature: bytesToHex(signMessage(sk, recordSigningMessage(unsigned))) };
}

/** Copia profunda (para manipular sin afectar el original). */
export const clone = <T>(v: T): T => structuredClone(v);
