/**
 * Puertos (interfaces) que la lógica de protocolo necesita del mundo exterior.
 * La capa `persistence/` los implementa con SQLite; las pruebas usan implementaciones en memoria.
 * El protocolo nunca importa una base de datos concreta.
 */
import type { ElectionParams, StoredBallot } from '../schema/index.js';
import type { Rejection } from './errors.js';

// ─────────────────────────────── Tokens ───────────────────────────────

export interface TokenRecord {
  readonly electionId: string;
  readonly tokenId: string;
  /** ISO 8601. */
  readonly issuedAt: string;
  /** ISO 8601, o null si el token aún no se ha usado. */
  readonly consumedAt: string | null;
}

export interface TokenRepository {
  /** Registra tokens emitidos. Falla si alguno ya existe (no se reemiten tokens). */
  insertIssued(records: readonly Omit<TokenRecord, 'consumedAt'>[]): void;

  find(electionId: string, tokenId: string): TokenRecord | undefined;

  /**
   * Marca el token como consumido de forma ATÓMICA: solo tiene éxito si existía y no estaba
   * consumido. Devuelve false en cualquier otro caso (incluida una carrera perdida).
   */
  markConsumed(electionId: string, tokenId: string, consumedAt: string): boolean;

  listByElection(electionId: string): TokenRecord[];
}

// ────────────────────────────── Elecciones ──────────────────────────────

export type ElectionState = 'open' | 'closed';

export interface ElectionRecord {
  readonly params: ElectionParams;
  readonly state: ElectionState;
  readonly closedAt: string | null;
}

/**
 * Material secreto de la autoridad para una elección (hex). En este prototipo se guarda en la
 * base local sin cifrar: limitación declarada (autoridad única y confiable, PLAN §5.3).
 */
export interface AuthoritySecrets {
  readonly electionId: string;
  /** x de ElGamal (escalar, 32 bytes little-endian). */
  readonly secretKey: string;
  /** k_tok de HMAC-SHA256 (32 bytes). */
  readonly macKey: string;
  /** Semilla Ed25519 para firmar el expediente (32 bytes). */
  readonly signSecretKey: string;
}

export interface ElectionRepository {
  insert(params: ElectionParams, secrets: AuthoritySecrets): void;
  find(electionId: string): ElectionRecord | undefined;
  findSecrets(electionId: string): AuthoritySecrets | undefined;
  /** Cierra la elección. Devuelve false si no existe o ya estaba cerrada. */
  markClosed(electionId: string, closedAt: string): boolean;
}

// ─────────────────────────────── Ballots ───────────────────────────────

export type InsertBallotResult = 'inserted' | 'duplicate';

export interface BallotRepository {
  /** Guarda un ballot aceptado. 'duplicate' si viola una unicidad (token, hash o ciphertext). */
  insert(ballot: StoredBallot): InsertBallotResult;
  hasBallotHash(electionId: string, ballotHash: string): boolean;
  hasCiphertext(electionId: string, alpha: string, beta: string): boolean;
  count(electionId: string): number;
  /** En orden de recepción. */
  listByElection(electionId: string): StoredBallot[];
}

// ─────────────────────────── Registro de rechazos ───────────────────────────

/**
 * Registro interno de rechazos (motivo explícito para pruebas negativas, PLAN §4).
 * Nunca recibe la credencial ni el MAC.
 */
export interface RejectionLog {
  record(electionId: string | null, rejection: Rejection, at: string): void;
}

// ─────────────────────────────── Otros ───────────────────────────────

/**
 * Ejecuta `work` en una transacción: o se aplican todos sus efectos o ninguno.
 * La urna lo usa para consumir el token y guardar el ballot como una sola operación (paso U5).
 */
export interface TransactionRunner {
  runInTransaction<T>(work: () => T): T;
}

/** Reloj inyectable (pruebas deterministas). */
export type Clock = () => Date;

export const systemClock: Clock = () => new Date();
