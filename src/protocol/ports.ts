/**
 * Puertos (interfaces) que la lógica de protocolo necesita del mundo exterior.
 * La capa `persistence/` los implementa con SQLite; las pruebas pueden usar implementaciones
 * en memoria. El protocolo nunca importa una base de datos concreta.
 */

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
