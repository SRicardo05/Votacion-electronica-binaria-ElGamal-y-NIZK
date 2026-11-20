/**
 * Migraciones del esquema, aplicadas en orden y registradas en `PRAGMA user_version`.
 * Nunca se edita una migración ya publicada: los cambios van en una migración nueva.
 */
export const MIGRATIONS: readonly string[] = [
  // 1 — Tokens de votación.
  `
  CREATE TABLE tokens (
    election_id TEXT NOT NULL CHECK (length(election_id) > 0),
    token_id    TEXT NOT NULL CHECK (length(token_id) = 32 AND token_id NOT GLOB '*[^0-9a-f]*'),
    issued_at   TEXT NOT NULL,
    consumed_at TEXT,
    PRIMARY KEY (election_id, token_id)
  ) STRICT;

  -- Restricción a nivel de base de datos: un token consumido no puede volver a marcarse
  -- ni "desconsumirse", aunque un error de la aplicación lo intente.
  CREATE TRIGGER tokens_consumed_once
  BEFORE UPDATE OF consumed_at ON tokens
  WHEN OLD.consumed_at IS NOT NULL
  BEGIN
    SELECT RAISE(ABORT, 'E_TOKEN_USED: el token ya fue consumido');
  END;

  -- Los tokens emitidos no se borran: forman parte del expediente.
  CREATE TRIGGER tokens_no_delete
  BEFORE DELETE ON tokens
  BEGIN
    SELECT RAISE(ABORT, 'los tokens emitidos no se pueden borrar');
  END;
  `,
];
