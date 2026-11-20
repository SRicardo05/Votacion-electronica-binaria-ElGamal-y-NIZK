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

  // 2 — Elecciones, secretos de la autoridad, ballots aceptados y registro de rechazos.
  `
  CREATE TABLE elections (
    election_id TEXT PRIMARY KEY CHECK (length(election_id) = 32 AND election_id NOT GLOB '*[^0-9a-f]*'),
    params_json TEXT NOT NULL,
    state       TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'closed')),
    closed_at   TEXT,
    CHECK ((state = 'open') = (closed_at IS NULL))
  ) STRICT;

  -- Los parámetros publicados son inmutables y una elección cerrada no se reabre.
  CREATE TRIGGER elections_params_immutable
  BEFORE UPDATE OF params_json, election_id ON elections
  BEGIN
    SELECT RAISE(ABORT, 'los parámetros publicados son inmutables');
  END;

  CREATE TRIGGER elections_no_reopen
  BEFORE UPDATE OF state ON elections
  WHEN OLD.state = 'closed'
  BEGIN
    SELECT RAISE(ABORT, 'E_CLOSED: una elección cerrada no se reabre');
  END;

  CREATE TRIGGER elections_no_delete
  BEFORE DELETE ON elections
  BEGIN
    SELECT RAISE(ABORT, 'las elecciones no se pueden borrar');
  END;

  -- Separado de "elections" para que nunca se filtre al serializar los parámetros públicos.
  CREATE TABLE authority_secrets (
    election_id     TEXT PRIMARY KEY REFERENCES elections (election_id),
    secret_key      TEXT NOT NULL CHECK (length(secret_key) = 64),
    mac_key         TEXT NOT NULL CHECK (length(mac_key) = 64),
    sign_secret_key TEXT NOT NULL CHECK (length(sign_secret_key) = 64)
  ) STRICT;

  CREATE TABLE ballots (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    election_id TEXT NOT NULL REFERENCES elections (election_id),
    token_id    TEXT NOT NULL,
    version     TEXT NOT NULL,
    alpha       TEXT NOT NULL CHECK (length(alpha) = 64),
    beta        TEXT NOT NULL CHECK (length(beta) = 64),
    proof_json  TEXT NOT NULL,
    ballot_hash TEXT NOT NULL CHECK (length(ballot_hash) = 64),
    received_at TEXT NOT NULL,
    UNIQUE (election_id, token_id),
    UNIQUE (election_id, ballot_hash),
    UNIQUE (election_id, alpha, beta),
    FOREIGN KEY (election_id, token_id) REFERENCES tokens (election_id, token_id)
  ) STRICT;

  -- Un ballot solo entra con la elección abierta y con su token ya consumido (en la misma transacción).
  CREATE TRIGGER ballots_require_open
  BEFORE INSERT ON ballots
  WHEN (SELECT state FROM elections WHERE election_id = NEW.election_id) IS NOT 'open'
  BEGIN
    SELECT RAISE(ABORT, 'E_CLOSED: la elección no está abierta');
  END;

  CREATE TRIGGER ballots_require_consumed_token
  BEFORE INSERT ON ballots
  WHEN (SELECT consumed_at FROM tokens WHERE election_id = NEW.election_id AND token_id = NEW.token_id) IS NULL
  BEGIN
    SELECT RAISE(ABORT, 'E_TOKEN_UNKNOWN: el token no existe o no fue consumido');
  END;

  -- Los ballots aceptados son de solo inserción.
  CREATE TRIGGER ballots_no_update
  BEFORE UPDATE ON ballots
  BEGIN
    SELECT RAISE(ABORT, 'los ballots aceptados no se pueden modificar');
  END;

  CREATE TRIGGER ballots_no_delete
  BEFORE DELETE ON ballots
  BEGIN
    SELECT RAISE(ABORT, 'los ballots aceptados no se pueden borrar');
  END;

  CREATE TABLE rejections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    election_id TEXT,
    step        TEXT NOT NULL CHECK (step IN ('U0', 'U1', 'U2', 'U3', 'U4', 'U5')),
    code        TEXT NOT NULL,
    reason      TEXT NOT NULL,
    at          TEXT NOT NULL
  ) STRICT;
  `,
];
