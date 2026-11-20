/**
 * Raíz de composición: conecta SQLite → protocolo → HTTP y arranca el servidor local.
 *
 * Variables de entorno:
 *   PORT           puerto (por defecto 3000)
 *   HOST           interfaz (por defecto 127.0.0.1: el prototipo es solo local)
 *   DB_PATH        archivo SQLite (por defecto data/urna.db)
 *   ADMIN_API_KEY  clave de administración (≥ 16 caracteres). Si falta, se genera una y se muestra.
 */
import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

import { createSqliteRepositories, openDatabase } from '../persistence/index.js';
import { BallotBox, ElectionService } from '../protocol/index.js';
import { createApp } from './app.js';

const port = Number(process.env.PORT ?? 3000);
const host = process.env.HOST ?? '127.0.0.1';
const dbPath = process.env.DB_PATH ?? 'data/urna.db';
const adminApiKey = process.env.ADMIN_API_KEY ?? randomBytes(24).toString('base64url');

mkdirSync(dirname(dbPath), { recursive: true });
const db = openDatabase(dbPath);
const repos = createSqliteRepositories(db);

const app = createApp({
  elections: new ElectionService(repos),
  ballotBox: new BallotBox(repos),
  adminApiKey,
});

const server = app.listen(port, host, () => {
  console.log(`Urna escuchando en http://${host}:${port} (base: ${dbPath})`);
  if (process.env.ADMIN_API_KEY === undefined) console.log(`ADMIN_API_KEY generada: ${adminApiKey}`);
});

const shutdown = (): void => {
  server.close(() => {
    db.close();
    process.exit(0);
  });
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
