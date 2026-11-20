/**
 * Cliente de votación por línea de comandos.
 *
 *   npm run vote -- --server <url> --election <id> --credential <token_id.mac> --choice si|no
 *                   [--params-sha256 <huella>] [--json]
 *
 * 1. Descarga los parámetros públicos y los valida (esquema v1, elección correcta, huella si se fija).
 * 2. Cifra el voto y genera la prueba OR LOCALMENTE (la urna nunca ve el voto en claro).
 * 3. Envía el ballot y muestra el recibo (ballot_hash) para comprobarlo luego en el expediente.
 *
 * Códigos de salida: 0 aceptado, 1 rechazado por la urna, 2 uso incorrecto / error de red / parámetros
 * no confiables (en este caso NO se envía nada).
 */
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import type { Vote } from '../crypto/index.js';
import { ElectionParamsSchema, paramsFingerprint } from '../schema/index.js';
import { buildBallot } from './ballotBuilder.js';

export interface VoterCliIo {
  readonly fetch: typeof fetch;
  readonly out: (line: string) => void;
}

const USAGE =
  'Uso: vote --server <url> --election <id> --credential <token_id.mac> --choice si|no [--params-sha256 <huella>] [--json]';

const CREDENTIAL_RE = /^[0-9a-f]{32}\.[0-9a-f]{64}$/;
const CHOICES: Record<string, Vote> = { si: 1, sí: 1, no: 0 };

class CliError extends Error {}

function parse(argv: readonly string[]) {
  const { values } = parseArgs({
    args: [...argv],
    strict: true,
    options: {
      server: { type: 'string' },
      election: { type: 'string' },
      credential: { type: 'string' },
      choice: { type: 'string' },
      'params-sha256': { type: 'string' },
      json: { type: 'boolean', default: false },
    },
  });
  const { server, election, credential, choice } = values;
  if (server === undefined || election === undefined || credential === undefined || choice === undefined) {
    throw new CliError(USAGE);
  }
  const vote = CHOICES[choice.toLowerCase()];
  if (vote === undefined) throw new CliError(`--choice debe ser "si" o "no"\n${USAGE}`);
  if (!CREDENTIAL_RE.test(credential)) throw new CliError('la credencial debe tener el formato <token_id>.<mac> (hex)');
  return { server: server.replace(/\/+$/, ''), election, credential, vote, pin: values['params-sha256'], json: values.json };
}

export async function runVoterCli(argv: readonly string[], io: VoterCliIo): Promise<number> {
  let args: ReturnType<typeof parse>;
  try {
    args = parse(argv);
  } catch (e) {
    io.out(e instanceof CliError ? e.message : `${(e as Error).message}\n${USAGE}`);
    return 2;
  }
  const base = `${args.server}/elections/${encodeURIComponent(args.election)}`;

  // ── 1. Parámetros públicos ──
  let paramsJson: unknown;
  try {
    const res = await io.fetch(`${base}/params`);
    if (!res.ok) {
      io.out(`No se pudieron obtener los parámetros (HTTP ${res.status}).`);
      return 2;
    }
    paramsJson = await res.json();
  } catch (e) {
    io.out(`No se pudo contactar al servidor: ${(e as Error).message}`);
    return 2;
  }
  const parsed = ElectionParamsSchema.safeParse(paramsJson);
  if (!parsed.success) {
    io.out('Los parámetros recibidos no cumplen el formato v1: no se envía el voto.');
    return 2;
  }
  const params = parsed.data;
  if (params.election_id !== args.election) {
    io.out('El servidor devolvió parámetros de otra elección: no se envía el voto.');
    return 2;
  }
  const fingerprint = paramsFingerprint(params);
  if (args.pin !== undefined && args.pin.toLowerCase() !== fingerprint) {
    io.out(`La huella de los parámetros no coincide (esperada ${args.pin}, recibida ${fingerprint}): no se envía el voto.`);
    return 2;
  }

  // ── 2. Cifrado + prueba OR locales ──
  const ballot = buildBallot(params, args.credential, args.vote);

  // ── 3. Envío ──
  let status: number;
  let body: Record<string, unknown>;
  try {
    const res = await io.fetch(`${base}/ballots`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(ballot),
    });
    status = res.status;
    body = (await res.json()) as Record<string, unknown>;
  } catch (e) {
    io.out(`Error enviando el ballot: ${(e as Error).message}`);
    return 2;
  }

  const accepted = body.accepted === true;
  if (args.json) {
    io.out(JSON.stringify({ ...body, http_status: status, params_sha256: fingerprint }, null, 2));
  } else if (accepted) {
    io.out(`Voto ACEPTADO en la elección ${params.election_id}`);
    io.out(`  Pregunta: ${params.question}`);
    io.out(`  Huella de los parámetros: ${fingerprint}`);
    io.out(`  Recibo (ballot_hash): ${String(body.ballot_hash)}`);
    io.out('  Tras el cierre, compruebe su recibo con:  npm run verify -- expediente.json --ballot-hash <recibo>');
  } else {
    io.out(`Voto RECHAZADO (HTTP ${status}): paso ${String(body.step)}, código ${String(body.code)}`);
  }
  return accepted ? 0 : 1;
}

if (process.argv[1] !== undefined && resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1])) {
  void runVoterCli(process.argv.slice(2), {
    fetch,
    out: (l) => {
      console.log(l);
    },
  }).then((code) => {
    process.exitCode = code;
  });
}
