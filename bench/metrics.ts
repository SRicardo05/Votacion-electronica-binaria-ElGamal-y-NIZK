/**
 * Métricas experimentales (fase 8; formato fijado en §8.3 del Entregable 1).
 *
 *   npm run bench -- [--repeats 30] [--sizes 1,5,10,20] [--out results]
 *
 * Para cada N se corren R elecciones independientes (SQLite en memoria), precedidas de una ronda de
 * calentamiento que se descarta (compilación JIT). En cada elección:
 *   - creación:      buildBallot (cifrado ElGamal + prueba OR) de cada votante          → N muestras
 *   - verif. cripto: decodeBallotHex + verifyVoteProof (U1 + U3) de cada ballot          → N muestras
 *   - urna:          BallotBox.submit completo (U0–U5, incluye HMAC y SQLite)            → N muestras
 *   - auditoría:     verifyRecord sobre el expediente de N ballots (A1–A9)              → 1 muestra
 * Se reportan mediana y p95 en milisegundos.
 */
import { cpus, platform, release } from 'node:os';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import { buildBallot } from '../src/client/index.js';
import { type Vote, decodeBallotHex, decodeNonIdentityPointHex, verifyVoteProof } from '../src/crypto/index.js';
import { createSqliteRepositories, openDatabase } from '../src/persistence/index.js';
import { BallotBox, ElectionService } from '../src/protocol/index.js';
import { type BallotSubmission, canonicalJson } from '../src/schema/index.js';
import { verifyRecord } from '../src/verifier/index.js';

export interface Stat {
  readonly median: number;
  readonly p95: number;
  readonly samples: number;
}

export interface SizeResult {
  readonly n: number;
  /** α, β y la prueba en binario: 2 + 8 elementos de 32 bytes. */
  readonly ballotBinaryBytes: number;
  /** Ballot enviado por el cliente (JSON canónico, incluye credencial). */
  readonly ballotJsonBytes: number;
  /** Ballot publicado en el expediente (JSON canónico). */
  readonly storedBallotJsonBytes: number;
  /** Expediente completo (JSON canónico). */
  readonly recordJsonBytes: number;
  readonly creationMs: Stat;
  readonly cryptoVerifyMs: Stat;
  readonly urnSubmitMs: Stat;
  readonly auditMs: Stat;
}

export interface BenchResult {
  readonly environment: Record<string, string>;
  readonly repeats: number;
  readonly results: readonly SizeResult[];
}

export function stat(samples: readonly number[]): Stat {
  if (samples.length === 0) throw new RangeError('stat: sin muestras');
  const s = [...samples].sort((a, b) => a - b);
  const at = (q: number) => s[Math.min(s.length - 1, Math.ceil(q * s.length) - 1)] ?? 0;
  const mid = Math.floor(s.length / 2);
  const median = s.length % 2 === 1 ? (s[mid] ?? 0) : ((s[mid - 1] ?? 0) + (s[mid] ?? 0)) / 2;
  return { median, p95: at(0.95), samples: s.length };
}

const time = <T>(fn: () => T): [T, number] => {
  const t0 = performance.now();
  const value = fn();
  return [value, performance.now() - t0];
};

const bytes = (v: unknown): number => Buffer.byteLength(canonicalJson(v), 'utf8');

interface RoundSamples {
  creation: number[];
  cryptoVerify: number[];
  urnSubmit: number[];
  audit: number;
  sizes: { ballot: number; stored: number; record: number };
}

/** Una elección completa de N votantes, cronometrando cada fase. */
function runRound(n: number): RoundSamples {
  const db = openDatabase(':memory:');
  try {
    const repos = createSqliteRepositories(db);
    const elections = new ElectionService(repos);
    const box = new BallotBox(repos);
    const params = elections.create({ question: '¿Métricas?', nMaxVoters: 20 });
    const creds = elections.issueTokens(params.election_id, n);
    const publicKey = decodeNonIdentityPointHex(params.public_key);

    const creation: number[] = [];
    const ballots: BallotSubmission[] = creds.map((c, i) => {
      const [b, ms] = time(() => buildBallot(params, c, (i % 2) as Vote));
      creation.push(ms);
      return b;
    });

    const cryptoVerify = ballots.map((b) => {
      const tokenId = b.credential.split('.')[0] ?? '';
      const [, ms] = time(() => {
        const d = decodeBallotHex(b.ciphertext, b.proof);
        if (!d.ok) throw new Error(d.code);
        const v = verifyVoteProof({ electionId: params.election_id, tokenId, publicKey }, d.ciphertext, d.proof);
        if (!v.valid) throw new Error(v.code);
      });
      return ms;
    });

    const urnSubmit = ballots.map((b) => {
      const [outcome, ms] = time(() => box.submit(params.election_id, b));
      if (!outcome.ok) throw new Error(`ballot rechazado durante la medición: ${outcome.rejection.code}`);
      return ms;
    });

    const record = elections.close(params.election_id);
    const json = JSON.parse(JSON.stringify(record)) as unknown; // como lo leería el verificador desde archivo
    const [report, audit] = time(() => verifyRecord(json));
    if (!report.ok) throw new Error('el expediente medido no verifica');

    const first = ballots[0];
    const stored = record.ballots[0];
    return {
      creation,
      cryptoVerify,
      urnSubmit,
      audit,
      sizes: { ballot: first ? bytes(first) : 0, stored: stored ? bytes(stored) : 0, record: bytes(record) },
    };
  } finally {
    db.close();
  }
}

export interface BenchOptions {
  readonly sizes: readonly number[];
  readonly repeats: number;
  /** Progreso opcional. */
  readonly onProgress?: (msg: string) => void;
}

export function runBenchmarks(opts: BenchOptions): BenchResult {
  if (!Number.isInteger(opts.repeats) || opts.repeats < 1) throw new RangeError('repeats debe ser ≥ 1');
  for (const n of opts.sizes) {
    if (!Number.isInteger(n) || n < 1 || n > 20) throw new RangeError('cada tamaño debe estar en [1, 20]');
  }

  runRound(Math.max(...opts.sizes)); // calentamiento (descartado)

  const results = opts.sizes.map((n): SizeResult => {
    const all: RoundSamples[] = [];
    for (let r = 0; r < opts.repeats; r++) all.push(runRound(n));
    opts.onProgress?.(`N = ${n}: ${opts.repeats} elecciones medidas`);
    const first = all[0];
    if (first === undefined) throw new Error('sin rondas');
    return {
      n,
      ballotBinaryBytes: 10 * 32,
      ballotJsonBytes: first.sizes.ballot,
      storedBallotJsonBytes: first.sizes.stored,
      recordJsonBytes: first.sizes.record,
      creationMs: stat(all.flatMap((a) => a.creation)),
      cryptoVerifyMs: stat(all.flatMap((a) => a.cryptoVerify)),
      urnSubmitMs: stat(all.flatMap((a) => a.urnSubmit)),
      auditMs: stat(all.map((a) => a.audit)),
    };
  });

  const cpu = cpus()[0];
  return {
    environment: {
      fecha: new Date().toISOString(),
      node: process.version,
      so: `${platform()} ${release()}`,
      cpu: cpu ? `${cpu.model.trim()} (${cpus().length} hilos)` : 'desconocida',
    },
    repeats: opts.repeats,
    results,
  };
}

const f = (x: number): string => x.toFixed(3);
const ms = (s: Stat): string => `${f(s.median)} (p95 ${f(s.p95)})`;

export function formatMarkdown(b: BenchResult): string {
  const lines = [
    '# Métricas experimentales',
    '',
    `Generado con \`npm run bench\` — ${b.repeats} elecciones por tamaño; tiempos en ms como **mediana (p95)**.`,
    '',
    ...Object.entries(b.environment).map(([k, v]) => `- **${k}:** ${v}`),
    '',
    '## Tabla del Entregable 1 (§8.3)',
    '',
    '| N.º de votos | Tamaño de ballot (bytes) | Tiempo de creación (ms) | Tiempo de verificación por voto (ms) | Tiempo total de auditoría (ms) |',
    '|---:|---:|---:|---:|---:|',
    ...b.results.map(
      (r) =>
        `| ${r.n} | ${r.ballotBinaryBytes} binario / ${r.ballotJsonBytes} JSON | ${ms(r.creationMs)} | ${ms(r.urnSubmitMs)} | ${ms(r.auditMs)} |`,
    ),
    '',
    '## Detalle',
    '',
    '| N | Ballot publicado (bytes JSON) | Expediente (bytes JSON) | Verificación cripto U1+U3 (ms) | Muestras por voto | Muestras de auditoría |',
    '|---:|---:|---:|---:|---:|---:|',
    ...b.results.map(
      (r) =>
        `| ${r.n} | ${r.storedBallotJsonBytes} | ${r.recordJsonBytes} | ${ms(r.cryptoVerifyMs)} | ${r.creationMs.samples} | ${r.auditMs.samples} |`,
    ),
    '',
    '## Qué mide cada columna',
    '',
    '- **Tamaño de ballot:** binario = α, β y la prueba OR (A0, B0, A1, B1, c0, c1, s0, s1): 10 × 32 = 320 bytes. ' +
      'JSON = mensaje enviado por el cliente en JSON canónico (hex + credencial + metadatos).',
    '- **Tiempo de creación:** en el cliente, cifrado ElGamal + prueba OR (`buildBallot`).',
    '- **Tiempo de verificación por voto:** en la urna, el envío completo U0–U5 (esquema, decodificación, HMAC del ' +
      'token, prueba OR, duplicados y transacción SQLite). La columna "Verificación cripto" aísla U1 + U3.',
    '- **Tiempo total de auditoría:** el verificador independiente sobre el expediente de N ballots (A1–A9: firma, ' +
      'hashes, N pruebas OR y agregado recalculado). Crece linealmente con N.',
    '',
  ];
  return lines.join('\n');
}

export function formatCsv(b: BenchResult): string {
  const header = [
    'n', 'ballot_binary_bytes', 'ballot_json_bytes', 'stored_ballot_json_bytes', 'record_json_bytes',
    'creation_ms_median', 'creation_ms_p95', 'crypto_verify_ms_median', 'crypto_verify_ms_p95',
    'urn_submit_ms_median', 'urn_submit_ms_p95', 'audit_ms_median', 'audit_ms_p95', 'repeats',
  ];
  const rows = b.results.map((r) =>
    [
      r.n, r.ballotBinaryBytes, r.ballotJsonBytes, r.storedBallotJsonBytes, r.recordJsonBytes,
      f(r.creationMs.median), f(r.creationMs.p95), f(r.cryptoVerifyMs.median), f(r.cryptoVerifyMs.p95),
      f(r.urnSubmitMs.median), f(r.urnSubmitMs.p95), f(r.auditMs.median), f(r.auditMs.p95), b.repeats,
    ].join(','),
  );
  return `${[header.join(','), ...rows].join('\n')}\n`;
}

if (process.argv[1] !== undefined && resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1])) {
  const { values } = parseArgs({
    options: {
      repeats: { type: 'string', default: '30' },
      sizes: { type: 'string', default: '1,5,10,20' },
      out: { type: 'string', default: 'results' },
    },
  });
  const result = runBenchmarks({
    repeats: Number(values.repeats),
    sizes: values.sizes.split(',').map(Number),
    onProgress: (m) => {
      console.log(m);
    },
  });
  mkdirSync(values.out, { recursive: true });
  writeFileSync(join(values.out, 'metrics.csv'), formatCsv(result));
  writeFileSync(join(values.out, 'metrics.md'), formatMarkdown(result));
  writeFileSync(join(values.out, 'metrics.json'), `${JSON.stringify(result, null, 2)}\n`);
  console.log('');
  console.log(formatMarkdown(result));
  console.log(`Resultados en ${values.out}/metrics.{md,csv,json}`);
}
