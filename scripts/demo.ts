/**
 * Demo de extremo a extremo (fase 7):
 *
 *   npm run demo -- [--voters 20] [--yes 13] [--out data/demo/expediente.json] [--db <archivo.db>]
 *
 * 1. Levanta la urna (Express + SQLite) en un puerto libre de 127.0.0.1.
 * 2. La autoridad crea la elección y emite un token por votante.
 * 3. Cada votante vota con la CLI (`runVoterCli`), fijando la huella de los parámetros.
 * 4. Intentos maliciosos: MAC falsificado y prueba OR alterada (con el token del último votante, que
 *    después vota con éxito) y token reutilizado → paso de rechazo de cada uno.
 * 5. La autoridad cierra; se descarga el expediente y lo audita el verificador independiente.
 */
import { randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import { createApp } from '../src/api/app.js';
import { buildBallot, runVoterCli } from '../src/client/index.js';
import { createSqliteRepositories, openDatabase } from '../src/persistence/index.js';
import { BallotBox, ElectionService } from '../src/protocol/index.js';
import { type AuditRecord, type ElectionParams, paramsFingerprint } from '../src/schema/index.js';
import { formatReport, verifyRecord } from '../src/verifier/index.js';

export interface DemoOptions {
  readonly voters: number;
  readonly yes: number;
  readonly out: string;
  readonly db: string;
}

export interface DemoSummary {
  readonly electionId: string;
  readonly expected: { readonly yes: number; readonly no: number };
  readonly declared: AuditRecord['declared_result'];
  readonly attacks: readonly { readonly name: string; readonly step: string; readonly code: string }[];
  readonly verifierOk: boolean;
  readonly receiptIncluded: boolean;
  readonly recordPath: string;
}

export async function runDemo(opts: DemoOptions, out: (line: string) => void): Promise<DemoSummary> {
  if (!Number.isInteger(opts.voters) || opts.voters < 2 || opts.voters > 20) {
    throw new RangeError('--voters debe estar en [2, 20]');
  }
  if (!Number.isInteger(opts.yes) || opts.yes < 0 || opts.yes > opts.voters) {
    throw new RangeError('--yes debe estar en [0, voters]');
  }

  const db = openDatabase(opts.db);
  const repos = createSqliteRepositories(db);
  const adminKey = randomBytes(24).toString('base64url');
  const app = createApp({ elections: new ElectionService(repos), ballotBox: new BallotBox(repos), adminApiKey: adminKey });
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>((ok) => server.once('listening', () => { ok(); }));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const admin = { Authorization: `Bearer ${adminKey}`, 'Content-Type': 'application/json' };
  const postJson = async (path: string, body: unknown, headers: Record<string, string>) =>
    fetch(base + path, { method: 'POST', headers, body: JSON.stringify(body) });

  try {
    out(`== 1. Urna escuchando en ${base}`);

    // ── 2. Autoridad: elección y tokens ──
    const params = (await (
      await postJson('/admin/elections', { question: '¿Aprueba la propuesta del curso?', n_max_voters: 20 }, admin)
    ).json()) as ElectionParams;
    const fingerprint = paramsFingerprint(params);
    const id = params.election_id;
    out(`== 2. Elección ${id} creada. Huella de parámetros: ${fingerprint}`);
    const { credentials } = (await (
      await postJson(`/admin/elections/${id}/tokens`, { count: opts.voters }, admin)
    ).json()) as { credentials: string[] };
    out(`   ${credentials.length} tokens emitidos, uno por votante`);

    // ── 3. Votantes ──
    out(`== 3. Votación: ${opts.yes} sí / ${opts.voters - opts.yes} no (cada voto se cifra y prueba en el cliente)`);
    const receipts: string[] = [];
    const vote = async (i: number) => {
      const lines: string[] = [];
      const code = await runVoterCli(
        ['--server', base, '--election', id, '--credential', credentials[i] ?? '', '--choice', i < opts.yes ? 'si' : 'no',
          '--params-sha256', fingerprint, '--json'],
        { fetch, out: (l) => lines.push(l) },
      );
      if (code !== 0) throw new Error(`el votante ${i + 1} fue rechazado: ${lines.join(' ')}`);
      receipts.push(String((JSON.parse(lines.join('\n')) as { ballot_hash: unknown }).ballot_hash));
    };
    const last = opts.voters - 1;
    for (let i = 0; i < last; i++) await vote(i);
    out(`   ${receipts.length} votos aceptados. Recibo del votante 1: ${receipts[0] ?? ''}`);

    // ── 4. Ataques ──
    out('== 4. Intentos maliciosos');
    const attack = async (name: string, body: unknown) => {
      const res = await postJson(`/elections/${id}/ballots`, body, { 'Content-Type': 'application/json' });
      const r = (await res.json()) as { step: string; code: string };
      out(`   ${name.padEnd(46)} → HTTP ${res.status}, paso ${r.step}, ${r.code}`);
      return { name, step: r.step, code: r.code };
    };
    // Con la credencial del último votante, que todavía no ha votado:
    const lastCred = credentials[last] ?? '';
    const forgedMac = `${lastCred.slice(0, 33)}${lastCred.slice(33).replace(/./, (c) => (c === '0' ? '1' : '0'))}`;
    const honest = buildBallot(params, lastCred, 1);
    const attacks = [
      await attack('credencial con MAC falsificado', buildBallot(params, forgedMac, 1)),
      await attack('prueba OR con los retos intercambiados', {
        ...honest,
        proof: { ...honest.proof, c0: honest.proof.c1, c1: honest.proof.c0 },
      }),
    ];
    await vote(last);
    out(`   el votante ${opts.voters} vota con éxito: los intentos rechazados no consumieron su token`);
    attacks.push(await attack('votar dos veces con el mismo token', buildBallot(params, credentials[0] ?? '', 0)));

    // ── 5. Cierre, expediente y verificación ──
    const closed = await postJson(`/admin/elections/${id}/close`, {}, admin);
    if (closed.status !== 200) throw new Error(`no se pudo cerrar la elección (HTTP ${closed.status})`);
    const record = (await (await fetch(`${base}/elections/${id}/record`)).json()) as AuditRecord;
    mkdirSync(dirname(opts.out), { recursive: true });
    writeFileSync(opts.out, `${JSON.stringify(record, null, 2)}\n`);
    out(`== 5. Elección cerrada. Expediente guardado en ${opts.out}`);
    out('');

    const report = verifyRecord(JSON.parse(JSON.stringify(record)), { ballotHash: receipts[0] ?? '' });
    formatReport(report).forEach((l) => {
      out(l);
    });

    return {
      electionId: id,
      expected: { yes: opts.yes, no: opts.voters - opts.yes },
      declared: record.declared_result,
      attacks,
      verifierOk: report.ok,
      receiptIncluded: report.receipt?.found === true,
      recordPath: opts.out,
    };
  } finally {
    await new Promise<void>((ok) => server.close(() => { ok(); }));
    db.close();
  }
}

if (process.argv[1] !== undefined && resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1])) {
  const { values } = parseArgs({
    options: {
      voters: { type: 'string', default: '20' },
      yes: { type: 'string', default: '13' },
      out: { type: 'string', default: 'data/demo/expediente.json' },
      db: { type: 'string', default: ':memory:' },
    },
  });
  runDemo({ voters: Number(values.voters), yes: Number(values.yes), out: values.out, db: values.db }, (l) => {
    console.log(l);
  })
    .then((s) => {
      const tallyOk = s.declared.yes === s.expected.yes && s.declared.no === s.expected.no;
      console.log('');
      console.log(`Resultado esperado ${s.expected.yes}/${s.expected.no}, anunciado ${s.declared.yes}/${s.declared.no}: ${tallyOk ? 'coinciden' : 'NO coinciden'}`);
      process.exitCode = tallyOk && s.verifierOk && s.receiptIncluded ? 0 : 1;
    })
    .catch((e: unknown) => {
      console.error(e);
      process.exitCode = 1;
    });
}
