/**
 * CLI del verificador independiente.
 *
 *   npm run verify -- <expediente.json> [--ballot-hash <hash>] [--json]
 *
 * Código de salida: 0 si todo lo verificable pasa y lo declarado es consistente; 1 si no;
 * 2 si el uso es incorrecto o el archivo no se puede leer.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { type VerificationReport, verifyRecord } from './verifyRecord.js';

export interface CliIo {
  readonly readFile: (path: string) => string;
  readonly out: (line: string) => void;
}

const USAGE = 'Uso: verify <expediente.json> [--ballot-hash <hash>] [--json]';

export function formatReport(r: VerificationReport): string[] {
  const lines: string[] = [];
  lines.push('═══ A. VERIFICADO CRIPTOGRÁFICAMENTE ═══');
  for (const c of r.verified.checks) {
    lines.push(`  [${c.ok ? 'OK' : 'FALLA'}] ${c.id} ${c.description}`);
    for (const f of c.failures) lines.push(`         - ${f}`);
  }
  lines.push(`  Ballots publicados: ${r.verified.n_ballots}`);
  if (r.verified.recomputed_aggregate !== null) {
    lines.push('  Agregado recalculado por el verificador:');
    lines.push(`    α = ${r.verified.recomputed_aggregate.alpha}`);
    lines.push(`    β = ${r.verified.recomputed_aggregate.beta}`);
  }
  lines.push('');
  lines.push('═══ B. DECLARADO POR LA AUTORIDAD (NO VERIFICADO CRIPTOGRÁFICAMENTE) ═══');
  if (r.declared.result === null) {
    lines.push('  (sin resultado: el expediente no es legible)');
  } else {
    const { yes, no, n_ballots } = r.declared.result;
    lines.push(`  Resultado anunciado: sí = ${yes}, no = ${no}, total = ${n_ballots}`);
    lines.push(`  Consistencia trivial (0 ≤ sí ≤ total, sí + no = total): ${r.declared.consistent ? 'OK' : 'FALLA'}`);
  }
  for (const n of r.declared.notes) lines.push(`  * ${n}`);
  if (r.receipt !== undefined) {
    lines.push('');
    lines.push(`Recibo ${r.receipt.ballot_hash}: ${r.receipt.found ? 'INCLUIDO en el expediente' : 'NO ENCONTRADO'}`);
  }
  lines.push('');
  lines.push(r.ok ? 'RESULTADO: expediente consistente' : 'RESULTADO: el expediente NO pasa la verificación');
  return lines;
}

export function runCli(argv: readonly string[], io: CliIo): number {
  const args = [...argv];
  const json = args.includes('--json');
  const hashIdx = args.indexOf('--ballot-hash');
  const ballotHash = hashIdx >= 0 ? args[hashIdx + 1] : undefined;
  if (hashIdx >= 0 && (ballotHash === undefined || ballotHash.startsWith('--'))) {
    io.out(USAGE);
    return 2;
  }
  const positional = args.filter((a, i) => !a.startsWith('--') && (hashIdx < 0 || i !== hashIdx + 1));
  const [path] = positional;
  if (path === undefined || positional.length !== 1) {
    io.out(USAGE);
    return 2;
  }

  let input: unknown;
  try {
    input = JSON.parse(io.readFile(path));
  } catch (e) {
    io.out(`No se pudo leer ${path}: ${(e as Error).message}`);
    return 2;
  }

  const report = verifyRecord(input, ballotHash === undefined ? {} : { ballotHash });
  if (json) io.out(JSON.stringify(report, null, 2));
  else formatReport(report).forEach((l) => {
    io.out(l);
  });
  const receiptOk = report.receipt === undefined || report.receipt.found;
  return report.ok && receiptOk ? 0 : 1;
}

// Ejecución directa (no al importarlo desde las pruebas).
if (process.argv[1] !== undefined && resolve(fileURLToPath(import.meta.url)) === resolve(process.argv[1])) {
  process.exitCode = runCli(process.argv.slice(2), {
    readFile: (p) => readFileSync(p, 'utf8'),
    out: (l) => {
      console.log(l);
    },
  });
}
