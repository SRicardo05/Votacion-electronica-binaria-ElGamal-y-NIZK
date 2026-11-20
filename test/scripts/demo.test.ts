import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { runDemo } from '../../scripts/demo.js';
import { verifyRecord } from '../../src/verifier/index.js';

describe('demo de extremo a extremo', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'voto-demo-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('vota, rechaza los ataques en el paso esperado, cierra y el expediente guardado verifica', async () => {
    const out = join(dir, 'expediente.json');
    const lines: string[] = [];
    const summary = await runDemo({ voters: 5, yes: 3, out, db: ':memory:' }, (l) => lines.push(l));

    expect(summary.declared).toEqual({ yes: 3, no: 2, n_ballots: 5 });
    expect(summary.attacks.map((a) => [a.step, a.code])).toEqual([
      ['U2', 'E_TOKEN_MAC'],
      ['U3', 'E_PROOF_EQ_0'],
      ['U2', 'E_TOKEN_USED'],
    ]);
    expect(summary.verifierOk).toBe(true);
    expect(summary.receiptIncluded).toBe(true);
    expect(verifyRecord(JSON.parse(readFileSync(out, 'utf8'))).ok).toBe(true);
    expect(lines.join('\n')).toContain('B. DECLARADO POR LA AUTORIDAD');
  });

  it('valida sus opciones', async () => {
    const opts = { out: join(dir, 'x.json'), db: ':memory:' };
    await expect(runDemo({ ...opts, voters: 21, yes: 1 }, () => undefined)).rejects.toThrow(RangeError);
    await expect(runDemo({ ...opts, voters: 3, yes: 4 }, () => undefined)).rejects.toThrow(RangeError);
  });
});
