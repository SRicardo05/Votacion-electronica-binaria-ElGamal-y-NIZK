/**
 * El expediente de ejemplo citado en docs/ENTREGA2.md §5 debe seguir verificando con el código actual
 * (si cambia el formato, hay que regenerarlo con `npm run demo -- --out docs/ejemplo/expediente.json`).
 */
import { readFileSync } from 'node:fs';

import { verifyRecord } from '../../src/verifier/index.js';

describe('expediente de ejemplo de la documentación', () => {
  const record: unknown = JSON.parse(
    readFileSync(new URL('../../docs/ejemplo/expediente.json', import.meta.url), 'utf8'),
  );

  it('verifica y coincide con los valores citados en ENTREGA2.md', () => {
    const report = verifyRecord(record);
    expect(report.ok).toBe(true);
    expect(report.verified.recomputed_aggregate).toEqual({
      alpha: '5e67ea79e4a13dcbcb2b09b67df519bb6759386949018e7874630e3ab67d922f',
      beta: 'b0ef019417923e7e458721ddb8a906e0e2949e7b31df4d5fc3286a442b986a06',
    });
    expect(report.declared.result).toEqual({ yes: 13, no: 7, n_ballots: 20 });
  });
});
