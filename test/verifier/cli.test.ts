import { runCli } from '../../src/verifier/index.js';
import { clone, runElection } from '../helpers/electionFixtures.js';

describe('CLI del verificador', () => {
  const { record, receipts } = runElection([1, 0, 1]);
  const files: Record<string, string> = {
    'ok.json': JSON.stringify(record),
    'manipulado.json': JSON.stringify({ ...clone(record), declared_result: { yes: 0, no: 3, n_ballots: 3 } }),
    'roto.json': '{ no es json',
  };

  const run = (...argv: string[]) => {
    const lines: string[] = [];
    const code = runCli(argv, {
      readFile: (p) => {
        const content = files[p];
        if (content === undefined) throw new Error('ENOENT');
        return content;
      },
      out: (l) => lines.push(l),
    });
    return { code, text: lines.join('\n') };
  };

  it('expediente honesto → código 0 y reporte con las secciones A y B separadas', () => {
    const { code, text } = run('ok.json');
    expect(code).toBe(0);
    expect(text).toContain('A. VERIFICADO CRIPTOGRÁFICAMENTE');
    expect(text).toContain('B. DECLARADO POR LA AUTORIDAD (NO VERIFICADO CRIPTOGRÁFICAMENTE)');
    expect(text).toContain(`α = ${record.aggregate.alpha}`);
    expect(text).toContain('Resultado anunciado: sí = 2, no = 1, total = 3');
    expect(text).toContain('RESULTADO: expediente consistente');
  });

  it('expediente manipulado → código 1 e indica la comprobación que falla', () => {
    const { code, text } = run('manipulado.json');
    expect(code).toBe(1);
    expect(text).toContain('[FALLA] A4');
  });

  it('--json produce el reporte estructurado', () => {
    const { code, text } = run('ok.json', '--json');
    expect(code).toBe(0);
    expect((JSON.parse(text) as { ok: boolean }).ok).toBe(true);
  });

  it('--ballot-hash: 0 si el recibo está incluido, 1 si no', () => {
    expect(run('ok.json', '--ballot-hash', receipts[0] ?? '').code).toBe(0);
    const missing = run('ok.json', '--ballot-hash', 'f'.repeat(64));
    expect(missing.code).toBe(1);
    expect(missing.text).toContain('NO ENCONTRADO');
  });

  it.each([
    ['sin argumentos', []],
    ['dos archivos', ['ok.json', 'otro.json']],
    ['--ballot-hash sin valor', ['ok.json', '--ballot-hash']],
  ])('uso incorrecto (%s) → código 2', (_caso, argv) => {
    expect(run(...argv).code).toBe(2);
  });

  it('archivo inexistente o JSON inválido → código 2', () => {
    expect(run('nada.json').code).toBe(2);
    expect(run('roto.json').code).toBe(2);
  });
});
