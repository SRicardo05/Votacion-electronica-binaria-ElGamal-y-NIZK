import { formatCsv, formatMarkdown, runBenchmarks, stat } from '../../bench/metrics.js';

describe('estadísticas', () => {
  it('mediana y p95 (método nearest-rank)', () => {
    expect(stat([3, 1, 2])).toEqual({ median: 2, p95: 3, samples: 3 });
    expect(stat([4, 1, 3, 2])).toEqual({ median: 2.5, p95: 4, samples: 4 });
    const hundred = Array.from({ length: 100 }, (_, i) => i + 1);
    expect(stat(hundred).p95).toBe(95);
    expect(stat(hundred).median).toBe(50.5);
  });

  it('rechaza una lista vacía', () => {
    expect(() => stat([])).toThrow(RangeError);
  });
});

describe('runBenchmarks', () => {
  const result = runBenchmarks({ sizes: [1, 3], repeats: 2 });

  it('mide cada tamaño con el número de muestras esperado', () => {
    expect(result.results.map((r) => r.n)).toEqual([1, 3]);
    const [one, three] = result.results;
    expect(one?.creationMs.samples).toBe(2); // 1 voto × 2 elecciones
    expect(three?.creationMs.samples).toBe(6); // 3 votos × 2 elecciones
    expect(three?.urnSubmitMs.samples).toBe(6);
    expect(three?.auditMs.samples).toBe(2); // una auditoría por elección
  });

  it('el ballot ocupa 320 bytes en binario y su tamaño JSON no depende de N', () => {
    for (const r of result.results) expect(r.ballotBinaryBytes).toBe(320);
    expect(result.results[0]?.ballotJsonBytes).toBe(result.results[1]?.ballotJsonBytes);
  });

  it('el expediente crece con N y todos los tiempos son positivos', () => {
    const [one, three] = result.results;
    expect(three?.recordJsonBytes).toBeGreaterThan(one?.recordJsonBytes ?? Infinity);
    for (const r of result.results) {
      for (const s of [r.creationMs, r.cryptoVerifyMs, r.urnSubmitMs, r.auditMs]) {
        expect(s.median).toBeGreaterThan(0);
        expect(s.p95).toBeGreaterThanOrEqual(s.median);
      }
    }
  });

  it('formatea la tabla del Entregable 1 y el CSV', () => {
    const md = formatMarkdown(result);
    expect(md).toContain('| N.º de votos | Tamaño de ballot (bytes) | Tiempo de creación (ms) |');
    expect(md).toMatch(/\| 3 \| 320 binario \/ \d+ JSON \|/);
    const csv = formatCsv(result).trim().split('\n');
    expect(csv).toHaveLength(3);
    expect(csv[0]?.split(',')).toHaveLength(14);
  });

  it('valida sus opciones', () => {
    expect(() => runBenchmarks({ sizes: [21], repeats: 1 })).toThrow(RangeError);
    expect(() => runBenchmarks({ sizes: [1], repeats: 0 })).toThrow(RangeError);
  });
});
