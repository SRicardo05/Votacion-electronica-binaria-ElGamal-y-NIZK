import { BallotSubmissionSchema, canonicalJson, computeBallotHash } from '../../src/schema/index.js';

const proof = { A0: 'a', B0: 'b', A1: 'c', B1: 'd', c0: 'e', c1: 'f', s0: 'g', s1: 'h' };
const core = { version: 'v1', election_id: 'e', token_id: 't', ciphertext: { alpha: 'x', beta: 'y' }, proof };

describe('JSON canónico (RFC 8785)', () => {
  it('ordena claves y elimina espacios', () => {
    expect(canonicalJson({ b: 1, a: { d: 'x', c: [2, 1] } })).toBe('{"a":{"c":[2,1],"d":"x"},"b":1}');
  });

  it('rechaza valores no serializables', () => {
    expect(() => canonicalJson(undefined)).toThrow(TypeError);
  });
});

describe('computeBallotHash', () => {
  it('no depende del orden de las claves', () => {
    const reordered = { proof, ciphertext: { beta: 'y', alpha: 'x' }, token_id: 't', election_id: 'e', version: 'v1' };
    expect(computeBallotHash(reordered)).toBe(computeBallotHash(core));
  });

  it('ignora campos que no forman parte del núcleo (p. ej. received_at)', () => {
    expect(computeBallotHash({ ...core, received_at: 'ahora', ballot_hash: 'z' } as typeof core)).toBe(computeBallotHash(core));
  });

  it('cambia si cambia cualquier campo del núcleo', () => {
    const h = computeBallotHash(core);
    expect(computeBallotHash({ ...core, token_id: 'u' })).not.toBe(h);
    expect(computeBallotHash({ ...core, proof: { ...proof, s1: 'i' } })).not.toBe(h);
  });
});

describe('BallotSubmissionSchema', () => {
  const valid = { version: 'v1', election_id: 'e', credential: 'c', ciphertext: core.ciphertext, proof };

  it('acepta la estructura exacta', () => {
    expect(BallotSubmissionSchema.safeParse(valid).success).toBe(true);
  });

  it.each([
    ['campo extra en la raíz', { ...valid, extra: 1 }],
    ['campo extra en la prueba', { ...valid, proof: { ...proof, z: 'z' } }],
    ['tipo incorrecto', { ...valid, version: 1 }],
    ['campo hex demasiado largo', { ...valid, ciphertext: { alpha: 'a'.repeat(129), beta: 'y' } }],
  ])('rechaza %s', (_caso, body) => {
    expect(BallotSubmissionSchema.safeParse(body).success).toBe(false);
  });
});
