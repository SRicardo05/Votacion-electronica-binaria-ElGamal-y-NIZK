import {
  CryptoErrorCode,
  G,
  IDENTITY,
  ORDER,
  type Scalar,
  bytesToHex,
  decodeNonIdentityPointHex,
  decodePointHex,
  decodeScalarHex,
  encodePointHex,
  encodeScalar,
  encodeScalarHex,
  mulPublic,
  mulSecret,
  randomScalar,
  scalarAdd,
  scalarMul,
  scalarSub,
  toScalar,
} from '../../src/crypto/index.js';

/** Afirma que `fn` lanza un CryptoError con el código indicado. */
function expectCode(fn: () => unknown, code: string): void {
  expect(fn).toThrow(expect.objectContaining({ code }) as Error);
}

describe('parámetros del grupo', () => {
  it('el orden es q = 2^252 + 27742317777372353535851937790883648493', () => {
    expect(ORDER).toBe(2n ** 252n + 27742317777372353535851937790883648493n);
  });

  it('q·G es la identidad: (q − 1)·G + G = 0', () => {
    expect(mulSecret(toScalar(ORDER - 1n), G).add(G).equals(IDENTITY)).toBe(true);
  });
});

describe('codificación de puntos (RFC 9496, Apéndice A)', () => {
  // Múltiplos del generador: B·0, B·1, B·2, B·3.
  const multiples = [
    '0000000000000000000000000000000000000000000000000000000000000000',
    'e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76',
    '6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919',
    '94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259',
  ];

  it.each(multiples.map((hex, k) => [k, hex] as const))('k·G con k = %d coincide con el vector', (k, hex) => {
    const p = k === 0 ? IDENTITY : mulSecret(toScalar(BigInt(k)), G);
    expect(encodePointHex(p)).toBe(hex);
    expect(decodePointHex(hex).equals(p)).toBe(true);
  });

  it.each([
    ['codificación de campo no canónica', '00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'],
    ['codificación de campo no canónica (p)', 'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'],
    ['elemento de campo "negativo"', '0100000000000000000000000000000000000000000000000000000000000000'],
    ['bit alto activado', '0000000000000000000000000000000000000000000000000000000000000080'],
    ['punto 1·G con un bit volteado', 'e3f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76'],
  ])('rechaza %s', (_caso, hex) => {
    expectCode(() => decodePointHex(hex), CryptoErrorCode.POINT_ENCODING);
  });

  it.each([
    ['hex en mayúsculas', 'E2F2AE0A6ABC4E71A884A961C500515F58E30B6AA582DD8DB6A65945E08D2D76'],
    ['longitud incorrecta', 'e2f2ae0a'],
    ['cadena vacía', ''],
  ])('rechaza %s', (_caso, hex) => {
    expectCode(() => decodePointHex(hex), CryptoErrorCode.POINT_ENCODING);
  });

  it('decodeNonIdentityPointHex rechaza la identidad', () => {
    expectCode(() => decodeNonIdentityPointHex(multiples[0] ?? ''), CryptoErrorCode.IDENTITY);
    expect(decodeNonIdentityPointHex(multiples[1] ?? '').equals(G)).toBe(true);
  });
});

describe('codificación de escalares', () => {
  it('acepta q − 1 y hace ida y vuelta', () => {
    const s = toScalar(ORDER - 1n);
    expect(decodeScalarHex(encodeScalarHex(s))).toBe(s);
  });

  it('rechaza q y valores mayores (no canónicos)', () => {
    const qHex = bytesToHex(encodeScalar(ORDER as Scalar));
    expectCode(() => decodeScalarHex(qHex), CryptoErrorCode.SCALAR_RANGE);
    expectCode(() => decodeScalarHex('ff'.repeat(32)), CryptoErrorCode.SCALAR_RANGE);
  });

  it('rechaza hex con formato inválido', () => {
    expectCode(() => decodeScalarHex('AB'.repeat(32)), CryptoErrorCode.SCALAR_RANGE);
    expectCode(() => decodeScalarHex('00'.repeat(31)), CryptoErrorCode.SCALAR_RANGE);
  });

  it('la aritmética es módulo q', () => {
    const a = toScalar(ORDER - 1n);
    const one = toScalar(1n);
    expect(scalarAdd(a, one)).toBe(0n);
    expect(scalarSub(toScalar(0n), one)).toBe(ORDER - 1n);
    expect(scalarMul(a, a)).toBe(1n); // (−1)² = 1
    expect(toScalar(-5n)).toBe(ORDER - 5n);
  });
});

describe('multiplicación escalar', () => {
  it('mulSecret y mulPublic coinciden', () => {
    const s = randomScalar();
    expect(mulSecret(s, G).equals(mulPublic(s, G))).toBe(true);
  });

  it('mulPublic admite 0 (escalares enviados por un adversario); mulSecret no', () => {
    expect(mulPublic(toScalar(0n), G).is0()).toBe(true);
    expect(() => mulSecret(toScalar(0n), G)).toThrow(RangeError);
  });

  it('distributividad: (a + b)·G = a·G + b·G', () => {
    const a = randomScalar();
    const b = randomScalar();
    expect(mulPublic(scalarAdd(a, b), G).equals(mulSecret(a, G).add(mulSecret(b, G)))).toBe(true);
  });
});

describe('randomScalar', () => {
  it('produce escalares en [1, q) y distintos entre sí', () => {
    const seen = new Set<bigint>();
    for (let i = 0; i < 50; i++) {
      const s = randomScalar();
      expect(s > 0n && s < ORDER).toBe(true);
      seen.add(s);
    }
    expect(seen.size).toBe(50);
  });
});
