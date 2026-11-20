import {
  CryptoErrorCode,
  G,
  IDENTITY,
  type Vote,
  addCiphertexts,
  aggregateCiphertexts,
  decodeBallotCiphertextHex,
  decryptSmall,
  discreteLogSmall,
  encodeCiphertextHex,
  encodePointHex,
  encryptPoint,
  encryptVote,
  generateKeyPair,
  mulPublic,
  mulSecret,
  randomScalar,
  toScalar,
} from '../../src/crypto/index.js';

const MAX_VOTERS = 20;

function expectCode(fn: () => unknown, code: string): void {
  expect(fn).toThrow(expect.objectContaining({ code }) as Error);
}

function randomVotes(n: number): Vote[] {
  return Array.from({ length: n }, () => (Math.random() < 0.5 ? 0 : 1));
}

describe('generación de claves', () => {
  it('H = x·G con x ≠ 0', () => {
    const { secretKey, publicKey } = generateKeyPair();
    expect(secretKey).not.toBe(0n);
    expect(publicKey.equals(mulSecret(secretKey, G))).toBe(true);
  });
});

describe('cifrado de un voto', () => {
  const keys = generateKeyPair();

  it('cumple (α, β) = (r·G, v·G + r·H) con r fijo', () => {
    const r = toScalar(123456789n);
    for (const v of [0, 1] as const) {
      const { ciphertext, randomness } = encryptVote(keys.publicKey, v, r);
      expect(randomness).toBe(r);
      expect(ciphertext.alpha.equals(mulSecret(r, G))).toBe(true);
      const expectedBeta = mulPublic(toScalar(BigInt(v)), G).add(mulSecret(r, keys.publicKey));
      expect(ciphertext.beta.equals(expectedBeta)).toBe(true);
    }
  });

  it.each([0, 1] as const)('Dec(Enc(%d)) = %d', (v) => {
    const { ciphertext } = encryptVote(keys.publicKey, v);
    expect(decryptSmall(keys.secretKey, ciphertext, 1)).toBe(v);
  });

  it('es aleatorizado: dos cifrados del mismo voto difieren', () => {
    const a = encodeCiphertextHex(encryptVote(keys.publicKey, 1).ciphertext);
    const b = encodeCiphertextHex(encryptVote(keys.publicKey, 1).ciphertext);
    expect(a.alpha).not.toBe(b.alpha);
    expect(a.beta).not.toBe(b.beta);
  });

  it('rechaza votos fuera de {0, 1} en tiempo de ejecución', () => {
    expect(() => encryptVote(keys.publicKey, 2 as Vote)).toThrow(RangeError);
  });

  it('rechaza una clave pública identidad', () => {
    expectCode(() => encryptVote(IDENTITY, 1), CryptoErrorCode.IDENTITY);
  });

  it('ElGamal por sí solo NO impide cifrar 2: esa garantía es de la prueba OR', () => {
    const two = mulPublic(toScalar(2n), G);
    const ct = encryptPoint(keys.publicKey, two, randomScalar());
    expect(decryptSmall(keys.secretKey, ct, MAX_VOTERS)).toBe(2);
  });
});

describe('agregación homomórfica', () => {
  const keys = generateKeyPair();
  const tally = (votes: Vote[]): number =>
    decryptSmall(
      keys.secretKey,
      aggregateCiphertexts(votes.map((v) => encryptVote(keys.publicKey, v).ciphertext)),
      votes.length,
    );

  it('Enc(a) + Enc(b) descifra a a + b', () => {
    const sum = addCiphertexts(encryptVote(keys.publicKey, 1).ciphertext, encryptVote(keys.publicKey, 1).ciphertext);
    expect(decryptSmall(keys.secretKey, sum, 2)).toBe(2);
  });

  it('todos los votos en 0 → 0', () => {
    expect(tally(Array<Vote>(MAX_VOTERS).fill(0))).toBe(0);
  });

  it('todos los votos en 1 → 20', () => {
    expect(tally(Array<Vote>(MAX_VOTERS).fill(1))).toBe(MAX_VOTERS);
  });

  it('distribución mixta conocida (13 sí / 7 no) → 13', () => {
    const votes: Vote[] = [...Array<Vote>(13).fill(1), ...Array<Vote>(7).fill(0)];
    expect(tally(votes)).toBe(13);
  });

  it.each([1, 5, 10, 20])('%d votos aleatorios → la suma esperada', (n) => {
    const votes = randomVotes(n);
    expect(tally(votes)).toBe(votes.reduce<number>((a, v) => a + v, 0));
  });

  it('elección sin votos: el agregado vacío descifra a 0', () => {
    expect(tally([])).toBe(0);
  });
});

describe('descifrado acotado', () => {
  const keys = generateKeyPair();

  it('falla con E_TALLY_OUT_OF_RANGE si el total supera la cota', () => {
    const agg = aggregateCiphertexts(
      Array.from({ length: 5 }, () => encryptVote(keys.publicKey, 1).ciphertext),
    );
    expectCode(() => decryptSmall(keys.secretKey, agg, 4), CryptoErrorCode.TALLY_OUT_OF_RANGE);
  });

  it('con una clave equivocada no se obtiene un total válido', () => {
    const other = generateKeyPair();
    const ct = encryptVote(keys.publicKey, 1).ciphertext;
    expectCode(() => decryptSmall(other.secretKey, ct, MAX_VOTERS), CryptoErrorCode.TALLY_OUT_OF_RANGE);
  });

  it('discreteLogSmall valida la cota', () => {
    expect(discreteLogSmall(IDENTITY, 0)).toBe(0);
    expect(() => discreteLogSmall(G, -1)).toThrow(RangeError);
    expect(() => discreteLogSmall(G, 1.5)).toThrow(RangeError);
    expect(() => discreteLogSmall(G, 1_000_000)).toThrow(RangeError);
  });
});

describe('serialización de ciphertexts', () => {
  const keys = generateKeyPair();

  it('hace ida y vuelta', () => {
    const ct = encryptVote(keys.publicKey, 1).ciphertext;
    const decoded = decodeBallotCiphertextHex(encodeCiphertextHex(ct));
    expect(decoded.alpha.equals(ct.alpha)).toBe(true);
    expect(decoded.beta.equals(ct.beta)).toBe(true);
  });

  it('rechaza α = identidad (r = 0 dejaría el voto en claro)', () => {
    const ct = encodeCiphertextHex(encryptVote(keys.publicKey, 1).ciphertext);
    expectCode(
      () => decodeBallotCiphertextHex({ alpha: encodePointHex(IDENTITY), beta: ct.beta }),
      CryptoErrorCode.IDENTITY,
    );
  });

  it('rechaza un β con codificación inválida', () => {
    const ct = encodeCiphertextHex(encryptVote(keys.publicKey, 0).ciphertext);
    expectCode(
      () => decodeBallotCiphertextHex({ alpha: ct.alpha, beta: 'ff'.repeat(32) }),
      CryptoErrorCode.POINT_ENCODING,
    );
  });
});
