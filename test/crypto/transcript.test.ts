import { readFileSync } from 'node:fs';

import {
  G,
  OR_PROOF_DST,
  bytesToHex,
  decodeBallotCiphertextHex,
  decodePointHex,
  encodePoint,
  encryptVote,
  generateKeyPair,
  lengthPrefixed,
  proveVote,
  buildOrProofTranscript,
} from '../../src/crypto/index.js';
import { type OrProofVectors, buildOrProofVectors } from '../helpers/orProofVectors.js';

describe('lengthPrefixed', () => {
  it('antepone la longitud UTF-8 en uint32 big-endian', () => {
    expect(bytesToHex(lengthPrefixed('v1'))).toBe('000000027631');
    expect(bytesToHex(lengthPrefixed(''))).toBe('00000000');
    // "ñ" ocupa 2 bytes en UTF-8: la longitud cuenta bytes, no caracteres.
    expect(bytesToHex(lengthPrefixed('ñ'))).toBe('00000002c3b1');
  });

  it('es inyectivo frente a concatenaciones ambiguas', () => {
    const a = bytesToHex(new Uint8Array([...lengthPrefixed('ab'), ...lengthPrefixed('c')]));
    const b = bytesToHex(new Uint8Array([...lengthPrefixed('a'), ...lengthPrefixed('bc')]));
    expect(a).not.toBe(b);
  });
});

describe('estructura del transcript (PLAN §2.4)', () => {
  const keys = generateKeyPair();
  const ctx = { electionId: 'e1', tokenId: 't1', publicKey: keys.publicKey };
  const enc = encryptVote(keys.publicKey, 1);
  const proof = proveVote(ctx, enc, 1);
  const T = buildOrProofTranscript(ctx, enc.ciphertext, proof);

  it('empieza con el DST de 24 bytes sin prefijo', () => {
    expect(OR_PROOF_DST).toHaveLength(24);
    expect(new TextDecoder().decode(T.slice(0, 24))).toBe(OR_PROOF_DST);
  });

  it('termina con G, H, α, β, A0, B0, A1, B1 (8 × 32 bytes) en ese orden', () => {
    const points = [G, keys.publicKey, enc.ciphertext.alpha, enc.ciphertext.beta, proof.A0, proof.B0, proof.A1, proof.B1];
    const tail = T.slice(T.length - 8 * 32);
    points.forEach((p, i) => {
      expect(bytesToHex(tail.slice(32 * i, 32 * (i + 1)))).toBe(bytesToHex(encodePoint(p)));
    });
  });

  it('tiene la longitud exacta esperada', () => {
    const lp = (s: string) => 4 + new TextEncoder().encode(s).length;
    const expected = 24 + lp('v1') + lp('VOTE-BIN-v1:ristretto255:sha512:hmac-sha256:ed25519') + lp('e1') + lp('t1') + 8 * 32;
    expect(T.length).toBe(expected);
  });
});

describe('vectores de prueba versionados (test/vectors/or-proof.json)', () => {
  const stored = JSON.parse(
    readFileSync(new URL('../vectors/or-proof.json', import.meta.url), 'utf8'),
  ) as OrProofVectors;

  it('la implementación reproduce exactamente los vectores guardados', () => {
    // Si este test falla tras un cambio intencional del formato, hay que subir la versión
    // del protocolo; no basta con regenerar los vectores.
    expect(buildOrProofVectors()).toEqual(stored);
  });

  it('el transcript guardado contiene el ciphertext del caso', () => {
    for (const c of stored.cases) {
      const ct = decodeBallotCiphertextHex(c.ciphertext);
      expect(c.transcript).toContain(bytesToHex(encodePoint(ct.alpha)) + bytesToHex(encodePoint(ct.beta)));
      expect(decodePointHex(stored.public_key).is0()).toBe(false);
    }
  });
});
