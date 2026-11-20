import { bytesToHex, constantTimeEqual, generateMacKey, hmacSha256 } from '../../src/crypto/index.js';

describe('HMAC-SHA256', () => {
  it('coincide con el vector de RFC 4231 (caso 1, clave rellenada a 32 bytes)', () => {
    // RFC 4231 caso 1 usa una clave de 20 bytes; HMAC rellena con ceros hasta el bloque,
    // así que la misma clave extendida con ceros a 32 bytes produce el mismo MAC.
    const key = new Uint8Array(32);
    key.fill(0x0b, 0, 20);
    expect(bytesToHex(hmacSha256(key, new TextEncoder().encode('Hi There')))).toBe(
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    );
  });

  it('exige claves de 32 bytes', () => {
    expect(() => hmacSha256(new Uint8Array(16), new Uint8Array())).toThrow(RangeError);
  });

  it('genera claves aleatorias distintas de 32 bytes', () => {
    const a = generateMacKey();
    expect(a).toHaveLength(32);
    expect(bytesToHex(a)).not.toBe(bytesToHex(generateMacKey()));
  });
});

describe('constantTimeEqual', () => {
  it('compara contenido y longitud', () => {
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
  });
});
