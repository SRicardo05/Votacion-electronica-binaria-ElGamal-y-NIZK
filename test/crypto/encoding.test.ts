import {
  bigIntToBytesLE,
  bytesToBigIntLE,
  bytesToHex,
  concatBytes,
  strictHexToBytes,
} from '../../src/crypto/index.js';

describe('strictHexToBytes', () => {
  it('decodifica hex en minúsculas con la longitud exacta', () => {
    expect(strictHexToBytes('00ff10', 3)).toEqual(new Uint8Array([0x00, 0xff, 0x10]));
  });

  it.each([
    ['mayúsculas', '00FF10'],
    ['prefijo 0x', '0x00ff'],
    ['longitud corta', '00ff'],
    ['longitud larga', '00ff1000'],
    ['carácter no hex', '00fg10'],
    ['espacios', '00 f10'],
  ])('rechaza %s', (_caso, hex) => {
    expect(strictHexToBytes(hex, 3)).toBeNull();
  });

  it('hace ida y vuelta con bytesToHex', () => {
    const bytes = new Uint8Array([1, 2, 254, 255]);
    expect(strictHexToBytes(bytesToHex(bytes), 4)).toEqual(bytes);
  });
});

describe('enteros little-endian', () => {
  it('codifica y decodifica en little-endian', () => {
    expect(bigIntToBytesLE(0x0102n, 2)).toEqual(new Uint8Array([0x02, 0x01]));
    expect(bytesToBigIntLE(new Uint8Array([0x02, 0x01]))).toBe(0x0102n);
  });

  it('rechaza valores que no caben o negativos', () => {
    expect(() => bigIntToBytesLE(256n, 1)).toThrow(RangeError);
    expect(() => bigIntToBytesLE(-1n, 1)).toThrow(RangeError);
  });
});

describe('concatBytes', () => {
  it('concatena en orden', () => {
    expect(concatBytes(new Uint8Array([1]), new Uint8Array([]), new Uint8Array([2, 3]))).toEqual(
      new Uint8Array([1, 2, 3]),
    );
  });
});
