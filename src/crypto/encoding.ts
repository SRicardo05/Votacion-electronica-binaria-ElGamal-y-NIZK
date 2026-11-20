/**
 * Codificación estricta de bytes. Ninguna otra capa manipula hex o bytes crudos:
 * todo dato externo pasa por aquí antes de convertirse en punto o escalar.
 *
 * Regla: hex en minúsculas, sin prefijo "0x", longitud exacta. Cualquier otra forma
 * se rechaza (evita maleabilidad por representaciones alternativas del mismo valor).
 */

const HEX_RE = /^[0-9a-f]*$/;

/** Decodifica hex estricto. Devuelve `null` si el formato no es exactamente el esperado. */
export function strictHexToBytes(hex: string, expectedBytes: number): Uint8Array | null {
  if (hex.length !== expectedBytes * 2 || !HEX_RE.test(hex)) return null;
  const out = new Uint8Array(expectedBytes);
  for (let i = 0; i < expectedBytes; i++) {
    out[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

/** Interpreta bytes como entero little-endian (convención de Ristretto255 para escalares). */
export function bytesToBigIntLE(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i] ?? 0);
  return n;
}

/** Codifica `n` (0 ≤ n < 256^length) como `length` bytes little-endian. */
export function bigIntToBytesLE(n: bigint, length: number): Uint8Array {
  if (n < 0n) throw new RangeError('bigIntToBytesLE: valor negativo');
  const out = new Uint8Array(length);
  let v = n;
  for (let i = 0; i < length; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new RangeError(`bigIntToBytesLE: no cabe en ${length} bytes`);
  return out;
}

/** Concatena arreglos de bytes. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((acc, p) => acc + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}
