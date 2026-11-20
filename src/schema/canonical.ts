/**
 * JSON canónico (RFC 8785, JCS): claves ordenadas, sin espacios, números en forma canónica.
 * Se usa para todo lo que se hashea o firma (ballot_hash, expediente), de modo que cualquier
 * implementación que reciba el mismo objeto obtenga exactamente los mismos bytes.
 */
import canonicalize from 'canonicalize';

export function canonicalJson(value: unknown): string {
  const out = canonicalize(value);
  if (out === undefined) throw new TypeError('canonicalJson: valor no serializable');
  return out;
}

export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalJson(value));
}
