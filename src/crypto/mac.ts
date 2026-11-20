/**
 * HMAC-SHA256 (RFC 2104) para autenticar los tokens de votación, y comparación en tiempo constante.
 */
import { randomBytes, timingSafeEqual } from 'node:crypto';

import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

export const MAC_KEY_BYTES = 32;
export const MAC_BYTES = 32;

export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  if (key.length !== MAC_KEY_BYTES) throw new RangeError(`la clave HMAC debe tener ${MAC_KEY_BYTES} bytes`);
  return hmac(sha256, key, message);
}

export function generateMacKey(): Uint8Array {
  return new Uint8Array(randomBytes(MAC_KEY_BYTES));
}

/** Igualdad de bytes en tiempo constante (para MACs: evita filtrar cuántos bytes coinciden). */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}
