import { sha512 } from '@noble/hashes/sha2.js';

import { bytesToBigIntLE } from './encoding.js';
import { type Scalar, toScalar } from './group.js';

/**
 * H(T) mod q con SHA-512 (64 bytes interpretados little-endian, como en Ed25519).
 * Con 512 bits el sesgo de la reducción mod q (~2^252) es < 2^-259; con SHA-256 no sería
 * despreciable porque 2^256 ≈ 16·q.
 */
export function hashToScalar(bytes: Uint8Array): Scalar {
  return toScalar(bytesToBigIntLE(sha512(bytes)));
}
