import { randomBytes } from 'node:crypto';

import { bytesToBigIntLE } from './encoding.js';
import { type Scalar, toScalar } from './group.js';

/**
 * Escalar uniforme en Z_q \ {0}.
 * Se toman 64 bytes (512 bits) y se reducen mod q: el sesgo es < 2^-259, despreciable.
 */
export function randomScalar(): Scalar {
  for (;;) {
    const s = toScalar(bytesToBigIntLE(randomBytes(64)));
    if (s !== 0n) return s;
  }
}
