/**
 * Fuente de escalares determinista para vectores de prueba reproducibles.
 * NUNCA usar fuera de pruebas: la seguridad de la prueba OR depende de que w, c_f, s_f y r
 * sean impredecibles.
 */
import { type Scalar, type ScalarSource, concatBytes, hashToScalar, lengthPrefixed } from '../../src/crypto/index.js';

export function deterministicScalars(seed: string): ScalarSource {
  let counter = 0;
  return (): Scalar => {
    for (;;) {
      const s = hashToScalar(concatBytes(lengthPrefixed('test-rng'), lengthPrefixed(seed), lengthPrefixed(String(counter++))));
      if (s !== 0n) return s;
    }
  };
}
