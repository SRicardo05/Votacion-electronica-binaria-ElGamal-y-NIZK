/** Regenera test/vectors/or-proof.json. Uso: npm run vectors */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildOrProofVectors } from '../test/helpers/orProofVectors.js';

const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'test', 'vectors', 'or-proof.json');
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, `${JSON.stringify(buildOrProofVectors(), null, 2)}\n`);
console.log(`Vectores escritos en ${out}`);
