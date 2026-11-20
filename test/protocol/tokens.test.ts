import { generateMacKey } from '../../src/crypto/index.js';
import { computeTokenMac, formatCredential, parseCredential } from '../../src/protocol/index.js';
import { InMemoryTokenRepository, InMemoryTransactionRunner } from '../helpers/inMemoryRepositories.js';
import { describeTokenRepositoryContract, describeTokenService } from '../helpers/tokenContract.js';

const memoryBackend = () => {
  const tokens = new InMemoryTokenRepository();
  return { tokens, transactions: new InMemoryTransactionRunner([tokens]) };
};

describeTokenRepositoryContract('memoria', memoryBackend);
describeTokenService('memoria', memoryBackend);

describe('formato de credencial', () => {
  it('formatCredential y parseCredential son inversas', () => {
    const c = { tokenId: 'ab'.repeat(16), mac: 'cd'.repeat(32) };
    expect(parseCredential(formatCredential(c))).toEqual(c);
  });

  it('el MAC depende de la clave, la elección y el token', () => {
    const k = generateMacKey();
    const base = computeTokenMac(k, 'e', 't');
    expect(computeTokenMac(k, 'e', 't')).toEqual(base);
    expect(computeTokenMac(generateMacKey(), 'e', 't')).not.toEqual(base);
    expect(computeTokenMac(k, 'e2', 't')).not.toEqual(base);
    expect(computeTokenMac(k, 'e', 't2')).not.toEqual(base);
    // Prefijos de longitud: ("ab","c") y ("a","bc") no colisionan.
    expect(computeTokenMac(k, 'ab', 'c')).not.toEqual(computeTokenMac(k, 'a', 'bc'));
  });
});
