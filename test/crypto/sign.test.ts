import {
  bytesToHex,
  generateSigningKeyPair,
  signMessage,
  signingPublicKey,
  strictHexToBytes,
  verifySignature,
} from '../../src/crypto/index.js';

const hex = (h: string, n: number): Uint8Array => {
  const b = strictHexToBytes(h, n);
  if (b === null) throw new Error('hex inválido en el vector');
  return b;
};

describe('Ed25519', () => {
  it('coincide con el vector 1 de RFC 8032 (mensaje vacío)', () => {
    const sk = hex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 32);
    const pk = signingPublicKey(sk);
    expect(bytesToHex(pk)).toBe('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a');
    const sig = signMessage(sk, new Uint8Array());
    expect(bytesToHex(sig)).toBe(
      'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
    );
    expect(verifySignature(sig, new Uint8Array(), pk)).toBe(true);
  });

  it('rechaza mensaje alterado, firma alterada y clave equivocada', () => {
    const { secretKey, publicKey } = generateSigningKeyPair();
    const msg = new TextEncoder().encode('expediente');
    const sig = signMessage(secretKey, msg);
    expect(verifySignature(sig, msg, publicKey)).toBe(true);
    expect(verifySignature(sig, new TextEncoder().encode('expedientE'), publicKey)).toBe(false);
    const badSig = sig.slice();
    badSig[0] = (badSig[0] ?? 0) ^ 1;
    expect(verifySignature(badSig, msg, publicKey)).toBe(false);
    expect(verifySignature(sig, msg, generateSigningKeyPair().publicKey)).toBe(false);
  });

  it('devuelve false (sin lanzar) ante longitudes inválidas', () => {
    const { publicKey } = generateSigningKeyPair();
    expect(verifySignature(new Uint8Array(10), new Uint8Array(), publicKey)).toBe(false);
    expect(verifySignature(new Uint8Array(64), new Uint8Array(), new Uint8Array(5))).toBe(false);
  });
});
