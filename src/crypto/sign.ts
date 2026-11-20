/**
 * Firmas Ed25519 (RFC 8032) de la autoridad sobre el expediente de la elección.
 * La clave pública de firma se publica en los parámetros ANTES de abrir la votación.
 */
import { ed25519 } from '@noble/curves/ed25519.js';

export const SIGN_SECRET_KEY_BYTES = 32;
export const SIGN_PUBLIC_KEY_BYTES = 32;
export const SIGNATURE_BYTES = 64;

export interface SigningKeyPair {
  readonly secretKey: Uint8Array;
  readonly publicKey: Uint8Array;
}

export function generateSigningKeyPair(): SigningKeyPair {
  const { secretKey, publicKey } = ed25519.keygen();
  return { secretKey, publicKey };
}

export function signingPublicKey(secretKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(secretKey);
}

export function signMessage(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, secretKey);
}

/** Verificación estricta RFC 8032 (sin las reglas permisivas de ZIP-215). Nunca lanza. */
export function verifySignature(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
  if (signature.length !== SIGNATURE_BYTES || publicKey.length !== SIGN_PUBLIC_KEY_BYTES) return false;
  try {
    return ed25519.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}
