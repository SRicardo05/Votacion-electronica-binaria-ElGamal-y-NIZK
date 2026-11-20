/**
 * Construcción del ballot en el cliente: cifra el voto y genera la prueba OR localmente.
 * Solo necesita los parámetros PÚBLICOS y la credencial del votante; nunca ve claves de la autoridad.
 */
import {
  PROTOCOL_VERSION,
  type Vote,
  decodeNonIdentityPointHex,
  encodeCiphertextHex,
  encodeOrProofHex,
  encryptVote,
  proveVote,
} from '../crypto/index.js';
import { type BallotSubmission, type ElectionParams, ElectionParamsSchema } from '../schema/index.js';

/** token_id es la parte de la credencial antes del punto; el MAC no interviene en la prueba. */
function tokenIdOf(credential: string): string {
  const [tokenId = ''] = credential.split('.');
  return tokenId;
}

export function buildBallot(params: ElectionParams, credential: string, vote: Vote): BallotSubmission {
  // Rechaza parámetros con otra versión/suite antes de usar su clave pública.
  const p = ElectionParamsSchema.parse(params);
  const publicKey = decodeNonIdentityPointHex(p.public_key);
  const ctx = { electionId: p.election_id, tokenId: tokenIdOf(credential), publicKey };
  const encryption = encryptVote(publicKey, vote);
  const proof = proveVote(ctx, encryption, vote);
  return {
    version: PROTOCOL_VERSION,
    election_id: p.election_id,
    credential,
    ciphertext: encodeCiphertextHex(encryption.ciphertext),
    proof: encodeOrProofHex(proof),
  };
}
