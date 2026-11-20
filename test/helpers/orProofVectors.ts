/**
 * Construcción de los vectores de prueba de la prueba OR (PLAN §2.4).
 * Se usa en dos lugares: `npm run vectors` los escribe en test/vectors/or-proof.json, y la
 * suite de pruebas los regenera y exige que coincidan byte a byte con el archivo versionado.
 */
import {
  G,
  OR_PROOF_DST,
  PROTOCOL_VERSION,
  SUITE_ID,
  type Vote,
  buildOrProofTranscript,
  bytesToHex,
  computeChallenge,
  encodeCiphertextHex,
  encodeOrProofHex,
  encodePointHex,
  encodeScalarHex,
  encryptVote,
  mulSecret,
  proveVote,
} from '../../src/crypto/index.js';
import { deterministicScalars } from './deterministic.js';

export const VECTOR_SEED = 'VOTE-BIN-v1/or-proof-vectors';

export function buildOrProofVectors() {
  const rand = deterministicScalars(VECTOR_SEED);
  const secretKey = rand();
  const publicKey = mulSecret(secretKey, G);
  const electionId = 'eleccion-aula-2026';

  const cases = ([0, 1] as const).map((vote: Vote, i) => {
    const tokenId = i === 0 ? '00112233445566778899aabbccddeeff' : 'ffeeddccbbaa99887766554433221100';
    const ctx = { electionId, tokenId, publicKey };
    const encryption = encryptVote(publicKey, vote, rand());
    const proof = proveVote(ctx, encryption, vote, rand);
    return {
      name: `voto-${vote}`,
      vote,
      token_id: tokenId,
      r: encodeScalarHex(encryption.randomness),
      ciphertext: encodeCiphertextHex(encryption.ciphertext),
      transcript: bytesToHex(buildOrProofTranscript(ctx, encryption.ciphertext, proof)),
      challenge: encodeScalarHex(computeChallenge(ctx, encryption.ciphertext, proof)),
      proof: encodeOrProofHex(proof),
    };
  });

  return {
    description: 'Vectores deterministas de la prueba OR CDS + Fiat–Shamir. Escalares little-endian, puntos Ristretto255.',
    version: PROTOCOL_VERSION,
    suite_id: SUITE_ID,
    dst: OR_PROOF_DST,
    seed: VECTOR_SEED,
    election_id: electionId,
    generator: encodePointHex(G),
    secret_key: encodeScalarHex(secretKey),
    public_key: encodePointHex(publicKey),
    cases,
  };
}

export type OrProofVectors = ReturnType<typeof buildOrProofVectors>;
