/**
 * Identificadores fijos de la suite criptográfica (PLAN §0). Cualquier cambio en grupo, hash,
 * MAC, firma o formato del transcript exige una nueva versión: no se reinterpretan datos v1.
 */
export const PROTOCOL_VERSION = 'v1';

export const SUITE_ID = 'VOTE-BIN-v1:ristretto255:sha512:hmac-sha256:ed25519';

/** Etiqueta de separación de dominio del transcript de la prueba OR (24 bytes ASCII). */
export const OR_PROOF_DST = 'VOTE-BIN-v1/cds-or-proof';
