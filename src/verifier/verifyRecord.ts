/**
 * Verificador independiente del expediente (PLAN §5.3).
 *
 * Opera SOLO sobre el expediente publicado: no usa la clave privada, ni la base de datos, ni la red.
 * Importa únicamente las capas `crypto` y `schema` (regla de arquitectura en eslint.config.js).
 *
 * El reporte separa:
 *   A. Lo que se VERIFICA criptográficamente (firma, ballots, pruebas OR, agregado recalculado).
 *   B. Lo que solo DECLARA la autoridad (resultado sí/no y elegibilidad): no verificable con este
 *      expediente, porque no hay prueba de descifrado y los tokens los emite la propia autoridad.
 */
import {
  type CiphertextHex,
  G,
  PROTOCOL_VERSION,
  SUITE_ID,
  aggregateCiphertexts,
  decodeBallotCiphertextHex,
  decodeNonIdentityPointHex,
  decodePointHex,
  encodeCiphertextHex,
  strictHexToBytes,
  verifySignature,
  verifyVoteProofHex,
} from '../crypto/index.js';
import {
  type AuditRecord,
  AuditRecordSchema,
  computeBallotHash,
  recordSignatureBytes,
  recordSigningMessage,
} from '../schema/index.js';

export interface Check {
  readonly id: string;
  readonly description: string;
  readonly ok: boolean;
  /** Detalle de los fallos (vacío si ok). */
  readonly failures: readonly string[];
}

export interface VerificationReport {
  /** A. Verificado criptográficamente. */
  readonly verified: {
    readonly checks: readonly Check[];
    readonly all_ok: boolean;
    /** Agregado recalculado a partir de los ballots publicados (null si no se pudo calcular). */
    readonly recomputed_aggregate: CiphertextHex | null;
    readonly n_ballots: number;
  };
  /** B. Declarado por la autoridad (NO verificado criptográficamente). */
  readonly declared: {
    readonly result: AuditRecord['declared_result'] | null;
    /** Solo consistencia trivial: 0 ≤ sí ≤ n y sí + no = n. */
    readonly consistent: boolean;
    readonly notes: readonly string[];
  };
  /** Comprobación opcional de un recibo (ballot_hash) de votante. */
  readonly receipt?: { readonly ballot_hash: string; readonly found: boolean };
  /** true si todo lo verificable pasa y lo declarado es consistente. */
  readonly ok: boolean;
}

export const DECLARED_NOTES: readonly string[] = [
  'Sin prueba de descifrado (Chaum–Pedersen sobre (G, H, A, B − k·G)), el verificador no puede confirmar que el ' +
    'resultado anunciado corresponde al agregado. La confianza en el descifrado recae en la autoridad.',
  'La elegibilidad no es verificable públicamente: la autoridad emite los tokens y conoce la clave HMAC, así que ' +
    'podría votar con tokens sobrantes sin que este verificador lo detecte.',
];

class CheckList {
  readonly checks: Check[] = [];

  add(id: string, description: string, failures: readonly string[]): boolean {
    this.checks.push({ id, description, ok: failures.length === 0, failures });
    return failures.length === 0;
  }
}

/** Duplicados de una lista (para reportarlos). */
function duplicates(values: readonly string[]): string[] {
  const seen = new Set<string>();
  const dups = new Set<string>();
  for (const v of values) (seen.has(v) ? dups : seen).add(v);
  return [...dups];
}

export interface VerifyOptions {
  /** Recibo de un votante a buscar en el expediente. */
  readonly ballotHash?: string;
}

export function verifyRecord(input: unknown, options: VerifyOptions = {}): VerificationReport {
  const list = new CheckList();

  // ── A1: estructura ──
  const parsed = AuditRecordSchema.safeParse(input);
  list.add('A1', 'El expediente cumple el esquema v1', parsed.success ? [] : [parsed.error.message]);
  if (!parsed.success) return finish(list, null, 0, null, options, []);
  const record = parsed.data;
  const { params, ballots } = record;

  // ── A2: versión y suite ──
  list.add('A2', 'Versión y suite criptográfica esperadas', [
    ...(record.version === PROTOCOL_VERSION ? [] : [`versión ${record.version}`]),
    ...(record.suite_id === SUITE_ID ? [] : [`suite ${record.suite_id}`]),
    ...(params.suite_id === record.suite_id ? [] : ['la suite de params no coincide']),
  ]);

  // ── A3: parámetros ──
  const paramFailures: string[] = [];
  let publicKeyOk = false;
  try {
    if (!decodePointHex(params.generator).equals(G)) paramFailures.push('el generador no es el estándar');
    decodeNonIdentityPointHex(params.public_key);
    publicKeyOk = true;
  } catch (e) {
    paramFailures.push(`clave pública o generador inválidos: ${(e as Error).message}`);
  }
  list.add('A3', 'Parámetros públicos coherentes (generador estándar, clave pública válida)', paramFailures);

  // ── A4: firma ──
  const sig = recordSignatureBytes(record);
  const signPk = strictHexToBytes(params.authority_sign_pk, 32);
  const sigOk = sig !== null && signPk !== null && verifySignature(sig, recordSigningMessage(record), signPk);
  list.add('A4', 'Firma Ed25519 de la autoridad válida sobre el expediente', sigOk ? [] : ['firma inválida']);

  // ── A5: tokens ──
  const { issued, consumed } = record.tokens;
  const issuedSet = new Set(issued);
  list.add('A5', 'Tokens: sin repetidos, consumidos ⊆ emitidos, emitidos ≤ n_max_voters', [
    ...duplicates(issued).map((t) => `token emitido repetido: ${t}`),
    ...duplicates(consumed).map((t) => `token consumido repetido: ${t}`),
    ...consumed.filter((t) => !issuedSet.has(t)).map((t) => `token consumido no emitido: ${t}`),
    ...(issued.length > params.n_max_voters ? [`${issued.length} tokens emitidos > ${params.n_max_voters}`] : []),
  ]);

  // ── A6: integridad de cada ballot ──
  const ballotFailures: string[] = [];
  ballots.forEach((b, i) => {
    if (b.version !== PROTOCOL_VERSION) ballotFailures.push(`ballot #${i}: versión ${b.version}`);
    if (b.election_id !== params.election_id) ballotFailures.push(`ballot #${i}: election_id distinto`);
    if (!issuedSet.has(b.token_id)) ballotFailures.push(`ballot #${i}: token no emitido`);
    if (computeBallotHash(b) !== b.ballot_hash) ballotFailures.push(`ballot #${i}: ballot_hash no coincide con su contenido`);
  });
  for (const t of duplicates(ballots.map((b) => b.token_id))) ballotFailures.push(`token usado en varios ballots: ${t}`);
  for (const h of duplicates(ballots.map((b) => b.ballot_hash))) ballotFailures.push(`ballot_hash repetido: ${h}`);
  for (const c of duplicates(ballots.map((b) => `${b.ciphertext.alpha}:${b.ciphertext.beta}`))) {
    ballotFailures.push(`ciphertext repetido: ${c.slice(0, 16)}…`);
  }
  const ballotTokens = [...ballots.map((b) => b.token_id)].sort();
  if (ballotTokens.join() !== [...consumed].sort().join()) {
    ballotFailures.push('los tokens consumidos no coinciden con los tokens de los ballots publicados');
  }
  list.add('A6', 'Ballots íntegros: hash, elección, token emitido y único, sin duplicados', ballotFailures);

  // ── A7: prueba OR de cada ballot ──
  const proofFailures: string[] = [];
  if (publicKeyOk) {
    const publicKey = decodeNonIdentityPointHex(params.public_key);
    ballots.forEach((b, i) => {
      const result = verifyVoteProofHex({ electionId: params.election_id, tokenId: b.token_id, publicKey }, b.ciphertext, b.proof);
      if (!result.valid) proofFailures.push(`ballot #${i}: ${result.step} ${result.code}`);
    });
  } else {
    proofFailures.push('no se pueden verificar las pruebas sin una clave pública válida');
  }
  list.add('A7', 'Cada ballot tiene una prueba OR válida (cifra 0 o 1)', proofFailures);

  // ── A8: agregado recalculado ──
  let recomputed: CiphertextHex | null = null;
  const aggFailures: string[] = [];
  try {
    recomputed = encodeCiphertextHex(aggregateCiphertexts(ballots.map((b) => decodeBallotCiphertextHex(b.ciphertext))));
    if (recomputed.alpha !== record.aggregate.alpha || recomputed.beta !== record.aggregate.beta) {
      aggFailures.push('el agregado publicado no es la suma de los ballots publicados');
    }
  } catch (e) {
    aggFailures.push(`no se pudo recalcular el agregado: ${(e as Error).message}`);
  }
  list.add('A8', 'Agregado recalculado = agregado publicado', aggFailures);

  // ── A9: conteo ──
  list.add('A9', 'n_ballots declarado = ballots publicados ≤ n_max_voters', [
    ...(record.declared_result.n_ballots === ballots.length
      ? []
      : [`n_ballots declarado ${record.declared_result.n_ballots} ≠ ${ballots.length} publicados`]),
    ...(ballots.length > params.n_max_voters ? [`${ballots.length} ballots > n_max_voters`] : []),
  ]);

  return finish(list, recomputed, ballots.length, record, options, ballots.map((b) => b.ballot_hash));
}

function finish(
  list: CheckList,
  recomputed: CiphertextHex | null,
  nBallots: number,
  record: AuditRecord | null,
  options: VerifyOptions,
  ballotHashes: readonly string[],
): VerificationReport {
  const allOk = list.checks.every((c) => c.ok);
  const result = record?.declared_result ?? null;
  const consistent =
    result !== null && result.yes <= result.n_ballots && result.yes + result.no === result.n_ballots;
  return {
    verified: { checks: list.checks, all_ok: allOk, recomputed_aggregate: recomputed, n_ballots: nBallots },
    declared: { result, consistent, notes: DECLARED_NOTES },
    ...(options.ballotHash === undefined
      ? {}
      : { receipt: { ballot_hash: options.ballotHash, found: ballotHashes.includes(options.ballotHash) } }),
    ok: allOk && consistent,
  };
}
