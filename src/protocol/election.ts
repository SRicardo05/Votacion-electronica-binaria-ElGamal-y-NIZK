/**
 * Operaciones de la autoridad electoral: crear la elección (claves + parámetros públicos),
 * emitir tokens y consultar el estado. El cierre y el escrutinio llegan en la fase 6.
 */
import { randomBytes } from 'node:crypto';

import {
  G,
  PROTOCOL_VERSION,
  SUITE_ID,
  bytesToHex,
  encodePointHex,
  encodeScalarHex,
  generateKeyPair,
  generateMacKey,
  generateSigningKeyPair,
  strictHexToBytes,
} from '../crypto/index.js';
import { type ElectionParams, ElectionParamsSchema, MAX_VOTERS, OPTIONS } from '../schema/index.js';
import { AdminError, AdminErrorCode } from './errors.js';
import {
  type BallotRepository,
  type Clock,
  type ElectionRecord,
  type ElectionRepository,
  type ElectionState,
  type TokenRepository,
  type TransactionRunner,
  systemClock,
} from './ports.js';
import { TokenService } from './tokens.js';

export interface ElectionServiceDeps {
  readonly elections: ElectionRepository;
  readonly tokens: TokenRepository;
  readonly ballots: BallotRepository;
  readonly transactions: TransactionRunner;
  readonly clock?: Clock;
}

export interface CreateElectionInput {
  readonly question: string;
  readonly nMaxVoters: number;
}

export interface ElectionStatus {
  readonly election_id: string;
  readonly state: ElectionState;
  readonly n_max_voters: number;
  readonly n_tokens_issued: number;
  readonly n_tokens_consumed: number;
  readonly n_ballots: number;
}

/** Recupera la clave HMAC de una elección (la usan ElectionService y BallotBox). */
export function macKeyOf(elections: ElectionRepository, electionId: string): Uint8Array {
  const hex = elections.findSecrets(electionId)?.macKey;
  const key = hex === undefined ? null : strictHexToBytes(hex, 32);
  if (key === null) throw new Error(`secretos de la elección ${electionId} ausentes o corruptos`);
  return key;
}

export class ElectionService {
  private readonly deps: ElectionServiceDeps;
  private readonly clock: Clock;

  constructor(deps: ElectionServiceDeps) {
    this.deps = deps;
    this.clock = deps.clock ?? systemClock;
  }

  /** Genera claves (ElGamal, HMAC, Ed25519), publica los parámetros y abre la elección. */
  create(input: CreateElectionInput): ElectionParams {
    const question = input.question.trim();
    if (question.length === 0 || question.length > 500) {
      throw new AdminError(AdminErrorCode.INVALID_INPUT, 'la pregunta debe tener entre 1 y 500 caracteres');
    }
    if (!Number.isInteger(input.nMaxVoters) || input.nMaxVoters < 1 || input.nMaxVoters > MAX_VOTERS) {
      throw new AdminError(AdminErrorCode.INVALID_INPUT, `n_max_voters debe ser un entero en [1, ${MAX_VOTERS}]`);
    }

    const elgamal = generateKeyPair();
    const signing = generateSigningKeyPair();
    const electionId = bytesToHex(randomBytes(16));

    // El parse valida que construimos exactamente el formato publicado.
    const params = ElectionParamsSchema.parse({
      version: PROTOCOL_VERSION,
      suite_id: SUITE_ID,
      election_id: electionId,
      question,
      options: [...OPTIONS],
      n_max_voters: input.nMaxVoters,
      generator: encodePointHex(G),
      public_key: encodePointHex(elgamal.publicKey),
      authority_sign_pk: bytesToHex(signing.publicKey),
      opened_at: this.clock().toISOString(),
    } satisfies ElectionParams);

    this.deps.transactions.runInTransaction(() => {
      this.deps.elections.insert(params, {
        electionId,
        secretKey: encodeScalarHex(elgamal.secretKey),
        macKey: bytesToHex(generateMacKey()),
        signSecretKey: bytesToHex(signing.secretKey),
      });
    });
    return params;
  }

  getParams(electionId: string): ElectionParams | undefined {
    return this.deps.elections.find(electionId)?.params;
  }

  /** Emite `count` tokens, sin superar n_max_voters en total. Devuelve las credenciales (una sola vez). */
  issueTokens(electionId: string, count: number): string[] {
    return this.deps.transactions.runInTransaction(() => {
      const election = this.requireOpen(electionId);
      if (!Number.isInteger(count) || count < 1) {
        throw new AdminError(AdminErrorCode.INVALID_INPUT, 'count debe ser un entero ≥ 1');
      }
      const issued = this.deps.tokens.listByElection(electionId).length;
      if (issued + count > election.params.n_max_voters) {
        throw new AdminError(
          AdminErrorCode.TOKEN_LIMIT,
          `ya hay ${issued} tokens emitidos; el máximo es ${election.params.n_max_voters}`,
        );
      }
      return this.tokenService(electionId).issue(electionId, count);
    });
  }

  status(electionId: string): ElectionStatus {
    const election = this.requireExisting(electionId);
    const tokens = this.deps.tokens.listByElection(electionId);
    return {
      election_id: electionId,
      state: election.state,
      n_max_voters: election.params.n_max_voters,
      n_tokens_issued: tokens.length,
      n_tokens_consumed: tokens.filter((t) => t.consumedAt !== null).length,
      n_ballots: this.deps.ballots.count(electionId),
    };
  }

  private tokenService(electionId: string): TokenService {
    return new TokenService({
      tokens: this.deps.tokens,
      transactions: this.deps.transactions,
      macKey: macKeyOf(this.deps.elections, electionId),
      clock: this.clock,
    });
  }

  private requireExisting(electionId: string): ElectionRecord {
    const election = this.deps.elections.find(electionId);
    if (election === undefined) throw new AdminError(AdminErrorCode.ELECTION, 'la elección no existe');
    return election;
  }

  private requireOpen(electionId: string): ElectionRecord {
    const election = this.requireExisting(electionId);
    if (election.state !== 'open') throw new AdminError(AdminErrorCode.CLOSED, 'la elección está cerrada');
    return election;
  }
}
