/**
 * Urna: valida y almacena ballots siguiendo los pasos U0–U5 (PLAN §4).
 *
 *   U0  formato del mensaje, versión, elección existente y abierta
 *   U1  decodificación estricta de puntos y escalares (V1–V2)
 *   U2  token: formato → MAC → emitido → no consumido
 *   U3  prueba OR atada a (elección, token, clave pública) (V3–V5)
 *   U4  no duplicado: ballot_hash nuevo y (α, β) no aceptado antes
 *   U5  transacción: consumir token + guardar ballot (todo o nada)
 *
 * Un reenvío exacto de un ballot aceptado se rechaza ya en U2 (E_TOKEN_USED), porque su token
 * quedó consumido; U4 es una segunda barrera (p. ej. el mismo (α, β) re-probado con otro token).
 */
import { decodeBallotHex, decodeNonIdentityPointHex, verifyVoteProof } from '../crypto/index.js';
import { type BallotCore, BallotSubmissionSchema, type StoredBallot, computeBallotHash } from '../schema/index.js';
import { macKeyOf } from './election.js';
import { type Outcome, RejectCode, type Rejection, accept, reject } from './errors.js';
import {
  type BallotRepository,
  type Clock,
  type ElectionRepository,
  type RejectionLog,
  type TokenRepository,
  type TransactionRunner,
  systemClock,
} from './ports.js';
import { TokenService } from './tokens.js';

export interface BallotBoxDeps {
  readonly elections: ElectionRepository;
  readonly tokens: TokenRepository;
  readonly ballots: BallotRepository;
  readonly transactions: TransactionRunner;
  readonly rejections: RejectionLog;
  readonly clock?: Clock;
}

/** Recibo que se devuelve al votante: con `ballot_hash` puede comprobar luego que su voto está en el expediente. */
export interface Receipt {
  readonly election_id: string;
  readonly ballot_hash: string;
  readonly received_at: string;
}

/** Señal interna para deshacer la transacción de U5 cuando falla una unicidad. */
class AbortU5 extends Error {
  constructor(readonly rejection: Rejection) {
    super(rejection.code);
  }
}

export class BallotBox {
  private readonly deps: BallotBoxDeps;
  private readonly clock: Clock;

  constructor(deps: BallotBoxDeps) {
    this.deps = deps;
    this.clock = deps.clock ?? systemClock;
  }

  /** `electionId` viene de la ruta; `body` es el JSON recibido, sin validar. */
  submit(electionId: string, body: unknown): Outcome<Receipt> {
    const outcome = this.validateAndStore(electionId, body);
    if (!outcome.ok) {
      const known = this.deps.elections.find(electionId) !== undefined;
      this.deps.rejections.record(known ? electionId : null, outcome.rejection, this.clock().toISOString());
    }
    return outcome;
  }

  private validateAndStore(electionId: string, body: unknown): Outcome<Receipt> {
    const { elections, ballots } = this.deps;

    // ── U0: formato y estado ──
    const parsed = BallotSubmissionSchema.safeParse(body);
    if (!parsed.success) {
      return reject('U0', RejectCode.FORMAT, 'el mensaje no cumple el esquema del ballot');
    }
    const sub = parsed.data;
    if (sub.version !== 'v1') return reject('U0', RejectCode.VERSION, `versión no soportada: ${sub.version}`);
    if (sub.election_id !== electionId) {
      return reject('U0', RejectCode.ELECTION, 'election_id del ballot no coincide con la elección');
    }
    const election = elections.find(electionId);
    if (election === undefined) return reject('U0', RejectCode.ELECTION, 'la elección no existe');
    if (election.state !== 'open') return reject('U0', RejectCode.CLOSED, 'la elección está cerrada');

    // ── U1: decodificación estricta ──
    const decoded = decodeBallotHex(sub.ciphertext, sub.proof);
    if (!decoded.ok) return reject('U1', decoded.code, decoded.reason);

    // ── U2: token ──
    const tokens = this.tokenService(electionId);
    const token = tokens.check(electionId, sub.credential);
    if (!token.ok) return token;
    const tokenId = token.value;

    // ── U3: prueba OR atada al contexto ──
    const ctx = { electionId, tokenId, publicKey: decodeNonIdentityPointHex(election.params.public_key) };
    const verification = verifyVoteProof(ctx, decoded.ciphertext, decoded.proof);
    if (!verification.valid) return reject('U3', verification.code, verification.reason);

    // ── U4: duplicados ──
    const core: BallotCore = {
      version: sub.version,
      election_id: electionId,
      token_id: tokenId,
      ciphertext: sub.ciphertext,
      proof: sub.proof,
    };
    const ballotHash = computeBallotHash(core);
    if (ballots.hasBallotHash(electionId, ballotHash)) {
      return reject('U4', RejectCode.REPLAY, 'este ballot ya fue aceptado');
    }
    if (ballots.hasCiphertext(electionId, sub.ciphertext.alpha, sub.ciphertext.beta)) {
      return reject('U4', RejectCode.DUP_CIPHERTEXT, 'este ciphertext ya fue aceptado con otro token');
    }

    // ── U5: consumo del token + almacenamiento, atómicos ──
    const stored: StoredBallot = { ...core, received_at: this.clock().toISOString(), ballot_hash: ballotHash };
    try {
      this.deps.transactions.runInTransaction(() => {
        if (elections.find(electionId)?.state !== 'open') {
          throw new AbortU5({ step: 'U5', code: RejectCode.CLOSED, reason: 'la elección se cerró durante el envío' });
        }
        const consumed = tokens.consume(electionId, tokenId);
        if (!consumed.ok) throw new AbortU5(consumed.rejection);
        if (ballots.insert(stored) === 'duplicate') {
          throw new AbortU5({ step: 'U5', code: RejectCode.DUP_CIPHERTEXT, reason: 'otro envío concurrente ganó la carrera' });
        }
      });
    } catch (e) {
      if (e instanceof AbortU5) return { ok: false, rejection: e.rejection };
      throw e;
    }

    return accept({ election_id: electionId, ballot_hash: ballotHash, received_at: stored.received_at });
  }

  private tokenService(electionId: string): TokenService {
    return new TokenService({
      tokens: this.deps.tokens,
      transactions: this.deps.transactions,
      macKey: macKeyOf(this.deps.elections, electionId),
      clock: this.clock,
    });
  }
}
