/**
 * Interfaz HTTP. Las rutas solo traducen HTTP ↔ protocolo: validan la forma de la entrada,
 * delegan en ElectionService / BallotBox y mapean los códigos de rechazo a estados HTTP.
 *
 *   POST /admin/elections                 (admin)  crear elección → parámetros públicos
 *   POST /admin/elections/:id/tokens      (admin)  emitir tokens → credenciales
 *   POST /admin/elections/:id/close       (admin)  cerrar, escrutar y publicar el expediente firmado
 *   GET  /elections/:id/params                     parámetros públicos
 *   GET  /elections/:id/status                     conteos (sin ballots individuales)
 *   POST /elections/:id/ballots                    enviar ballot → recibo
 *   GET  /elections/:id/record                     expediente firmado (tras el cierre)
 */
import express, { type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';

import { constantTimeEqual } from '../crypto/index.js';
import { AdminError, AdminErrorCode, type BallotBox, type ElectionService, RejectCode } from '../protocol/index.js';

export interface AppDeps {
  readonly elections: ElectionService;
  readonly ballotBox: BallotBox;
  /** Clave de las rutas de administración (cabecera `Authorization: Bearer <clave>`). */
  readonly adminApiKey: string;
}

const CreateElectionBody = z.strictObject({
  question: z.string().min(1).max(500),
  n_max_voters: z.number().int(),
});

const IssueTokensBody = z.strictObject({ count: z.number().int() });

/** Código de rechazo → estado HTTP. */
export function httpStatusFor(code: string): number {
  switch (code) {
    case RejectCode.ELECTION:
      return 404;
    case RejectCode.CLOSED:
    case AdminErrorCode.NOT_CLOSED:
    case RejectCode.TOKEN_USED:
    case RejectCode.REPLAY:
    case RejectCode.DUP_CIPHERTEXT:
    case AdminErrorCode.TOKEN_LIMIT:
      return 409;
    case RejectCode.TOKEN_FORMAT:
    case RejectCode.TOKEN_MAC:
    case RejectCode.TOKEN_UNKNOWN:
      return 403;
    case RejectCode.FORMAT:
    case RejectCode.VERSION:
    case AdminErrorCode.INVALID_INPUT:
      return 400;
    default:
      // U1 (codificación) y U3 (prueba): el mensaje está bien formado pero no es válido.
      return 422;
  }
}

function requireAdmin(apiKey: string) {
  const expected = new TextEncoder().encode(apiKey);
  return (req: Request, res: Response, next: NextFunction): void => {
    const header = req.get('authorization') ?? '';
    const given = new TextEncoder().encode(header.startsWith('Bearer ') ? header.slice(7) : '');
    if (!constantTimeEqual(given, expected)) {
      res.status(401).json({ error: 'E_UNAUTHORIZED' });
      return;
    }
    next();
  };
}

/** `:id` de la ruta como string (Express 5 lo tipa como string | string[]). */
function electionIdParam(req: Request): string {
  const id: unknown = req.params.id;
  return typeof id === 'string' ? id : '';
}

function sendAdminError(res: Response, e: unknown): void {
  if (e instanceof AdminError) {
    res.status(httpStatusFor(e.code)).json({ error: e.code, message: e.message });
    return;
  }
  throw e;
}

export function createApp(deps: AppDeps): express.Express {
  if (deps.adminApiKey.length < 16) throw new Error('adminApiKey debe tener al menos 16 caracteres');
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '16kb', strict: true }));

  const admin = requireAdmin(deps.adminApiKey);

  // ── Administración ──
  app.post('/admin/elections', admin, (req, res) => {
    const body = CreateElectionBody.safeParse(req.body);
    if (!body.success) {
      res.status(400).json({ error: AdminErrorCode.INVALID_INPUT });
      return;
    }
    try {
      const params = deps.elections.create({ question: body.data.question, nMaxVoters: body.data.n_max_voters });
      res.status(201).json(params);
    } catch (e) {
      sendAdminError(res, e);
    }
  });

  app.post('/admin/elections/:id/tokens', admin, (req, res) => {
    const body = IssueTokensBody.safeParse(req.body);
    if (!body.success) {
      res.status(400).json({ error: AdminErrorCode.INVALID_INPUT });
      return;
    }
    try {
      const credentials = deps.elections.issueTokens(electionIdParam(req), body.data.count);
      res.status(201).json({ election_id: electionIdParam(req), credentials });
    } catch (e) {
      sendAdminError(res, e);
    }
  });

  app.post('/admin/elections/:id/close', admin, (req, res) => {
    try {
      res.status(200).json(deps.elections.close(electionIdParam(req)));
    } catch (e) {
      sendAdminError(res, e);
    }
  });

  // ── Público ──
  app.get('/elections/:id/record', (req, res) => {
    try {
      res.json(deps.elections.getRecord(electionIdParam(req)));
    } catch (e) {
      sendAdminError(res, e);
    }
  });

  app.get('/elections/:id/params', (req, res) => {
    const params = deps.elections.getParams(electionIdParam(req));
    if (params === undefined) {
      res.status(404).json({ error: RejectCode.ELECTION });
      return;
    }
    res.json(params);
  });

  app.get('/elections/:id/status', (req, res) => {
    try {
      res.json(deps.elections.status(electionIdParam(req)));
    } catch (e) {
      sendAdminError(res, e);
    }
  });

  app.post('/elections/:id/ballots', (req, res) => {
    const outcome = deps.ballotBox.submit(electionIdParam(req), req.body);
    if (outcome.ok) {
      res.status(201).json({ accepted: true, ...outcome.value });
      return;
    }
    // Al cliente: paso y código, sin el detalle interno (queda en el registro de rechazos).
    const { step, code } = outcome.rejection;
    res.status(httpStatusFor(code)).json({ accepted: false, step, code });
  });

  // ── Errores ──
  app.use((_req, res) => {
    res.status(404).json({ error: 'E_NOT_FOUND' });
  });

  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const type = (err as { type?: unknown } | null)?.type;
    if (type === 'entity.parse.failed') {
      res.status(400).json({ accepted: false, step: 'U0', code: RejectCode.FORMAT });
      return;
    }
    if (type === 'entity.too.large') {
      res.status(413).json({ accepted: false, step: 'U0', code: RejectCode.FORMAT });
      return;
    }
    console.error(err);
    res.status(500).json({ error: 'E_INTERNAL' });
  });

  return app;
}
