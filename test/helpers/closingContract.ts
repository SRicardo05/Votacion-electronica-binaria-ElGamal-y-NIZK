/**
 * Cierre de la elección: escrutinio del agregado y expediente firmado, contra cada backend.
 */
import { buildBallot } from '../../src/client/ballotBuilder.js';
import { type Vote } from '../../src/crypto/index.js';
import { AdminErrorCode, BallotBox, ElectionService, RejectCode } from '../../src/protocol/index.js';
import { AuditRecordSchema } from '../../src/schema/index.js';
import { verifyRecord } from '../../src/verifier/index.js';
import type { Backend } from './ballotBoxContract.js';
import { expectRejection } from './ballotBoxContract.js';
import { runElection } from './electionFixtures.js';

export function describeClosing(name: string, make: () => Backend): void {
  describe(`Cierre y expediente (${name})`, () => {
    let backend: Backend;
    beforeEach(() => {
      backend = make();
    });
    afterEach(() => backend.close?.());

    const votes = (yes: number, no: number): Vote[] => [...Array<Vote>(yes).fill(1), ...Array<Vote>(no).fill(0)];

    it.each([
      ['todos en 0', 0, 6],
      ['todos en 1', 6, 0],
      ['13 sí / 7 no', 13, 7],
      ['elección sin votos', 0, 0],
    ])('%s → resultado declarado exacto y expediente verificable', (_caso, yes, no) => {
      const { record } = runElection(votes(yes, no), { repos: backend.repos });
      expect(record.declared_result).toEqual({ yes, no, n_ballots: yes + no });
      expect(AuditRecordSchema.safeParse(record).success).toBe(true);
      expect(verifyRecord(record).ok).toBe(true);
    });

    it('el expediente lista tokens emitidos y consumidos ordenados, sin MAC', () => {
      const { record, unusedCredentials } = runElection(votes(2, 1), { spare: 2, repos: backend.repos });
      expect(record.tokens.issued).toHaveLength(5);
      expect(record.tokens.consumed).toHaveLength(3);
      expect([...record.tokens.issued].sort()).toEqual(record.tokens.issued);
      const mac = unusedCredentials[0]?.split('.')[1] ?? 'x';
      expect(JSON.stringify(record)).not.toContain(mac);
    });

    it('el expediente no contiene ningún secreto de la autoridad', () => {
      const { record, repos } = runElection(votes(1, 1), { repos: backend.repos });
      const secrets = repos.elections.findSecrets(record.params.election_id);
      const text = JSON.stringify(record);
      for (const s of [secrets?.secretKey, secrets?.macKey, secrets?.signSecretKey]) expect(text).not.toContain(s);
    });

    it('se guarda y se publica idéntico (misma firma) tras el cierre', () => {
      const { record } = runElection(votes(1, 0), { repos: backend.repos });
      const service = new ElectionService(backend.repos);
      expect(service.getRecord(record.params.election_id)).toEqual(record);
    });

    it('después del cierre: no se vota, no se emiten tokens y no se cierra otra vez', () => {
      const repos = backend.repos;
      const service = new ElectionService(repos);
      const params = service.create({ question: '¿?', nMaxVoters: 3 });
      const [c0 = '', c1 = ''] = service.issueTokens(params.election_id, 2);
      const box = new BallotBox(repos);
      expect(box.submit(params.election_id, buildBallot(params, c0, 1)).ok).toBe(true);
      service.close(params.election_id);
      expectRejection(box.submit(params.election_id, buildBallot(params, c1, 1)), 'U0', RejectCode.CLOSED);
      expect(() => service.issueTokens(params.election_id, 1)).toThrow(AdminErrorCode.CLOSED);
      expect(() => service.close(params.election_id)).toThrow(AdminErrorCode.CLOSED);
      expect(service.status(params.election_id).state).toBe('closed');
    });

    it('el expediente no existe antes del cierre', () => {
      const service = new ElectionService(backend.repos);
      const params = service.create({ question: '¿?', nMaxVoters: 3 });
      expect(() => service.getRecord(params.election_id)).toThrow(AdminErrorCode.NOT_CLOSED);
    });
  });
}
