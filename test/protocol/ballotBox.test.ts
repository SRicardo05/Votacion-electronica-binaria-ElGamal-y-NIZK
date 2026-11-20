import { buildBallot } from '../../src/client/ballotBuilder.js';
import { BallotBox, ElectionService, RejectCode } from '../../src/protocol/index.js';
import { describeBallotBox, expectRejection } from '../helpers/ballotBoxContract.js';
import { describeClosing } from '../helpers/closingContract.js';
import { createInMemoryRepositories } from '../helpers/inMemoryRepositories.js';

describeBallotBox('memoria', () => {
  const repos = createInMemoryRepositories();
  return {
    repos,
    rejectionsLogged: () => repos.rejections.entries.map((e) => ({ ...e.rejection })),
  };
});

describe('U5 — atomicidad (solo con dobles en memoria: simula carreras)', () => {
  it('si la inserción del ballot choca con una unicidad, U5 rechaza y el consumo del token se deshace', () => {
    const repos = createInMemoryRepositories();
    const elections = new ElectionService(repos);
    const params = elections.create({ question: '¿?', nMaxVoters: 3 });
    const [c0 = ''] = elections.issueTokens(params.election_id, 1);
    const tokenId = c0.split('.')[0] ?? '';

    // Simula que una solicitud concurrente guardó un ballot conflictivo justo después de U4:
    // las comprobaciones de U4 no lo ven y la inserción de U5 lo reporta como duplicado.
    const racyBallots = Object.assign(Object.create(repos.ballots) as typeof repos.ballots, {
      hasCiphertext: () => false,
      hasBallotHash: () => false,
      insert: () => 'duplicate' as const,
    });
    const box = new BallotBox({ ...repos, ballots: racyBallots });

    expectRejection(box.submit(params.election_id, buildBallot(params, c0, 1)), 'U5', RejectCode.DUP_CIPHERTEXT);
    expect(repos.tokens.find(params.election_id, tokenId)?.consumedAt).toBeNull();
  });

  it('si la elección se cierra entre U0 y U5, el ballot se rechaza en U5 y el token no se consume', () => {
    const repos = createInMemoryRepositories();
    const elections = new ElectionService(repos);
    const params = elections.create({ question: '¿?', nMaxVoters: 3 });
    const [c0 = ''] = elections.issueTokens(params.election_id, 1);

    let calls = 0;
    const closingElections = Object.assign(Object.create(repos.elections) as typeof repos.elections, {
      find: (eid: string) => {
        calls += 1;
        // La 2.ª consulta (dentro de la transacción de U5) ve la elección ya cerrada.
        if (calls === 2) repos.elections.markClosed(eid, new Date().toISOString());
        return repos.elections.find(eid);
      },
    });
    const box = new BallotBox({ ...repos, elections: closingElections });
    expectRejection(box.submit(params.election_id, buildBallot(params, c0, 1)), 'U5', RejectCode.CLOSED);
    expect(repos.tokens.find(params.election_id, c0.split('.')[0] ?? '')?.consumedAt).toBeNull();
  });
});

describeClosing('memoria', () => {
  const repos = createInMemoryRepositories();
  return { repos, rejectionsLogged: () => repos.rejections.entries.map((e) => ({ ...e.rejection })) };
});
