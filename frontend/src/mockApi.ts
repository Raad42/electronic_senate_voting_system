import type { AuditEvent, BallotConfig, BallotSubmission, ElectorAuthorisation, OfficialSession } from '../types/api'

// Legacy dummy API kept for older prototype files; it does not call the backend.
const wait = (milliseconds = 300) => new Promise((resolve) => setTimeout(resolve, milliseconds))

export const mockApi = {
  async obtainElectorAuthorisation(state: string): Promise<ElectorAuthorisation> {
    await wait()
    return {
      authorisationToken: 'demo-single-use-capability',
      state,
      expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
    }
  },

  async getBallotConfig(state: string, electionId: string): Promise<BallotConfig> {
    await wait()
    return {
      state,
      electionId,
      configurationVersion: 'cfg-2026-03',
      candidates: [
        { candidateId: 'CAND-041', displayName: 'Candidate 041', party: 'Party A' },
        { candidateId: 'CAND-052', displayName: 'Candidate 052', party: 'Party B' },
        { candidateId: 'CAND-063', displayName: 'Candidate 063', party: 'Party C' },
      ],
    }
  },

  async submitBallot(): Promise<BallotSubmission> {
    await wait(600)
    return {
      submissionId: 'sub-demo-000001',
      status: 'ACCEPTED',
      submittedAt: new Date().toISOString(),
    }
  },

  async getOfficialSession(): Promise<OfficialSession> {
    await wait()
    return {
      role: 'RECOUNT_DELEGATE',
      sessionExpiresAt: '2026-10-28T13:06:00Z',
      scope: { state: 'SA', electionId: 'senate-2026', countId: 'count-2026-01' },
    }
  },

  async getAuditEvents(): Promise<{ events: AuditEvent[]; chainStatus: string }> {
    await wait()
    return {
      chainStatus: 'VALID',
      events: [
        {
          eventId: 'audit-2026-000041',
          eventType: 'EXCLUSION_APPROVED',
          actorType: 'OFFICIAL',
          actorId: 'operator-017',
          resourceId: 'exc-2026-000001',
          timestamp: '2026-10-28T05:08:00Z',
          previousHash: 'sha256:previous-demo-hash',
          eventHash: 'sha256:current-demo-hash',
        },
      ],
    }
  },
}
