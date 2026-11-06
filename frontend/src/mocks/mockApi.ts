import type { AuditEvent, BallotConfig, BallotSubmission, ElectorAuthorisation, ExclusionRequest, ExclusionResponse, OfficialSession } from '../types/api'

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

  async submitExclusion(payload: ExclusionRequest): Promise<ExclusionResponse> {
    await wait(600)
    if (payload.candidateId !== 'CAND-041') {
      return { status: 'REJECTED', reason: 'Candidate is outside the delegate state scope.' }
    }
    if (payload.supportingEvidenceId !== 'HC-2026-17') {
      return { status: 'REJECTED', reason: 'Supporting evidence could not be verified against the approved record.' }
    }
    return {
      status: 'APPROVED',
      exclusionId: 'exc-demo-000001',
      auditEventId: 'audit-demo-000042',
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
          electionId: 'senate-2026',
          state: 'SA',
          countId: 'count-2026-01',
          timestamp: '2026-10-28T05:08:00Z',
          previousHash: 'sha256:previous-demo-hash',
          eventHash: 'sha256:current-demo-hash',
        },
        {
          eventId: 'audit-2026-000040',
          eventType: 'COUNT_STARTED',
          actorType: 'SERVICE',
          actorId: 'count-service',
          resourceId: 'count-2026-01',
          electionId: 'senate-2026',
          state: 'SA',
          countId: 'count-2026-01',
          timestamp: '2026-10-28T05:01:00Z',
          previousHash: 'sha256:chain-root-demo-hash',
          eventHash: 'sha256:count-start-demo-hash',
        },
        {
          eventId: 'audit-2026-000039',
          eventType: 'QUERY_REFUSED',
          actorType: 'OFFICIAL',
          actorId: 'operator-017',
          resourceId: 'ballot-identity-lookup',
          electionId: 'senate-2026',
          state: 'SA',
          countId: null,
          timestamp: '2026-10-28T04:59:00Z',
          previousHash: 'sha256:query-previous-demo-hash',
          eventHash: 'sha256:query-refused-demo-hash',
        },
      ],
    }
  },
}
