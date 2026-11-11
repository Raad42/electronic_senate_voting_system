// Shared frontend data shapes for API requests and responses.
export type Candidate = {
  candidateId: string
  displayName: string
  party: string
}

export type BallotConfig = {
  electionId: string
  state: string
  configurationVersion: string
  candidates: Candidate[]
}

export type ElectorAuthorisation = {
  authorisationToken: string
  state: string
  expiresAt: string
}

export type BallotSelection = {
  candidateId: string
  rank: number
}

export type BallotSubmission = {
  submissionId: string
  status: 'ACCEPTED' | 'REJECTED'
  submittedAt: string
}

export type OfficialSession = {
  role: string
  sessionExpiresAt: string
  scope: {
    state: string
    electionId: string
    countId: string | null
  }
  operatorId?: string
  /** Echoed back in the X-CSRF-Token header on every state-changing request. */
  csrfToken?: string
}

export type OfficialRole = 'ELECTION_OFFICIAL' | 'COUNT_OPERATOR' | 'RECOUNT_DELEGATE' | 'AUDITOR'

export type OfficialLogin = {
  username: string
  password: string
  otp: string
  role: OfficialRole
}

export type ExclusionRequest = {
  electionId: string
  state: string
  candidateId: string
  recountPhase: 'OPEN' | 'CLOSED'
  exclusionGround: 'COURT_ORDER' | 'OTHER'
  supportingEvidenceId: string
  /** Fresh one-time code: entering an exclusion is irreversible, so it needs step-up. */
  stepUpCode: string
}

export type ExclusionResponse = {
  status: 'APPROVED' | 'REJECTED'
  exclusionId?: string
  auditEventId?: string
  reason?: string
  excludedCandidates?: string[]
  elected?: string[]
}

export type AuditEvent = {
  eventId: string
  eventType: string
  actorType: string
  actorId: string
  resourceId: string
  electionId: string
  state: string
  countId: string | null
  timestamp: string
  previousHash: string
  eventHash: string
}
