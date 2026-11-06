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
}

export type ExclusionRequest = {
  electionId: string
  state: string
  candidateId: string
  recountPhase: 'OPEN' | 'CLOSED'
  exclusionGround: 'COURT_ORDER' | 'OTHER'
  supportingEvidenceId: string
}

export type ExclusionResponse = {
  status: 'APPROVED' | 'REJECTED'
  exclusionId?: string
  auditEventId?: string
  reason?: string
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
