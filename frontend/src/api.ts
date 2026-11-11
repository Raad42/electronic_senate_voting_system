// Legacy shared types kept for older prototype files.
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

export type AuditEvent = {
  eventId: string
  eventType: string
  actorType: string
  actorId: string
  resourceId: string
  timestamp: string
  previousHash: string
  eventHash: string
}
