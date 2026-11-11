import type {
  AuditEvent,
  BallotConfig,
  BallotSelection,
  BallotSubmission,
  ElectorAuthorisation,
  OfficialSession,
} from '../types/api'
import { mockApi } from '../mocks/mockApi'

// Legacy API client kept for older prototype files.
const baseUrl = import.meta.env.VITE_API_BASE_URL ?? '/api'
const useMockApi = (import.meta.env.VITE_USE_MOCK_API ?? 'true') === 'true'

export const api = {
  obtainElectorAuthorisation: (state: string): Promise<ElectorAuthorisation> =>
    useMockApi
      ? mockApi.obtainElectorAuthorisation(state)
      : request<ElectorAuthorisation>('/auth/elector/authorisation', {
          method: 'POST',
          body: JSON.stringify({ state }),
        }),

  getBallotConfig: (state: string, electionId: string): Promise<BallotConfig> =>
    useMockApi
      ? mockApi.getBallotConfig(state, electionId)
      : request<BallotConfig>(`/ballots/config?state=${state}&electionId=${electionId}`),

  submitBallot: (
    authorisationToken: string,
    electionId: string,
    state: string,
    selections: BallotSelection[],
    configurationVersion: string,
  ): Promise<BallotSubmission> =>
    useMockApi
      ? mockApi.submitBallot()
      : request<BallotSubmission>('/ballots', {
          method: 'POST',
          body: JSON.stringify({
            authorisationToken,
            electionId,
            state,
            selections,
            configurationVersion,
          }),
        }),

  getOfficialSession: (): Promise<OfficialSession> =>
    useMockApi ? mockApi.getOfficialSession() : request<OfficialSession>('/auth/session'),

  getAuditEvents: (): Promise<{ events: AuditEvent[]; chainStatus: string }> =>
    useMockApi
      ? mockApi.getAuditEvents()
      : request<{ events: AuditEvent[]; chainStatus: string }>('/audit/events?limit=50'),
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers ?? {}),
    },
  })

  if (!response.ok) {
    const errorBody = await response.json().catch(() => null)
    const message = errorBody?.error?.message ?? `Request failed with status ${response.status}`
    throw new Error(message)
  }

  return response.json() as Promise<T>
}
