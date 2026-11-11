import type {
  AuditEvent,
  BallotConfig,
  BallotSelection,
  BallotSubmission,
  ElectorAuthorisation,
  ExclusionRequest,
  ExclusionResponse,
  OfficialLogin,
  OfficialSession,
} from '../types/api'
import { mockApi } from '../mocks/mockApi'

const baseUrl = import.meta.env.VITE_API_BASE_URL ?? '/api'
// Switch between the live backend and the local dummy API from the environment.
const useMockApi = (import.meta.env.VITE_USE_MOCK_API ?? 'true') === 'true'

// The official session lives in an HttpOnly cookie the page cannot read. The CSRF synchroniser
// token comes back in the session response and is kept in memory only (never localStorage).
let csrfToken: string | null = null

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly retryAfterSeconds?: number

  constructor(status: number, code: string, message: string, retryAfterSeconds?: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.retryAfterSeconds = retryAfterSeconds
  }
}

export const api = {
  obtainElectorAuthorisation: (
    state: string,
    voterId: string,
    password: string,
    electionId: string,
  ): Promise<ElectorAuthorisation> =>
    useMockApi
      ? mockApi.obtainElectorAuthorisation(state)
      : request<ElectorAuthorisation>('/auth/elector/authorisation', {
          method: 'POST',
          body: JSON.stringify({ state, voterId, password, electionId }),
        }),

  getBallotConfig: (state: string, electionId: string): Promise<BallotConfig> =>
    useMockApi
      ? mockApi.getBallotConfig(state, electionId)
      : request<BallotConfig>(
          `/ballots/config?state=${encodeURIComponent(state)}&electionId=${encodeURIComponent(electionId)}`,
        ),

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

  officialLogin: async (credentials: OfficialLogin): Promise<OfficialSession> => {
    if (useMockApi) return mockApi.getOfficialSession()
    await request<unknown>('/auth/officials/login', { method: 'POST', body: JSON.stringify(credentials) })
    return api.getOfficialSession()
  },

  officialLogout: async (): Promise<void> => {
    if (!useMockApi) await request<unknown>('/auth/officials/logout', { method: 'POST' })
    csrfToken = null
  },

  getOfficialSession: async (): Promise<OfficialSession> => {
    if (useMockApi) return mockApi.getOfficialSession()
    const session = await request<OfficialSession>('/auth/session')
    csrfToken = session.csrfToken ?? null
    return session
  },

  submitExclusion: (payload: ExclusionRequest): Promise<ExclusionResponse> =>
    useMockApi
      ? mockApi.submitExclusion(payload)
      : request<ExclusionResponse>('/recount/exclusions', {
          method: 'POST',
          body: JSON.stringify(payload),
        }),

  getAuditEvents: (): Promise<{ events: AuditEvent[]; chainStatus: string }> =>
    useMockApi
      ? mockApi.getAuditEvents()
      : request<{ events: AuditEvent[]; chainStatus: string }>('/audit/events?limit=50'),
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  // Keep all live API requests going through one response and error path.
  const method = (options.method ?? 'GET').toUpperCase()
  const response = await fetch(`${baseUrl}${path}`, {
    ...options,
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      ...(method !== 'GET' && csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
      ...(options.headers ?? {}),
    },
  })

  if (!response.ok) {
    const errorBody = await response.json().catch(() => null)
    const retryAfterHeader = response.headers.get('Retry-After')
    const retryAfterSeconds = retryAfterHeader ? Number(retryAfterHeader) : undefined
    const message = errorBody?.error?.message ?? `Request failed with status ${response.status}`
    const code = errorBody?.error?.code ?? `HTTP_${response.status}`
    if (response.status === 401) csrfToken = null
    throw new ApiError(response.status, code, message, Number.isFinite(retryAfterSeconds) ? retryAfterSeconds : undefined)
  }

  return response.json() as Promise<T>
}

/** A user-facing sentence for any failed request. */
export function describeError(error: unknown, fallback: string): string {
  if (!(error instanceof ApiError)) return fallback
  if (error.status === 429) {
    return `Too many requests. Try again in ${error.retryAfterSeconds ?? 60} seconds.`
  }
  return error.message || fallback
}
