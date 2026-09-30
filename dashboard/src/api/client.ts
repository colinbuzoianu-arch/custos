import type {
  Agent,
  Approval,
  AuditSearchFilters,
  AuditSearchResult,
  CreateAgentInput,
  IssuedToken,
  LoginResponse,
  Me,
  Overview,
  PolicyVersion,
  SavePolicyDraftInput,
  UpdateAgentInput,
  ValidateResult,
} from './types'

const BASE = '/api'

// The CSRF token for the current session, held only in memory - never
// localStorage/sessionStorage, so it never outlives the tab. `/me`
// recovers it after a page refresh from the still-live session cookie.
let csrfToken: string | null = null

export function setCsrfToken(token: string | null): void {
  csrfToken = token
}

export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase()
  const headers = new Headers(init.headers)
  if (init.body !== undefined && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  // Only mutating requests carry the CSRF header - matches
  // CurrentUser::check_csrf, which only ever runs on write handlers.
  if (method !== 'GET' && csrfToken) {
    headers.set('X-CSRF-Token', csrfToken)
  }

  const response = await fetch(`${BASE}${path}`, {
    ...init,
    method,
    headers,
    // Same-origin in both dev (via the Vite proxy) and production (the
    // dashboard is served by Control itself) - the session cookie is
    // HttpOnly and same-site, so this is never a cross-origin request.
    credentials: 'same-origin',
  })

  if (!response.ok) {
    throw new ApiError(response.status, response.statusText)
  }
  if (response.status === 204) {
    return undefined as T
  }
  return (await response.json()) as T
}

/** Like `request`, but for the one endpoint (`/policies/diff`) that
 * returns a plain-text body, not JSON. */
async function requestText(path: string, init: RequestInit = {}): Promise<string> {
  const response = await fetch(`${BASE}${path}`, {
    ...init,
    credentials: 'same-origin',
  })
  if (!response.ok) {
    throw new ApiError(response.status, response.statusText)
  }
  return response.text()
}

function toQueryString(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) search.set(key, String(value))
  }
  const query = search.toString()
  return query === '' ? '' : `?${query}`
}

export const api = {
  login(tenant: string, email: string, password: string): Promise<LoginResponse> {
    return request<LoginResponse>('/login', {
      method: 'POST',
      body: JSON.stringify({ tenant, email, password }),
    })
  },

  logout(): Promise<void> {
    return request<void>('/logout', { method: 'POST' })
  },

  /** `null` (never throws for a 401) - "not logged in" is an expected,
   * routine outcome here, not an error condition to propagate. */
  async me(): Promise<Me | null> {
    try {
      return await request<Me>('/me')
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        return null
      }
      throw e
    }
  },

  overview(): Promise<Overview> {
    return request<Overview>('/overview')
  },

  listAgents(): Promise<Agent[]> {
    return request<Agent[]>('/agents')
  },

  getAgent(id: string): Promise<Agent> {
    return request<Agent>(`/agents/${id}`)
  },

  createAgent(input: CreateAgentInput): Promise<Agent> {
    return request<Agent>('/agents', { method: 'POST', body: JSON.stringify(input) })
  },

  updateAgent(id: string, patch: UpdateAgentInput): Promise<Agent> {
    return request<Agent>(`/agents/${id}`, { method: 'PATCH', body: JSON.stringify(patch) })
  },

  /** Shown exactly once in this response - never retrievable again, not
   * even by calling this again (that issues a brand new token). */
  issueToken(id: string): Promise<IssuedToken> {
    return request<IssuedToken>(`/agents/${id}/token`, { method: 'POST' })
  },

  listPolicyVersions(): Promise<PolicyVersion[]> {
    return request<PolicyVersion[]>('/policies')
  },

  savePolicyDraft(input: SavePolicyDraftInput): Promise<PolicyVersion> {
    return request<PolicyVersion>('/policies', { method: 'POST', body: JSON.stringify(input) })
  },

  /** Pure syntax/schema check - never creates a version, safe to call on
   * every keystroke (debounced by the caller). */
  validatePolicy(policy_text: string, schema_text?: string | null): Promise<ValidateResult> {
    return request<ValidateResult>('/policies/validate', {
      method: 'POST',
      body: JSON.stringify({ policy_text, schema_text }),
    })
  },

  publishPolicyVersion(version: number): Promise<void> {
    return request<void>(`/policies/${version}/publish`, { method: 'POST' })
  },

  diffPolicyVersions(from: number, to: number): Promise<string> {
    return requestText(`/policies/diff${toQueryString({ from, to })}`)
  },

  searchAudit(filters: AuditSearchFilters): Promise<AuditSearchResult> {
    return request<AuditSearchResult>(`/audit${toQueryString({ ...filters })}`)
  },

  listPendingApprovals(): Promise<Approval[]> {
    return request<Approval[]>('/approvals')
  },

  approveApproval(id: string, comment?: string): Promise<Approval> {
    return request<Approval>(`/approvals/${id}/approve`, {
      method: 'POST',
      body: JSON.stringify({ comment: comment || null }),
    })
  },

  rejectApproval(id: string, comment?: string): Promise<Approval> {
    return request<Approval>(`/approvals/${id}/reject`, {
      method: 'POST',
      body: JSON.stringify({ comment: comment || null }),
    })
  },
}
