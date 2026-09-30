import type { Agent, LoginResponse, Me, Overview } from './types'

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
}
