import { useCallback, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'

import { api, setCsrfToken } from '../api/client'
import { AuthContext } from './context'
import type { AuthState } from './context'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [auth, setAuth] = useState<AuthState | undefined | null>(undefined)

  useEffect(() => {
    let cancelled = false
    void api.me().then((me) => {
      if (cancelled) return
      if (me) {
        setCsrfToken(me.csrf_token)
        // `/me` doesn't echo back the tenant slug the user typed, only
        // that a session exists - fine, nothing in this dashboard needs
        // it once logged in.
        setAuth({ role: me.role, tenant: '' })
      } else {
        setAuth(null)
      }
    })
    return () => {
      cancelled = true
    }
  }, [])

  const login = useCallback(async (tenant: string, email: string, password: string) => {
    const result = await api.login(tenant, email, password)
    setCsrfToken(result.csrf_token)
    setAuth({ role: result.role, tenant })
  }, [])

  const logout = useCallback(async () => {
    await api.logout()
    setCsrfToken(null)
    setAuth(null)
  }, [])

  const value = useMemo(() => ({ auth, login, logout }), [auth, login, logout])

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
