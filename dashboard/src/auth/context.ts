import { createContext } from 'react'

import type { Role } from '../api/types'

export interface AuthState {
  role: Role
  tenant: string
}

export interface AuthContextValue {
  /** `undefined` while `/me` hasn't resolved yet, `null` once resolved and
   * logged out. */
  auth: AuthState | undefined | null
  login: (tenant: string, email: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

export const AuthContext = createContext<AuthContextValue | null>(null)
