import { useContext } from 'react'

import { AuthContext } from './context'
import type { AuthContextValue } from './context'

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) {
    throw new Error('useAuth must be used inside an AuthProvider')
  }
  return ctx
}
