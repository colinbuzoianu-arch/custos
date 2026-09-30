import type { ReactNode } from 'react'
import { Navigate } from 'react-router-dom'

import { useAuth } from '../auth/useAuth'

export function RequireAuth({ children }: { children: ReactNode }) {
  const { auth } = useAuth()

  // `undefined` means `/me` hasn't resolved yet - render nothing rather
  // than bouncing to /login and immediately back once it does.
  if (auth === undefined) {
    return null
  }
  if (auth === null) {
    return <Navigate to="/login" replace />
  }
  return <>{children}</>
}
