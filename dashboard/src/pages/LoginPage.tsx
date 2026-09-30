import { useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Navigate } from 'react-router-dom'

import { ApiError } from '../api/client'
import { useAuth } from '../auth/useAuth'

export function LoginPage() {
  const { t } = useTranslation()
  const { auth, login } = useAuth()
  const [tenant, setTenant] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  if (auth) {
    return <Navigate to="/overview" replace />
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      await login(tenant, email, password)
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setError(t('login.errorInvalid'))
      } else if (err instanceof ApiError && err.status === 429) {
        setError(t('login.errorLockedOut'))
      } else {
        setError(t('login.errorGeneric'))
      }
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main style={{ maxWidth: '360px', margin: '4rem auto', padding: '0 1rem' }}>
      <h1>{t('login.heading')}</h1>
      <form onSubmit={(e) => void handleSubmit(e)} noValidate>
        <div className="field">
          <label htmlFor="tenant">{t('login.tenant')}</label>
          <input
            id="tenant"
            name="tenant"
            autoComplete="organization"
            required
            value={tenant}
            onChange={(e) => setTenant(e.target.value)}
            style={{ width: '100%' }}
          />
        </div>
        <div className="field">
          <label htmlFor="email">{t('login.email')}</label>
          <input
            id="email"
            name="email"
            type="email"
            autoComplete="username"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            style={{ width: '100%' }}
          />
        </div>
        <div className="field">
          <label htmlFor="password">{t('login.password')}</label>
          <input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={{ width: '100%' }}
          />
        </div>
        {error && (
          <p className="error-text" role="alert">
            {error}
          </p>
        )}
        <button type="submit" disabled={submitting} style={{ width: '100%' }}>
          {submitting ? t('login.submitting') : t('login.submit')}
        </button>
      </form>
    </main>
  )
}
