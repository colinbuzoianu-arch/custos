import { useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'

import { ApiError, api } from '../api/client'

export function AgentCreatePage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      const agent = await api.createAgent({
        name,
        description: description.trim() === '' ? null : description,
      })
      navigate(`/agents/${agent.id}`)
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setError(t('agents.errorNameTaken'))
      } else {
        setError(t('login.errorGeneric'))
      }
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div>
      <h1>{t('agents.create')}</h1>
      <form onSubmit={(e) => void handleSubmit(e)} noValidate style={{ maxWidth: '480px' }}>
        <div className="field">
          <label htmlFor="agent-name">{t('agents.name')}</label>
          <input
            id="agent-name"
            required
            value={name}
            onChange={(e) => setName(e.target.value)}
            style={{ width: '100%' }}
          />
        </div>
        <div className="field">
          <label htmlFor="agent-description">{t('agents.description')}</label>
          <input
            id="agent-description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            style={{ width: '100%' }}
          />
        </div>
        {error && (
          <p className="error-text" role="alert">
            {error}
          </p>
        )}
        <button type="submit" disabled={submitting || name.trim() === ''}>
          {t('common.save')}
        </button>
      </form>
    </div>
  )
}
