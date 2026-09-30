import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useParams } from 'react-router-dom'

import { api } from '../api/client'
import type { Agent } from '../api/types'

export function AgentDetailPage() {
  const { t } = useTranslation()
  const { id } = useParams<{ id: string }>()
  const [agent, setAgent] = useState<Agent | null>(null)
  const [error, setError] = useState(false)
  const [busy, setBusy] = useState(false)
  const [issuedToken, setIssuedToken] = useState<string | null>(null)

  useEffect(() => {
    if (!id) return
    let cancelled = false
    api
      .getAgent(id)
      .then((a) => {
        if (!cancelled) setAgent(a)
      })
      .catch(() => {
        if (!cancelled) setError(true)
      })
    return () => {
      cancelled = true
    }
  }, [id])

  async function toggleStatus() {
    if (!agent) return
    const nextStatus = agent.status === 'active' ? 'disabled' : 'active'
    if (nextStatus === 'disabled' && !window.confirm(t('agents.confirmDisable'))) {
      return
    }
    setBusy(true)
    try {
      setAgent(await api.updateAgent(agent.id, { status: nextStatus }))
    } finally {
      setBusy(false)
    }
  }

  async function handleIssueToken() {
    if (!agent) return
    setBusy(true)
    try {
      const { token } = await api.issueToken(agent.id)
      setIssuedToken(token)
    } finally {
      setBusy(false)
    }
  }

  if (error) {
    return <p className="error-text">{t('login.errorGeneric')}</p>
  }
  if (!agent) {
    return <p>{t('common.loading')}</p>
  }

  return (
    <div>
      <p>
        <Link to="/agents">{t('agents.heading')}</Link>
      </p>
      <h1>{agent.name}</h1>
      <dl>
        <div>
          <dt>{t('agents.status')}</dt>
          <dd>{agent.status}</dd>
        </div>
        <div>
          <dt>{t('agents.description')}</dt>
          <dd>{agent.description ?? '—'}</dd>
        </div>
        <div>
          <dt>{t('agents.expiry')}</dt>
          <dd>{agent.expiry_date ?? '—'}</dd>
        </div>
      </dl>

      {issuedToken && (
        <div role="alert" className="field">
          <p>{t('agents.tokenShownOnce')}</p>
          <code style={{ wordBreak: 'break-all' }}>{issuedToken}</code>
        </div>
      )}

      <div style={{ display: 'flex', gap: '0.75rem' }}>
        <button type="button" onClick={() => void toggleStatus()} disabled={busy}>
          {agent.status === 'active' ? t('agents.disable') : t('agents.enable')}
        </button>
        <button type="button" className="secondary" onClick={() => void handleIssueToken()} disabled={busy}>
          {t('agents.issueToken')}
        </button>
      </div>
    </div>
  )
}
