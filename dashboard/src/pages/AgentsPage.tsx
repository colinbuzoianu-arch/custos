import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router-dom'

import { api } from '../api/client'
import type { Agent } from '../api/types'

export function AgentsPage() {
  const { t } = useTranslation()
  const [agents, setAgents] = useState<Agent[] | null>(null)
  const [error, setError] = useState(false)

  useEffect(() => {
    let cancelled = false
    api
      .listAgents()
      .then((data) => {
        if (!cancelled) setAgents(data)
      })
      .catch(() => {
        if (!cancelled) setError(true)
      })
    return () => {
      cancelled = true
    }
  }, [])

  if (error) {
    return <p className="error-text">{t('login.errorGeneric')}</p>
  }
  if (!agents) {
    return <p>{t('common.loading')}</p>
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
        <h1>{t('agents.heading')}</h1>
        <Link to="/agents/new" className="button-link">
          {t('agents.create')}
        </Link>
      </div>
      <table>
        <thead>
          <tr>
            <th scope="col">{t('agents.name')}</th>
            <th scope="col">{t('agents.status')}</th>
            <th scope="col">{t('agents.expiry')}</th>
          </tr>
        </thead>
        <tbody>
          {agents.map((agent) => (
            <tr key={agent.id}>
              <th scope="row">
                <Link to={`/agents/${agent.id}`}>{agent.name}</Link>
              </th>
              <td>{agent.status}</td>
              <td>{agent.expiry_date ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
