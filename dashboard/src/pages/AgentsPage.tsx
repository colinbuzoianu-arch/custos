import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { api } from '../api/client'
import type { Agent } from '../api/types'

// Create / disable / issue-token are deliberately not here yet - this
// commit scaffolds the dashboard and wires up read-only data; those
// mutating actions (and the "token shown once" flow they need) are
// tracked as the rest of session 14's Agents page.
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
      <h1>{t('agents.heading')}</h1>
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
              <th scope="row">{agent.name}</th>
              <td>{agent.status}</td>
              <td>{agent.expiry_date ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
