import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { api } from '../api/client'
import type { Overview } from '../api/types'

export function OverviewPage() {
  const { t } = useTranslation()
  const [overview, setOverview] = useState<Overview | null>(null)
  const [error, setError] = useState(false)

  useEffect(() => {
    let cancelled = false
    api
      .overview()
      .then((data) => {
        if (!cancelled) setOverview(data)
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
  if (!overview) {
    return <p>{t('common.loading')}</p>
  }

  const { decisions_today, blocked_percent, top_blocked_agents, top_blocked_tools, gateways } =
    overview

  return (
    <div>
      <h1>{t('overview.heading')}</h1>

      <section aria-labelledby="decisions-today-heading">
        <h2 id="decisions-today-heading">{t('overview.decisionsToday')}</h2>
        <dl>
          <div>
            <dt>{t('overview.allowed')}</dt>
            <dd>{decisions_today.allow}</dd>
          </div>
          <div>
            <dt>{t('overview.blocked')}</dt>
            <dd>{decisions_today.block}</dd>
          </div>
          <div>
            <dt>{t('overview.held')}</dt>
            <dd>{decisions_today.hold}</dd>
          </div>
          <div>
            <dt>{t('overview.blockedPercent')}</dt>
            <dd>{blocked_percent.toFixed(1)}%</dd>
          </div>
        </dl>
      </section>

      <section aria-labelledby="top-blocked-agents-heading">
        <h2 id="top-blocked-agents-heading">{t('overview.topBlockedAgents')}</h2>
        {top_blocked_agents.length === 0 ? (
          <p>{t('overview.noData')}</p>
        ) : (
          <ul>
            {top_blocked_agents.map((row) => (
              <li key={row.name}>
                {row.name} — {row.count}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="top-blocked-tools-heading">
        <h2 id="top-blocked-tools-heading">{t('overview.topBlockedTools')}</h2>
        {top_blocked_tools.length === 0 ? (
          <p>{t('overview.noData')}</p>
        ) : (
          <ul>
            {top_blocked_tools.map((row) => (
              <li key={row.name}>
                {row.name} — {row.count}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="gateway-health-heading">
        <h2 id="gateway-health-heading">{t('overview.gatewayHealth')}</h2>
        <table>
          <thead>
            <tr>
              <th scope="col">{t('overview.gatewayName')}</th>
              <th scope="col">{t('overview.lastHeartbeat')}</th>
              <th scope="col">{t('overview.chainStatus')}</th>
            </tr>
          </thead>
          <tbody>
            {gateways.map((gw) => (
              <tr key={gw.id}>
                <th scope="row">{gw.name}</th>
                <td>{gw.last_heartbeat_at ?? t('overview.never')}</td>
                <td>{gw.chain_status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  )
}
