import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { ApiError, api } from '../api/client'
import type { Approval } from '../api/types'

export function ApprovalsPage() {
  const { t } = useTranslation()
  const [approvals, setApprovals] = useState<Approval[] | null>(null)
  const [error, setError] = useState(false)
  const [comments, setComments] = useState<Record<string, string>>({})
  const [busyId, setBusyId] = useState<string | null>(null)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [fourEyesErrorId, setFourEyesErrorId] = useState<string | null>(null)

  function load() {
    api
      .listPendingApprovals()
      .then(setApprovals)
      .catch(() => setError(true))
  }

  useEffect(load, [])

  async function handleResolve(approval: Approval, approve: boolean) {
    setBusyId(approval.id)
    setFourEyesErrorId(null)
    try {
      await (approve
        ? api.approveApproval(approval.id, comments[approval.id])
        : api.rejectApproval(approval.id, comments[approval.id]))
      setApprovals((prev) => (prev ?? []).filter((a) => a.id !== approval.id))
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        setFourEyesErrorId(approval.id)
      } else {
        setError(true)
      }
    } finally {
      setBusyId(null)
    }
  }

  if (error) {
    return <p className="error-text">{t('login.errorGeneric')}</p>
  }
  if (!approvals) {
    return <p>{t('common.loading')}</p>
  }

  return (
    <div>
      <h1>{t('approvals.heading')}</h1>
      {approvals.length === 0 && <p>{t('approvals.noPending')}</p>}

      <ul style={{ listStyle: 'none', padding: 0 }}>
        {approvals.map((approval) => (
          <li
            key={approval.id}
            style={{
              border: '1px solid var(--color-border)',
              borderRadius: '4px',
              padding: '1rem',
              marginBottom: '0.75rem',
            }}
          >
            <p>
              <strong>{approval.agent}</strong> → <strong>{approval.tool}</strong>
              {approval.four_eyes && (
                <span style={{ marginLeft: '0.5rem' }} title={t('approvals.fourEyesHint')}>
                  ({t('approvals.fourEyes')})
                </span>
              )}
            </p>
            <p>{approval.reason}</p>

            <button
              type="button"
              className="secondary"
              onClick={() => setExpandedId(expandedId === approval.id ? null : approval.id)}
            >
              {t('approvals.findings')}
            </button>
            {expandedId === approval.id && (
              <pre style={{ background: 'white', padding: '1rem', overflow: 'auto' }}>
                {JSON.stringify(approval.findings, null, 2)}
              </pre>
            )}

            <div className="field">
              <label htmlFor={`comment-${approval.id}`}>{t('approvals.comment')}</label>
              <input
                id={`comment-${approval.id}`}
                value={comments[approval.id] ?? ''}
                onChange={(e) =>
                  setComments((prev) => ({ ...prev, [approval.id]: e.target.value }))
                }
                style={{ width: '100%' }}
              />
            </div>

            {fourEyesErrorId === approval.id && (
              <p className="error-text" role="alert">
                {t('approvals.fourEyesError')}
              </p>
            )}

            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <button
                type="button"
                disabled={busyId === approval.id}
                onClick={() => void handleResolve(approval, true)}
              >
                {t('approvals.approve')}
              </button>
              <button
                type="button"
                className="danger"
                disabled={busyId === approval.id}
                onClick={() => void handleResolve(approval, false)}
              >
                {t('approvals.reject')}
              </button>
            </div>
          </li>
        ))}
      </ul>
    </div>
  )
}
