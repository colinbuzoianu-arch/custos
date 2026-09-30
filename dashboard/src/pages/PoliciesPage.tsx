import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import CodeMirror from '@uiw/react-codemirror'

import { api } from '../api/client'
import type { PolicyVersion, ValidateResult } from '../api/types'
import { useAuth } from '../auth/useAuth'
import { cedarLanguage } from '../editor/cedarLanguage'

const VALIDATE_DEBOUNCE_MS = 500

export function PoliciesPage() {
  const { t } = useTranslation()
  const { auth } = useAuth()

  const [versions, setVersions] = useState<PolicyVersion[] | null>(null)
  const [loadError, setLoadError] = useState(false)
  const [selectedVersion, setSelectedVersion] = useState<number | null>(null)
  const [policyText, setPolicyText] = useState('')
  const [message, setMessage] = useState('')
  const [validation, setValidation] = useState<ValidateResult | null>(null)
  const [saving, setSaving] = useState(false)
  const [publishing, setPublishing] = useState(false)
  const [diffFrom, setDiffFrom] = useState<number | null>(null)
  const [diffTo, setDiffTo] = useState<number | null>(null)
  const [diffText, setDiffText] = useState<string | null>(null)

  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    let cancelled = false
    api
      .listPolicyVersions()
      .then((data) => {
        if (cancelled) return
        setVersions(data)
        const latest = data[0]
        if (latest) {
          setSelectedVersion(latest.version)
          setPolicyText(latest.policy_text)
          setMessage('')
        }
      })
      .catch(() => {
        if (!cancelled) setLoadError(true)
      })
    return () => {
      cancelled = true
    }
  }, [])

  // Debounced "validate as you type" - never saves anything, see
  // POST /api/policies/validate's own doc comment for why this can't just
  // reuse the save-draft endpoint.
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => {
      if (policyText.trim() === '') {
        setValidation(null)
        return
      }
      api
        .validatePolicy(policyText)
        .then(setValidation)
        .catch(() => setValidation(null))
    }, VALIDATE_DEBOUNCE_MS)
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current)
    }
  }, [policyText])

  if (auth && auth.role !== 'admin') {
    return <p>{t('policies.adminOnly')}</p>
  }

  function selectVersion(v: PolicyVersion) {
    setSelectedVersion(v.version)
    setPolicyText(v.policy_text)
    setMessage('')
  }

  async function handleSaveDraft() {
    setSaving(true)
    try {
      const saved = await api.savePolicyDraft({ policy_text: policyText, message: message || null })
      const list = await api.listPolicyVersions()
      setVersions(list)
      setSelectedVersion(saved.version)
      setMessage('')
    } finally {
      setSaving(false)
    }
  }

  async function handlePublish(version: PolicyVersion) {
    if (!window.confirm(t('policies.confirmPublish', { version: version.version }))) {
      return
    }
    setPublishing(true)
    try {
      await api.publishPolicyVersion(version.version)
      setVersions(await api.listPolicyVersions())
    } finally {
      setPublishing(false)
    }
  }

  async function handleShowDiff() {
    if (diffFrom === null || diffTo === null) return
    setDiffText(await api.diffPolicyVersions(diffFrom, diffTo))
  }

  if (loadError) {
    return <p className="error-text">{t('login.errorGeneric')}</p>
  }
  if (!versions) {
    return <p>{t('common.loading')}</p>
  }

  const selected = versions.find((v) => v.version === selectedVersion) ?? null

  return (
    <div>
      <h1>{t('policies.heading')}</h1>

      <div style={{ display: 'flex', gap: '2rem', alignItems: 'flex-start' }}>
        <section aria-labelledby="policy-versions-heading" style={{ minWidth: '200px' }}>
          <h2 id="policy-versions-heading">{t('policies.versions')}</h2>
          <ul style={{ listStyle: 'none', padding: 0 }}>
            {versions.map((v) => (
              <li key={v.id}>
                <button
                  type="button"
                  className={v.version === selectedVersion ? '' : 'secondary'}
                  onClick={() => selectVersion(v)}
                  style={{ width: '100%', textAlign: 'left', marginBottom: '0.25rem' }}
                >
                  v{v.version} {v.published && `· ${t('policies.published')}`}
                  {!v.valid && ` · ${t('policies.invalid')}`}
                </button>
              </li>
            ))}
          </ul>
        </section>

        <section aria-labelledby="policy-editor-heading" style={{ flex: 1 }}>
          <h2 id="policy-editor-heading">
            {selectedVersion ? t('policies.editingVersion', { version: selectedVersion }) : t('policies.newDraft')}
          </h2>
          <CodeMirror
            value={policyText}
            height="320px"
            extensions={[cedarLanguage]}
            onChange={(value) => setPolicyText(value)}
          />
          {validation && !validation.valid && (
            <p className="error-text" role="alert">
              {validation.validation_error}
            </p>
          )}
          {validation?.valid && <p style={{ color: 'var(--color-ok)' }}>{t('policies.valid')}</p>}

          <div className="field">
            <label htmlFor="policy-message">{t('policies.message')}</label>
            <input
              id="policy-message"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              style={{ width: '100%' }}
            />
          </div>

          <div style={{ display: 'flex', gap: '0.75rem' }}>
            <button type="button" onClick={() => void handleSaveDraft()} disabled={saving}>
              {t('policies.saveDraft')}
            </button>
            {selected && !selected.published && (
              <button
                type="button"
                disabled={!selected.valid || publishing}
                onClick={() => void handlePublish(selected)}
              >
                {t('policies.publish')}
              </button>
            )}
          </div>
        </section>
      </div>

      <section aria-labelledby="policy-diff-heading">
        <h2 id="policy-diff-heading">{t('policies.diff')}</h2>
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-end' }}>
          <div className="field">
            <label htmlFor="diff-from">{t('policies.from')}</label>
            <select
              id="diff-from"
              value={diffFrom ?? ''}
              onChange={(e) => setDiffFrom(e.target.value === '' ? null : Number(e.target.value))}
            >
              <option value="">—</option>
              {versions.map((v) => (
                <option key={v.id} value={v.version}>
                  v{v.version}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="diff-to">{t('policies.to')}</label>
            <select
              id="diff-to"
              value={diffTo ?? ''}
              onChange={(e) => setDiffTo(e.target.value === '' ? null : Number(e.target.value))}
            >
              <option value="">—</option>
              {versions.map((v) => (
                <option key={v.id} value={v.version}>
                  v{v.version}
                </option>
              ))}
            </select>
          </div>
          <button type="button" onClick={() => void handleShowDiff()} disabled={diffFrom === null || diffTo === null}>
            {t('policies.showDiff')}
          </button>
        </div>
        {diffText !== null && (
          <pre style={{ background: 'white', padding: '1rem', overflow: 'auto' }}>{diffText}</pre>
        )}
      </section>
    </div>
  )
}
