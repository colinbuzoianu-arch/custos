import { useState } from 'react'
import type { FormEvent } from 'react'
import { useTranslation } from 'react-i18next'

import { api } from '../api/client'
import type { AuditRecordSummary, AuditSearchFilters } from '../api/types'

/** A safety cap on export, not a claim that results never exceed it - the
 * search API has no server-side export, so export means "walk every page
 * with the current filters through the same paginated endpoint the table
 * uses," and that has to stop somewhere. */
const EXPORT_PAGE_LIMIT = 200
const MAX_EXPORT_PAGES = 50

const CSV_COLUMNS: (keyof AuditRecordSummary)[] = [
  'seq',
  'ts',
  'agent',
  'tool',
  'verdict',
  'policy_version',
  'gateway_id',
  'ingested_at',
]

function toCsv(records: AuditRecordSummary[]): string {
  const escape = (value: unknown) => {
    const text = value === null || value === undefined ? '' : String(value)
    return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
  }
  const header = CSV_COLUMNS.join(',')
  const rows = records.map((r) => CSV_COLUMNS.map((c) => escape(r[c])).join(','))
  return [header, ...rows].join('\n')
}

function downloadBlob(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

export function AuditSearchPage() {
  const { t } = useTranslation()
  const [agent, setAgent] = useState('')
  const [tool, setTool] = useState('')
  const [verdict, setVerdict] = useState('')
  const [policyVersion, setPolicyVersion] = useState('')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')

  const [results, setResults] = useState<AuditRecordSummary[]>([])
  const [cursor, setCursor] = useState<string | null>(null)
  const [searched, setSearched] = useState(false)
  const [loading, setLoading] = useState(false)
  const [exporting, setExporting] = useState(false)

  function currentFilters(): AuditSearchFilters {
    return {
      agent: agent || undefined,
      tool: tool || undefined,
      verdict: verdict || undefined,
      policy_version: policyVersion || undefined,
      from: from ? new Date(from).toISOString() : undefined,
      to: to ? new Date(to).toISOString() : undefined,
    }
  }

  async function handleSearch(e: FormEvent) {
    e.preventDefault()
    setLoading(true)
    try {
      const result = await api.searchAudit({ ...currentFilters(), limit: 50 })
      setResults(result.records)
      setCursor(result.next_cursor)
      setSearched(true)
    } finally {
      setLoading(false)
    }
  }

  async function handleLoadMore() {
    if (!cursor) return
    setLoading(true)
    try {
      const result = await api.searchAudit({ ...currentFilters(), cursor, limit: 50 })
      setResults((prev) => [...prev, ...result.records])
      setCursor(result.next_cursor)
    } finally {
      setLoading(false)
    }
  }

  async function collectAllForExport(): Promise<AuditRecordSummary[]> {
    const all: AuditRecordSummary[] = []
    let pageCursor: string | undefined
    for (let page = 0; page < MAX_EXPORT_PAGES; page++) {
      const result = await api.searchAudit({
        ...currentFilters(),
        cursor: pageCursor,
        limit: EXPORT_PAGE_LIMIT,
      })
      all.push(...result.records)
      if (!result.next_cursor) break
      pageCursor = result.next_cursor
    }
    return all
  }

  async function handleExport(format: 'csv' | 'json') {
    setExporting(true)
    try {
      const all = await collectAllForExport()
      if (format === 'csv') {
        downloadBlob('audit-export.csv', toCsv(all), 'text/csv')
      } else {
        downloadBlob('audit-export.json', JSON.stringify(all, null, 2), 'application/json')
      }
    } finally {
      setExporting(false)
    }
  }

  return (
    <div>
      <h1>{t('audit.heading')}</h1>

      <form onSubmit={(e) => void handleSearch(e)} noValidate>
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div className="field">
            <label htmlFor="audit-agent">{t('audit.agent')}</label>
            <input id="audit-agent" value={agent} onChange={(e) => setAgent(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="audit-tool">{t('audit.tool')}</label>
            <input id="audit-tool" value={tool} onChange={(e) => setTool(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="audit-verdict">{t('audit.verdict')}</label>
            <select id="audit-verdict" value={verdict} onChange={(e) => setVerdict(e.target.value)}>
              <option value="">—</option>
              <option value="ALLOW">ALLOW</option>
              <option value="BLOCK">BLOCK</option>
              <option value="HOLD">HOLD</option>
            </select>
          </div>
          <div className="field">
            <label htmlFor="audit-policy-version">{t('audit.policyVersion')}</label>
            <input
              id="audit-policy-version"
              value={policyVersion}
              onChange={(e) => setPolicyVersion(e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="audit-from">{t('audit.from')}</label>
            <input id="audit-from" type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="audit-to">{t('audit.to')}</label>
            <input id="audit-to" type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} />
          </div>
          <button type="submit" disabled={loading}>
            {t('audit.search')}
          </button>
        </div>
      </form>

      {searched && results.length === 0 && <p>{t('audit.noResults')}</p>}

      {results.length > 0 && (
        <>
          <div style={{ display: 'flex', gap: '0.75rem', margin: '1rem 0' }}>
            <button type="button" className="secondary" disabled={exporting} onClick={() => void handleExport('csv')}>
              {exporting ? t('audit.exporting') : t('audit.exportCsv')}
            </button>
            <button
              type="button"
              className="secondary"
              disabled={exporting}
              onClick={() => void handleExport('json')}
            >
              {exporting ? t('audit.exporting') : t('audit.exportJson')}
            </button>
          </div>

          <table>
            <thead>
              <tr>
                <th scope="col">{t('audit.agent')}</th>
                <th scope="col">{t('audit.tool')}</th>
                <th scope="col">{t('audit.verdict')}</th>
                <th scope="col">{t('audit.policyVersion')}</th>
              </tr>
            </thead>
            <tbody>
              {results.map((record) => (
                <tr key={record.id}>
                  <td>{record.agent ?? '—'}</td>
                  <td>{record.tool ?? '—'}</td>
                  <td>{record.verdict ?? '—'}</td>
                  <td>{record.policy_version ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {cursor && (
            <button type="button" onClick={() => void handleLoadMore()} disabled={loading}>
              {t('audit.loadMore')}
            </button>
          )}
        </>
      )}
    </div>
  )
}
