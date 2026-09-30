import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

import type { AuditRecordSummary } from '../api/types'

const MAX_EVENTS = 200

export function LiveDecisionsPage() {
  const { t } = useTranslation()
  const [events, setEvents] = useState<AuditRecordSummary[]>([])
  const [paused, setPaused] = useState(false)
  const [connected, setConnected] = useState(true)
  const [selected, setSelected] = useState<AuditRecordSummary | null>(null)
  const [filterAgent, setFilterAgent] = useState('')
  const [filterTool, setFilterTool] = useState('')
  const [filterVerdict, setFilterVerdict] = useState('')

  // `paused` is read inside the EventSource's message handler, which is
  // set up once - a ref (not the state variable) keeps that handler
  // reading the current value without having to reconnect the stream
  // every time the pause button is toggled. Updated from an effect, never
  // during render, so this can't interact badly with concurrent rendering.
  const pausedRef = useRef(paused)
  useEffect(() => {
    pausedRef.current = paused
  }, [paused])

  useEffect(() => {
    const source = new EventSource('/api/audit/stream')
    source.onopen = () => setConnected(true)
    source.onerror = () => setConnected(false)
    source.onmessage = (event: MessageEvent<string>) => {
      if (pausedRef.current) return
      try {
        const record = JSON.parse(event.data) as AuditRecordSummary
        setEvents((prev) => [record, ...prev].slice(0, MAX_EVENTS))
      } catch {
        // Malformed event - drop it rather than crash the live view.
      }
    }
    return () => source.close()
  }, [])

  const filtered = events.filter(
    (e) =>
      (filterAgent === '' || (e.agent ?? '').includes(filterAgent)) &&
      (filterTool === '' || (e.tool ?? '').includes(filterTool)) &&
      (filterVerdict === '' || (e.verdict ?? '') === filterVerdict),
  )

  return (
    <div>
      <h1>{t('live.heading')}</h1>
      {!connected && <p className="error-text">{t('live.connectionLost')}</p>}

      <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem', alignItems: 'flex-end' }}>
        <div className="field">
          <label htmlFor="live-filter-agent">{t('live.filterAgent')}</label>
          <input
            id="live-filter-agent"
            value={filterAgent}
            onChange={(e) => setFilterAgent(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="live-filter-tool">{t('live.filterTool')}</label>
          <input id="live-filter-tool" value={filterTool} onChange={(e) => setFilterTool(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="live-filter-verdict">{t('live.filterVerdict')}</label>
          <select
            id="live-filter-verdict"
            value={filterVerdict}
            onChange={(e) => setFilterVerdict(e.target.value)}
          >
            <option value="">—</option>
            <option value="ALLOW">ALLOW</option>
            <option value="BLOCK">BLOCK</option>
            <option value="HOLD">HOLD</option>
          </select>
        </div>
        <button type="button" className="secondary" onClick={() => setPaused((p) => !p)}>
          {paused ? t('live.resume') : t('live.pause')}
        </button>
      </div>

      <div style={{ display: 'flex', gap: '1.5rem' }}>
        <table style={{ flex: 1 }}>
          <thead>
            <tr>
              <th scope="col">{t('audit.agent')}</th>
              <th scope="col">{t('audit.tool')}</th>
              <th scope="col">{t('audit.verdict')}</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((record) => (
              <tr key={record.id}>
                <td>
                  <button type="button" className="secondary" onClick={() => setSelected(record)}>
                    {record.agent ?? '—'}
                  </button>
                </td>
                <td>{record.tool ?? '—'}</td>
                <td>{record.verdict ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>

        {selected && (
          <aside style={{ minWidth: '320px' }} aria-label={t('live.details')}>
            <h2>{t('live.details')}</h2>
            <button type="button" className="secondary" onClick={() => setSelected(null)}>
              {t('common.close')}
            </button>
            <pre style={{ background: 'white', padding: '1rem', overflow: 'auto' }}>
              {JSON.stringify(selected.record, null, 2)}
            </pre>
          </aside>
        )}
      </div>

      {filtered.length === 0 && <p>{t('live.noEvents')}</p>}
    </div>
  )
}
