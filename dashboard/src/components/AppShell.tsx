import { useTranslation } from 'react-i18next'
import { NavLink, Outlet } from 'react-router-dom'

import { SUPPORTED_LANGUAGES } from '../i18n'
import { useAuth } from '../auth/useAuth'

export function AppShell() {
  const { t, i18n } = useTranslation()
  const { auth, logout } = useAuth()

  return (
    <div>
      <header
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '1rem 1.5rem',
          borderBottom: '1px solid var(--color-border)',
        }}
      >
        <strong>{t('app.name')}</strong>
        <nav
          aria-label={t('app.name')}
          style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}
        >
          <NavLink to="/overview">{t('nav.overview')}</NavLink>
          <NavLink to="/agents">{t('nav.agents')}</NavLink>
          <NavLink to="/live">{t('nav.live')}</NavLink>
          <NavLink to="/audit">{t('nav.audit')}</NavLink>
          {auth?.role === 'admin' && <NavLink to="/policies">{t('nav.policies')}</NavLink>}
          <label>
            <span className="visually-hidden">Language</span>
            <select
              value={i18n.resolvedLanguage}
              onChange={(e) => void i18n.changeLanguage(e.target.value)}
            >
              {SUPPORTED_LANGUAGES.map((lang) => (
                <option key={lang} value={lang}>
                  {lang.toUpperCase()}
                </option>
              ))}
            </select>
          </label>
          <button type="button" className="secondary" onClick={() => void logout()}>
            {t('nav.logout')}
          </button>
        </nav>
      </header>
      <main style={{ padding: '1.5rem' }}>
        <Outlet />
      </main>
    </div>
  )
}
