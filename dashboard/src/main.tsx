import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'

import './styles/theme.css'
import './i18n'
import { App } from './App.tsx'

const rootElement = document.getElementById('root')
if (!rootElement) {
  throw new Error('#root element is missing from index.html')
}

createRoot(rootElement).render(
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
)
