import i18n from 'i18next'
import LanguageDetector from 'i18next-browser-languagedetector'
import { initReactI18next } from 'react-i18next'

import de from './locales/de.json'
import en from './locales/en.json'
import ro from './locales/ro.json'

export const SUPPORTED_LANGUAGES = ['en', 'de', 'ro'] as const
export type SupportedLanguage = (typeof SUPPORTED_LANGUAGES)[number]

void i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      en: { translation: en },
      de: { translation: de },
      ro: { translation: ro },
    },
    fallbackLng: 'en',
    supportedLngs: SUPPORTED_LANGUAGES,
    interpolation: {
      // React already escapes everything it renders.
      escapeValue: false,
    },
  })

export default i18n
