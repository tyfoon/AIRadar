// Bridge to the vanilla JS i18n system (window.t / window.getLocale)
// During shell migration this will be replaced with a React i18n provider.

declare global {
  interface Window {
    t?: (key: string, params?: Record<string, unknown>) => string;
    getLocale?: () => string;
    formatNumber?: (n: number) => string;
  }
}

export function t(key: string, params?: Record<string, unknown>): string {
  if (typeof window.t === 'function') return window.t(key, params);
  return key;
}

export function getLocale(): string {
  if (typeof window.getLocale === 'function') return window.getLocale();
  return 'en';
}
