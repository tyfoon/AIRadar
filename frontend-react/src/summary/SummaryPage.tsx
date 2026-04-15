// Summary page — thin React shell that delegates alert rendering to vanilla
// helpers in app.js (_renderAlertCard, loadSummaryDashboard, generateSummaryAI,
// clearAllAlerts). React owns the layout, the 30s refresh interval, and the
// outer card chrome; the vanilla code keeps ownership of the per-alert DOM
// because _renderAlertCard has deep ties to module-local state (_summaryAlerts,
// _reputationCache) and its onclick handlers expect those globals.
//
// Contract with app.js:
//   - We render <div id="summary-alerts-container" /> which loadSummaryDashboard
//     fills via innerHTML. React never touches that node after first render.
//   - <button id="btn-clear-all-alerts"> and <button id="summary-ai-btn"> use
//     the same IDs that clearAllAlerts() / generateSummaryAI() read.
//   - <div id="summary-ai-response" /> is filled by generateSummaryAI().
// This keeps the migration surgical — no duplicated alert rendering logic.

import { useEffect, useRef } from 'react';

declare global {
  interface Window {
    loadSummaryDashboard?: () => Promise<void>;
    generateSummaryAI?: () => Promise<void>;
    clearAllAlerts?: () => Promise<void>;
    t?: (key: string, params?: Record<string, string>) => string;
  }
}

function tr(key: string, fallback: string): string {
  try {
    const v = window.t?.(key);
    if (v && v !== key) return v;
  } catch { /* ignore */ }
  return fallback;
}

export default function SummaryPage() {
  // Guard so a rapid remount doesn't fire two parallel fetches
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    let cancelled = false;

    const tick = () => {
      if (cancelled) return;
      window.loadSummaryDashboard?.();
    };

    // Initial load + 30s refresh, mirroring other React pages' refetch cadence.
    tick();
    timerRef.current = window.setInterval(tick, 30_000);

    return () => {
      cancelled = true;
      if (timerRef.current != null) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    };
  }, []);

  return (
    <section className="space-y-6">
      {/* AI Assistant Card */}
      <div className="relative overflow-hidden bg-gradient-to-br from-indigo-50 via-white to-purple-50 dark:from-indigo-950/30 dark:via-white/[0.03] dark:to-purple-950/30 border border-indigo-200 dark:border-indigo-700/30 rounded-xl p-6">
        <div className="absolute -top-8 -right-8 w-32 h-32 bg-indigo-500/10 dark:bg-indigo-500/15 rounded-full blur-3xl" />
        <div className="relative flex items-start justify-between gap-4">
          <div className="flex items-start gap-3 min-w-0 flex-1">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center flex-shrink-0 shadow-lg shadow-indigo-500/30">
              <i className="ph-duotone ph-sparkle text-xl text-white" />
            </div>
            <div className="flex-1 min-w-0">
              <h3 className="text-base font-semibold text-slate-800 dark:text-white">
                {tr('summary.aiTitle', 'AI Samenvatting')}
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {tr('summary.aiSubtitle', 'Laat Gemini de actieve meldingen in gewone taal uitleggen.')}
              </p>
            </div>
          </div>
          <button
            id="summary-ai-btn"
            onClick={() => window.generateSummaryAI?.()}
            className="flex-shrink-0 px-4 py-2 rounded-lg bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white text-xs font-semibold shadow-lg shadow-indigo-500/30 transition-all active:scale-95"
          >
            <span className="inline-flex items-center gap-1.5">
              <span className="text-sm">✨</span>
              <span>{tr('summary.aiButton', 'Genereer AI Samenvatting')}</span>
            </span>
          </button>
        </div>
        {/* Filled by generateSummaryAI() — React leaves this node alone */}
        <div id="summary-ai-response" className="mt-4 hidden" />
      </div>

      {/* Action Inbox */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
            {tr('summary.inboxTitle', 'Actie Inbox')}
          </h3>
          <button
            id="btn-clear-all-alerts"
            onClick={() => window.clearAllAlerts?.()}
            className="flex-shrink-0 px-4 py-2 rounded-lg bg-slate-500 hover:bg-slate-600 text-white text-xs font-semibold shadow-sm transition-colors active:scale-95 hidden"
          >
            <span className="inline-flex items-center gap-1.5">
              <i className="ph-duotone ph-broom text-sm" />
              <span>{tr('summary.clearAll', 'Clear all alerts')}</span>
            </span>
          </button>
        </div>
        {/* Filled by loadSummaryDashboard() — React must not re-render children.
            We pass an empty children prop so React's reconciler keeps hands off. */}
        <div id="summary-alerts-container" className="space-y-3">
          <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-8 text-center">
            <div className="inline-block w-6 h-6 border-2 border-slate-300 dark:border-slate-600 border-t-indigo-500 rounded-full animate-spin" />
            <p className="text-sm text-slate-400 dark:text-slate-500 mt-3">
              {tr('summary.loading', 'Meldingen ophalen...')}
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
