import { useState, useCallback, useMemo } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { fetchActiveAlerts, fetchAiSummary } from './api';
import type { ActiveAlert } from './types';
import AlertCard, { ANOMALY_TYPES } from '../shared/AlertCard';
import type { AlertData } from '../shared/AlertCard';
// formatBytes imported via AlertCard internally
import { useDeviceLookup } from '../utils/useDeviceLookup';

function tr(key: string, fallback: string): string {
  try {
    const v = (window as any).t?.(key);
    if (v && v !== key) return v;
  } catch { /* ignore */ }
  return fallback;
}

function serviceName(s: string): string {
  return s.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

// ---------------------------------------------------------------------------
// Map ActiveAlert -> AlertData for the unified AlertCard
// ---------------------------------------------------------------------------
function toAlertData(alert: ActiveAlert, nameByIp: (ip: string) => string): AlertData {
  const d = alert.details || {};

  // Build description based on alert type
  let description = '';
  let countryCode: string | undefined;
  let favicon: string | undefined;

  if (alert.alert_type === 'vpn_tunnel') {
    description = `${d.vpn_service || alert.service_or_dest}${d.dest_ip ? ` \u2192 ${d.dest_ip}` : ''}`;
  } else if (alert.alert_type === 'stealth_vpn_tunnel') {
    description = `${d.protocol || 'Unknown protocol'}${d.dest_ip ? ` \u2192 ${d.dest_ip}` : ''}`;
  } else if (alert.alert_type === 'beaconing_threat') {
    description = `${d.dest_sni || d.dest_ip || alert.service_or_dest}`;
    countryCode = d.country_code;
  } else if (alert.alert_type === 'new_device') {
    description = `${alert.vendor || 'Unknown vendor'}`;
  } else if (alert.alert_type === 'inbound_threat' || alert.alert_type === 'inbound_port_scan') {
    description = `from ${d.source_ip || '?'}${d.target_port ? ` \u2192 port ${d.target_port}` : ''}`;
    countryCode = d.country_code;
  } else if (alert.alert_type === 'iot_lateral_movement') {
    description = `${d.port_label || `port ${d.target_port}`}${d.target_ip ? ` \u2192 ${d.target_ip}` : ''}`;
  } else if (alert.alert_type === 'iot_volume_spike') {
    description = d.spike_detail || alert.service_or_dest;
  } else if (alert.alert_type === 'upload') {
    description = serviceName(alert.service_or_dest);
    if (d.dest_domain) {
      favicon = `https://www.google.com/s2/favicons?domain=${d.dest_domain}&sz=32`;
    }
  } else {
    description = serviceName(alert.service_or_dest);
  }

  // Device name: use display_name from alert, or fall back to useDeviceLookup
  const deviceName = alert.display_name || alert.hostname || nameByIp(alert.mac_address) || alert.mac_address;

  return {
    alert_id: alert.alert_id,
    mac_address: alert.mac_address,
    alert_type: alert.alert_type,
    service_or_dest: alert.service_or_dest,
    category: alert.category,
    device_name: deviceName,
    description,
    country_code: countryCode,
    severity: d.severity,
    timestamp: alert.timestamp,
    hits: alert.hits,
    total_bytes: alert.total_bytes,
    beacon_score: d.beacon_score,
    favicon_url: favicon,
  };
}

// ---------------------------------------------------------------------------
// AI Summary Card
// ---------------------------------------------------------------------------
function AiSummaryCard() {
  const [loading, setLoading] = useState(false);
  const [summary, setSummary] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const generate = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchAiSummary();
      setSummary(data.summary);
    } catch (err: any) {
      setError(err?.message || 'Failed to generate summary');
    } finally {
      setLoading(false);
    }
  };

  return (
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
          onClick={generate}
          disabled={loading}
          className="flex-shrink-0 px-4 py-2 rounded-lg bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white text-xs font-semibold shadow-lg shadow-indigo-500/30 transition-all active:scale-95 disabled:opacity-50"
        >
          {loading ? (
            <span className="inline-flex items-center gap-1.5">
              <span className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              <span>Generating...</span>
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5">
              <span className="text-sm">✨</span>
              <span>{tr('summary.aiButton', 'Genereer AI Samenvatting')}</span>
            </span>
          )}
        </button>
      </div>

      {summary && (
        <div className="relative mt-4 p-4 bg-white/60 dark:bg-white/[0.03] rounded-lg border border-indigo-100 dark:border-indigo-800/30">
          <p className="text-sm text-slate-700 dark:text-slate-300 whitespace-pre-wrap">{summary}</p>
        </div>
      )}

      {error && (
        <div className="relative mt-4 p-3 bg-red-50 dark:bg-red-950/20 rounded-lg">
          <p className="text-xs text-red-600 dark:text-red-400">{error}</p>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Summary Page
// ---------------------------------------------------------------------------
export default function SummaryPage() {
  const queryClient = useQueryClient();
  const { nameByIp } = useDeviceLookup();

  const { data, isLoading } = useQuery({
    queryKey: ['summary-alerts'],
    queryFn: () => fetchActiveAlerts(24),
    refetchInterval: 30_000,
  });

  const handleAction = useCallback((alertId: string, _action: string) => {
    // Optimistically remove from cache
    queryClient.setQueryData(['summary-alerts'], (old: AlertsResponse | undefined) => {
      if (!old) return old;
      return {
        ...old,
        count: old.count - 1,
        alerts: old.alerts.filter(a => a.alert_id !== alertId),
      };
    });
  }, [queryClient]);

  const handleClearAll = useCallback(async () => {
    if (!data?.alerts.length) return;
    const { createException } = await import('../shared/alertApi');
    let ok = 0, fail = 0;
    for (const alert of data.alerts) {
      try {
        await createException({
          mac_address: alert.mac_address,
          alert_type: alert.alert_type,
          destination: alert.service_or_dest || null,
          dismissed_score: alert.details?.beacon_score ?? null,
        });
        ok++;
      } catch { fail++; }
    }
    queryClient.invalidateQueries({ queryKey: ['summary-alerts'] });
    console.log(`[summary] Cleared ${ok} alerts, ${fail} failed`);
  }, [data, queryClient]);

  const alerts = data?.alerts ?? [];

  const alertCards = useMemo(() => {
    const anomalies = alerts.filter(a => ANOMALY_TYPES.has(a.alert_type));
    const standard = alerts.filter(a => !ANOMALY_TYPES.has(a.alert_type));
    return [...anomalies, ...standard].map(a => toAlertData(a, nameByIp));
  }, [alerts, nameByIp]);

  return (
    <section className="space-y-6">
      {/* AI Summary */}
      <AiSummaryCard />

      {/* Action Inbox */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">
            {tr('summary.inboxTitle', 'Actie Inbox')}
            {alerts.length > 0 && (
              <span className="ml-2 text-xs font-normal text-slate-400">({alerts.length})</span>
            )}
          </h3>
          {alerts.length > 1 && (
            <button
              onClick={handleClearAll}
              className="flex-shrink-0 px-4 py-2 rounded-lg bg-slate-500 hover:bg-slate-600 text-white text-xs font-semibold shadow-sm transition-colors active:scale-95"
            >
              <span className="inline-flex items-center gap-1.5">
                <i className="ph-duotone ph-broom text-sm" />
                <span>{tr('summary.clearAll', 'Clear all alerts')}</span>
              </span>
            </button>
          )}
        </div>

        {isLoading && (
          <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-8 text-center">
            <div className="inline-block w-6 h-6 border-2 border-slate-300 dark:border-slate-600 border-t-indigo-500 rounded-full animate-spin" />
            <p className="text-sm text-slate-400 dark:text-slate-500 mt-3">
              {tr('summary.loading', 'Meldingen ophalen...')}
            </p>
          </div>
        )}

        {!isLoading && alertCards.length === 0 && (
          <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-8 text-center">
            <i className="ph-duotone ph-shield-check text-4xl text-emerald-500" />
            <p className="text-sm font-medium text-slate-600 dark:text-slate-300 mt-3">
              {tr('summary.allClear', 'All clear — geen actieve meldingen')}
            </p>
          </div>
        )}

        {!isLoading && alertCards.length > 0 && (
          <div className="space-y-3">
            {alertCards.map(a => (
              <AlertCard key={a.alert_id} alert={a} onAction={handleAction} />
            ))}
          </div>
        )}
      </div>
    </section>
  );
}

// Re-export type for queryClient usage
type AlertsResponse = { count: number; window_hours: number; alerts: ActiveAlert[] };
