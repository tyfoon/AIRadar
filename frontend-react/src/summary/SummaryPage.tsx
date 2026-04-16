import { useState, useCallback } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { fetchActiveAlerts, dismissAlert, fetchAiSummary } from './api';
import type { ActiveAlert } from './types';
import { formatBytes } from '../colors';

// ---------------------------------------------------------------------------
// Alert type metadata
// ---------------------------------------------------------------------------
const ALERT_META: Record<string, { icon: string; label: string; color: string; severity?: string }> = {
  beaconing_threat:     { icon: 'ph-siren',           label: 'Malware beacon',   color: 'red',    severity: 'critical' },
  vpn_tunnel:           { icon: 'ph-lock-key',        label: 'VPN tunnel',       color: 'amber' },
  stealth_vpn_tunnel:   { icon: 'ph-mask-sad',        label: 'Stealth tunnel',   color: 'red' },
  upload:               { icon: 'ph-upload-simple',   label: 'Data upload',      color: 'amber' },
  service_access:       { icon: 'ph-globe-simple',    label: 'Service access',   color: 'indigo' },
  new_device:           { icon: 'ph-wifi-high',       label: 'New device',       color: 'blue' },
  iot_lateral_movement: { icon: 'ph-arrows-left-right', label: 'Lateral movement', color: 'red' },
  iot_suspicious_port:  { icon: 'ph-warning',         label: 'Suspicious port',  color: 'red' },
  iot_new_country:      { icon: 'ph-globe-hemisphere-west', label: 'New country', color: 'red' },
  iot_volume_spike:     { icon: 'ph-chart-line-up',   label: 'Volume spike',     color: 'amber' },
  inbound_threat:       { icon: 'ph-shield-warning',  label: 'Inbound threat',   color: 'red' },
  inbound_port_scan:    { icon: 'ph-magnifying-glass', label: 'Port scan',       color: 'amber' },
};

const ANOMALY_TYPES = new Set([
  'beaconing_threat', 'vpn_tunnel', 'stealth_vpn_tunnel', 'new_device',
  'iot_lateral_movement', 'iot_suspicious_port', 'iot_new_country',
  'iot_volume_spike', 'inbound_threat', 'inbound_port_scan',
]);

function tr(key: string, fallback: string): string {
  try {
    const v = (window as any).t?.(key);
    if (v && v !== key) return v;
  } catch { /* ignore */ }
  return fallback;
}

function timeAgo(ts: string): string {
  const diff = (Date.now() - new Date(ts).getTime()) / 1000;
  if (diff < 60) return 'just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function deviceName(alert: ActiveAlert): string {
  return alert.display_name || alert.hostname || alert.mac_address;
}

function serviceName(s: string): string {
  return s.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

// ---------------------------------------------------------------------------
// Alert Card
// ---------------------------------------------------------------------------
function AlertCard({ alert, onDismiss }: { alert: ActiveAlert; onDismiss: (alert: ActiveAlert, expiresAt?: string) => void }) {
  const [expanded, setExpanded] = useState(false);
  const [fading, setFading] = useState(false);

  const meta = ALERT_META[alert.alert_type] || { icon: 'ph-warning', label: alert.alert_type, color: 'slate' };
  const isAnomaly = ANOMALY_TYPES.has(alert.alert_type);

  const handleDismiss = (expiresAt?: string) => {
    setFading(true);
    setTimeout(() => onDismiss(alert, expiresAt), 200);
  };

  const snoozeHours = (h: number) => {
    const exp = new Date(Date.now() + h * 3600_000).toISOString();
    handleDismiss(exp);
  };

  // Build description based on alert type
  let description = '';
  const d = alert.details;
  if (alert.alert_type === 'vpn_tunnel') {
    description = `${d.vpn_service || alert.service_or_dest}${d.dest_ip ? ` → ${d.dest_ip}` : ''}`;
  } else if (alert.alert_type === 'stealth_vpn_tunnel') {
    description = `${d.protocol || 'Unknown protocol'}${d.dest_ip ? ` → ${d.dest_ip}` : ''}`;
  } else if (alert.alert_type === 'beaconing_threat') {
    description = `${d.dest_sni || d.dest_ip || alert.service_or_dest}${d.country_code ? ` (${d.country_code})` : ''}`;
  } else if (alert.alert_type === 'new_device') {
    description = `${alert.vendor || 'Unknown vendor'}`;
  } else if (alert.alert_type === 'inbound_threat' || alert.alert_type === 'inbound_port_scan') {
    description = `from ${d.source_ip || '?'}${d.country_code ? ` (${d.country_code})` : ''}${d.target_port ? ` → port ${d.target_port}` : ''}`;
  } else if (alert.alert_type === 'iot_lateral_movement') {
    description = `${d.port_label || `port ${d.target_port}`}${d.target_ip ? ` → ${d.target_ip}` : ''}`;
  } else if (alert.alert_type === 'iot_volume_spike') {
    description = d.spike_detail || alert.service_or_dest;
  } else {
    description = serviceName(alert.service_or_dest);
  }

  const borderColor = isAnomaly ? 'border-red-200 dark:border-red-900/40' : 'border-slate-200 dark:border-white/[0.05]';
  const bgColor = isAnomaly ? 'bg-red-50/50 dark:bg-red-950/20' : 'bg-white dark:bg-white/[0.03]';

  return (
    <div
      className={`${bgColor} border ${borderColor} rounded-xl p-4 transition-all duration-200 ${fading ? 'opacity-0 scale-95' : ''}`}
    >
      <div className="flex items-start gap-3">
        {/* Icon */}
        <div className={`w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 bg-${meta.color}-100 dark:bg-${meta.color}-900/30`}>
          <i className={`ph-duotone ${meta.icon} text-lg text-${meta.color}-500`} />
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold text-slate-800 dark:text-slate-200 truncate">
              {deviceName(alert)}
            </span>
            <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-medium bg-${meta.color}-100 dark:bg-${meta.color}-900/30 text-${meta.color}-700 dark:text-${meta.color}-400`}>
              {meta.label}
            </span>
            {d.severity && (
              <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-bold ${
                d.severity === 'Critical' || d.severity === 'HIGH' ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400' :
                'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400'
              }`}>
                {d.severity}
              </span>
            )}
          </div>

          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 truncate">
            {description}
          </p>

          <div className="flex items-center gap-3 mt-1 text-[10px] text-slate-400">
            <span>{timeAgo(alert.timestamp)}</span>
            <span>{alert.hits} {alert.hits === 1 ? 'hit' : 'hits'}</span>
            {alert.total_bytes > 0 && <span>{formatBytes(alert.total_bytes)}</span>}
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-1 flex-shrink-0">
          <button
            onClick={() => handleDismiss()}
            title="Dismiss"
            className="w-8 h-8 rounded-lg flex items-center justify-center text-emerald-500 hover:bg-emerald-50 dark:hover:bg-emerald-900/20 transition-colors"
          >
            <i className="ph-duotone ph-check text-lg" />
          </button>
          <button
            onClick={() => setExpanded(!expanded)}
            title="More actions"
            className="w-8 h-8 rounded-lg flex items-center justify-center text-slate-400 hover:bg-slate-100 dark:hover:bg-white/[0.05] transition-colors"
          >
            <i className={`ph-duotone ${expanded ? 'ph-caret-up' : 'ph-dots-three'} text-lg`} />
          </button>
        </div>
      </div>

      {/* Expanded actions */}
      {expanded && (
        <div className="mt-3 pt-3 border-t border-slate-200 dark:border-white/[0.05] flex flex-wrap items-center gap-2">
          <span className="text-[10px] text-slate-400 mr-1">Snooze:</span>
          {[1, 4, 8].map(h => (
            <button
              key={h}
              onClick={() => snoozeHours(h)}
              className="text-[10px] px-2 py-1 rounded-md bg-slate-100 dark:bg-white/[0.05] text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-white/[0.08] transition-colors"
            >
              {h}h
            </button>
          ))}
          <div className="w-px h-4 bg-slate-200 dark:bg-white/10 mx-1" />
          <button
            onClick={() => handleDismiss()}
            className="text-[10px] px-2 py-1 rounded-md bg-slate-100 dark:bg-white/[0.05] text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-white/[0.08] transition-colors"
          >
            Ignore permanently
          </button>
          {!isAnomaly && (
            <a
              href={`#/rules`}
              className="text-[10px] px-2 py-1 rounded-md bg-indigo-50 dark:bg-indigo-900/20 text-indigo-600 dark:text-indigo-400 hover:bg-indigo-100 dark:hover:bg-indigo-900/30 transition-colors"
            >
              Set rule →
            </a>
          )}
        </div>
      )}
    </div>
  );
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

  const { data, isLoading } = useQuery({
    queryKey: ['summary-alerts'],
    queryFn: () => fetchActiveAlerts(24),
    refetchInterval: 30_000,
  });

  const handleDismiss = useCallback(async (alert: ActiveAlert, expiresAt?: string) => {
    try {
      await dismissAlert(
        alert.mac_address,
        alert.alert_type,
        alert.service_or_dest,
        expiresAt,
        alert.details?.beacon_score,
      );
      // Optimistically remove from cache
      queryClient.setQueryData(['summary-alerts'], (old: AlertsResponse | undefined) => {
        if (!old) return old;
        return {
          ...old,
          count: old.count - 1,
          alerts: old.alerts.filter(a => a.alert_id !== alert.alert_id),
        };
      });
    } catch (err) {
      console.error('Failed to dismiss alert:', err);
    }
  }, [queryClient]);

  const handleClearAll = useCallback(async () => {
    if (!data?.alerts.length) return;
    const alerts = data.alerts;
    let ok = 0, fail = 0;
    for (const alert of alerts) {
      try {
        await dismissAlert(alert.mac_address, alert.alert_type, alert.service_or_dest);
        ok++;
      } catch { fail++; }
    }
    queryClient.invalidateQueries({ queryKey: ['summary-alerts'] });
    console.log(`[summary] Cleared ${ok} alerts, ${fail} failed`);
  }, [data, queryClient]);

  const alerts = data?.alerts ?? [];
  const anomalies = alerts.filter(a => ANOMALY_TYPES.has(a.alert_type));
  const standard = alerts.filter(a => !ANOMALY_TYPES.has(a.alert_type));

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

        {!isLoading && alerts.length === 0 && (
          <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-8 text-center">
            <i className="ph-duotone ph-shield-check text-4xl text-emerald-500" />
            <p className="text-sm font-medium text-slate-600 dark:text-slate-300 mt-3">
              {tr('summary.allClear', 'All clear — geen actieve meldingen')}
            </p>
          </div>
        )}

        {!isLoading && alerts.length > 0 && (
          <div className="space-y-3">
            {/* Anomalies first */}
            {anomalies.map(a => (
              <AlertCard key={a.alert_id} alert={a} onDismiss={handleDismiss} />
            ))}
            {/* Then standard alerts */}
            {standard.map(a => (
              <AlertCard key={a.alert_id} alert={a} onDismiss={handleDismiss} />
            ))}
          </div>
        )}
      </div>
    </section>
  );
}

// Re-export type for queryClient usage
type AlertsResponse = { count: number; window_hours: number; alerts: ActiveAlert[] };
