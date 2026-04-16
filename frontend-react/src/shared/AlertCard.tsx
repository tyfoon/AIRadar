// ---------------------------------------------------------------------------
// Unified AlertCard — renders all alert types consistently.
//
// Variants:
//   - Anomaly alerts (beaconing, VPN, IoT, inbound): only Manage Alert tab
//   - Service alerts (upload, service_access): Manage Alert + Block Activity tabs
//   - Snoozed state: dimmed, shows snooze expiry, cancel button
//   - Dismissed state: dimmed, strikethrough, trash button for permanent delete
//
// Design: matches alertcard-mockup.html v2.1
// ---------------------------------------------------------------------------
import { useState, useCallback, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import { createException, deleteException, upsertPolicy, fetchPolicies, fetchDeviceGroups } from './alertApi';
import type { ServicePolicy, DeviceGroup } from './alertApi';
import { formatBytes } from '../colors';

// Toast bridge to vanilla JS
declare global {
  interface Window {
    showToast?: (msg: string, type?: string) => void;
  }
}

// ---------------------------------------------------------------------------
// Alert type metadata
// ---------------------------------------------------------------------------
export const ALERT_META: Record<string, { icon: string; label: string; color: string }> = {
  beaconing_threat:     { icon: 'ph-siren',                label: 'Malware beacon',    color: 'red' },
  vpn_tunnel:           { icon: 'ph-lock-key',             label: 'VPN tunnel',        color: 'amber' },
  stealth_vpn_tunnel:   { icon: 'ph-mask-sad',             label: 'Stealth tunnel',    color: 'red' },
  upload:               { icon: 'ph-cloud-arrow-up',       label: 'Data upload',       color: 'amber' },
  service_access:       { icon: 'ph-cube',                 label: 'Service access',    color: 'indigo' },
  new_device:           { icon: 'ph-wifi-high',            label: 'New device',        color: 'blue' },
  iot_lateral_movement: { icon: 'ph-shuffle',              label: 'Lateral movement',  color: 'red' },
  iot_suspicious_port:  { icon: 'ph-plug',                 label: 'Suspicious port',   color: 'amber' },
  iot_new_country:      { icon: 'ph-globe-hemisphere-west',label: 'New country',       color: 'amber' },
  iot_volume_spike:     { icon: 'ph-chart-line-up',        label: 'Volume spike',      color: 'amber' },
  inbound_threat:       { icon: 'ph-shield-warning',       label: 'Inbound threat',    color: 'red' },
  inbound_port_scan:    { icon: 'ph-scan',                 label: 'Port scan',         color: 'amber' },
};

// Snooze-only types — no Block Activity tab available.
// new_device: informational, nothing to block.
// iot_volume_spike: ambiguous target.
// inbound_*: would need IP-ban API (CrowdSec/iptables), not service policy.
export const ANOMALY_TYPES = new Set([
  'new_device', 'iot_volume_spike',
]);
const INBOUND_TYPES = new Set(['inbound_threat', 'inbound_port_scan']);

// All other alert types get both Manage Alert + Block Activity tabs:
// vpn_tunnel, stealth_vpn_tunnel, beaconing_threat → block via iptables/policy
// iot_lateral_movement, iot_suspicious_port, iot_new_country → block dest/service
// upload, service_access → block via DNS/policy (original behavior)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
export interface AlertData {
  /** Unique id for keying / matching */
  alert_id: string;
  mac_address: string;
  alert_type: string;
  /** Service name or destination (used as exception destination) */
  service_or_dest: string;
  category?: string;
  /** Friendly device name */
  device_name: string;
  /** Human-readable description line */
  description: string;
  /** Country code for flag display (2-letter ISO) */
  country_code?: string;
  /** Severity badge text */
  severity?: string;
  /** When the alert was created */
  timestamp: string;
  /** Number of hits/connections */
  hits?: number;
  /** Total bytes transferred */
  total_bytes?: number;
  /** Beacon score (for beaconing alerts) */
  beacon_score?: number;
  /** Favicon URL for service icon */
  favicon_url?: string;
  /** Exception ID if this alert is dismissed/snoozed */
  exception_id?: number;
  /** If snoozed, when the snooze expires */
  snoozed_until?: string;
  /** Whether alert is permanently dismissed */
  is_dismissed?: boolean;
}

export interface AlertCardProps {
  alert: AlertData;
  /** Compact variant (smaller padding, single-line) */
  compact?: boolean;
  /** Show trash button instead of dismiss (for detail pages with dismissed alerts) */
  showTrash?: boolean;
  /** Called after any action (dismiss, snooze, policy change, delete) */
  onAction?: (alertId: string, action: string) => void;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function timeAgo(ts: string): string {
  const diff = (Date.now() - new Date(ts).getTime()) / 1000;
  if (diff < 60) return 'just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h`;
  return `${Math.floor(diff / 86400)}d`;
}

function snoozeExpiry(hours: number): string {
  return new Date(Date.now() + hours * 3600_000).toISOString();
}

// Color utilities — Tailwind can't do dynamic classes, so we map them
const COLOR_MAP: Record<string, { bg: string; bgDim: string; text: string; border: string; borderDim: string }> = {
  red:    { bg: 'bg-red-500/10',    bgDim: 'bg-slate-500/10',    text: 'text-red-500',    border: 'border-red-800/40',    borderDim: 'border-slate-700/30' },
  amber:  { bg: 'bg-amber-500/10',  bgDim: 'bg-slate-500/10',    text: 'text-amber-500',  border: 'border-amber-800/40',  borderDim: 'border-slate-700/30' },
  blue:   { bg: 'bg-blue-500/10',   bgDim: 'bg-slate-500/10',    text: 'text-blue-500',   border: 'border-blue-800/40',   borderDim: 'border-slate-700/30' },
  indigo: { bg: 'bg-indigo-500/10', bgDim: 'bg-slate-500/10',    text: 'text-indigo-500', border: 'border-indigo-800/40', borderDim: 'border-slate-700/30' },
  slate:  { bg: 'bg-slate-500/10',  bgDim: 'bg-slate-500/10',    text: 'text-slate-500',  border: 'border-slate-700/40',  borderDim: 'border-slate-700/30' },
};

// ---------------------------------------------------------------------------
// AlertCard Component
// ---------------------------------------------------------------------------
export default function AlertCard({ alert, compact = false, showTrash = false, onAction }: AlertCardProps) {
  const [expanded, setExpanded] = useState(false);
  const [fading, setFading] = useState(false);
  const [tab, setTab] = useState<'alert' | 'activity'>('alert');

  const meta = ALERT_META[alert.alert_type] || { icon: 'ph-warning', label: alert.alert_type, color: 'slate' };
  const isAnomaly = ANOMALY_TYPES.has(alert.alert_type);
  const isInbound = INBOUND_TYPES.has(alert.alert_type);
  const isSnoozeOnly = isAnomaly || isInbound; // no Block Activity tab
  const isSnoozed = !!alert.snoozed_until && new Date(alert.snoozed_until) > new Date();
  const isDismissed = !!alert.is_dismissed;
  const colors = COLOR_MAP[meta.color] || COLOR_MAP.slate;

  // --- Action handlers ---

  const fadeAndCallback = useCallback((action: string) => {
    setFading(true);
    setTimeout(() => onAction?.(alert.alert_id, action), 200);
  }, [alert.alert_id, onAction]);

  const handleDismiss = useCallback(async () => {
    try {
      await createException({
        mac_address: alert.mac_address,
        alert_type: alert.alert_type,
        destination: alert.service_or_dest || null,
        dismissed_score: alert.beacon_score ?? null,
      });
      fadeAndCallback('dismiss');
    } catch (err) {
      window.showToast?.(`Failed to dismiss: ${(err as Error).message}`, 'error');
    }
  }, [alert, fadeAndCallback]);

  const handleSnooze = useCallback(async (hours: number) => {
    try {
      await createException({
        mac_address: alert.mac_address,
        alert_type: alert.alert_type,
        destination: alert.service_or_dest || null,
        expires_at: snoozeExpiry(hours),
        dismissed_score: alert.beacon_score ?? null,
      });
      fadeAndCallback('snooze');
    } catch (err) {
      window.showToast?.(`Failed to snooze: ${(err as Error).message}`, 'error');
    }
  }, [alert, fadeAndCallback]);

  const handlePermanent = useCallback(async () => {
    try {
      await createException({
        mac_address: alert.mac_address,
        alert_type: alert.alert_type,
        destination: alert.service_or_dest || null,
        dismissed_score: alert.beacon_score ?? null,
        // expires_at = null means permanent
      });
      fadeAndCallback('permanent');
    } catch (err) {
      window.showToast?.(`Failed to silence: ${(err as Error).message}`, 'error');
    }
  }, [alert, fadeAndCallback]);

  const handleCancelSnooze = useCallback(async () => {
    if (alert.exception_id) {
      try {
        await deleteException(alert.exception_id);
        onAction?.(alert.alert_id, 'unsnooze');
      } catch (err) {
        window.showToast?.(`Failed: ${(err as Error).message}`, 'error');
      }
    }
  }, [alert, onAction]);

  const handleDelete = useCallback(async () => {
    if (alert.exception_id) {
      try {
        await deleteException(alert.exception_id);
        fadeAndCallback('delete');
      } catch (err) {
        window.showToast?.(`Failed to delete: ${(err as Error).message}`, 'error');
      }
    }
  }, [alert, fadeAndCallback]);

  const handleCustomSnooze = useCallback(async (isoDate: string) => {
    try {
      await createException({
        mac_address: alert.mac_address,
        alert_type: alert.alert_type,
        destination: alert.service_or_dest || null,
        expires_at: isoDate,
        dismissed_score: alert.beacon_score ?? null,
      });
      fadeAndCallback('snooze');
    } catch (err) {
      window.showToast?.(`Failed to snooze: ${(err as Error).message}`, 'error');
    }
  }, [alert, fadeAndCallback]);

  // --- Snoozed state ---
  if (isSnoozed) {
    const until = new Date(alert.snoozed_until!).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return (
      <div className={`bg-white/[0.02] border ${colors.borderDim} rounded-xl opacity-50 transition-all ${fading ? 'opacity-0 scale-95' : ''}`}>
        <div className={`flex items-center gap-3 ${compact ? 'px-3 py-2.5' : 'px-4 py-3'}`}>
          <div className={`flex-shrink-0 ${compact ? 'w-7 h-7' : 'w-8 h-8'} rounded-lg ${colors.bg} flex items-center justify-center`}>
            <i className={`ph-duotone ${meta.icon} ${compact ? 'text-sm' : 'text-base'} ${colors.text}`} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-slate-200">{meta.label}</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-blue-500/15 text-blue-400 font-medium flex items-center gap-1">
                <i className="ph-duotone ph-clock text-xs" /> Snoozed until {until}
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              <span className="text-slate-300">{alert.device_name}</span>
              <span className="mx-1 text-slate-600">&rarr;</span>
              {alert.description}
            </p>
          </div>
          <button
            onClick={handleCancelSnooze}
            className="flex-shrink-0 p-1.5 rounded-lg hover:bg-white/[0.08] text-slate-500 hover:text-slate-300 transition-colors"
            title="Cancel snooze"
          >
            <i className="ph-duotone ph-alarm text-base" />
          </button>
        </div>
      </div>
    );
  }

  // --- Dismissed state (detail pages) ---
  if (isDismissed && showTrash) {
    return (
      <div className={`bg-white/[0.02] border ${colors.borderDim} rounded-xl opacity-40 transition-all ${fading ? 'opacity-0 scale-95' : ''}`}>
        <div className={`flex items-center gap-3 ${compact ? 'px-3 py-2.5' : 'px-4 py-3'}`}>
          <div className={`flex-shrink-0 ${compact ? 'w-7 h-7' : 'w-8 h-8'} rounded-lg bg-slate-500/10 flex items-center justify-center`}>
            <i className={`ph-duotone ${meta.icon} ${compact ? 'text-sm' : 'text-base'} text-slate-500`} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-slate-400 line-through">{meta.label}</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-slate-500/15 text-slate-500 font-medium">
                {alert.snoozed_until ? 'Permanently ignored' : 'Dismissed'}
              </span>
            </div>
            <p className="text-[11px] text-slate-500 mt-0.5">
              <span className="text-slate-400">{alert.device_name}</span>
              <span className="mx-1 text-slate-600">&rarr;</span>
              {alert.description}
            </p>
          </div>
          {alert.timestamp && (
            <span className="text-[10px] text-slate-600 tabular-nums flex-shrink-0">{timeAgo(alert.timestamp)}</span>
          )}
          <button
            onClick={handleDelete}
            className="flex-shrink-0 p-1.5 rounded-lg hover:bg-red-500/15 text-slate-600 hover:text-red-400 transition-colors"
            title="Delete permanently"
          >
            <i className="ph-duotone ph-trash text-base" />
          </button>
        </div>
      </div>
    );
  }

  // --- Active state (default) ---
  return (
    <div className={`bg-white/[0.03] border ${colors.border} rounded-xl transition-all duration-200 ${fading ? 'opacity-0 scale-95' : ''}`}>
      {/* Collapsed row */}
      <div className={`flex items-center gap-${compact ? '2.5' : '3'} ${compact ? 'px-3 py-2.5' : 'px-4 py-3'}`}>
        {/* Icon */}
        <div className={`flex-shrink-0 ${compact ? 'w-7 h-7' : 'w-8 h-8'} rounded-lg ${colors.bg} flex items-center justify-center`}>
          <i className={`ph-duotone ${meta.icon} ${compact ? 'text-sm' : 'text-base'} ${colors.text}`} />
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className={`${compact ? 'text-xs' : 'text-sm'} font-semibold text-slate-200`}>{meta.label}</span>
            {alert.severity && (
              <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-medium ${
                alert.severity === 'Critical' || alert.severity === 'HIGH'
                  ? 'bg-red-500/15 text-red-400'
                  : 'bg-amber-500/15 text-amber-400'
              }`}>
                {alert.severity}
              </span>
            )}
          </div>
          <p className="text-[11px] text-slate-400 mt-0.5">
            <span className="text-slate-300">{alert.device_name}</span>
            <span className="mx-1 text-slate-600">&rarr;</span>
            {alert.favicon_url && (
              <img src={alert.favicon_url} className="inline w-3.5 h-3.5 rounded-sm mr-1" alt="" />
            )}
            <span>{alert.description}</span>
            {alert.country_code && (
              <span className="ml-1.5">
                <span className={`fi fi-${alert.country_code.toLowerCase()} rounded-sm text-[10px]`} />
              </span>
            )}
            {alert.hits != null && alert.hits > 0 && (
              <>
                <span className="mx-1 text-slate-600">&middot;</span>
                <span>{alert.hits} conn</span>
              </>
            )}
            {alert.total_bytes != null && alert.total_bytes > 0 && (
              <>
                <span className="mx-1 text-slate-600">&middot;</span>
                <span>{formatBytes(alert.total_bytes)}</span>
              </>
            )}
          </p>
        </div>

        {/* Timestamp */}
        <span className="text-[10px] text-slate-500 tabular-nums flex-shrink-0">{timeAgo(alert.timestamp)}</span>

        {/* Action icons */}
        <button
          onClick={handleDismiss}
          className={`flex-shrink-0 ${compact ? 'p-1' : 'p-1.5'} rounded-lg hover:bg-emerald-500/15 text-slate-500 hover:text-emerald-400 transition-colors`}
          title="Dismiss this alert (won't appear again)"
        >
          <i className={`ph-duotone ph-check-circle ${compact ? 'text-sm' : 'text-base'}`} />
        </button>
        <button
          onClick={() => setExpanded(!expanded)}
          className={`flex-shrink-0 ${compact ? 'p-1' : 'p-1.5'} rounded-lg ${
            expanded
              ? 'bg-white/[0.06] text-slate-300'
              : 'hover:bg-white/[0.08] text-slate-500 hover:text-slate-300'
          } transition-colors`}
          title="Snooze, silence, or block this activity"
        >
          <i className={`ph-duotone ph-dots-three-circle ${compact ? 'text-sm' : 'text-base'}`} />
        </button>
      </div>

      {/* Expanded panel */}
      {expanded && (
        <div className="border-t border-white/[0.05] bg-white/[0.015]">
          {isSnoozeOnly ? (
            // Anomalies + inbound: single manage-alert panel, no tabs
            <ManageAlertPanel
              onSnooze={handleSnooze}
              onPermanent={handlePermanent}
              onCustom={handleCustomSnooze}
              isAnomaly={isAnomaly}
              isInbound={isInbound}
            />
          ) : (
            // Service alerts: tabs for Manage Alert + Block Activity
            <>
              <div className="flex gap-1 px-4 pt-3 pb-0">
                <button
                  onClick={() => setTab('alert')}
                  className={`px-3 py-1.5 rounded-t-lg text-xs font-medium transition-colors ${
                    tab === 'alert'
                      ? 'bg-white/[0.08] text-slate-200'
                      : 'text-slate-500 hover:text-slate-300'
                  }`}
                  title="Snooze or permanently silence this alert"
                >
                  <i className="ph-duotone ph-bell-slash text-xs" /> Manage Alert
                </button>
                <button
                  onClick={() => setTab('activity')}
                  className={`px-3 py-1.5 rounded-t-lg text-xs font-medium transition-colors ${
                    tab === 'activity'
                      ? 'bg-white/[0.08] text-slate-200'
                      : 'text-slate-500 hover:text-slate-300'
                  }`}
                  title="Block, allow, or set alerts for this service"
                >
                  <i className="ph-duotone ph-shield-warning text-xs" /> Block Activity
                </button>
              </div>
              {tab === 'alert' && (
                <ManageAlertPanel
                  onSnooze={handleSnooze}
                  onPermanent={handlePermanent}
                  onCustom={handleCustomSnooze}
                />
              )}
              {tab === 'activity' && (
                <BlockActivityPanel
                  mac={alert.mac_address}
                  serviceName={alert.service_or_dest}
                  category={alert.category}
                  deviceName={alert.device_name}
                  onDone={() => onAction?.(alert.alert_id, 'policy')}
                />
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Manage Alert Panel (snooze / silence)
// ---------------------------------------------------------------------------
function ManageAlertPanel({
  onSnooze,
  onPermanent,
  onCustom,
  isAnomaly = false,
  isInbound = false,
}: {
  onSnooze: (hours: number) => void;
  onPermanent: () => void;
  onCustom: (iso: string) => void;
  isAnomaly?: boolean;
  isInbound?: boolean;
}) {
  const [showCustom, setShowCustom] = useState(false);
  const dtRef = useRef<HTMLInputElement>(null);

  return (
    <div className="px-4 py-3 border-t border-white/[0.04]">
      {(isAnomaly || isInbound) && (
        <div className="flex items-center gap-2 mb-2.5">
          <i className="ph-duotone ph-bell-slash text-xs text-slate-500" />
          <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Manage alert</span>
          <span className="text-[10px] text-slate-600 ml-1">— does not affect the traffic itself</span>
        </div>
      )}
      {!isAnomaly && !isInbound && (
        <p className="text-[10px] text-slate-500 mb-2.5">Snooze or silence this warning — does not affect the traffic itself.</p>
      )}

      {!showCustom ? (
        <div className="flex flex-wrap gap-1.5">
          {[1, 4, 8, 24].map(h => (
            <button
              key={h}
              onClick={() => onSnooze(h)}
              className="px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-blue-500/15 border border-white/[0.06] hover:border-blue-500/20 text-slate-400 hover:text-blue-300 text-xs font-medium transition-colors"
              title={`Snooze for ${h} hour${h > 1 ? 's' : ''}`}
            >
              {h}h
            </button>
          ))}
          <button
            onClick={() => setShowCustom(true)}
            className="px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.06] text-slate-400 text-xs font-medium transition-colors"
            title="Pick a custom date and time"
          >
            <i className="ph-duotone ph-clock-countdown text-xs" /> Custom...
          </button>
          <span className="w-px bg-white/[0.06] mx-0.5" />
          <button
            onClick={onPermanent}
            className="px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.06] text-slate-400 text-xs font-medium transition-colors"
            title="Permanently silence — never show again"
          >
            Permanent
          </button>
        </div>
      ) : (
        <div className="flex items-center gap-2">
          <input
            ref={dtRef}
            type="datetime-local"
            className="flex-1 bg-white/[0.06] border border-white/[0.08] rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
          <button
            onClick={() => {
              const v = dtRef.current?.value;
              if (v) onCustom(new Date(v).toISOString());
            }}
            className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-colors"
          >
            Set
          </button>
          <button
            onClick={() => setShowCustom(false)}
            className="px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] text-slate-400 text-xs font-medium transition-colors"
          >
            Cancel
          </button>
        </div>
      )}

      {isAnomaly && (
        <p className="text-[10px] text-slate-600 mt-2.5 italic">
          <i className="ph-duotone ph-info text-xs" />{' '}
          Network anomalies can only be snoozed or silenced — use the Rules page to block specific services.
        </p>
      )}
      {isInbound && (
        <p className="text-[10px] text-slate-600 mt-2.5 italic">
          <i className="ph-duotone ph-info text-xs" />{' '}
          Inbound attacks are blocked by CrowdSec automatically. Snooze to hide this alert.
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Block Activity Panel (scope + action + duration)
// ---------------------------------------------------------------------------
type Scope = 'global' | 'group' | 'device';
type PolicyAction = 'allow' | 'alert' | 'block';

function BlockActivityPanel({
  mac,
  serviceName,
  category,
  deviceName,
  onDone,
}: {
  mac: string;
  serviceName?: string;
  category?: string;
  deviceName: string;
  onDone?: () => void;
}) {
  const [scope, setScope] = useState<Scope>('device');
  const [action, setAction] = useState<PolicyAction>('block');
  const [pending, setPending] = useState(false);
  const [showCustom, setShowCustom] = useState(false);
  const dtRef = useRef<HTMLInputElement>(null);

  // Fetch device groups to show Group option
  const { data: groups = [] } = useQuery<DeviceGroup[]>({
    queryKey: ['device-groups', mac],
    queryFn: () => fetchDeviceGroups(mac),
    staleTime: 120_000,
  });

  // Fetch existing policy for this service
  const { data: existingPolicies = [] } = useQuery<ServicePolicy[]>({
    queryKey: ['policies', mac, serviceName, category],
    queryFn: () => fetchPolicies({ service_name: serviceName || undefined }),
    staleTime: 30_000,
  });

  // Find matching existing rule
  const existingRule = existingPolicies.find(p => {
    if (serviceName && p.service_name === serviceName) return true;
    if (category && p.category === category) return true;
    return false;
  });

  const applyPolicy = useCallback(async (expiresAt?: string | null) => {
    setPending(true);
    try {
      await upsertPolicy({
        scope,
        mac_address: scope === 'device' ? mac : null,
        group_id: scope === 'group' && groups.length > 0 ? groups[0].id : null,
        service_name: serviceName || null,
        category: !serviceName ? (category || null) : null,
        action,
        expires_at: expiresAt ?? null,
      });
      const scopeLabel = scope === 'global' ? 'globally' : scope === 'group' ? `for ${groups[0]?.name || 'group'}` : `for ${deviceName}`;
      window.showToast?.(`${serviceName || category || 'Service'}: ${action} ${scopeLabel}`, 'success');
      onDone?.();
    } catch (err) {
      window.showToast?.(`Failed: ${(err as Error).message}`, 'error');
    } finally {
      setPending(false);
    }
  }, [scope, action, mac, serviceName, category, groups, deviceName, onDone]);

  const handleRemoveRule = useCallback(async () => {
    if (!existingRule) return;
    setPending(true);
    try {
      const r = await fetch(`/api/policies/${existingRule.id}`, { method: 'DELETE' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      window.showToast?.('Rule removed', 'success');
      onDone?.();
    } catch (err) {
      window.showToast?.(`Failed: ${(err as Error).message}`, 'error');
    } finally {
      setPending(false);
    }
  }, [existingRule, onDone]);

  const firstGroup = groups[0];

  return (
    <div className="px-4 py-3 border-t border-white/[0.04]">
      <p className="text-[10px] text-slate-500 mb-2.5">Block or allow this service — affects actual network traffic.</p>

      {/* Scope + Action on one row */}
      <div className="flex items-start gap-4 mb-3">
        {/* Scope */}
        <div>
          <span className="text-[10px] text-slate-500 block mb-1.5">Apply to</span>
          <div className="flex items-center gap-1 bg-white/[0.04] rounded-lg p-0.5">
            <ScopeButton
              active={scope === 'global'}
              onClick={() => setScope('global')}
              icon="ph-globe"
              label="Global"
              tooltip="Apply to all devices on the network"
            />
            {firstGroup && (
              <ScopeButton
                active={scope === 'group'}
                onClick={() => setScope('group')}
                icon="ph-users-three"
                label="Group"
                tooltip={`Apply to all devices in '${firstGroup.name}'`}
              />
            )}
            <ScopeButton
              active={scope === 'device'}
              onClick={() => setScope('device')}
              icon="ph-device-mobile"
              label="Device"
              tooltip={`Apply only to ${deviceName}`}
            />
          </div>
        </div>

        {/* Action */}
        <div>
          <span className="text-[10px] text-slate-500 block mb-1.5">Action</span>
          <div className="flex gap-1 bg-white/[0.04] rounded-lg p-0.5">
            <ActionButton
              active={action === 'allow'}
              onClick={() => setAction('allow')}
              icon="ph-check"
              label="Allow"
              tooltip="Explicitly allow — override any broader block rule"
              color="emerald"
            />
            <ActionButton
              active={action === 'alert'}
              onClick={() => setAction('alert')}
              icon="ph-warning"
              label="Alert"
              tooltip="Allow but show a warning when used"
              color="amber"
            />
            <ActionButton
              active={action === 'block'}
              onClick={() => setAction('block')}
              icon="ph-x"
              label="Block"
              tooltip="Block all traffic to this service"
              color="red"
            />
          </div>
        </div>
      </div>

      {/* Duration */}
      <div>
        <span className="text-[10px] text-slate-500 block mb-1.5">Duration</span>
        {!showCustom ? (
          <div className="flex flex-wrap gap-1.5">
            {[1, 4, 8, 24].map(h => (
              <button
                key={h}
                disabled={pending}
                onClick={() => applyPolicy(snoozeExpiry(h))}
                className="px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-blue-500/15 border border-white/[0.06] hover:border-blue-500/20 text-slate-400 hover:text-blue-300 text-xs font-medium transition-colors disabled:opacity-50"
                title={`${action === 'block' ? 'Block' : action === 'allow' ? 'Allow' : 'Alert'} for ${h} hour${h > 1 ? 's' : ''}`}
              >
                {h}h
              </button>
            ))}
            <button
              onClick={() => setShowCustom(true)}
              className="px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.06] text-slate-400 text-xs font-medium transition-colors"
              title="Pick a custom date and time"
            >
              <i className="ph-duotone ph-clock-countdown text-xs" /> Custom...
            </button>
            <span className="w-px bg-white/[0.06] mx-0.5" />
            <button
              disabled={pending}
              onClick={() => applyPolicy(null)}
              className="px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.06] text-slate-400 text-xs font-medium transition-colors disabled:opacity-50"
              title={`${action === 'block' ? 'Block' : action === 'allow' ? 'Allow' : 'Alert'} permanently — never expires`}
            >
              Permanent
            </button>
          </div>
        ) : (
          <div className="flex items-center gap-2">
            <input
              ref={dtRef}
              type="datetime-local"
              className="flex-1 bg-white/[0.06] border border-white/[0.08] rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
            <button
              disabled={pending}
              onClick={() => {
                const v = dtRef.current?.value;
                if (v) applyPolicy(new Date(v).toISOString());
              }}
              className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-colors disabled:opacity-50"
            >
              Set
            </button>
            <button
              onClick={() => setShowCustom(false)}
              className="px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] text-slate-400 text-xs font-medium transition-colors"
            >
              Cancel
            </button>
          </div>
        )}
      </div>

      {/* Existing rule indicator */}
      {existingRule && (
        <div className="mt-3 flex items-center gap-2 text-[10px]">
          <i className={`ph-duotone ph-shield-warning text-xs ${existingRule.action === 'block' ? 'text-red-400' : existingRule.action === 'allow' ? 'text-emerald-400' : 'text-amber-400'}`} />
          <span className={existingRule.action === 'block' ? 'text-red-400' : existingRule.action === 'allow' ? 'text-emerald-400' : 'text-amber-400'}>
            Currently {existingRule.action}ed {existingRule.scope === 'global' ? 'globally' : `for ${existingRule.scope}`}
            {existingRule.expires_at ? ` until ${new Date(existingRule.expires_at).toLocaleString()}` : ' (permanent)'}
          </span>
          <button
            onClick={handleRemoveRule}
            disabled={pending}
            className="text-slate-500 hover:text-red-400 underline transition-colors ml-1 disabled:opacity-50"
            title="Remove the existing rule"
          >
            Remove rule
          </button>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Small UI pieces
// ---------------------------------------------------------------------------

function ScopeButton({ active, onClick, icon, label, tooltip }: {
  active: boolean; onClick: () => void; icon: string; label: string; tooltip: string;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors ${
        active
          ? 'bg-blue-600 text-white shadow-sm'
          : 'text-slate-400 hover:text-slate-300'
      }`}
      title={tooltip}
    >
      <i className={`ph-duotone ${icon} text-xs`} /> {label}
    </button>
  );
}

function ActionButton({ active, onClick, icon, label, tooltip, color }: {
  active: boolean; onClick: () => void; icon: string; label: string; tooltip: string; color: string;
}) {
  const activeCls = color === 'red' ? 'bg-red-500 text-white shadow-sm font-semibold'
    : color === 'amber' ? 'bg-amber-500 text-white shadow-sm font-semibold'
    : 'bg-emerald-500 text-white shadow-sm font-semibold';

  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-1 px-3 py-1 rounded-md text-[11px] font-medium transition-colors ${
        active ? activeCls : 'text-slate-400'
      }`}
      title={tooltip}
    >
      <i className={`ph-duotone ${icon} text-xs`} /> {label}
    </button>
  );
}
