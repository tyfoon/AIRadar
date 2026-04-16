import { useState, useMemo, useCallback } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { fetchPrivacyStats, exportPrivacyCsvUrl } from './api';
import type {
  PrivacyStatsResponse, TopBlocked, TopTracker, RecentTracker,
  VpnAlert, BeaconAlert, BeaconStatus, SecurityStats,
} from './types';
import { svcColor, svcDisplayName, SvcBadge } from '../category/serviceHelpers';
import { useDeviceLookup } from '../utils/useDeviceLookup';
import AlertCard from '../shared/AlertCard';
import type { AlertData } from '../shared/AlertCard';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function formatNumber(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
  return String(n);
}

function fmtTime(ts: string): string {
  try {
    const d = new Date(ts.endsWith('Z') ? ts : ts + 'Z');
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch { return ts; }
}

/** Group blocked domains by company/category for the bar chart */
function groupBlockedByCompany(domains: TopBlocked[]): { label: string; count: number; domains: string[] }[] {
  const map = new Map<string, { count: number; domains: string[] }>();
  for (const d of domains) {
    const key = d.company || d.domain;
    const existing = map.get(key);
    if (existing) {
      existing.count += d.count;
      existing.domains.push(d.domain);
    } else {
      map.set(key, { count: d.count, domains: [d.domain] });
    }
  }
  return Array.from(map.entries())
    .map(([label, v]) => ({ label, count: v.count, domains: v.domains }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);
}

/** Collapse consecutive tracker events by key within 60s */
function collapseEvents(events: RecentTracker[]): (RecentTracker & { _count: number; _newest: string; _oldest: string })[] {
  if (!events.length) return [];
  const result: (RecentTracker & { _count: number; _newest: string; _oldest: string })[] = [];
  let current = { ...events[0], _count: 1, _newest: events[0].timestamp, _oldest: events[0].timestamp };
  const key = (e: RecentTracker) => `${e.service}|${e.detection_type}|${e.source_ip}`;

  for (let i = 1; i < events.length; i++) {
    const e = events[i];
    if (key(e) === key(current)) {
      const diff = Math.abs(new Date(current._oldest).getTime() - new Date(e.timestamp).getTime());
      if (diff < 60_000) {
        current._count++;
        current._oldest = e.timestamp;
        continue;
      }
    }
    result.push(current);
    current = { ...e, _count: 1, _newest: e.timestamp, _oldest: e.timestamp };
  }
  result.push(current);
  return result;
}

// Device-name lookup for this page is now handled by useDeviceLookup()
// (see utils/useDeviceLookup.ts). The old helper read window.deviceMap
// (which is MAC-keyed) with an IP, so it always missed and silently fell
// back to the raw IP — that's why every device column showed IP numbers.

// Periods
const PERIODS = [
  { label: 'Last hour', value: 60 },
  { label: 'Last 24h', value: 1440 },
  { label: 'Last 7d', value: 10080 },
  { label: 'All time', value: 0 },
] as const;

// Bar chart colors
const BAR_COLORS = [
  '#ef4444', '#f97316', '#f59e0b', '#84cc16', '#22c55e',
  '#14b8a6', '#06b6d4', '#3b82f6', '#8b5cf6', '#ec4899',
];

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------
export default function PrivacyPage() {
  const [period, setPeriod] = useState(1440);
  const [serviceFilter, setServiceFilter] = useState('');
  const [deviceFilter, _setDeviceFilter] = useState('');

  // IP → friendly device name lookup (shared cache with Devices page).
  const { nameByIp } = useDeviceLookup();

  // Expandable panels
  const [showBlocked, setShowBlocked] = useState(false);
  const [showTrackerDetails, setShowTrackerDetails] = useState(false);
  const [showVpnDetail, setShowVpnDetail] = useState(false);

  const queryClient = useQueryClient();

  const handleAlertAction = useCallback((_id: string, _action: string) => {
    // Refetch privacy stats to get updated alert list
    queryClient.invalidateQueries({ queryKey: ['privacy-stats'] });
  }, [queryClient]);

  const { data, isLoading, refetch } = useQuery<PrivacyStatsResponse>({
    queryKey: ['privacy-stats', period, serviceFilter, deviceFilter],
    queryFn: () => fetchPrivacyStats({
      service: serviceFilter || undefined,
      source_ip: deviceFilter || undefined,
      periodMinutes: period || undefined,
    }),
    refetchInterval: 30_000,
    staleTime: 15_000,
  });

  const adguard = data?.adguard;
  const trackers = data?.trackers;
  const vpnAlerts = data?.vpn_alerts ?? [];
  const beaconAlerts = data?.beaconing_alerts ?? [];
  const beaconStatus = data?.beaconing_status ?? null;
  const security = data?.security;

  // Grouped blocked for bar chart
  const groupedBlocked = useMemo(
    () => groupBlockedByCompany(adguard?.top_blocked ?? []),
    [adguard?.top_blocked],
  );

  // Top trackers for donut
  const topTrackers = useMemo(
    () => (trackers?.top_trackers ?? []).slice(0, 10),
    [trackers?.top_trackers],
  );

  // Collapsed recent events
  const collapsed = useMemo(
    () => collapseEvents(trackers?.recent ?? []),
    [trackers?.recent],
  );

  // Service options for filter
  const serviceOptions = useMemo(
    () => [...new Set((trackers?.top_trackers ?? []).map(t => t.service))].sort(),
    [trackers?.top_trackers],
  );

  // Active beacons (not dismissed)
  const activeBeacons = useMemo(
    () => beaconAlerts.filter(a => !a.dismissed),
    [beaconAlerts],
  );

  const handleExport = useCallback(() => {
    window.open(exportPrivacyCsvUrl(), '_blank');
  }, []);

  if (isLoading && !data) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* ── Stat Cards ── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        <StatCard label="DNS Lookups" value={formatNumber(adguard?.total_queries ?? 0)} />
        <StatCard
          label="Threats Blocked"
          value={formatNumber(adguard?.blocked_queries ?? 0)}
          subtitle={`${adguard?.block_percentage ?? 0}% of all traffic`}
          color="red"
          onClick={() => setShowBlocked(v => !v)}
          expandable
        />
        <StatCard
          label="Trackers Found"
          value={formatNumber(trackers?.total_detected ?? 0)}
          color="amber"
          onClick={() => setShowTrackerDetails(v => !v)}
          expandable
        />
        <StatCard
          label="Tracker Companies"
          value={String(topTrackers.length)}
          color="purple"
        />
        <VpnStatCard
          alerts={vpnAlerts}
          onClick={() => setShowVpnDetail(v => !v)}
        />
        <SecurityStatCard stats={security ?? null} beacons={activeBeacons} />
      </div>

      {/* ── VPN Detail Panel ── */}
      {showVpnDetail && (
        <ExpandablePanel
          title="VPN & Evasion Alerts"
          icon="ph-lock-key"
          color="orange"
          onClose={() => setShowVpnDetail(false)}
        >
          <VpnAlertsList alerts={vpnAlerts} onAction={handleAlertAction} />
        </ExpandablePanel>
      )}

      {/* ── Blocked Domains Panel ── */}
      {showBlocked && (
        <ExpandablePanel
          title="Blocked Domains"
          icon="ph-shield-warning"
          color="red"
          onClose={() => setShowBlocked(false)}
        >
          <BlockedDomainsList domains={adguard?.top_blocked ?? []} />
        </ExpandablePanel>
      )}

      {/* ── Tracker Details Panel ── */}
      {showTrackerDetails && (
        <ExpandablePanel
          title="Detected Trackers"
          icon="ph-eye"
          color="amber"
          onClose={() => setShowTrackerDetails(false)}
        >
          <TrackerDetailsList trackers={topTrackers} />
        </ExpandablePanel>
      )}

      {/* ── Beacon / C2 Alerts ── */}
      {(beaconAlerts.length > 0 || beaconStatus) && (
        <BeaconPanel alerts={beaconAlerts} status={beaconStatus} onAction={handleAlertAction} />
      )}

      {/* ── Filter Bar ── */}
      <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl px-4 py-3 flex flex-wrap items-center gap-3">
        <span className="text-xs text-slate-500 dark:text-slate-400 font-medium">Filters</span>
        <select
          value={serviceFilter}
          onChange={e => setServiceFilter(e.target.value)}
          className="text-xs px-2 py-1.5 rounded-lg border border-slate-200 dark:border-white/[0.1] bg-white dark:bg-white/[0.05] text-slate-700 dark:text-slate-300"
        >
          <option value="">All trackers</option>
          {serviceOptions.map(s => (
            <option key={s} value={s}>{svcDisplayName(s)}</option>
          ))}
        </select>
        <select
          value={period}
          onChange={e => setPeriod(Number(e.target.value))}
          className="text-xs px-2 py-1.5 rounded-lg border border-slate-200 dark:border-white/[0.1] bg-white dark:bg-white/[0.05] text-slate-700 dark:text-slate-300"
        >
          {PERIODS.map(p => (
            <option key={p.value} value={p.value}>{p.label}</option>
          ))}
        </select>
        <button
          onClick={() => refetch()}
          className="ml-auto px-3 py-1.5 rounded-lg bg-blue-700 hover:bg-blue-600 text-white text-xs font-medium transition-colors"
        >
          Apply
        </button>
        <button
          onClick={handleExport}
          className="px-3 py-1.5 rounded-lg bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-200 text-xs font-medium transition-colors"
        >
          Export CSV
        </button>
      </div>

      {/* ── Charts Row ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top Blocked bar chart */}
        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
          <h3 className="text-lg font-semibold text-slate-700 dark:text-slate-300 mb-4">Top Blocked</h3>
          {adguard?.status === 'ok' ? (
            groupedBlocked.length > 0 ? (
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={groupedBlocked} layout="vertical" margin={{ left: 80, right: 16, top: 4, bottom: 4 }}>
                  <XAxis type="number" tick={{ fontSize: 11 }} />
                  <YAxis
                    type="category"
                    dataKey="label"
                    tick={{ fontSize: 11 }}
                    width={75}
                    tickFormatter={(v: string) => v.length > 20 ? v.slice(0, 18) + '…' : v}
                  />
                  <Tooltip
                    contentStyle={{ fontSize: 12, borderRadius: 8, border: 'none', boxShadow: '0 4px 12px rgba(0,0,0,.15)' }}
                    formatter={(value: any, _: any, entry: any) => {
                      const domains = entry.payload.domains as string[];
                      const domainList = domains?.slice(0, 5).join('\n') + (domains?.length > 5 ? `\n+${domains.length - 5} more` : '');
                      return [formatNumber(Number(value)) + '\n' + domainList, 'Blocked'];
                    }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {groupedBlocked.map((_, i) => (
                      <Cell key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <p className="text-slate-400 dark:text-slate-500 text-center py-8 text-sm">No blocked domains yet.</p>
            )
          ) : (
            <p className="text-slate-400 dark:text-slate-500 text-center py-8 text-sm">
              Ad blocker not active on DNS yet.
            </p>
          )}
        </div>

        {/* Tracker Breakdown donut */}
        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
          <h3 className="text-lg font-semibold text-slate-700 dark:text-slate-300 mb-4">Tracker Breakdown</h3>
          {topTrackers.length > 0 ? (
            <div className="flex items-start gap-4">
              <div className="flex-shrink-0" style={{ width: 180, height: 180 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={topTrackers}
                      dataKey="hits"
                      nameKey="service"
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      innerRadius={40}
                      paddingAngle={2}
                    >
                      {topTrackers.map((t, i) => (
                        <Cell key={i} fill={svcColor(t.service)} />
                      ))}
                    </Pie>
                    <Tooltip
                      formatter={(value: any, name: any) => [formatNumber(Number(value)) + ' hits', svcDisplayName(String(name))]}
                      contentStyle={{ fontSize: 12, borderRadius: 8, border: 'none', boxShadow: '0 4px 12px rgba(0,0,0,.15)' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="flex flex-wrap gap-1.5 flex-1 min-w-0">
                {topTrackers.map(t => (
                  <span
                    key={t.service}
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium bg-slate-100 dark:bg-slate-700/50"
                  >
                    <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: svcColor(t.service) }} />
                    <span className="text-slate-600 dark:text-slate-300 truncate">{svcDisplayName(t.service)}</span>
                    <span className="text-slate-400 dark:text-slate-500">{formatNumber(t.hits)}</span>
                  </span>
                ))}
              </div>
            </div>
          ) : (
            <p className="text-slate-400 dark:text-slate-500 text-center py-8 text-sm">No trackers detected.</p>
          )}
        </div>
      </div>

      {/* ── Recent Tracker Activity Table ── */}
      <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
        <h3 className="text-lg font-semibold text-slate-700 dark:text-slate-300 mb-4">Recent Tracker Activity</h3>
        <div className="overflow-x-auto max-h-72 overflow-y-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400 font-medium border-b border-slate-200 dark:border-white/[0.05] sticky top-0 bg-white dark:bg-[#0B0C10]">
              <tr>
                <th className="py-3 px-4 font-medium">Time</th>
                <th className="py-3 px-4 font-medium">Tracker</th>
                <th className="py-3 px-4 font-medium">Type</th>
                <th className="py-3 px-4 font-medium">Source</th>
              </tr>
            </thead>
            <tbody className="text-slate-600 dark:text-slate-300">
              {collapsed.length === 0 ? (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-slate-400 dark:text-slate-500 text-sm">
                    No tracker activity detected.
                  </td>
                </tr>
              ) : (
                collapsed.map((e, i) => (
                  <tr key={i} className="border-b border-slate-100 dark:border-white/[0.04] hover:bg-slate-50 dark:hover:bg-slate-700/20">
                    <td className="py-3 px-4 text-xs tabular-nums text-slate-400 dark:text-slate-500 whitespace-nowrap">
                      {fmtTime(e._newest)}
                      {e._count > 1 && (
                        <span className="text-[10px] text-slate-400 dark:text-slate-500"> – {fmtTime(e._oldest)}</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <SvcBadge svc={e.service} />
                      {e._count > 1 && (
                        <span className="ml-1.5 text-[10px] px-1.5 py-0.5 rounded-full bg-slate-100 dark:bg-white/[0.08] text-slate-500 dark:text-slate-400 font-medium">
                          ×{e._count}
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-xs text-slate-500 dark:text-slate-400">
                      {e.detection_type === 'sni_hello' ? 'DNS Query' : e.detection_type}
                    </td>
                    <td className="py-3 px-4 text-xs text-slate-500 dark:text-slate-400" title={e.source_ip}>
                      {nameByIp(e.source_ip) !== e.source_ip ? (
                        <span className="text-slate-700 dark:text-slate-200">{nameByIp(e.source_ip)}</span>
                      ) : (
                        <span className="font-mono">{e.source_ip}</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function StatCard({ label, value, subtitle, color, onClick, expandable }: {
  label: string; value: string; subtitle?: string;
  color?: 'red' | 'amber' | 'purple';
  onClick?: () => void; expandable?: boolean;
}) {
  const colorClasses = {
    red: 'dark:bg-red-900/10 dark:border-red-700/30 text-red-500 dark:text-red-400',
    amber: 'dark:bg-amber-900/10 dark:border-amber-700/30 text-amber-500 dark:text-amber-400',
    purple: 'dark:bg-purple-900/10 dark:border-purple-700/30 text-purple-500 dark:text-purple-400',
  };
  const cc = color ? colorClasses[color] : '';
  return (
    <div
      className={`bg-white border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 transition-all ${cc} ${onClick ? 'cursor-pointer hover:shadow-md' : ''}`}
      onClick={onClick}
    >
      <p className={`text-xs font-medium ${color ? '' : 'text-slate-500 dark:text-slate-400'}`}>
        {label} {expandable && <span className="text-slate-400 dark:text-slate-500">▾</span>}
      </p>
      <p className={`text-2xl font-bold mt-2 tabular-nums ${color ? '' : 'text-slate-800 dark:text-white'}`}>{value}</p>
      {subtitle && <p className="text-[10px] text-slate-400 dark:text-slate-500 mt-1">{subtitle}</p>}
    </div>
  );
}

function VpnStatCard({ alerts, onClick }: { alerts: VpnAlert[]; onClick: () => void }) {
  const count = alerts.length;
  const isActive = count > 0;
  return (
    <div
      className={`bg-white border rounded-xl p-5 cursor-pointer transition-all hover:shadow-md ${
        isActive
          ? 'border-orange-500/40 dark:border-orange-500/30 dark:bg-orange-900/10'
          : 'border-slate-200 dark:border-white/[0.05] dark:bg-white/[0.03]'
      }`}
      onClick={onClick}
    >
      <p className="text-xs text-orange-500 dark:text-orange-400 font-medium">
        VPN Connections <span className="text-slate-400 dark:text-slate-500">▾</span>
      </p>
      <p className="text-2xl font-bold mt-2 tabular-nums text-orange-500 dark:text-orange-400">{count}</p>
      <p className="text-[10px] mt-1">
        <span className={isActive ? 'text-orange-500 dark:text-orange-400' : 'text-emerald-500 dark:text-emerald-400'}>
          {isActive ? `${count} device${count !== 1 ? 's' : ''} using VPN` : 'No tunnels detected'}
        </span>
      </p>
    </div>
  );
}

function SecurityStatCard({ stats, beacons }: { stats: SecurityStats | null; beacons: BeaconAlert[] }) {
  const total24h = stats?.total_24h ?? 0;
  const spark = stats?.sparkline_7d ?? [0, 0, 0, 0, 0, 0, 0];
  const max = Math.max(1, ...spark);
  const hasThreats = beacons.length > 0 || total24h > 0;

  return (
    <div className={`bg-white border rounded-xl p-5 transition-all ${
      hasThreats
        ? 'border-red-500/40 dark:border-red-500/30 dark:bg-red-900/10'
        : 'border-slate-200 dark:border-white/[0.05] dark:bg-white/[0.03]'
    }`}>
      <p className="text-xs text-slate-500 dark:text-slate-400 font-medium">Security 24h</p>
      <div className="flex items-end gap-3 mt-2">
        <p className={`text-2xl font-bold tabular-nums ${hasThreats ? 'text-red-500 dark:text-red-400' : ''}`}>{total24h}</p>
        {/* 7-day sparkline */}
        <svg viewBox="0 0 64 20" className="w-16 h-5 flex-shrink-0">
          {spark.map((v: number, i: number) => {
            const barW = 64 / 7;
            const gap = 1.5;
            const h = Math.max(2, (v / max) * 18);
            const x = i * barW + gap / 2;
            return (
              <rect
                key={i}
                x={x}
                y={20 - h}
                width={barW - gap}
                height={h}
                rx={0.5}
                fill={hasThreats ? '#ef4444' : '#94a3b8'}
                opacity={v > 0 ? 0.9 : 0.35}
              />
            );
          })}
        </svg>
      </div>
      <p className="text-[10px] text-slate-400 dark:text-slate-500 mt-1">
        {stats?.total_7d ?? 0} in 7 days
      </p>
    </div>
  );
}

function ExpandablePanel({ title, icon, color, onClose, children }: {
  title: string; icon: string; color: string; onClose: () => void; children: React.ReactNode;
}) {
  const bgMap: Record<string, string> = {
    orange: 'dark:bg-orange-900/5 dark:border-orange-700/20',
    red: 'dark:bg-red-900/5 dark:border-red-700/20',
    amber: 'dark:bg-amber-900/5 dark:border-amber-700/20',
  };
  const textMap: Record<string, string> = {
    orange: 'text-orange-500 dark:text-orange-400',
    red: 'text-red-500 dark:text-red-400',
    amber: 'text-amber-500 dark:text-amber-400',
  };
  return (
    <div className={`bg-white border border-slate-200 ${bgMap[color] ?? ''} rounded-xl p-5 transition-all`}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <i className={`ph-duotone ${icon} text-base ${textMap[color] ?? ''}`} />
          <h3 className={`text-lg font-semibold ${textMap[color] ?? ''}`}>{title}</h3>
        </div>
        <button onClick={onClose} className="text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-300">
          × Close
        </button>
      </div>
      {children}
    </div>
  );
}

function vpnToAlertData(a: VpnAlert): AlertData {
  const svcName = a.vpn_service?.startsWith('vpn_')
    ? svcDisplayName(a.vpn_service)
    : a.vpn_service || 'VPN';
  return {
    alert_id: `vpn-${a.mac_address || a.source_ip}-${a.vpn_service}`,
    mac_address: a.mac_address || '',
    alert_type: a.is_stealth ? 'stealth_vpn_tunnel' : 'vpn_tunnel',
    service_or_dest: a.vpn_service || '',
    device_name: a.display_name || a.hostname || a.source_ip,
    description: svcName,
    severity: a.is_stealth ? 'Stealth' : undefined,
    timestamp: a.last_seen,
    hits: a.hits,
    total_bytes: a.total_bytes,
  };
}

function VpnAlertsList({ alerts, onAction }: { alerts: VpnAlert[]; onAction?: (id: string, action: string) => void }) {
  if (alerts.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-6 text-center">
        <div className="w-10 h-10 rounded-full bg-emerald-500/10 dark:bg-emerald-500/15 flex items-center justify-center mb-2">
          <i className="ph-duotone ph-shield-check text-xl text-emerald-500 dark:text-emerald-400" />
        </div>
        <p className="text-sm text-slate-500 dark:text-slate-400">No VPN or evasion tunnels detected.</p>
        <p className="text-[10px] text-slate-400 dark:text-slate-500 mt-1">Monitoring for VPN, Tor, and stealth tunnels.</p>
      </div>
    );
  }
  return (
    <div className="space-y-2">
      {alerts.map((a, i) => (
        <AlertCard
          key={`vpn-${i}`}
          alert={vpnToAlertData(a)}
          onAction={onAction}
        />
      ))}
    </div>
  );
}

function BlockedDomainsList({ domains }: { domains: TopBlocked[] }) {
  if (domains.length === 0) {
    return <p className="text-sm text-slate-400 py-4 text-center">No blocked domains.</p>;
  }
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 max-h-64 overflow-y-auto">
      {domains.slice(0, 50).map((d, i) => (
        <div key={i} className="flex items-center justify-between px-3 py-1.5 rounded bg-slate-50 dark:bg-white/[0.03] text-xs">
          <span className="text-slate-600 dark:text-slate-300 truncate mr-2">{d.domain}</span>
          <span className="text-red-500 dark:text-red-400 font-medium tabular-nums flex-shrink-0">{formatNumber(d.count)}</span>
        </div>
      ))}
    </div>
  );
}

function TrackerDetailsList({ trackers }: { trackers: TopTracker[] }) {
  if (trackers.length === 0) {
    return <p className="text-sm text-slate-400 py-4 text-center">No trackers detected.</p>;
  }
  const maxHits = Math.max(1, ...trackers.map(t => t.hits));
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 max-h-64 overflow-y-auto">
      {trackers.map((t, i) => (
        <div key={i} className="relative px-3 py-2 rounded bg-slate-50 dark:bg-white/[0.03] overflow-hidden">
          <div
            className="absolute inset-y-0 left-0 opacity-10"
            style={{ width: `${(t.hits / maxHits) * 100}%`, backgroundColor: svcColor(t.service) }}
          />
          <div className="relative flex items-center justify-between">
            <SvcBadge svc={t.service} />
            <span className="text-xs font-medium tabular-nums text-slate-600 dark:text-slate-300">{formatNumber(t.hits)}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function beaconToAlertData(a: BeaconAlert): AlertData {
  const dest = a.dest_sni || a.dest_ptr || a.dest_ip;
  let description = dest;
  if (a.dest_asn_org) description += ` (${a.dest_asn_org})`;
  if (a.score) description += ` · Score: ${a.score}`;

  return {
    alert_id: `beacon-${a.mac_address || a.source_ip}-${a.dest_ip}`,
    mac_address: a.mac_address || '',
    alert_type: 'beaconing_threat',
    service_or_dest: a.dest_sni || a.dest_ip,
    device_name: a.display_name || a.hostname || a.source_ip,
    description,
    country_code: a.dest_country || undefined,
    severity: a.score >= 70 ? 'Critical' : a.score >= 40 ? 'HIGH' : undefined,
    timestamp: a.last_seen,
    hits: a.total_hits || a.hits,
    total_bytes: a.total_bytes || 0,
    beacon_score: a.score,
    is_dismissed: a.dismissed,
  };
}

function BeaconPanel({ alerts, status, onAction }: { alerts: BeaconAlert[]; status: BeaconStatus | null; onAction?: (id: string, action: string) => void }) {
  const active = alerts.filter(a => !a.dismissed);
  const dismissed = alerts.filter(a => a.dismissed);
  const hasActive = active.length > 0;

  return (
    <div className={`bg-white border rounded-xl p-5 ${
      hasActive
        ? 'border-red-500/30 dark:border-red-700/40 dark:bg-red-900/5'
        : 'border-slate-200 dark:border-white/[0.05] dark:bg-white/[0.03]'
    }`}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <i className="ph-duotone ph-radar text-base text-slate-500 dark:text-slate-400" />
          <h3 className="text-lg font-semibold text-slate-700 dark:text-slate-300">Beaconing / C2 Threats</h3>
          {hasActive ? (
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-red-500 text-white font-bold animate-pulse">
              {active.length} threats
            </span>
          ) : (
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400 font-medium">
              All clear
            </span>
          )}
        </div>
      </div>

      {hasActive && (
        <div className="mb-3 px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700/40 flex items-start gap-2">
          <i className="ph-duotone ph-warning text-base mt-0.5 text-red-500 flex-shrink-0" />
          <p className="text-xs text-red-700 dark:text-red-300">
            <span className="font-semibold">Warning:</span>{' '}
            One or more devices are exhibiting highly periodic outbound connection patterns consistent with malware command & control traffic.
          </p>
        </div>
      )}

      {alerts.length === 0 ? (
        <div className="flex items-center gap-2.5 text-emerald-600 dark:text-emerald-400">
          <i className="ph-duotone ph-shield-check text-xl flex-shrink-0" />
          <span className="text-sm font-medium">No suspicious malware beacons detected.</span>
        </div>
      ) : (
        <div className="space-y-2">
          {/* Active alerts with full actions */}
          {active.map((a, i) => (
            <AlertCard
              key={`beacon-active-${i}`}
              alert={beaconToAlertData(a)}
              onAction={onAction}
            />
          ))}
          {/* Dismissed alerts with trash button */}
          {dismissed.map((a, i) => (
            <AlertCard
              key={`beacon-dismissed-${i}`}
              alert={beaconToAlertData(a)}
              showTrash
              onAction={onAction}
            />
          ))}
        </div>
      )}

      {/* Scanner status footer */}
      {status && <BeaconStatusFooter status={status} />}
    </div>
  );
}

function BeaconStatusFooter({ status }: { status: BeaconStatus }) {
  let line: string;
  let cls = 'text-slate-400 dark:text-slate-500';

  if (status.last_error) {
    line = `Scanner error: ${status.last_error}`;
    cls = 'text-red-500 dark:text-red-400';
  } else if (status.running && status.scans_completed === 0) {
    line = 'First scan in progress…';
  } else if (status.scans_completed === 0) {
    line = 'Warming up — first scan starts ~90s after restart.';
  } else {
    const when = status.last_scan_at ? fmtTime(status.last_scan_at) : '—';
    const pLabel = status.last_findings === 1 ? '1 pattern found' : `${status.last_findings} patterns found`;
    line = `Last scan: ${when} · ${pLabel}`;
  }

  return (
    <div className={`mt-3 pt-2 border-t border-slate-100 dark:border-white/[0.04] text-[11px] ${cls} flex items-center gap-1.5`}>
      <i className="ph-duotone ph-clock text-xs flex-shrink-0" />
      <span>{line}</span>
    </div>
  );
}
