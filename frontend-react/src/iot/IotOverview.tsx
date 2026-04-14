import { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip as RTooltip,
  ResponsiveContainer,
} from 'recharts';
import {
  forceSimulation, forceLink, forceManyBody, forceCenter, forceCollide,
} from 'd3-force';
import type { SimulationNodeDatum, SimulationLinkDatum } from 'd3-force';
import { fetchFleet, fetchAnomalies, fetchTrafficHistory, fetchNetworkGraph, dismissAnomaly } from './api';
import type { FleetDevice, Anomaly, IotTab, TrafficHistoryResponse, NetworkNode, NetworkEdge } from './types';
import type { NetworkGraphResponse } from './types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function fmtBytes(b: number): string {
  if (b >= 1099511627776) return (b / 1099511627776).toFixed(2) + ' TB';
  if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GB';
  if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
  if (b >= 1024) return (b / 1024).toFixed(0) + ' KB';
  return b + ' B';
}

function fmtNumber(n: number): string {
  return n >= 1000 ? n.toLocaleString() : String(n);
}

function timeAgo(iso: string | null): string {
  if (!iso) return '—';
  const d = Date.now() - new Date(iso).getTime();
  if (d < 60000) return 'just now';
  if (d < 3600000) return `${Math.floor(d / 60000)}m ago`;
  if (d < 86400000) return `${Math.floor(d / 3600000)}h ago`;
  return `${Math.floor(d / 86400000)}d ago`;
}

function FlagIcon({ cc, size = '1em' }: { cc: string; size?: string }) {
  if (!cc || cc.length !== 2) return null;
  return <span className={`fi fi-${cc.toLowerCase()} rounded-sm shadow-sm inline-block`} style={{ fontSize: size }} />;
}

function deviceName(d: { display_name?: string | null; hostname?: string | null; mac_address?: string; ips?: string[] }): string {
  return d.display_name || d.hostname || d.ips?.[0] || d.mac_address || '?';
}

const HEALTH_RING: Record<string, string> = {
  green: 'ring-emerald-500/40',
  orange: 'ring-amber-500/50',
  red: 'ring-red-500/50',
};
const HEALTH_DOT: Record<string, string> = {
  green: 'bg-emerald-500',
  orange: 'bg-amber-500',
  red: 'bg-red-500',
};

const DETECTION_LABELS: Record<string, { label: string; icon: string; color: string }> = {
  iot_lateral_movement: { label: 'Lateral movement', icon: 'ph-flow-arrow', color: 'text-red-500' },
  iot_suspicious_port: { label: 'Suspicious port', icon: 'ph-warning-octagon', color: 'text-amber-500' },
  iot_new_country: { label: 'New country', icon: 'ph-globe-hemisphere-west', color: 'text-indigo-500' },
  iot_volume_spike: { label: 'Volume spike', icon: 'ph-chart-line-up', color: 'text-orange-500' },
};

function isDarkMode(): boolean {
  return typeof document !== 'undefined' && document.documentElement.classList.contains('dark');
}

const PORT_LABELS: Record<number, string> = {
  22: 'SSH', 23: 'Telnet', 25: 'SMTP', 80: 'HTTP', 443: 'HTTPS',
  445: 'SMB', 3306: 'MySQL', 3389: 'RDP', 5432: 'Postgres', 5900: 'VNC',
  6379: 'Redis', 8080: 'HTTP-alt', 8443: 'HTTPS-alt', 27017: 'MongoDB',
};

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------
export default function IotOverview() {
  const [tab, setTab] = useState<IotTab>('anomalies');
  const [networkHours, setNetworkHours] = useState(24);
  const queryClient = useQueryClient();

  const { data: fleet, isLoading: fleetLoading } = useQuery({
    queryKey: ['iot-fleet'],
    queryFn: fetchFleet,
    staleTime: 30_000,
    refetchInterval: 60_000,
  });
  const { data: anomalyData } = useQuery({
    queryKey: ['iot-anomalies'],
    queryFn: () => fetchAnomalies(24),
    staleTime: 30_000,
    refetchInterval: 60_000,
  });
  const { data: networkData } = useQuery({
    queryKey: ['iot-network', networkHours],
    queryFn: () => fetchNetworkGraph(networkHours),
    staleTime: 60_000,
    enabled: tab === 'network',
  });

  const anomalies = anomalyData?.anomalies || [];
  const activeAnomalies = anomalies.filter(a => !a.dismissed);
  const devices = fleet?.devices || [];

  const handleDismiss = useCallback(async (a: Anomaly) => {
    if (!confirm(`Dismiss this ${DETECTION_LABELS[a.detection_type]?.label || a.detection_type} alert and whitelist it?`)) return;
    await dismissAnomaly(a.source_ip, a.detection_type, a.detail);
    queryClient.invalidateQueries({ queryKey: ['iot-anomalies'] });
    queryClient.invalidateQueries({ queryKey: ['iot-fleet'] });
  }, [queryClient]);

  const tabCls = (key: IotTab) => {
    const base = 'relative inline-flex items-center gap-1.5 px-4 py-1.5 rounded-md text-xs font-medium transition-colors';
    return key === tab
      ? `${base} bg-blue-700 text-white shadow-sm`
      : `${base} text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300`;
  };

  const badge = (n: number, color = 'bg-slate-600 dark:bg-slate-300 text-white dark:text-slate-900') =>
    n > 0 ? <span className={`ml-1 min-w-[18px] h-4 px-1.5 rounded-full text-[10px] font-semibold leading-4 text-center tabular-nums ${color}`}>{n}</span> : null;

  return (
    <div className="space-y-4">
      {/* Tabs */}
      <div className="flex items-center gap-1 bg-slate-100 dark:bg-white/[0.04] rounded-lg p-1 w-fit">
        <button className={tabCls('anomalies')} onClick={() => setTab('anomalies')}>
          <i className="ph-duotone ph-warning text-sm" /> Anomalies
          {badge(activeAnomalies.length, activeAnomalies.length > 0 ? 'bg-red-600 text-white' : 'bg-slate-600 dark:bg-slate-300 text-white dark:text-slate-900')}
        </button>
        <button className={tabCls('fleet')} onClick={() => setTab('fleet')}>
          <i className="ph-duotone ph-cpu text-sm" /> IoT Fleet
          {badge(devices.length)}
        </button>
        <button className={tabCls('network')} onClick={() => setTab('network')}>
          <i className="ph-duotone ph-graph text-sm" /> Internal Traffic
        </button>
      </div>

      {/* Stats (always visible) */}
      <StatsRow fleet={fleet || null} anomalyCount={activeAnomalies.length} loading={fleetLoading} />

      {/* Tab panels */}
      {tab === 'anomalies' && (
        <AnomaliesPanel anomalies={anomalies} onDismiss={handleDismiss} />
      )}
      {tab === 'fleet' && (
        <FleetPanel devices={devices} loading={fleetLoading} />
      )}
      {tab === 'network' && (
        <NetworkPanel
          data={networkData || null}
          hours={networkHours}
          onHoursChange={setNetworkHours}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Stats row
// ---------------------------------------------------------------------------
function StatsRow({ fleet, anomalyCount, loading }: {
  fleet: { total_devices: number; total_bytes_24h: number; top_talker: string | null } | null;
  anomalyCount: number;
  loading: boolean;
}) {
  const skeleton = 'h-7 w-20 bg-slate-200 dark:bg-white/[0.06] rounded animate-pulse';
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      <StatCard label="IoT Devices" loading={loading}>
        <span className="text-xl font-bold tabular-nums">{fleet?.total_devices ?? 0}</span>
      </StatCard>
      <StatCard label="Data (24h)" loading={loading}>
        <span className="text-xl font-bold tabular-nums">{fmtBytes(fleet?.total_bytes_24h ?? 0)}</span>
      </StatCard>
      <StatCard label="Anomalies" loading={loading} highlight={anomalyCount > 0}>
        <span className={`text-xl font-bold tabular-nums ${anomalyCount > 0 ? 'text-red-500' : ''}`}>{anomalyCount}</span>
      </StatCard>
      <StatCard label="Top Talker" loading={loading}>
        <span className="text-lg font-bold truncate">{fleet?.top_talker ?? '—'}</span>
      </StatCard>
    </div>
  );
}

function StatCard({ label, children, loading, highlight }: {
  label: string; children: React.ReactNode; loading?: boolean; highlight?: boolean;
}) {
  return (
    <div className={`bg-white dark:bg-white/[0.03] border rounded-xl p-4 ${
      highlight ? 'border-red-300 dark:border-red-800/50' : 'border-slate-200 dark:border-white/[0.05]'
    }`}>
      <p className="text-[11px] text-slate-400 dark:text-slate-500 font-medium">{label}</p>
      <div className="mt-1">
        {loading ? <div className="h-7 w-20 bg-slate-200 dark:bg-white/[0.06] rounded animate-pulse" /> : children}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Anomalies panel
// ---------------------------------------------------------------------------
function AnomaliesPanel({ anomalies, onDismiss }: { anomalies: Anomaly[]; onDismiss: (a: Anomaly) => void }) {
  const sorted = useMemo(() => {
    const active = anomalies.filter(a => !a.dismissed).sort((a, b) => b.last_seen.localeCompare(a.last_seen));
    const dismissed = anomalies.filter(a => a.dismissed).sort((a, b) => b.last_seen.localeCompare(a.last_seen));
    return [...active, ...dismissed];
  }, [anomalies]);

  if (sorted.length === 0) {
    return (
      <div className="py-12 text-center text-sm text-slate-400">
        <i className="ph-duotone ph-shield-check text-3xl block mb-2 opacity-40" />
        No anomalies detected in the last 24 hours
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {sorted.map((a, i) => <AnomalyCard key={`${a.source_ip}-${a.detection_type}-${a.detail}-${i}`} anomaly={a} onDismiss={onDismiss} />)}
    </div>
  );
}

function AnomalyCard({ anomaly: a, onDismiss }: { anomaly: Anomaly; onDismiss: (a: Anomaly) => void }) {
  const meta = DETECTION_LABELS[a.detection_type] || { label: a.detection_type, icon: 'ph-question', color: 'text-slate-500' };
  const name = a.display_name || a.hostname || a.source_ip;

  // Parse detail for human-readable info
  let detailLine = a.detail;
  let newCountryCC: string | null = null;
  if (a.detection_type === 'iot_lateral_movement') {
    const m = a.detail.match(/lateral_(\d+)_(.+)/);
    if (m) detailLine = `→ ${m[2]} on port ${m[1]} (${PORT_LABELS[+m[1]] || 'unknown'})`;
  } else if (a.detection_type === 'iot_suspicious_port') {
    const m = a.detail.match(/port_(\d+)/);
    if (m) detailLine = `Port ${m[1]} (${PORT_LABELS[+m[1]] || 'unusual'})`;
  } else if (a.detection_type === 'iot_new_country') {
    const m = a.detail.match(/country_([A-Z]{2})/);
    if (m) newCountryCC = m[1];
  }

  return (
    <div className={`bg-white dark:bg-white/[0.03] border rounded-xl p-4 transition-all ${
      a.dismissed
        ? 'border-slate-200 dark:border-white/[0.04] opacity-50'
        : 'border-red-200 dark:border-red-800/40 shadow-sm'
    }`}>
      <div className="flex items-center gap-3">
        {/* Icon */}
        <div className={`flex-shrink-0 w-9 h-9 rounded-lg flex items-center justify-center ${
          a.dismissed ? 'bg-slate-100 dark:bg-white/[0.04]' : 'bg-red-50 dark:bg-red-900/20'
        }`}>
          <i className={`ph-duotone ${meta.icon} text-lg ${meta.color}`} />
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <p className="text-xs font-semibold text-slate-700 dark:text-slate-200">{meta.label}</p>
            {a.dismissed && (
              <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-white/[0.05] text-slate-400 font-medium">dismissed</span>
            )}
          </div>
          <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
            <span className="font-medium text-slate-600 dark:text-slate-300">{name}</span>
            {' — '}
            {newCountryCC ? <><FlagIcon cc={newCountryCC} /> New country: {newCountryCC}</> : detailLine}
          </p>
        </div>

        {/* Stats */}
        <div className="flex-shrink-0 text-right text-[10px] text-slate-400">
          <p className="tabular-nums">{fmtNumber(a.hits)} hits</p>
          <p>{timeAgo(a.last_seen)}</p>
        </div>

        {/* Dismiss */}
        {!a.dismissed && (
          <button onClick={() => onDismiss(a)}
            className="flex-shrink-0 p-1.5 rounded-lg text-slate-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
            title="Dismiss & whitelist">
            <i className="ph-duotone ph-x-circle text-base" />
          </button>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Fleet panel
// ---------------------------------------------------------------------------
function FleetPanel({ devices, loading }: { devices: FleetDevice[]; loading: boolean }) {
  if (loading) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4 h-48 animate-pulse" />
        ))}
      </div>
    );
  }

  if (devices.length === 0) {
    return (
      <div className="py-12 text-center text-sm text-slate-400">
        <i className="ph-duotone ph-cpu text-3xl block mb-2 opacity-40" />
        No IoT devices detected yet
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
      {devices.map(d => <FleetCard key={d.mac_address} device={d} />)}
    </div>
  );
}

function FleetCard({ device: d }: { device: FleetDevice }) {
  const name = deviceName(d);
  const healthRing = HEALTH_RING[d.health] || HEALTH_RING.green;

  // Throughput bar: current vs baseline
  const ratio = d.baseline_avg_bytes_24h && d.baseline_avg_bytes_24h > 0
    ? d.bytes_24h / d.baseline_avg_bytes_24h
    : null;
  const barPct = ratio ? Math.min(ratio * 100, 300) / 3 : null; // normalize to 0-100
  const barColor = ratio && ratio > 3 ? 'bg-red-500' : ratio && ratio > 2 ? 'bg-amber-500' : 'bg-blue-500';

  return (
    <div
      className={`bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4 ring-2 ${healthRing} cursor-pointer hover:shadow-md transition-all`}
      onClick={() => {
        if (typeof (window as any).openDeviceDrawer === 'function') {
          (window as any).openDeviceDrawer(d.mac_address, null, null);
        }
      }}
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2 min-w-0">
          <div className="relative">
            <i className="ph-duotone ph-cpu text-lg text-slate-500 dark:text-slate-400" />
            {d.online && (
              <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-emerald-500 ring-2 ring-white dark:ring-slate-900" />
            )}
          </div>
          <div className="min-w-0">
            <p className="text-xs font-semibold text-slate-700 dark:text-slate-200 truncate">{name}</p>
            <p className="text-[10px] text-slate-400 truncate">{d.vendor || d.device_type}</p>
          </div>
        </div>
        <BaselineBadge status={d.baseline_status} days={d.baseline_days} />
      </div>

      {/* Sparkline */}
      <Sparkline mac={d.mac_address} />

      {/* Stats row */}
      <div className="flex items-center justify-between mt-2 text-[10px] text-slate-500 dark:text-slate-400">
        <span className="tabular-nums">{fmtBytes(d.bytes_24h)}</span>
        <span className="flex items-center gap-1">
          <span className="text-amber-500">↑{fmtBytes(d.orig_bytes_24h)}</span>
          <span className="text-blue-500">↓{fmtBytes(d.resp_bytes_24h)}</span>
        </span>
      </div>

      {/* Throughput bar */}
      {barPct !== null && (
        <div className="mt-1.5">
          <div className="w-full h-1 bg-slate-100 dark:bg-white/[0.04] rounded-full overflow-hidden">
            <div className={`h-full rounded-full transition-all ${barColor}`} style={{ width: `${Math.max(2, barPct)}%` }} />
          </div>
          <p className="text-[9px] text-slate-400 mt-0.5 tabular-nums">{(ratio! * 100).toFixed(0)}% of baseline</p>
        </div>
      )}

      {/* Footer: countries + destinations + anomalies */}
      <div className="flex items-center justify-between mt-2">
        <div className="flex gap-0.5">
          {d.top_countries.slice(0, 3).map(c => (
            <span key={c.cc} title={`${c.cc}: ${fmtBytes(c.bytes)}`}><FlagIcon cc={c.cc} size="1.1em" /></span>
          ))}
        </div>
        <div className="flex items-center gap-2 text-[10px] text-slate-400">
          <span title="Unique destinations"><i className="ph-duotone ph-map-pin text-xs" /> {d.destinations}</span>
          {d.anomalies > 0 && (
            <span className="text-red-500" title={`${d.anomalies} anomalies`}>
              <i className="ph-duotone ph-warning text-xs" /> {d.anomalies}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

function BaselineBadge({ status, days }: { status: string; days: number }) {
  if (status === 'ready') return null;
  const label = status === 'learning' ? 'Learning' : `Building ${days}/7d`;
  return (
    <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-100 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400 font-medium whitespace-nowrap">
      {label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Sparkline — Recharts area chart per device
// ---------------------------------------------------------------------------
function Sparkline({ mac }: { mac: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['iot-sparkline', mac],
    queryFn: () => fetchTrafficHistory(mac, 7),
    staleTime: 120_000,
  });

  if (isLoading) {
    return <div className="h-12 bg-slate-100 dark:bg-white/[0.03] rounded animate-pulse" />;
  }

  const points = data?.data || [];
  if (points.length < 2) {
    return (
      <div className="h-12 flex items-center justify-center text-[10px] text-slate-400">
        Collecting data...
      </div>
    );
  }

  // Downsample to max 168 points (1 per hour for 7 days) for smooth rendering
  const step = Math.max(1, Math.floor(points.length / 168));
  const sampled = points.filter((_, i) => i % step === 0).map(p => ({
    t: new Date(p.hour).getTime(),
    tx: p.tx,
    rx: p.rx,
  }));

  return (
    <div className="h-12">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={sampled} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
          <defs>
            <linearGradient id={`rx-${mac}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.3} />
              <stop offset="100%" stopColor="#3b82f6" stopOpacity={0.02} />
            </linearGradient>
            <linearGradient id={`tx-${mac}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#f59e0b" stopOpacity={0.25} />
              <stop offset="100%" stopColor="#f59e0b" stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <RTooltip
            contentStyle={{ background: 'rgba(0,0,0,.85)', border: 'none', borderRadius: 6, fontSize: 11, padding: '4px 8px' }}
            labelStyle={{ display: 'none' }}
            formatter={(v: number, name: string) => [fmtBytes(v), name === 'rx' ? '↓ RX' : '↑ TX']}
          />
          <Area type="monotone" dataKey="rx" stroke="#3b82f6" strokeWidth={1.5} fill={`url(#rx-${mac})`} dot={false} isAnimationActive={false} />
          <Area type="monotone" dataKey="tx" stroke="#f59e0b" strokeWidth={1} fill={`url(#tx-${mac})`} dot={false} isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Network panel — force-directed graph of internal device traffic
// ---------------------------------------------------------------------------
function NetworkPanel({ data, hours, onHoursChange }: {
  data: NetworkGraphResponse | null;
  hours: number;
  onHoursChange: (h: number) => void;
}) {
  const nodes = data?.nodes || [];
  const edges = data?.edges || [];
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ w: 800, h: 500 });

  // Track container width for responsive sizing
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const ro = new ResizeObserver(entries => {
      const { width } = entries[0].contentRect;
      if (width > 0) setDimensions({ w: width, h: Math.max(400, Math.min(600, width * 0.55)) });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  return (
    <div className="space-y-3">
      <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl overflow-hidden">
        <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-white/[0.05]">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
            <i className="ph-duotone ph-graph text-indigo-500" /> Internal device-to-device traffic
            {edges.length > 0 && (
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-100 dark:bg-white/[0.06] text-slate-500 dark:text-slate-400 font-medium">
                {nodes.length} devices · {edges.length} connections
              </span>
            )}
          </h3>
          <select
            value={hours}
            onChange={e => onHoursChange(+e.target.value)}
            className="text-xs border border-slate-200 dark:border-white/[0.1] rounded-md px-2 py-1.5 bg-white dark:bg-white/[0.05] text-slate-600 dark:text-slate-300"
          >
            <option value={1}>Last hour</option>
            <option value={4}>Last 4 hours</option>
            <option value={24}>Last 24 hours</option>
            <option value={48}>Last 48 hours</option>
            <option value={168}>Last 7 days</option>
          </select>
        </div>

        <div ref={containerRef} style={{
          background: isDarkMode()
            ? 'radial-gradient(circle at 50% 50%, rgba(99,102,241,0.03) 0%, transparent 70%), repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(255,255,255,0.02) 39px, rgba(255,255,255,0.02) 40px), repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(255,255,255,0.02) 39px, rgba(255,255,255,0.02) 40px)'
            : 'radial-gradient(circle at 50% 50%, rgba(99,102,241,0.02) 0%, transparent 70%), repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(0,0,0,0.03) 39px, rgba(0,0,0,0.03) 40px), repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(0,0,0,0.03) 39px, rgba(0,0,0,0.03) 40px)',
        }}>
          {edges.length === 0 ? (
            <div className="py-12 text-center text-sm text-slate-400">
              <i className="ph-duotone ph-shield-check text-3xl block mb-2 opacity-40" />
              No internal device-to-device traffic detected
            </div>
          ) : (
            <NetworkGraph nodes={nodes} edges={edges} width={dimensions.w} height={dimensions.h} />
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Network graph — Canvas + d3-force visualization
// ---------------------------------------------------------------------------

const NODE_COLORS: Record<string, { main: string; glow: string }> = {
  camera:  { main: '#f59e0b', glow: 'rgba(245,158,11,0.35)' },
  doorbell:{ main: '#f59e0b', glow: 'rgba(245,158,11,0.35)' },
  speaker: { main: '#8b5cf6', glow: 'rgba(139,92,246,0.35)' },
  router:  { main: '#6366f1', glow: 'rgba(99,102,241,0.4)'  },
  gateway: { main: '#6366f1', glow: 'rgba(99,102,241,0.4)'  },
  default: { main: '#3b82f6', glow: 'rgba(59,130,246,0.3)'  },
};

function getNodeColor(deviceClass: string | null, online: boolean) {
  if (!online) return { main: '#64748b', glow: 'rgba(100,116,139,0.15)' };
  const key = (deviceClass || '').toLowerCase();
  for (const [k, v] of Object.entries(NODE_COLORS)) {
    if (key.includes(k)) return v;
  }
  return NODE_COLORS.default;
}

interface GNode extends SimulationNodeDatum {
  id: string;
  label: string;
  online: boolean;
  ip: string;
  deviceClass: string | null;
  totalHits: number;
  radius: number;
}
interface GLink extends SimulationLinkDatum<GNode> {
  port: number;
  portLabel: string;
  hits: number;
}

function NetworkGraph({ nodes, edges, width, height }: {
  nodes: NetworkNode[];
  edges: NetworkEdge[];
  width: number;
  height: number;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const simRef = useRef<ReturnType<typeof forceSimulation<GNode>> | null>(null);
  const frameRef = useRef(0);
  const dragRef = useRef<{ node: GNode; offsetX: number; offsetY: number } | null>(null);
  const transformRef = useRef({ x: 0, y: 0, k: 1 });
  const nodesRef = useRef<GNode[]>([]);
  const linksRef = useRef<GLink[]>([]);
  // Particle positions along links (0..1 progress)
  const particlesRef = useRef<Map<number, number[]>>(new Map());

  const isDark = isDarkMode();

  // Build simulation when data changes
  useEffect(() => {
    const hitsByNode = new Map<string, number>();
    edges.forEach(e => {
      hitsByNode.set(e.source_ip, (hitsByNode.get(e.source_ip) || 0) + e.hits);
      hitsByNode.set(e.target_ip, (hitsByNode.get(e.target_ip) || 0) + e.hits);
    });
    const maxNodeHits = Math.max(...[...hitsByNode.values()], 1);

    const gNodes: GNode[] = nodes.map(n => ({
      id: n.ip,
      label: n.display_name || n.hostname || n.ip,
      online: n.last_seen ? Date.now() - new Date(n.last_seen).getTime() < 300000 : false,
      ip: n.ip,
      deviceClass: n.device_class,
      totalHits: hitsByNode.get(n.ip) || 0,
      radius: 10 + ((hitsByNode.get(n.ip) || 0) / maxNodeHits) * 16,
    }));

    // Add missing nodes from edges
    const ids = new Set(gNodes.map(n => n.id));
    edges.forEach(e => {
      [e.source_ip, e.target_ip].forEach(ip => {
        if (!ids.has(ip)) {
          gNodes.push({ id: ip, label: ip, online: false, ip, deviceClass: null, totalHits: hitsByNode.get(ip) || 0, radius: 10 });
          ids.add(ip);
        }
      });
    });

    const gLinks: GLink[] = edges.map(e => ({
      source: e.source_ip as any,
      target: e.target_ip as any,
      port: e.port,
      portLabel: e.port_label,
      hits: e.hits,
    }));

    // Init particles for each link
    const maxHits = Math.max(...edges.map(e => e.hits), 1);
    const particles = new Map<number, number[]>();
    gLinks.forEach((l, i) => {
      const count = Math.max(1, Math.ceil((l.hits / maxHits) * 4));
      const arr: number[] = [];
      for (let p = 0; p < count; p++) arr.push(Math.random());
      particles.set(i, arr);
    });
    particlesRef.current = particles;

    nodesRef.current = gNodes;
    linksRef.current = gLinks;

    // Stop previous simulation
    simRef.current?.stop();

    const sim = forceSimulation<GNode>(gNodes)
      .force('link', forceLink<GNode, GLink>(gLinks).id(d => d.id).distance(120))
      .force('charge', forceManyBody().strength(-300))
      .force('center', forceCenter(width / 2, height / 2))
      .force('collide', forceCollide<GNode>().radius(d => d.radius + 8))
      .alphaDecay(0.025)
      .velocityDecay(0.3);

    simRef.current = sim;

    return () => { sim.stop(); };
  }, [nodes, edges, width, height]);

  // Animation loop
  useEffect(() => {
    let raf: number;
    const maxHits = Math.max(...edges.map(e => e.hits), 1);

    const draw = () => {
      frameRef.current++;
      const canvas = canvasRef.current;
      if (!canvas) { raf = requestAnimationFrame(draw); return; }
      const ctx = canvas.getContext('2d');
      if (!ctx) { raf = requestAnimationFrame(draw); return; }
      const dpr = window.devicePixelRatio || 1;

      // Size canvas for retina
      if (canvas.width !== width * dpr || canvas.height !== height * dpr) {
        canvas.width = width * dpr;
        canvas.height = height * dpr;
        canvas.style.width = `${width}px`;
        canvas.style.height = `${height}px`;
        ctx.scale(dpr, dpr);
      }

      ctx.clearRect(0, 0, width, height);

      const gNodes = nodesRef.current;
      const gLinks = linksRef.current;
      const particles = particlesRef.current;

      // --- Draw links ---
      gLinks.forEach((l, i) => {
        const src = l.source as any as GNode;
        const tgt = l.target as any as GNode;
        if (src.x == null || tgt.x == null || src.y == null || tgt.y == null) return;

        const intensity = Math.min(1, (l.hits / maxHits) * 0.8 + 0.2);
        const lw = Math.max(1.5, Math.min(5, (l.hits / maxHits) * 5));

        // Link line
        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.lineTo(tgt.x, tgt.y);
        ctx.strokeStyle = isDark
          ? `rgba(239,68,68,${intensity * 0.3})`
          : `rgba(239,68,68,${intensity * 0.25})`;
        ctx.lineWidth = lw;
        if (l.hits / maxHits < 0.15) ctx.setLineDash([4, 3]);
        else ctx.setLineDash([]);
        ctx.stroke();
        ctx.setLineDash([]);

        // Arrow head
        const angle = Math.atan2(tgt.y - src.y, tgt.x - src.x);
        const arrowPos = 0.82;
        const ax = src.x + (tgt.x - src.x) * arrowPos;
        const ay = src.y + (tgt.y - src.y) * arrowPos;
        const arrowLen = 6;
        ctx.beginPath();
        ctx.moveTo(ax, ay);
        ctx.lineTo(ax - arrowLen * Math.cos(angle - 0.35), ay - arrowLen * Math.sin(angle - 0.35));
        ctx.lineTo(ax - arrowLen * Math.cos(angle + 0.35), ay - arrowLen * Math.sin(angle + 0.35));
        ctx.closePath();
        ctx.fillStyle = isDark ? 'rgba(239,68,68,0.6)' : 'rgba(239,68,68,0.5)';
        ctx.fill();

        // Animated particles
        const pArr = particles.get(i);
        if (pArr) {
          const speed = 0.003 + (l.hits / maxHits) * 0.006;
          const pSize = Math.max(2, Math.min(4, (l.hits / maxHits) * 4));
          for (let p = 0; p < pArr.length; p++) {
            pArr[p] = (pArr[p] + speed) % 1;
            const px = src.x + (tgt.x - src.x) * pArr[p];
            const py = src.y + (tgt.y - src.y) * pArr[p];
            ctx.beginPath();
            ctx.arc(px, py, pSize, 0, Math.PI * 2);
            ctx.fillStyle = isDark ? 'rgba(248,113,113,0.8)' : 'rgba(220,38,38,0.6)';
            ctx.fill();
          }
        }

        // Port label at midpoint
        const mx = (src.x + tgt.x) / 2;
        const my = (src.y + tgt.y) / 2;
        const fontSize = 9;
        ctx.font = `600 ${fontSize}px Inter, system-ui, sans-serif`;
        const text = l.portLabel;
        const tw = ctx.measureText(text).width;
        const padX = 4;
        const padY = 3;
        const pillH = fontSize + padY * 2;
        const rr = pillH / 2;

        ctx.save();
        ctx.shadowColor = 'rgba(0,0,0,0.12)';
        ctx.shadowBlur = 3;
        ctx.fillStyle = isDark ? 'rgba(127,29,29,0.8)' : 'rgba(254,226,226,0.95)';
        ctx.beginPath();
        ctx.roundRect(mx - tw / 2 - padX, my - pillH / 2, tw + padX * 2, pillH, rr);
        ctx.fill();
        ctx.restore();

        ctx.strokeStyle = isDark ? 'rgba(248,113,113,0.3)' : 'rgba(220,38,38,0.2)';
        ctx.lineWidth = 0.5;
        ctx.beginPath();
        ctx.roundRect(mx - tw / 2 - padX, my - pillH / 2, tw + padX * 2, pillH, rr);
        ctx.stroke();

        ctx.fillStyle = isDark ? '#fca5a5' : '#b91c1c';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(text, mx, my);

        // Hit count
        ctx.font = `500 7px Inter, system-ui, sans-serif`;
        ctx.fillStyle = isDark ? 'rgba(248,113,113,0.45)' : 'rgba(185,28,28,0.35)';
        ctx.fillText(`${fmtNumber(l.hits)}×`, mx, my + pillH / 2 + 7);
      });

      // --- Draw nodes ---
      const maxNodeHits = Math.max(...gNodes.map(n => n.totalHits), 1);
      gNodes.forEach(n => {
        if (n.x == null || n.y == null) return;
        const x = n.x;
        const y = n.y;
        const r = n.radius;
        const colors = getNodeColor(n.deviceClass, n.online);

        // Outer glow (pulsing for online)
        if (n.online) {
          const pulse = Math.sin(frameRef.current * 0.04) * 0.15 + 0.85;
          const glowR = r + 8;
          const grad = ctx.createRadialGradient(x, y, r * 0.5, x, y, glowR);
          grad.addColorStop(0, colors.glow);
          grad.addColorStop(1, 'transparent');
          ctx.beginPath();
          ctx.arc(x, y, glowR * pulse, 0, Math.PI * 2);
          ctx.fillStyle = grad;
          ctx.fill();
        }

        // Gradient body
        const bodyGrad = ctx.createRadialGradient(x - r * 0.3, y - r * 0.3, 0, x, y, r);
        bodyGrad.addColorStop(0, lighten(colors.main, isDark ? 0.25 : 0.15));
        bodyGrad.addColorStop(1, colors.main);
        ctx.beginPath();
        ctx.arc(x, y, r, 0, Math.PI * 2);
        ctx.fillStyle = bodyGrad;
        ctx.fill();

        // Glass highlight
        const hlGrad = ctx.createRadialGradient(x - r * 0.25, y - r * 0.35, 0, x, y, r);
        hlGrad.addColorStop(0, 'rgba(255,255,255,0.28)');
        hlGrad.addColorStop(0.5, 'rgba(255,255,255,0.04)');
        hlGrad.addColorStop(1, 'transparent');
        ctx.beginPath();
        ctx.arc(x, y, r, 0, Math.PI * 2);
        ctx.fillStyle = hlGrad;
        ctx.fill();

        // Border
        ctx.beginPath();
        ctx.arc(x, y, r, 0, Math.PI * 2);
        ctx.strokeStyle = isDark ? 'rgba(255,255,255,0.12)' : 'rgba(0,0,0,0.1)';
        ctx.lineWidth = 1;
        ctx.stroke();

        // Online dot
        if (n.online) {
          const dotR = Math.max(2.5, r * 0.2);
          const dx = x + r * 0.65;
          const dy = y - r * 0.65;
          ctx.beginPath();
          ctx.arc(dx, dy, dotR + 1.2, 0, Math.PI * 2);
          ctx.fillStyle = isDark ? '#0f1117' : '#fff';
          ctx.fill();
          ctx.beginPath();
          ctx.arc(dx, dy, dotR, 0, Math.PI * 2);
          ctx.fillStyle = '#10b981';
          ctx.fill();
        }

        // Label
        ctx.font = '600 11px Inter, system-ui, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        const labelY = y + r + 4;
        const tw = ctx.measureText(n.label).width;
        const px = 4;
        const py = 2;
        ctx.fillStyle = isDark ? 'rgba(15,17,23,0.75)' : 'rgba(255,255,255,0.85)';
        ctx.beginPath();
        ctx.roundRect(x - tw / 2 - px, labelY - py, tw + px * 2, 11 + py * 2, 6);
        ctx.fill();
        ctx.fillStyle = isDark ? '#e2e8f0' : '#1e293b';
        ctx.fillText(n.label, x, labelY);
      });

      raf = requestAnimationFrame(draw);
    };

    raf = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(raf);
  }, [edges, width, height, isDark]);

  // Mouse interaction: drag nodes
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const findNode = (mx: number, my: number): GNode | null => {
      // Search in reverse so top-drawn nodes are picked first
      for (let i = nodesRef.current.length - 1; i >= 0; i--) {
        const n = nodesRef.current[i];
        if (n.x == null || n.y == null) continue;
        const dx = mx - n.x;
        const dy = my - n.y;
        if (dx * dx + dy * dy <= (n.radius + 4) * (n.radius + 4)) return n;
      }
      return null;
    };

    const getPos = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      return { x: e.clientX - rect.left, y: e.clientY - rect.top };
    };

    const onDown = (e: MouseEvent) => {
      const { x, y } = getPos(e);
      const node = findNode(x, y);
      if (node) {
        dragRef.current = { node, offsetX: x - (node.x || 0), offsetY: y - (node.y || 0) };
        node.fx = node.x;
        node.fy = node.y;
        simRef.current?.alphaTarget(0.3).restart();
      }
    };

    const onMove = (e: MouseEvent) => {
      if (!dragRef.current) {
        // Cursor hint
        const { x, y } = getPos(e);
        canvas.style.cursor = findNode(x, y) ? 'grab' : 'default';
        return;
      }
      canvas.style.cursor = 'grabbing';
      const { x, y } = getPos(e);
      const d = dragRef.current;
      d.node.fx = x - d.offsetX;
      d.node.fy = y - d.offsetY;
    };

    const onUp = () => {
      if (dragRef.current) {
        dragRef.current.node.fx = null;
        dragRef.current.node.fy = null;
        dragRef.current = null;
        simRef.current?.alphaTarget(0);
      }
      canvas.style.cursor = 'default';
    };

    canvas.addEventListener('mousedown', onDown);
    canvas.addEventListener('mousemove', onMove);
    canvas.addEventListener('mouseup', onUp);
    canvas.addEventListener('mouseleave', onUp);
    return () => {
      canvas.removeEventListener('mousedown', onDown);
      canvas.removeEventListener('mousemove', onMove);
      canvas.removeEventListener('mouseup', onUp);
      canvas.removeEventListener('mouseleave', onUp);
    };
  }, []);

  return <canvas ref={canvasRef} style={{ width, height, display: 'block' }} />;
}

/** Lighten a hex color by mixing with white */
function lighten(hex: string, amount: number): string {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgb(${Math.round(r + (255 - r) * amount)},${Math.round(g + (255 - g) * amount)},${Math.round(b + (255 - b) * amount)})`;
}
