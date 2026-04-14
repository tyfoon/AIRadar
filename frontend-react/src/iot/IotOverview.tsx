import { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip as RTooltip,
  ResponsiveContainer,
} from 'recharts';
import ForceGraph2D from 'react-force-graph-2d';
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

        <div ref={containerRef}>
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

interface GraphNode {
  id: string;
  label: string;
  online: boolean;
  ip: string;
  deviceClass: string | null;
}
interface GraphLink {
  source: string;
  target: string;
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
  const fgRef = useRef<any>(null);

  const graphData = useMemo(() => {
    const nodeMap = new Map<string, NetworkNode>();
    nodes.forEach(n => nodeMap.set(n.ip, n));

    const graphNodes: GraphNode[] = nodes.map(n => ({
      id: n.ip,
      label: n.display_name || n.hostname || n.ip,
      online: n.last_seen ? Date.now() - new Date(n.last_seen).getTime() < 300000 : false,
      ip: n.ip,
      deviceClass: n.device_class,
    }));

    // Add any IPs in edges that aren't in nodes
    const nodeIds = new Set(graphNodes.map(n => n.id));
    edges.forEach(e => {
      if (!nodeIds.has(e.source_ip)) {
        graphNodes.push({ id: e.source_ip, label: e.source_ip, online: false, ip: e.source_ip, deviceClass: null });
        nodeIds.add(e.source_ip);
      }
      if (!nodeIds.has(e.target_ip)) {
        graphNodes.push({ id: e.target_ip, label: e.target_ip, online: false, ip: e.target_ip, deviceClass: null });
        nodeIds.add(e.target_ip);
      }
    });

    const maxHits = Math.max(...edges.map(e => e.hits), 1);
    const graphLinks: GraphLink[] = edges.map(e => ({
      source: e.source_ip,
      target: e.target_ip,
      port: e.port,
      portLabel: e.port_label,
      hits: e.hits,
    }));

    return { nodes: graphNodes, links: graphLinks, maxHits };
  }, [nodes, edges]);

  // Zoom to fit after initial layout
  useEffect(() => {
    const timer = setTimeout(() => {
      fgRef.current?.zoomToFit(400, 50);
    }, 500);
    return () => clearTimeout(timer);
  }, [graphData]);

  const isDark = typeof document !== 'undefined' && document.documentElement.classList.contains('dark');
  const maxHits = graphData.maxHits;

  return (
    <ForceGraph2D
      ref={fgRef}
      graphData={graphData}
      width={width}
      height={height}
      backgroundColor="transparent"
      // Node rendering
      nodeRelSize={6}
      nodeCanvasObject={(node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
        const n = node as GraphNode;
        const r = 6;
        const fontSize = Math.max(10 / globalScale, 1.5);

        // Node circle
        ctx.beginPath();
        ctx.arc(node.x!, node.y!, r, 0, 2 * Math.PI);
        ctx.fillStyle = n.online
          ? '#10b981'  // emerald-500
          : isDark ? '#475569' : '#94a3b8'; // slate-600 / slate-400
        ctx.fill();

        // Border ring
        ctx.strokeStyle = isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.08)';
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // Label
        ctx.font = `${fontSize}px Inter, system-ui, sans-serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.fillStyle = isDark ? '#e2e8f0' : '#334155';
        ctx.fillText(n.label, node.x!, node.y! + r + 2);
      }}
      nodePointerAreaPaint={(node: any, color: string, ctx: CanvasRenderingContext2D) => {
        ctx.beginPath();
        ctx.arc(node.x!, node.y!, 8, 0, 2 * Math.PI);
        ctx.fillStyle = color;
        ctx.fill();
      }}
      // Link rendering
      linkWidth={(link: any) => Math.max(1, Math.min(5, (link.hits / maxHits) * 5))}
      linkColor={() => isDark ? 'rgba(239,68,68,0.25)' : 'rgba(239,68,68,0.2)'}
      linkDirectionalArrowLength={4}
      linkDirectionalArrowRelPos={0.85}
      linkDirectionalArrowColor={() => isDark ? 'rgba(239,68,68,0.5)' : 'rgba(239,68,68,0.4)'}
      linkCanvasObjectMode={() => 'after'}
      linkCanvasObject={(link: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
        // Draw port label at midpoint
        if (globalScale < 0.6) return; // skip labels when zoomed out too far
        const l = link as GraphLink;
        const src = link.source;
        const tgt = link.target;
        if (!src?.x || !tgt?.x) return;
        const mx = (src.x + tgt.x) / 2;
        const my = (src.y + tgt.y) / 2;

        const fontSize = Math.max(8 / globalScale, 1.2);
        ctx.font = `bold ${fontSize}px Inter, system-ui, sans-serif`;
        const text = l.portLabel;
        const textWidth = ctx.measureText(text).width;
        const pad = 2 / globalScale;

        // Background pill
        ctx.fillStyle = isDark ? 'rgba(127,29,29,0.7)' : 'rgba(254,226,226,0.9)';
        ctx.beginPath();
        const rr = (fontSize + pad * 2) / 2;
        ctx.roundRect(mx - textWidth / 2 - pad, my - rr, textWidth + pad * 2, rr * 2, rr);
        ctx.fill();

        // Text
        ctx.fillStyle = isDark ? '#fca5a5' : '#dc2626';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(text, mx, my);
      }}
      // Tooltip
      nodeLabel={(node: any) => {
        const n = node as GraphNode;
        return `<div style="background:rgba(0,0,0,.85);color:#fff;padding:6px 10px;border-radius:6px;font-size:11px;line-height:1.4">
          <strong>${n.label}</strong><br/>
          <span style="opacity:.7">${n.ip}</span><br/>
          ${n.online ? '<span style="color:#10b981">● online</span>' : '<span style="opacity:.5">○ offline</span>'}
        </div>`;
      }}
      linkLabel={(link: any) => {
        const l = link as GraphLink;
        return `<div style="background:rgba(0,0,0,.85);color:#fff;padding:6px 10px;border-radius:6px;font-size:11px;line-height:1.4">
          <strong>${l.portLabel}</strong> (port ${l.port})<br/>
          ${fmtNumber(l.hits)} connections
        </div>`;
      }}
      // Physics
      d3AlphaDecay={0.03}
      d3VelocityDecay={0.3}
      cooldownTicks={100}
      enableNodeDrag={true}
      enableZoomInteraction={true}
    />
  );
}
