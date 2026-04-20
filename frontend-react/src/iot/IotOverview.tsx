import { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  forceSimulation, forceLink, forceManyBody, forceCenter, forceCollide,
} from 'd3-force';
import type { SimulationNodeDatum, SimulationLinkDatum } from 'd3-force';
import { fetchFleet, fetchAnomalies, fetchNetworkGraph } from './api';
import type { FleetDevice, Anomaly, IotTab, NetworkNode, NetworkEdge } from './types';
import type { NetworkGraphResponse } from './types';
import { FleetCard, fmtBytes } from './FleetCard';
import AlertCard from '../shared/AlertCard';
import type { AlertData } from '../shared/AlertCard';

// ---------------------------------------------------------------------------
// Helpers (local to IotOverview)
// ---------------------------------------------------------------------------
function fmtNumber(n: number): string {
  return n >= 1000 ? n.toLocaleString() : String(n);
}

// timeAgo is now handled inside the shared AlertCard component

function isDarkMode(): boolean {
  return typeof document !== 'undefined' && document.documentElement.classList.contains('dark');
}

// Detection labels are now defined in the shared AlertCard component (ALERT_META)

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

  const handleAlertAction = useCallback((_id: string, _action: string) => {
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
        <AnomaliesPanel anomalies={anomalies} onAction={handleAlertAction} />
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
// Anomalies panel — uses shared AlertCard
// ---------------------------------------------------------------------------
function anomalyToAlertData(a: Anomaly): AlertData {
  let description = a.detail;
  let countryCode: string | undefined;

  if (a.detection_type === 'iot_lateral_movement') {
    const m = a.detail.match(/lateral_(\d+)_(.+)/);
    if (m) description = `\u2192 ${m[2]} on port ${m[1]} (${PORT_LABELS[+m[1]] || 'unknown'})`;
  } else if (a.detection_type === 'iot_suspicious_port') {
    const m = a.detail.match(/port_(\d+)/);
    if (m) description = `Port ${m[1]} (${PORT_LABELS[+m[1]] || 'unusual'})`;
  } else if (a.detection_type === 'iot_new_country') {
    const m = a.detail.match(/country_([A-Z]{2})/);
    if (m) {
      countryCode = m[1];
      description = `New country: ${m[1]}`;
    }
  }

  return {
    alert_id: `iot-${a.source_ip}-${a.detection_type}-${a.detail}`,
    mac_address: a.mac || '',
    alert_type: a.detection_type,
    service_or_dest: a.detail,
    device_name: a.display_name || a.hostname || a.source_ip,
    description,
    country_code: countryCode,
    timestamp: a.last_seen,
    hits: a.hits,
    is_dismissed: a.dismissed,
  };
}

function AnomaliesPanel({ anomalies, onAction }: { anomalies: Anomaly[]; onAction: (id: string, action: string) => void }) {
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
      {sorted.map((a, i) => (
        <AlertCard
          key={`${a.source_ip}-${a.detection_type}-${a.detail}-${i}`}
          alert={anomalyToAlertData(a)}
          compact
          showTrash={a.dismissed}
          onAction={onAction}
        />
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Fleet panel
// ---------------------------------------------------------------------------
function FleetPanel({ devices, loading }: { devices: FleetDevice[]; loading: boolean }) {
  if (loading) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
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
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
      {devices.map(d => <FleetCard key={d.mac_address} device={d} />)}
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
  const rawNodes = data?.nodes || [];
  const rawEdges = data?.edges || [];
  // Hide the gateway/router by default. Everything flows through it so
  // its star-shape dwarfs the actual device-to-device relationships.
  const [hideGateway, setHideGateway] = useState(true);
  // Hide AI-Radar itself by default. It's the observer, not a device
  // of interest; every local API/SSH/AdGuard call terminates here and
  // it becomes a spurious hub in the graph. Toggle off to debug
  // AI-Radar's own LAN interactions.
  const [hideSelf, setHideSelf] = useState(true);
  // Infrastructure chatter toggle (DNS / NetBIOS / mDNS / SSDP /
  // LLMNR / WS-Discovery / DHCP / ICMP). Default OFF so users see
  // their full LAN activity when they open the tab — filter on only
  // when decluttering. Toggling on hides edges where >= 80% of the
  // bytes sit on infra ports (so a real RTSP flow with incidental
  // mDNS piggybacking stays visible either way).
  const [hideInfra, setHideInfra] = useState(false);
  const gatewayKeys = useMemo(() => {
    const keys = new Set<string>();
    rawNodes.forEach(n => {
      if (n.is_gateway) {
        if (n.mac) keys.add(n.mac);
        keys.add(n.ip);
      }
    });
    return keys;
  }, [rawNodes]);
  const selfKeys = useMemo(() => {
    const keys = new Set<string>();
    rawNodes.forEach(n => {
      if (n.is_self) {
        if (n.mac) keys.add(n.mac);
        keys.add(n.ip);
      }
    });
    return keys;
  }, [rawNodes]);
  // Edge filtering: apply both toggles. Node filtering is separate
  // because a node with only infra chatter still exists as a device,
  // just has no visible edges after filtering. d3-force drops orphan
  // nodes visually by floating them off-center, which is fine.
  const edges = useMemo(() => {
    return rawEdges.filter(e => {
      if (hideInfra && e.is_infrastructure) return false;
      if (hideGateway && (
        gatewayKeys.has(e.source_mac || e.source_ip) ||
        gatewayKeys.has(e.target_mac || e.target_ip)
      )) return false;
      if (hideSelf && (
        selfKeys.has(e.source_mac || e.source_ip) ||
        selfKeys.has(e.target_mac || e.target_ip)
      )) return false;
      return true;
    });
  }, [rawEdges, hideInfra, hideGateway, hideSelf, gatewayKeys, selfKeys]);
  // Nodes: keep only those actually touching a surviving edge (plus
  // gateway unless hidden). Avoids a cloud of orphan device names
  // floating with no visible connections.
  const nodes = useMemo(() => {
    const keep = new Set<string>();
    edges.forEach(e => {
      keep.add(e.source_ip);
      keep.add(e.target_ip);
    });
    return rawNodes.filter(n => {
      if (hideGateway && n.is_gateway) return false;
      if (hideSelf && n.is_self) return false;
      return keep.has(n.ip);
    });
  }, [rawNodes, edges, hideGateway, hideSelf]);
  const gatewayNode = rawNodes.find(n => n.is_gateway);
  const selfNode = rawNodes.find(n => n.is_self);
  const infraEdgeCount = rawEdges.filter(e => e.is_infrastructure).length;
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ w: 800, h: 500 });

  // Track container width for responsive sizing
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const ro = new ResizeObserver(entries => {
      const { width } = entries[0].contentRect;
      if (width > 0) setDimensions({ w: width, h: Math.max(300, Math.min(450, width * 0.4)) });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  return (
    <div className="space-y-3">
      <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl overflow-hidden">
        <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-white/[0.05] gap-3 flex-wrap">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
            <i className="ph-duotone ph-graph text-indigo-500" /> Internal device-to-device traffic
            {edges.length > 0 && (
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-100 dark:bg-white/[0.06] text-slate-500 dark:text-slate-400 font-medium">
                {nodes.length} devices · {edges.length} connections
              </span>
            )}
          </h3>
          <div className="flex items-center gap-2 flex-wrap">
            {infraEdgeCount > 0 && (
              <label
                className="flex items-center gap-1.5 text-[11px] text-slate-500 dark:text-slate-400 select-none cursor-pointer"
                title="DNS / NetBIOS / mDNS / SSDP / ICMP — discovery chatter that fans out one→many and drowns out real flows"
              >
                <input
                  type="checkbox"
                  checked={hideInfra}
                  onChange={e => setHideInfra(e.target.checked)}
                  className="accent-indigo-500 w-3.5 h-3.5"
                />
                Hide infrastructure chatter
                <span className="text-slate-400 dark:text-slate-500">({infraEdgeCount})</span>
              </label>
            )}
            {gatewayNode && (
              <label
                className="flex items-center gap-1.5 text-[11px] text-slate-500 dark:text-slate-400 select-none cursor-pointer"
                title={`Gateway: ${gatewayNode.display_name || gatewayNode.hostname || gatewayNode.ip}`}
              >
                <input
                  type="checkbox"
                  checked={hideGateway}
                  onChange={e => setHideGateway(e.target.checked)}
                  className="accent-indigo-500 w-3.5 h-3.5"
                />
                Hide gateway
              </label>
            )}
            {selfNode && (
              <label
                className="flex items-center gap-1.5 text-[11px] text-slate-500 dark:text-slate-400 select-none cursor-pointer"
                title="AI-Radar is the observer, not a device of interest. Every local API/SSH/AdGuard call terminates here."
              >
                <input
                  type="checkbox"
                  checked={hideSelf}
                  onChange={e => setHideSelf(e.target.checked)}
                  className="accent-indigo-500 w-3.5 h-3.5"
                />
                Hide AI-Radar
              </label>
            )}
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
        </div>

        {/* Direction legend — matches the edge colors used by NetworkGraph */}
        {edges.length > 0 && (
          <div className="flex items-center gap-3 px-4 py-1.5 text-[10px] text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-white/[0.04]">
            <span className="flex items-center gap-1">
              <span className="inline-block w-2.5 h-0.5 bg-amber-500 rounded-full" />
              src → peer (upload-dominant)
            </span>
            <span className="flex items-center gap-1">
              <span className="inline-block w-2.5 h-0.5 bg-blue-500 rounded-full" />
              peer → src (download-dominant)
            </span>
            <span className="flex items-center gap-1">
              <span className="inline-block w-2.5 h-0.5 bg-slate-400 rounded-full" />
              balanced
            </span>
          </div>
        )}

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

// Device type detection — matches label/deviceClass to an icon type
type IconType = 'router' | 'camera' | 'doorbell' | 'speaker' | 'phone' | 'laptop' | 'desktop' | 'tv' | 'tablet' | 'watch' | 'printer' | 'server' | 'light' | 'device';

const DEVICE_ICON_MAP: [RegExp, IconType][] = [
  [/router|gateway|udm|unifi|ubnt/i, 'router'],
  [/nest[\s-]?hello|doorbell/i, 'doorbell'],
  [/camera|cam\b/i, 'camera'],
  [/homepod|google[\s-]?home|echo|sonos|speaker/i, 'speaker'],
  [/iphone|pixel|galaxy|samsung|phone/i, 'phone'],
  [/macbook|laptop/i, 'laptop'],
  [/imac|mac[\s-]?pro|mac[\s-]?mini|desktop/i, 'desktop'],
  [/apple[\s-]?tv|chromecast|fire[\s-]?tv|roku|tv/i, 'tv'],
  [/ipad|tablet/i, 'tablet'],
  [/watch/i, 'watch'],
  [/printer/i, 'printer'],
  [/server|airadar|synology|qnap|nas\b/i, 'server'],
  [/hue|light|bulb|lamp/i, 'light'],
];

function getDeviceIconType(label: string, deviceClass: string | null): IconType {
  const text = `${label} ${deviceClass || ''}`;
  for (const [re, icon] of DEVICE_ICON_MAP) {
    if (re.test(text)) return icon;
  }
  return 'device';
}

/** Draw a device-type icon on Canvas at (cx, cy) with given size and color */
function drawDeviceIcon(ctx: CanvasRenderingContext2D, type: IconType, cx: number, cy: number, size: number, color: string) {
  ctx.save();
  ctx.strokeStyle = color;
  ctx.fillStyle = color;
  ctx.lineWidth = size * 0.1;
  ctx.lineCap = 'round';
  ctx.lineJoin = 'round';
  const s = size * 0.4; // half-size

  switch (type) {
    case 'router': {
      // Router: box with two antennas
      const bw = s * 0.9, bh = s * 0.4;
      ctx.strokeRect(cx - bw, cy - bh * 0.2, bw * 2, bh);
      // Antennas
      ctx.beginPath();
      ctx.moveTo(cx - bw * 0.5, cy - bh * 0.2);
      ctx.lineTo(cx - bw * 0.7, cy - bh * 1.3);
      ctx.moveTo(cx + bw * 0.5, cy - bh * 0.2);
      ctx.lineTo(cx + bw * 0.7, cy - bh * 1.3);
      ctx.stroke();
      // Dots on antennas
      ctx.beginPath();
      ctx.arc(cx - bw * 0.7, cy - bh * 1.3, size * 0.06, 0, Math.PI * 2);
      ctx.arc(cx + bw * 0.7, cy - bh * 1.3, size * 0.06, 0, Math.PI * 2);
      ctx.fill();
      break;
    }
    case 'camera': {
      // Video camera: rectangle + triangle lens
      const bw = s * 0.6, bh = s * 0.5;
      ctx.strokeRect(cx - bw - s * 0.15, cy - bh, bw * 1.6, bh * 2);
      ctx.beginPath();
      ctx.moveTo(cx + bw * 0.5, cy - bh * 0.5);
      ctx.lineTo(cx + s, cy);
      ctx.lineTo(cx + bw * 0.5, cy + bh * 0.5);
      ctx.closePath();
      ctx.stroke();
      break;
    }
    case 'doorbell': {
      // Bell shape
      ctx.beginPath();
      ctx.arc(cx, cy - s * 0.3, s * 0.55, Math.PI, 0);
      ctx.lineTo(cx + s * 0.7, cy + s * 0.3);
      ctx.lineTo(cx - s * 0.7, cy + s * 0.3);
      ctx.closePath();
      ctx.stroke();
      // Clapper
      ctx.beginPath();
      ctx.arc(cx, cy + s * 0.5, s * 0.12, 0, Math.PI * 2);
      ctx.fill();
      break;
    }
    case 'speaker': {
      // Speaker: rounded rect with circle
      const bw = s * 0.55, bh = s * 0.85;
      ctx.beginPath();
      ctx.roundRect(cx - bw, cy - bh, bw * 2, bh * 2, s * 0.2);
      ctx.stroke();
      ctx.beginPath();
      ctx.arc(cx, cy + bh * 0.15, s * 0.3, 0, Math.PI * 2);
      ctx.stroke();
      ctx.beginPath();
      ctx.arc(cx, cy - bh * 0.4, s * 0.12, 0, Math.PI * 2);
      ctx.fill();
      break;
    }
    case 'phone': {
      // Phone: tall rounded rect with notch
      const pw = s * 0.4, ph = s * 0.85;
      ctx.beginPath();
      ctx.roundRect(cx - pw, cy - ph, pw * 2, ph * 2, s * 0.15);
      ctx.stroke();
      ctx.beginPath();
      ctx.moveTo(cx - pw * 0.3, cy + ph * 0.75);
      ctx.lineTo(cx + pw * 0.3, cy + ph * 0.75);
      ctx.stroke();
      break;
    }
    case 'laptop': {
      // Laptop: screen + base
      ctx.strokeRect(cx - s * 0.7, cy - s * 0.6, s * 1.4, s * 0.9);
      ctx.beginPath();
      ctx.moveTo(cx - s * 0.9, cy + s * 0.45);
      ctx.lineTo(cx + s * 0.9, cy + s * 0.45);
      ctx.lineTo(cx + s * 0.7, cy + s * 0.3);
      ctx.lineTo(cx - s * 0.7, cy + s * 0.3);
      ctx.closePath();
      ctx.stroke();
      break;
    }
    case 'desktop': {
      // Monitor
      ctx.strokeRect(cx - s * 0.75, cy - s * 0.65, s * 1.5, s * 1);
      ctx.beginPath();
      ctx.moveTo(cx - s * 0.2, cy + s * 0.35);
      ctx.lineTo(cx + s * 0.2, cy + s * 0.35);
      ctx.moveTo(cx, cy + s * 0.35);
      ctx.lineTo(cx, cy + s * 0.6);
      ctx.moveTo(cx - s * 0.35, cy + s * 0.6);
      ctx.lineTo(cx + s * 0.35, cy + s * 0.6);
      ctx.stroke();
      break;
    }
    case 'tv': {
      // TV: wide rect + stand
      ctx.strokeRect(cx - s * 0.85, cy - s * 0.5, s * 1.7, s * 0.9);
      ctx.beginPath();
      ctx.moveTo(cx - s * 0.3, cy + s * 0.4);
      ctx.lineTo(cx - s * 0.5, cy + s * 0.65);
      ctx.moveTo(cx + s * 0.3, cy + s * 0.4);
      ctx.lineTo(cx + s * 0.5, cy + s * 0.65);
      ctx.stroke();
      break;
    }
    case 'server': {
      // Server: stacked rectangles
      const sw = s * 0.65, sh = s * 0.28;
      for (let i = -1; i <= 1; i++) {
        ctx.strokeRect(cx - sw, cy + i * sh * 1.3 - sh / 2, sw * 2, sh);
        ctx.beginPath();
        ctx.arc(cx + sw * 0.7, cy + i * sh * 1.3, sh * 0.15, 0, Math.PI * 2);
        ctx.fill();
      }
      break;
    }
    case 'light': {
      // Lightbulb
      ctx.beginPath();
      ctx.arc(cx, cy - s * 0.15, s * 0.45, 0, Math.PI * 2);
      ctx.stroke();
      ctx.beginPath();
      ctx.moveTo(cx - s * 0.2, cy + s * 0.3);
      ctx.lineTo(cx - s * 0.2, cy + s * 0.55);
      ctx.lineTo(cx + s * 0.2, cy + s * 0.55);
      ctx.lineTo(cx + s * 0.2, cy + s * 0.3);
      ctx.stroke();
      break;
    }
    default: {
      // Generic device: circuit/chip icon
      ctx.strokeRect(cx - s * 0.4, cy - s * 0.4, s * 0.8, s * 0.8);
      // Pins on sides
      const pins = 3;
      for (let i = 0; i < pins; i++) {
        const py = cy - s * 0.3 + i * s * 0.3;
        ctx.beginPath();
        ctx.moveTo(cx - s * 0.4, py);
        ctx.lineTo(cx - s * 0.7, py);
        ctx.moveTo(cx + s * 0.4, py);
        ctx.lineTo(cx + s * 0.7, py);
        ctx.stroke();
      }
      break;
    }
  }
  ctx.restore();
}

interface GNode extends SimulationNodeDatum {
  id: string;
  label: string;
  online: boolean;
  ip: string;
  deviceClass: string | null;
  totalHits: number;
  radius: number;
  iconType: IconType;
}
type EdgeDirection = 'out' | 'in' | 'balanced';

interface GLink extends SimulationLinkDatum<GNode> {
  port: number;
  portLabel: string;
  hits: number;
  bytes: number;
  direction: EdgeDirection;  // drives color + arrow direction
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

    // Preserve positions across rebuilds. When a filter toggle changes
    // the node set (e.g. "Hide infrastructure chatter" removes half the
    // edges and therefore half the nodes), naive .map() creates fresh
    // GNode objects with no x/y. d3 then re-initialises them on a tiny
    // phyllotaxis spiral around the origin — hence the "everything
    // clumps in the bottom-right" bug. Carrying x/y over lets surviving
    // nodes stay put and only new ones re-lay-out.
    const prevByIp = new Map<string, GNode>();
    nodesRef.current.forEach(n => { prevByIp.set(n.id, n); });

    const gNodes: GNode[] = nodes.map(n => {
      const label = n.display_name || n.hostname || n.ip;
      const prev = prevByIp.get(n.ip);
      return {
        id: n.ip,
        label,
        online: n.last_seen ? Date.now() - new Date(n.last_seen).getTime() < 300000 : false,
        ip: n.ip,
        deviceClass: n.device_class,
        totalHits: hitsByNode.get(n.ip) || 0,
        radius: 10 + ((hitsByNode.get(n.ip) || 0) / maxNodeHits) * 16,
        iconType: getDeviceIconType(label, n.device_class),
        // Preserve previous simulation position + velocity when present
        x: prev?.x, y: prev?.y, vx: prev?.vx, vy: prev?.vy,
      } as GNode;
    });

    // Add missing nodes from edges
    const ids = new Set(gNodes.map(n => n.id));
    edges.forEach(e => {
      [e.source_ip, e.target_ip].forEach(ip => {
        if (!ids.has(ip)) {
          const prev = prevByIp.get(ip);
          gNodes.push({
            id: ip, label: ip, online: false, ip, deviceClass: null,
            totalHits: hitsByNode.get(ip) || 0, radius: 10, iconType: 'device',
            x: prev?.x, y: prev?.y, vx: prev?.vx, vy: prev?.vy,
          } as GNode);
          ids.add(ip);
        }
      });
    });

    const gLinks: GLink[] = edges.map(e => {
      const orig = e.orig_bytes ?? 0;
      const resp = e.resp_bytes ?? 0;
      const total = orig + resp;
      // Direction: 60/40 split or stronger → dominant direction.
      // Otherwise balanced. Avoids flipping colors on tiny asymmetries.
      let direction: EdgeDirection = 'balanced';
      if (total > 0) {
        const outRatio = orig / total;
        if (outRatio >= 0.6) direction = 'out';
        else if (outRatio <= 0.4) direction = 'in';
      }
      return {
        source: e.source_ip as any,
        target: e.target_ip as any,
        port: e.port,
        portLabel: e.port_label,
        hits: e.hits,
        bytes: e.bytes ?? 0,
        direction,
      };
    });

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

    // Tune forces for actual canvas size. The prior hardcoded distance
    // 120 + charge -300 was tuned for a handful of nodes; with 30-50
    // nodes + 45 edges (normal home LAN after filters) that clumped
    // everything into one corner because charge wasn't strong enough
    // to counter link-springs + center-force. Scale with the canvas
    // area so layout uses the full pane.
    const linkDistance = Math.max(80, Math.min(180, Math.sqrt(width * height) / 8));
    const chargeStrength = -Math.max(400, Math.min(900, (width * height) / 1200));

    const sim = forceSimulation<GNode>(gNodes)
      .force('link', forceLink<GNode, GLink>(gLinks).id(d => d.id).distance(linkDistance))
      .force('charge', forceManyBody().strength(chargeStrength))
      .force('center', forceCenter(width / 2, height / 2))
      .force('collide', forceCollide<GNode>().radius(d => d.radius + 10))
      .alphaDecay(0.03)
      .velocityDecay(0.35);

    // Warm the layout synchronously so the first frame already shows
    // a readable graph instead of a tiny clump near the origin that
    // slowly expands. ~80 ticks is enough for 50-node graphs to
    // converge to a stable layout; the running timer keeps it
    // refining + responding to drags afterwards.
    sim.tick(80);

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

      // Edge color palette — keyed on direction of traffic flow.
      // 'out' = src uploads more (orange/amber); 'in' = peer uploads more
      // to src so from src's POV this is inbound/download (blue);
      // 'balanced' = neither direction dominates (neutral slate).
      // Colors match the legend strip rendered above the canvas.
      const palette = {
        out: {
          line:   isDark ? '245,158,11' : '217,119,6',    // amber
          arrow:  isDark ? 'rgba(245,158,11,0.7)' : 'rgba(217,119,6,0.6)',
          dot:    isDark ? 'rgba(251,191,36,0.85)' : 'rgba(217,119,6,0.65)',
          pillBg: isDark ? 'rgba(120,53,15,0.8)'   : 'rgba(254,243,199,0.95)',
          pillFg: isDark ? '#fcd34d'                : '#b45309',
          pillBd: isDark ? 'rgba(252,211,77,0.3)'  : 'rgba(217,119,6,0.25)',
        },
        in: {
          line:   isDark ? '59,130,246'  : '37,99,235',
          arrow:  isDark ? 'rgba(59,130,246,0.7)'  : 'rgba(37,99,235,0.6)',
          dot:    isDark ? 'rgba(147,197,253,0.85)' : 'rgba(37,99,235,0.6)',
          pillBg: isDark ? 'rgba(30,58,138,0.8)'   : 'rgba(219,234,254,0.95)',
          pillFg: isDark ? '#93c5fd'                : '#1e40af',
          pillBd: isDark ? 'rgba(147,197,253,0.3)' : 'rgba(37,99,235,0.25)',
        },
        balanced: {
          line:   isDark ? '148,163,184' : '100,116,139',
          arrow:  isDark ? 'rgba(148,163,184,0.55)' : 'rgba(100,116,139,0.5)',
          dot:    isDark ? 'rgba(203,213,225,0.75)' : 'rgba(100,116,139,0.55)',
          pillBg: isDark ? 'rgba(30,41,59,0.85)'   : 'rgba(241,245,249,0.95)',
          pillFg: isDark ? '#cbd5e1'                : '#475569',
          pillBd: isDark ? 'rgba(203,213,225,0.25)' : 'rgba(100,116,139,0.2)',
        },
      } as const;

      // --- Draw links ---
      gLinks.forEach((l, i) => {
        const src = l.source as any as GNode;
        const tgt = l.target as any as GNode;
        if (src.x == null || tgt.x == null || src.y == null || tgt.y == null) return;

        const intensity = Math.min(1, (l.hits / maxHits) * 0.8 + 0.2);
        const lw = Math.max(1.5, Math.min(5, (l.hits / maxHits) * 5));
        const c = palette[l.direction];

        // Link line
        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.lineTo(tgt.x, tgt.y);
        ctx.strokeStyle = `rgba(${c.line},${(isDark ? 0.45 : 0.4) * intensity})`;
        ctx.lineWidth = lw;
        if (l.hits / maxHits < 0.15) ctx.setLineDash([4, 3]);
        else ctx.setLineDash([]);
        ctx.stroke();
        ctx.setLineDash([]);

        // Arrow head — pointing in the direction of dominant byte flow.
        // For 'in' (src downloads), reverse so the arrow points src→src's
        // direction of incoming data. For balanced keep the default
        // src→tgt orientation (it still anchors the visual).
        const reverse = l.direction === 'in';
        const fromX = reverse ? tgt.x : src.x;
        const fromY = reverse ? tgt.y : src.y;
        const toX = reverse ? src.x : tgt.x;
        const toY = reverse ? src.y : tgt.y;
        const angle = Math.atan2(toY - fromY, toX - fromX);
        const arrowPos = 0.82;
        const ax = fromX + (toX - fromX) * arrowPos;
        const ay = fromY + (toY - fromY) * arrowPos;
        const arrowLen = 6;
        ctx.beginPath();
        ctx.moveTo(ax, ay);
        ctx.lineTo(ax - arrowLen * Math.cos(angle - 0.35), ay - arrowLen * Math.sin(angle - 0.35));
        ctx.lineTo(ax - arrowLen * Math.cos(angle + 0.35), ay - arrowLen * Math.sin(angle + 0.35));
        ctx.closePath();
        ctx.fillStyle = c.arrow;
        ctx.fill();

        // Animated particles — flow in the dominant-byte direction.
        const pArr = particles.get(i);
        if (pArr) {
          const speed = 0.003 + (l.hits / maxHits) * 0.006;
          const pSize = Math.max(2, Math.min(4, (l.hits / maxHits) * 4));
          for (let p = 0; p < pArr.length; p++) {
            pArr[p] = (pArr[p] + speed) % 1;
            const t = pArr[p];
            const px = fromX + (toX - fromX) * t;
            const py = fromY + (toY - fromY) * t;
            ctx.beginPath();
            ctx.arc(px, py, pSize, 0, Math.PI * 2);
            ctx.fillStyle = c.dot;
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
        ctx.fillStyle = c.pillBg;
        ctx.beginPath();
        ctx.roundRect(mx - tw / 2 - padX, my - pillH / 2, tw + padX * 2, pillH, rr);
        ctx.fill();
        ctx.restore();

        ctx.strokeStyle = c.pillBd;
        ctx.lineWidth = 0.5;
        ctx.beginPath();
        ctx.roundRect(mx - tw / 2 - padX, my - pillH / 2, tw + padX * 2, pillH, rr);
        ctx.stroke();

        ctx.fillStyle = c.pillFg;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(text, mx, my);

        // Hit count
        ctx.font = `500 7px Inter, system-ui, sans-serif`;
        ctx.fillStyle = isDark ? 'rgba(248,113,113,0.45)' : 'rgba(185,28,28,0.35)';
        ctx.fillText(`${fmtNumber(l.hits)}×`, mx, my + pillH / 2 + 7);
      });

      // --- Draw nodes ---
      gNodes.forEach(n => {
        if (n.x == null || n.y == null) return;
        const x = n.x;
        const y = n.y;
        const r = n.radius;
        const colors = getNodeColor(n.deviceClass, n.online);

        // Subtle glow behind icon (pulsing for online)
        if (n.online) {
          const pulse = Math.sin(frameRef.current * 0.04) * 0.12 + 0.88;
          const glowR = r * 0.9;
          const grad = ctx.createRadialGradient(x, y, 0, x, y, glowR * pulse);
          grad.addColorStop(0, colors.glow);
          grad.addColorStop(1, 'transparent');
          ctx.beginPath();
          ctx.arc(x, y, glowR * pulse, 0, Math.PI * 2);
          ctx.fillStyle = grad;
          ctx.fill();
        }

        // Device icon — drawn directly, no circle background
        const iconColor = n.online ? colors.main : (isDark ? '#64748b' : '#94a3b8');
        drawDeviceIcon(ctx, n.iconType, x, y, r * 1.1, iconColor);

        // Online dot
        if (n.online) {
          const dotR = Math.max(2, r * 0.15);
          const dx = x + r * 0.45;
          const dy = y - r * 0.45;
          ctx.beginPath();
          ctx.arc(dx, dy, dotR + 1, 0, Math.PI * 2);
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
        // Pin every node to its current position so the simulation's
        // force-link can't drag neighbours around when we move this
        // one — avoids the "elastic band" wobble where the whole
        // graph swims after the cursor. Only the dragged node has
        // its fx/fy updated during onMove; the others stay frozen
        // because their fx/fy overrides whatever the forces compute.
        nodesRef.current.forEach(n => {
          n.fx = n.x;
          n.fy = n.y;
        });
        // Reheat the simulation — required so each tick still runs
        // and propagates the dragged node's fx/fy into its rendered
        // x/y. Without this the drag looks completely frozen.
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
        // Only unpin the node the user was actually dragging. Leaving
        // all other nodes pinned (fx/fy = their x/y) means the
        // released node drifts gently toward its force-preferred spot
        // while the rest of the graph stays put — matching how the
        // user expects a drag to feel.
        const dragged = dragRef.current.node;
        dragged.fx = null;
        dragged.fy = null;
        dragRef.current = null;
        // Let alpha decay naturally to alphaTarget(0). Don't force
        // alpha(0) — that stops the timer entirely and the next drag
        // can't reheat it without running ticks first, which looked
        // like "drag is frozen".
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

