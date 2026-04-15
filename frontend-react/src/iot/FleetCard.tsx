/**
 * Shared IoT fleet components — used by both IotOverview and Dashboard.
 */
import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { AreaChart, Area, Tooltip as RTooltip, ResponsiveContainer } from 'recharts';
import { fetchTrafficHistory, fetchDestinationHistory } from './api';
import type { FleetDevice } from './types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
export function fmtBytes(b: number): string {
  if (b >= 1099511627776) return (b / 1099511627776).toFixed(2) + ' TB';
  if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GB';
  if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
  if (b >= 1024) return (b / 1024).toFixed(0) + ' KB';
  return b + ' B';
}

export function deviceName(d: { display_name?: string | null; hostname?: string | null; mac_address?: string; ips?: string[] }): string {
  return d.display_name || d.hostname || d.ips?.[0] || d.mac_address || '?';
}

export const HEALTH_RING: Record<string, string> = {
  green: 'ring-emerald-500/40',
  orange: 'ring-amber-500/50',
  red: 'ring-red-500/50',
};

export function FlagIcon({ cc, size = '1em' }: { cc: string; size?: string }) {
  if (!cc || cc.length !== 2) return null;
  return <span className={`fi fi-${cc.toLowerCase()} rounded-sm shadow-sm inline-block`} style={{ fontSize: size }} />;
}

// ---------------------------------------------------------------------------
// BaselineBadge
// ---------------------------------------------------------------------------
export function BaselineBadge({ status, days }: { status: string; days: number }) {
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
export function Sparkline({ mac }: { mac: string }) {
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
            formatter={(v: any, name: any) => [fmtBytes(v ?? 0), name === 'rx' ? '↓ RX' : '↑ TX']}
          />
          <Area type="monotone" dataKey="rx" stroke="#3b82f6" strokeWidth={1.5} fill={`url(#rx-${mac})`} dot={false} isAnimationActive={false} />
          <Area type="monotone" dataKey="tx" stroke="#f59e0b" strokeWidth={1} fill={`url(#tx-${mac})`} dot={false} isAnimationActive={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

// ---------------------------------------------------------------------------
// RadarChart — pure SVG behaviour fingerprint (6 axes)
// ---------------------------------------------------------------------------
const RADAR_DIMS = [
  { key: 'volume',       short: 'VOL', label: 'Volume' },
  { key: 'frequency',    short: 'FRQ', label: 'Frequency' },
  { key: 'regularity',   short: 'REG', label: 'Regularity' },
  { key: 'uploadRatio',  short: 'UP%', label: 'Upload %' },
  { key: 'destinations', short: 'DST', label: 'Destinations' },
  { key: 'deviation',    short: 'ANO', label: 'Deviation' },
] as const;

/** Health → colour mapping for radar/heatmap. */
const HEALTH_COLOR: Record<string, { stroke: string; fill: string; dot: string }> = {
  green: { stroke: '#10b981', fill: 'rgba(16,185,129,0.15)', dot: '#10b981' },
  orange: { stroke: '#f59e0b', fill: 'rgba(245,158,11,0.15)', dot: '#f59e0b' },
  red:    { stroke: '#ef4444', fill: 'rgba(239,68,68,0.15)',  dot: '#ef4444' },
};

/** Derive 0-100 radar dimensions from existing FleetDevice fields. */
function computeRadar(d: FleetDevice): Record<string, number> {
  // Volume: log scale — 1 KB=20, 1 MB=40, 100 MB=60, 1 GB=70, 10 GB=85, 100 GB=100
  const vol = d.bytes_24h > 0
    ? Math.min(100, Math.max(5, (Math.log10(d.bytes_24h) - 3) / 8 * 100))
    : 0;

  // Frequency: sqrt scale — 100 hits=10, 1k=32, 5k=71, 10k=100
  const freq = Math.min(100, Math.sqrt(d.hits_24h / 10000) * 100);

  // Regularity: how close to baseline (100 = exactly on baseline, 0 = 5x deviation)
  const ratio = d.baseline_avg_bytes_24h && d.baseline_avg_bytes_24h > 0
    ? d.bytes_24h / d.baseline_avg_bytes_24h : 1;
  const deviation = Math.abs(ratio - 1);  // 0 = perfect, 4.8 = 580%
  const reg = Math.max(0, 100 - deviation * 25);

  // Upload ratio: direct percentage (0-100)
  const upRatio = d.bytes_24h > 0 ? (d.orig_bytes_24h / d.bytes_24h) * 100 : 0;

  // Destinations: sqrt scale — 5=45, 10=63, 25=100, 50+=100
  const dests = Math.min(100, Math.sqrt(d.destinations / 25) * 100);

  // Deviation from normal: combines baseline deviation + anomaly count
  // 580% baseline alone should score high, anomalies add more
  const baselineDev = Math.min(50, deviation * 12);
  const anomalyDev = Math.min(50, d.anomalies * 20);
  const dev = Math.min(100, baselineDev + anomalyDev);

  return { volume: vol, frequency: freq, regularity: reg, uploadRatio: upRatio, destinations: dests, deviation: dev };
}

export function RadarChart({ device, size = 120 }: { device: FleetDevice; size?: number }) {
  const [tip, setTip] = useState<string | null>(null);
  const radar = useMemo(() => computeRadar(device), [device]);
  const n = RADAR_DIMS.length;
  const cx = size / 2, cy = size / 2, maxR = size / 2 - 18;
  const angleStep = (2 * Math.PI) / n;
  const hc = HEALTH_COLOR[device.health] || HEALTH_COLOR.green;
  const color = hc.stroke;
  const fill = hc.fill;

  // Grid rings
  const rings = [0.25, 0.5, 0.75, 1].map(r => {
    const pts = Array.from({ length: n }, (_, i) => {
      const a = -Math.PI / 2 + i * angleStep;
      return `${cx + Math.cos(a) * maxR * r},${cy + Math.sin(a) * maxR * r}`;
    }).join(' ');
    return <polygon key={r} points={pts} fill="none" stroke="rgba(255,255,255,0.08)" />;
  });

  // Axis lines
  const axes = Array.from({ length: n }, (_, i) => {
    const a = -Math.PI / 2 + i * angleStep;
    return <line key={i} x1={cx} y1={cy} x2={cx + Math.cos(a) * maxR} y2={cy + Math.sin(a) * maxR} stroke="rgba(255,255,255,0.08)" />;
  });

  // Data polygon + dots
  const points: string[] = [];
  const dots = RADAR_DIMS.map((dim, i) => {
    const a = -Math.PI / 2 + i * angleStep;
    const v = radar[dim.key] / 100;
    const x = cx + Math.cos(a) * maxR * v;
    const y = cy + Math.sin(a) * maxR * v;
    points.push(`${x},${y}`);
    return (
      <circle
        key={dim.key} cx={x} cy={y} r={2.5} fill={color}
        className="cursor-pointer transition-all hover:[r:4]"
        onMouseEnter={() => setTip(`${dim.label}: ${Math.round(radar[dim.key])}%`)}
        onMouseLeave={() => setTip(null)}
      />
    );
  });

  // Labels
  const labels = RADAR_DIMS.map((dim, i) => {
    const a = -Math.PI / 2 + i * angleStep;
    const lx = cx + Math.cos(a) * (maxR + 12);
    const ly = cy + Math.sin(a) * (maxR + 12);
    const anchor = Math.abs(Math.cos(a)) < 0.1 ? 'middle' : Math.cos(a) > 0 ? 'start' : 'end';
    return <text key={dim.key} x={lx} y={ly} textAnchor={anchor} dominantBaseline="central" fill="rgba(148,163,184,0.7)" fontSize={9} fontWeight={500}>{dim.short}</text>;
  });

  return (
    <div className="relative flex items-center justify-center">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="overflow-visible">
        {rings}{axes}
        <polygon points={points.join(' ')} fill={fill} stroke={color} strokeWidth={1.5} opacity={0.8} />
        {dots}{labels}
      </svg>
      {tip && (
        <div className="absolute -top-1 left-1/2 -translate-x-1/2 bg-black/90 text-slate-200 text-[10px] px-2 py-0.5 rounded pointer-events-none whitespace-nowrap z-10">
          {tip}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Heatmap — per-destination hourly traffic grid
// ---------------------------------------------------------------------------
export function Heatmap({ mac, health = 'green' }: { mac: string; health?: string }) {
  const [tip, setTip] = useState<{ text: string; x: number; y: number } | null>(null);
  const { data, isLoading } = useQuery({
    queryKey: ['iot-heatmap', mac],
    queryFn: () => fetchDestinationHistory(mac, 24),
    staleTime: 120_000,
  });

  if (isLoading) {
    return <div className="h-16 bg-slate-100 dark:bg-white/[0.03] rounded animate-pulse" />;
  }

  const dests = data?.destinations || [];
  if (dests.length === 0) {
    return (
      <div className="h-16 flex items-center justify-center text-[10px] text-slate-400">
        No destination data
      </div>
    );
  }

  // Compact cells: fit 24 hours in small space
  const cellW = 6, cellH = 10, padLeft = 48, gap = 1;
  const svgW = padLeft + 24 * cellW + 2;
  const svgH = dests.length * (cellH + gap) + 14;

  // Max for colour scale
  const maxVal = Math.max(1, ...dests.flatMap(d => d.hours));

  // Colour scale based on device health
  const useWarm = health === 'red' || health === 'orange';
  function intensity(v: number): string {
    const t = Math.sqrt(v / maxVal);
    if (useWarm) {
      return `rgb(${Math.round(30 + t * 225)},${Math.round(20 + t * 50)},${Math.round(10 + t * 20)})`;
    }
    return `rgb(${Math.round(15 + t * 30)},${Math.round(25 + t * 80)},${Math.round(60 + t * 196)})`;
  }

  return (
    <div className="relative">
      <svg width="100%" viewBox={`0 0 ${svgW} ${svgH}`} preserveAspectRatio="xMinYMin meet" className="overflow-visible">
        {dests.map((dest, ri) => {
          const y = ri * (cellH + gap);
          const label = dest.dest.length > 7 ? dest.dest.slice(0, 6) + '…' : dest.dest;
          return (
            <g key={dest.dest}>
              <text x={padLeft - 3} y={y + cellH / 2} textAnchor="end" dominantBaseline="central"
                fill="rgba(148,163,184,0.6)" fontSize={7}>{label}</text>
              {dest.hours.map((val, hi) => (
                <rect
                  key={hi}
                  x={padLeft + hi * cellW} y={y}
                  width={cellW - 1} height={cellH}
                  rx={1} ry={1}
                  fill={val > 0 ? intensity(val) : 'rgba(255,255,255,0.02)'}
                  className="cursor-pointer hover:stroke-white hover:[stroke-width:0.5]"
                  onMouseEnter={(e) => {
                    const rect = (e.target as SVGRectElement).getBoundingClientRect();
                    setTip({ text: `${dest.dest} @ ${hi}:00 — ${fmtBytes(val)}`, x: rect.x, y: rect.y });
                  }}
                  onMouseLeave={() => setTip(null)}
                />
              ))}
            </g>
          );
        })}
        {/* Hour labels */}
        {[0, 6, 12, 18].map(h => (
          <text key={h} x={padLeft + h * cellW + cellW / 2} y={dests.length * (cellH + gap) + 9}
            textAnchor="middle" fill="rgba(148,163,184,0.5)" fontSize={7}>{h}h</text>
        ))}
      </svg>
      {tip && (
        <div className="fixed bg-black/90 text-slate-200 text-[10px] px-2 py-0.5 rounded pointer-events-none whitespace-nowrap z-50"
          style={{ left: tip.x, top: tip.y - 24 }}>
          {tip.text}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// DeviceViz — radar + heatmap side-by-side, sparkline toggle
// ---------------------------------------------------------------------------
function DeviceViz({ device }: { device: FleetDevice }) {
  const [showTraffic, setShowTraffic] = useState(false);

  if (showTraffic) {
    return (
      <div>
        <button onClick={() => setShowTraffic(false)}
          className="text-[9px] text-slate-500 hover:text-slate-300 mb-1">
          ← Back to radar
        </button>
        <Sparkline mac={device.mac_address} />
      </div>
    );
  }

  return (
    <div>
      <div className="flex gap-2 items-start">
        {/* Radar — left side */}
        <div className="flex-shrink-0">
          <RadarChart device={device} size={110} />
        </div>
        {/* Heatmap — right side, fills remaining space */}
        <div className="flex-1 min-w-0 overflow-hidden">
          <Heatmap mac={device.mac_address} health={device.health} />
        </div>
      </div>
      <button onClick={() => setShowTraffic(true)}
        className="text-[9px] text-slate-500 hover:text-slate-300 mt-1">
        〰 Traffic history
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// FleetCard — full device card with radar/heatmap, baseline, flags, stats
// ---------------------------------------------------------------------------
export function FleetCard({ device: d }: { device: FleetDevice }) {
  const name = deviceName(d);
  const healthRing = HEALTH_RING[d.health] || HEALTH_RING.green;

  const ratio = d.baseline_avg_bytes_24h && d.baseline_avg_bytes_24h > 0
    ? d.bytes_24h / d.baseline_avg_bytes_24h
    : null;
  const barPct = ratio ? Math.min(ratio * 100, 300) / 3 : null;
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

      {/* Radar / Heatmap / Sparkline */}
      <DeviceViz device={d} />

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
