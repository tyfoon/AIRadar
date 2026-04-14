import { useState, useMemo, useRef, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  PieChart, Pie, Cell, ResponsiveContainer,
  AreaChart, Area,
} from 'recharts';
import {
  fetchHealth, fetchSystemPerf, fetchNetworkPerf,
  fetchPrivacyStats, fetchIpsStatus, fetchFleetSummary, fetchDashEvents,
} from './api';
import type { DashEvent } from './types';
import { categoryColor, categoryName, formatBytes, serviceName } from '../colors';
import { formatNumber, countryName, flagClass } from '../geo/utils';
import GeoMap from '../geo/GeoMap';
import { FleetCard } from '../iot/FleetCard';
import type { FleetDevice } from '../iot/types';

// ---------------------------------------------------------------------------
// Dashboard — System Overview
// ---------------------------------------------------------------------------
export default function Dashboard() {
  const health = useQuery({ queryKey: ['dash-health'], queryFn: fetchHealth, refetchInterval: 30_000 });
  const sysPerf = useQuery({ queryKey: ['dash-sys-perf'], queryFn: fetchSystemPerf, refetchInterval: 60_000 });
  const netPerf = useQuery({ queryKey: ['dash-net-perf'], queryFn: fetchNetworkPerf, refetchInterval: 60_000 });
  const privacy = useQuery({ queryKey: ['dash-privacy'], queryFn: fetchPrivacyStats, refetchInterval: 60_000 });
  const ips = useQuery({ queryKey: ['dash-ips'], queryFn: fetchIpsStatus, refetchInterval: 30_000 });
  const fleet = useQuery({ queryKey: ['dash-fleet'], queryFn: fetchFleetSummary, refetchInterval: 60_000 });
  const events = useQuery({ queryKey: ['dash-events'], queryFn: fetchDashEvents, refetchInterval: 30_000 });

  const deviceCount = fleet.data?.total_devices ?? 0;
  const onlineCount = fleet.data?.devices?.filter(d => d.online).length ?? 0;

  return (
    <div className="space-y-4">
      {/* ── Metric Cards (5 cards — System Health+Network merged) ── */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
        <MetricCard
          icon="ph-duotone ph-heartbeat"
          iconColor={health.data?.summary.all_ok ? 'text-emerald-500' : 'text-amber-500'}
          label="System Health"
          value={health.data ? `${health.data.summary.ok}/${health.data.summary.total}` : '...'}
          sub={sysPerf.data
            ? `CPU ${Math.round(sysPerf.data.host.cpu_percent)}% · Mem ${Math.round(sysPerf.data.host.memory.percent)}%`
            : health.data?.summary.all_ok ? 'All systems operational' : ''}
          subColor={health.data?.summary.all_ok ? 'text-emerald-500' : 'text-amber-500'}
        />
        <MetricCard
          icon="ph-duotone ph-devices"
          iconColor="text-blue-500"
          label="Devices"
          value={deviceCount}
          sub={`${onlineCount} online`}
        />
        <MetricCard
          icon="ph-duotone ph-pulse"
          iconColor="text-indigo-500"
          label="Events Today"
          value={events.data?.length ?? '...'}
          sub="AI + Cloud + all"
        />
        <MetricCard
          icon="ph-duotone ph-shield-warning"
          iconColor="text-red-500"
          label="Attacks 24h"
          value={ips.data?.inbound_attacks_24h ?? '...'}
          sub={ips.data ? `${ips.data.inbound_unique_ips_24h} unique IPs` : ''}
          subColor="text-red-400"
        />
        <MetricCard
          icon="ph-duotone ph-eye-slash"
          iconColor="text-violet-500"
          label="Privacy"
          value={privacy.data?.trackers.total_detected ?? '...'}
          sub="Trackers detected"
        />
      </div>

      {/* ── Globe + Category Donuts ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Globe (50%) */}
        <div className="bg-slate-950 rounded-xl overflow-hidden border border-slate-200 dark:border-white/[0.05]" style={{ minHeight: 380 }}>
          <GeoMap initialDirection="inbound" compact />
        </div>

        {/* Donuts grid (50%) */}
        <DonutGrid events={events.data ?? []} privacy={privacy.data} />
      </div>

      {/* ── IoT Fleet — top 3 devices, full width ── */}
      <IotFleetRow devices={fleet.data?.devices ?? []} />

      {/* ── Sankey — full width, compact ── */}
      <SankeyFlow events={events.data ?? []} />

      {/* ── Bottom Grid: IPS + Privacy + Network Perf ── */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <IpsPanel
          attacks={ips.data?.inbound_attacks_24h ?? 0}
          uniqueIps={ips.data?.inbound_unique_ips_24h ?? 0}
          blocked={ips.data?.inbound_blocked_24h ?? 0}
          topAttackers={ips.data?.inbound_attacks ?? []}
        />
        <PrivacyPanel
          trackersDetected={privacy.data?.trackers.total_detected ?? 0}
          topTrackers={privacy.data?.trackers.top_trackers ?? []}
          vpnAlerts={privacy.data?.vpn_alerts?.length ?? 0}
          beaconingThreats={privacy.data?.beaconing_alerts?.filter((b: any) => !b.dismissed).length ?? 0}
          sparkline={privacy.data?.security.sparkline_7d ?? []}
          adguardBlocked={privacy.data?.adguard.blocked_queries ?? 0}
          adguardPct={privacy.data?.adguard.block_percentage ?? 0}
        />
        <NetworkPerfPanel data={netPerf.data?.data ?? []} />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// MetricCard
// ---------------------------------------------------------------------------
function MetricCard({ icon, iconColor, label, value, sub, subColor }: {
  icon: string; iconColor: string; label: string;
  value: string | number; sub?: string; subColor?: string;
}) {
  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4">
      <div className="flex items-center gap-2 mb-2">
        <i className={`${icon} text-lg ${iconColor}`} />
        <span className="text-[11px] text-slate-400 dark:text-slate-500 font-medium uppercase tracking-wide">{label}</span>
      </div>
      <p className="text-2xl font-bold tabular-nums text-slate-700 dark:text-slate-100">{value}</p>
      {sub && <p className={`text-[11px] mt-0.5 ${subColor || 'text-slate-400'}`}>{sub}</p>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// DonutGrid — AI, Cloud, 7 content categories, Trackers
// ---------------------------------------------------------------------------
const CONTENT_CATEGORIES = ['streaming', 'gaming', 'social', 'shopping', 'news', 'adult', 'communication'] as const;

function DonutGrid({ events, privacy }: { events: DashEvent[]; privacy: any }) {
  const donuts = useMemo(() => {
    const byCat: Record<string, Record<string, number>> = {};
    events.forEach(e => {
      if (!byCat[e.category]) byCat[e.category] = {};
      byCat[e.category][e.ai_service] = (byCat[e.category][e.ai_service] || 0) + 1;
    });

    const make = (cat: string) => {
      const m = byCat[cat] || {};
      const data = Object.entries(m).map(([name, value]) => ({ name: serviceName(name), value, key: name }));
      const total = data.reduce((s, d) => s + d.value, 0);
      return { data, total };
    };

    return {
      ai: make('ai'),
      cloud: make('cloud'),
      content: CONTENT_CATEGORIES.map(c => ({ cat: c, ...make(c) })),
    };
  }, [events]);

  const trackerTotal = privacy?.trackers?.total_detected ?? 0;
  const trackerData = (privacy?.trackers?.top_trackers ?? []).slice(0, 5).map((t: any) => ({
    name: serviceName(t.service), value: t.hits, key: t.service,
  }));

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4">
      <p className="text-[11px] text-slate-400 dark:text-slate-500 font-medium uppercase tracking-wide mb-3">Traffic by Category</p>
      <div className="grid grid-cols-5 gap-2">
        {/* AI + Cloud — first row, slightly larger */}
        <TinyDonut label="AI" data={donuts.ai.data} total={donuts.ai.total} color={categoryColor('ai')} />
        <TinyDonut label="Cloud" data={donuts.cloud.data} total={donuts.cloud.total} color={categoryColor('cloud')} />
        {/* Content categories */}
        {donuts.content.map(c => (
          <TinyDonut key={c.cat} label={categoryName(c.cat)} data={c.data} total={c.total} color={categoryColor(c.cat)} />
        ))}
        {/* Trackers */}
        <TinyDonut label="Trackers" data={trackerData} total={trackerTotal} color={categoryColor('tracking')} />
      </div>
    </div>
  );
}

function TinyDonut({ label, data, total, color }: {
  label: string; data: { name: string; value: number; key: string }[];
  total: number; color: string;
}) {
  const COLORS = useMemo(() => {
    if (!data.length) return ['#334155'];
    const base = color;
    // Generate shades from the base color
    return data.map((_, i) => {
      const opacity = 1 - (i * 0.15);
      return i === 0 ? base : base + Math.round(opacity * 255).toString(16).padStart(2, '0').slice(0, 2);
    });
  }, [data, color]);

  const displayData = data.length ? data.slice(0, 6) : [{ name: 'None', value: 1, key: '_empty' }];
  const isEmpty = !data.length;

  return (
    <div className="flex flex-col items-center gap-1">
      <div style={{ width: 56, height: 56 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={displayData} dataKey="value" cx="50%" cy="50%"
              innerRadius={16} outerRadius={26} strokeWidth={0} paddingAngle={1}>
              {displayData.map((_, i) => <Cell key={i} fill={isEmpty ? '#334155' : COLORS[i % COLORS.length]} />)}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
      </div>
      <p className="text-[10px] font-medium text-slate-500 dark:text-slate-400 text-center leading-tight">{label}</p>
      <p className="text-xs font-bold tabular-nums text-slate-700 dark:text-slate-100">{formatNumber(total)}</p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// IoT Fleet Row — top 3 most active devices (full FleetCard from IoT page)
// ---------------------------------------------------------------------------
function IotFleetRow({ devices }: { devices: FleetDevice[] }) {
  const top = useMemo(() =>
    [...devices].sort((a, b) => b.bytes_24h - a.bytes_24h).slice(0, 3),
  [devices]);

  const total = devices.length;
  const online = devices.filter(d => d.online).length;
  const anomalies = devices.reduce((s, d) => s + d.anomalies, 0);

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <i className="ph-duotone ph-cpu text-lg text-teal-500" />
          <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">IoT Fleet</span>
        </div>
        <div className="flex items-center gap-3 text-[11px] text-slate-400">
          <span>{total} devices</span>
          <span className="text-emerald-500">{online} online</span>
          {anomalies > 0 && <span className="text-amber-500">{anomalies} anomalies</span>}
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {top.map(d => <FleetCard key={d.mac_address} device={d} />)}
        {top.length === 0 && (
          <div className="col-span-3 flex items-center justify-center text-xs text-slate-400 py-4">No IoT devices detected</div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sankey Flow — Pure SVG with gradient flows and hover effects
// ---------------------------------------------------------------------------
const CAT_COLORS: Record<string, string> = {
  AI: '#6366f1', Cloud: '#3b82f6', Streaming: '#e50914', Gaming: '#10b981',
  Social: '#f59e0b', Tracking: '#ef4444', Shopping: '#8b5cf6', News: '#06b6d4',
  Adult: '#64748b', Communication: '#0ea5e9',
};

interface SankeyNode { name: string; isDevice: boolean; value: number; y: number; h: number }
interface SankeyLink { source: string; target: string; raw: number; value: number; sy: number; ty: number; sh: number; th: number }

function SankeyFlow({ events }: { events: DashEvent[] }) {
  const [modeHits, setModeHits] = useState(false);
  const [excludeTop, setExcludeTop] = useState(false);
  const [hovered, setHovered] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(800);

  useEffect(() => {
    if (!containerRef.current) return;
    const measure = () => { if (containerRef.current) setWidth(containerRef.current.clientWidth); };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, []);

  const layout = useMemo(() => {
    if (!events.length) return null;

    const metric = modeHits ? () => 1 : (e: DashEvent) => (e.bytes_transferred || 1);
    const devName = (ip: string) => {
      if (typeof (window as any).deviceName === 'function') return (window as any).deviceName(ip);
      return ip;
    };

    const devTotals: Record<string, number> = {};
    events.forEach(e => { const d = devName(e.source_ip); devTotals[d] = (devTotals[d] || 0) + metric(e); });
    const topDev = Object.entries(devTotals).sort((a, b) => b[1] - a[1])[0];
    const topDevNameVal = topDev?.[0] ?? '';

    let filtered = events;
    if (excludeTop && topDevNameVal) filtered = events.filter(e => devName(e.source_ip) !== topDevNameVal);

    const flowMap: Record<string, number> = {};
    const dFlows: Record<string, number> = {};
    const cFlows: Record<string, number> = {};
    filtered.forEach(e => {
      const dev = devName(e.source_ip);
      const cat = categoryName(e.category);
      const val = metric(e);
      flowMap[`${dev}\0${cat}`] = (flowMap[`${dev}\0${cat}`] || 0) + val;
      dFlows[dev] = (dFlows[dev] || 0) + val;
      cFlows[cat] = (cFlows[cat] || 0) + val;
    });

    const top8 = new Set(Object.entries(dFlows).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([d]) => d));
    const devList = [...top8].sort((a, b) => (dFlows[b] || 0) - (dFlows[a] || 0));
    const catList = Object.entries(cFlows).sort((a, b) => b[1] - a[1]).map(([c]) => c);

    // Compact height
    const H = Math.max(200, Math.max(devList.length, catList.length) * 32);
    const nodeW = 12;
    const padL = 8;
    const padR = 8;
    const gap = 5;

    const totalDevVal = devList.reduce((s, d) => s + Math.sqrt(dFlows[d] || 0), 0);
    const devAvailH = H - gap * (devList.length - 1);
    let dy = 0;
    const devNodes: SankeyNode[] = devList.map(d => {
      const h = Math.max(10, (Math.sqrt(dFlows[d] || 0) / totalDevVal) * devAvailH);
      const node: SankeyNode = { name: d, isDevice: true, value: dFlows[d] || 0, y: dy, h };
      dy += h + gap;
      return node;
    });

    const totalCatVal = catList.reduce((s, c) => s + Math.sqrt(cFlows[c] || 0), 0);
    const catAvailH = H - gap * (catList.length - 1);
    let cy = 0;
    const catNodes: SankeyNode[] = catList.map(c => {
      const h = Math.max(10, (Math.sqrt(cFlows[c] || 0) / totalCatVal) * catAvailH);
      const node: SankeyNode = { name: c, isDevice: false, value: cFlows[c] || 0, y: cy, h };
      cy += h + gap;
      return node;
    });

    const devUsed: Record<string, number> = {};
    const catUsed: Record<string, number> = {};
    const links: SankeyLink[] = [];

    devList.forEach(dev => {
      const devFlowsForDev = Object.entries(flowMap)
        .filter(([k]) => k.startsWith(dev + '\0') && top8.has(dev))
        .sort((a, b) => b[1] - a[1]);

      const dn = devNodes.find(n => n.name === dev)!;
      const devTotal = Math.sqrt(dFlows[dev] || 0);

      devFlowsForDev.forEach(([key, raw]) => {
        const cat = key.split('\0')[1];
        const cn = catNodes.find(n => n.name === cat);
        if (!cn) return;

        const scaledVal = Math.sqrt(raw);
        const sh = (scaledVal / devTotal) * dn.h;
        const catTotal = Math.sqrt(cFlows[cat] || 0);
        const th = (scaledVal / catTotal) * cn.h;

        const sy = dn.y + (devUsed[dev] || 0);
        const ty = cn.y + (catUsed[cat] || 0);
        devUsed[dev] = (devUsed[dev] || 0) + sh;
        catUsed[cat] = (catUsed[cat] || 0) + th;

        links.push({ source: dev, target: cat, raw, value: scaledVal, sy, ty, sh, th });
      });
    });

    return { devNodes, catNodes, links, topDevName: topDevNameVal, height: H, nodeW, padL, padR, modeHits, dFlows, cFlows };
  }, [events, modeHits, excludeTop]);

  if (!layout || !events.length) return null;

  const { devNodes, catNodes, links, topDevName, height, nodeW, padL, padR, dFlows, cFlows } = layout;
  const labelW = 110;
  const svgW = width;
  const leftX = padL + labelW;
  const rightX = svgW - padR - labelW - nodeW;
  const svgH = height + 20;

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
          <i className="ph-duotone ph-flow-arrow text-blue-500" /> Network Flow
        </h3>
        <div className="flex items-center gap-3">
          {topDevName && (
            <label className="flex items-center gap-1.5 text-[11px] text-slate-500 dark:text-slate-400 cursor-pointer">
              <input type="checkbox" checked={excludeTop} onChange={e => setExcludeTop(e.target.checked)}
                className="rounded border-slate-300 dark:border-slate-600 text-blue-600" />
              Exclude {topDevName}
            </label>
          )}
          <button onClick={() => setModeHits(!modeHits)}
            className="text-[11px] px-2.5 py-1 rounded-md bg-slate-100 dark:bg-white/[0.05] text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-white/[0.08] transition-colors">
            {modeHits ? 'Hits' : 'Bytes'}
          </button>
        </div>
      </div>
      <div ref={containerRef} style={{ width: '100%' }}>
        <svg width={svgW} height={svgH} className="overflow-visible">
          <defs>
            {links.map((l, i) => {
              const srcColor = '#3b82f6';
              const tgtColor = CAT_COLORS[l.target] || '#6366f1';
              return (
                <linearGradient key={`lg-${i}`} id={`sankey-g-${i}`} x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%" stopColor={srcColor} stopOpacity={0.5} />
                  <stop offset="100%" stopColor={tgtColor} stopOpacity={0.5} />
                </linearGradient>
              );
            })}
          </defs>

          {links.map((l, i) => {
            const x0 = leftX + nodeW;
            const x1 = rightX;
            const midX = (x0 + x1) / 2;
            const y0s = l.sy + 10;
            const y0e = l.sy + l.sh + 10;
            const y1s = l.ty + 10;
            const y1e = l.ty + l.th + 10;
            const isHigh = hovered === l.source || hovered === l.target;
            const isDim = hovered && !isHigh;
            const d = `M${x0},${y0s} C${midX},${y0s} ${midX},${y1s} ${x1},${y1s} L${x1},${y1e} C${midX},${y1e} ${midX},${y0e} ${x0},${y0e} Z`;
            return (
              <path key={`link-${i}`} d={d} fill={`url(#sankey-g-${i})`}
                opacity={isDim ? 0.08 : isHigh ? 0.6 : 0.25}
                className="transition-opacity duration-200"
                onMouseEnter={() => setHovered(l.source)}
                onMouseLeave={() => setHovered(null)}>
                <title>{`${l.source} → ${l.target}: ${modeHits ? l.raw.toLocaleString() + ' hits' : formatBytes(l.raw)}`}</title>
              </path>
            );
          })}

          {devNodes.map(n => {
            const isHigh = hovered === n.name;
            const isDim = hovered && !isHigh && !links.some(l => l.source === n.name && l.target === hovered);
            return (
              <g key={`dn-${n.name}`}
                onMouseEnter={() => setHovered(n.name)}
                onMouseLeave={() => setHovered(null)}
                className="cursor-pointer"
              >
                <rect x={leftX} y={n.y + 10} width={nodeW} height={n.h} rx={3}
                  fill="#3b82f6"
                  opacity={isDim ? 0.3 : 1}
                  className="transition-opacity duration-200" />
                <text x={leftX - 6} y={n.y + 10 + n.h / 2} textAnchor="end" dominantBaseline="central"
                  className="text-[11px] fill-slate-600 dark:fill-slate-300 font-medium"
                  style={{ fontFamily: 'Inter, system-ui, sans-serif' }}
                  opacity={isDim ? 0.4 : 1}>
                  {n.name.length > 16 ? n.name.slice(0, 15) + '…' : n.name}
                </text>
                {isHigh && (
                  <text x={leftX - 6} y={n.y + 10 + n.h / 2 + 13} textAnchor="end" dominantBaseline="central"
                    className="text-[9px] fill-slate-400"
                    style={{ fontFamily: 'Inter, system-ui, sans-serif' }}>
                    {modeHits ? `${(dFlows[n.name] || 0).toLocaleString()} hits` : formatBytes(dFlows[n.name] || 0)}
                  </text>
                )}
              </g>
            );
          })}

          {catNodes.map(n => {
            const color = CAT_COLORS[n.name] || '#6366f1';
            const isHigh = hovered === n.name;
            const isDim = hovered && !isHigh && !links.some(l => l.target === n.name && l.source === hovered);
            return (
              <g key={`cn-${n.name}`}
                onMouseEnter={() => setHovered(n.name)}
                onMouseLeave={() => setHovered(null)}
                className="cursor-pointer"
              >
                <rect x={rightX} y={n.y + 10} width={nodeW} height={n.h} rx={3}
                  fill={color}
                  opacity={isDim ? 0.3 : 1}
                  className="transition-opacity duration-200" />
                <text x={rightX + nodeW + 6} y={n.y + 10 + n.h / 2} dominantBaseline="central"
                  className="text-[11px] fill-slate-600 dark:fill-slate-300 font-medium"
                  style={{ fontFamily: 'Inter, system-ui, sans-serif' }}
                  opacity={isDim ? 0.4 : 1}>
                  {n.name}
                </text>
                {isHigh && (
                  <text x={rightX + nodeW + 6} y={n.y + 10 + n.h / 2 + 13} dominantBaseline="central"
                    className="text-[9px] fill-slate-400"
                    style={{ fontFamily: 'Inter, system-ui, sans-serif' }}>
                    {modeHits ? `${(cFlows[n.name] || 0).toLocaleString()} hits` : formatBytes(cFlows[n.name] || 0)}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Network Performance Panel
// ---------------------------------------------------------------------------
function NetworkPerfPanel({ data }: { data: { ts: string; dns_ms: number | null; loss_pct: number | null; br_rx_bps: number | null; br_tx_bps: number | null }[] }) {
  const sparkData = useMemo(() =>
    data.map(d => ({
      dns: d.dns_ms ?? 0,
      loss: d.loss_pct ?? 0,
      rx: (d.br_rx_bps ?? 0) / 1024 / 1024,
      tx: (d.br_tx_bps ?? 0) / 1024 / 1024,
    })),
  [data]);

  const lastDns = sparkData.length ? sparkData[sparkData.length - 1].dns : 0;
  const lastLoss = sparkData.length ? sparkData[sparkData.length - 1].loss : 0;
  const lastRx = sparkData.length ? sparkData[sparkData.length - 1].rx : 0;

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
      <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5 mb-3">
        <i className="ph-duotone ph-chart-line-up text-cyan-500" /> Network Performance
      </h3>
      <div className="space-y-4">
        <DashSparkline label="DNS Latency" value={`${lastDns.toFixed(1)} ms`} data={sparkData} dataKey="dns" color="#06b6d4" />
        <DashSparkline label="Packet Loss" value={`${lastLoss.toFixed(2)}%`} data={sparkData} dataKey="loss" color={lastLoss > 1 ? '#ef4444' : '#10b981'} />
        <DashSparkline label="Throughput" value={`${lastRx.toFixed(1)} Mbps`} data={sparkData} dataKey="rx" color="#3b82f6" />
      </div>
    </div>
  );
}

function DashSparkline({ label, value, data, dataKey, color }: {
  label: string; value: string; data: any[]; dataKey: string; color: string;
}) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-[11px] text-slate-500 dark:text-slate-400">{label}</span>
        <span className="text-xs font-semibold tabular-nums text-slate-700 dark:text-slate-200">{value}</span>
      </div>
      <div style={{ height: 36 }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <defs>
              <linearGradient id={`grad-${dataKey}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={color} stopOpacity={0.3} />
                <stop offset="100%" stopColor={color} stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <Area type="monotone" dataKey={dataKey} stroke={color} strokeWidth={1.5}
              fill={`url(#grad-${dataKey})`} dot={false} isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// IPS / Security Panel
// ---------------------------------------------------------------------------
function IpsPanel({ attacks, uniqueIps, blocked, topAttackers }: {
  attacks: number; uniqueIps: number; blocked: number;
  topAttackers: { country_code: string; hit_count: number; source_ip: string; crowdsec_reason: string }[];
}) {
  const topCountries = useMemo(() => {
    const m: Record<string, number> = {};
    topAttackers.forEach(a => {
      if (a.country_code) m[a.country_code] = (m[a.country_code] || 0) + a.hit_count;
    });
    return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [topAttackers]);

  const blockedPct = attacks > 0 ? Math.round((blocked / attacks) * 100) : 100;

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
      <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5 mb-3">
        <i className="ph-duotone ph-shield-warning text-red-500" /> IPS / Security
      </h3>
      <div className="grid grid-cols-2 gap-3 mb-3">
        <div className="bg-red-50 dark:bg-red-900/10 rounded-lg p-3 text-center">
          <p className="text-xl font-bold tabular-nums text-red-600 dark:text-red-400">{formatNumber(attacks)}</p>
          <p className="text-[10px] text-red-500/70">attacks 24h</p>
        </div>
        <div className="bg-slate-50 dark:bg-white/[0.02] rounded-lg p-3 text-center">
          <p className="text-xl font-bold tabular-nums text-slate-700 dark:text-slate-200">{formatNumber(uniqueIps)}</p>
          <p className="text-[10px] text-slate-400">unique IPs</p>
        </div>
      </div>

      <div className="mb-3">
        <div className="flex items-center justify-between text-[10px] text-slate-400 mb-1">
          <span>Blocked: {blockedPct}%</span>
          <span>{formatNumber(blocked)} / {formatNumber(attacks)}</span>
        </div>
        <div className="w-full bg-slate-100 dark:bg-white/[0.04] rounded-full h-2">
          <div className="h-2 rounded-full bg-emerald-500 transition-all" style={{ width: `${blockedPct}%` }} />
        </div>
      </div>

      {topCountries.length > 0 && (
        <div>
          <p className="text-[10px] text-slate-400 mb-1.5">Top attacker countries</p>
          <div className="flex flex-wrap gap-1.5">
            {topCountries.map(([cc, hits]) => (
              <span key={cc} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] bg-red-50 dark:bg-red-900/15 text-red-600 dark:text-red-400">
                <span className={`${flagClass(cc)} text-xs`} />
                {countryName(cc)}
                <span className="opacity-60">{formatNumber(hits)}</span>
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Privacy Panel
// ---------------------------------------------------------------------------
function PrivacyPanel({ trackersDetected, topTrackers, vpnAlerts, beaconingThreats, sparkline, adguardBlocked, adguardPct }: {
  trackersDetected: number; topTrackers: { service: string; hits: number }[];
  vpnAlerts: number; beaconingThreats: number; sparkline: number[];
  adguardBlocked: number; adguardPct: number;
}) {
  const sparkData = sparkline.map((v, i) => ({ day: i, count: v }));

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
      <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5 mb-3">
        <i className="ph-duotone ph-eye-slash text-violet-500" /> Privacy & Trackers
      </h3>

      <div className="grid grid-cols-3 gap-2 mb-3">
        <div className="bg-violet-50 dark:bg-violet-900/10 rounded-lg p-2 text-center">
          <p className="text-lg font-bold tabular-nums text-violet-600 dark:text-violet-400">{formatNumber(trackersDetected)}</p>
          <p className="text-[9px] text-violet-500/70">trackers</p>
        </div>
        <div className="bg-amber-50 dark:bg-amber-900/10 rounded-lg p-2 text-center">
          <p className="text-lg font-bold tabular-nums text-amber-600 dark:text-amber-400">{vpnAlerts}</p>
          <p className="text-[9px] text-amber-500/70">VPN alerts</p>
        </div>
        <div className="bg-red-50 dark:bg-red-900/10 rounded-lg p-2 text-center">
          <p className="text-lg font-bold tabular-nums text-red-600 dark:text-red-400">{beaconingThreats}</p>
          <p className="text-[9px] text-red-500/70">beaconing</p>
        </div>
      </div>

      <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 mb-2">
        <span>AdGuard DNS blocked</span>
        <span className="font-medium">{formatNumber(adguardBlocked)} ({adguardPct.toFixed(1)}%)</span>
      </div>

      {sparkData.length > 0 && (
        <div>
          <p className="text-[10px] text-slate-400 mb-1">Security events (7 days)</p>
          <div style={{ height: 36 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={sparkData}>
                <defs>
                  <linearGradient id="grad-sec" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#8b5cf6" stopOpacity={0.3} />
                    <stop offset="100%" stopColor="#8b5cf6" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <Area type="monotone" dataKey="count" stroke="#8b5cf6" strokeWidth={1.5}
                  fill="url(#grad-sec)" dot={false} isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {topTrackers.length > 0 && (
        <div className="mt-2">
          <p className="text-[10px] text-slate-400 mb-1">Top trackers</p>
          <div className="space-y-1">
            {topTrackers.slice(0, 4).map(t => (
              <div key={t.service} className="flex items-center justify-between text-[11px]">
                <span className="text-slate-600 dark:text-slate-300 truncate">{serviceName(t.service)}</span>
                <span className="tabular-nums text-slate-400 flex-shrink-0 ml-2">{formatNumber(t.hits)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
