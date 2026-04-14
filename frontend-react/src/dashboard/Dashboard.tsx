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
import type {
  HealthService, DashEvent,
} from './types';
import { categoryName, formatBytes, serviceName } from '../colors';
import { formatNumber, countryName, flagClass } from '../geo/utils';
import GeoMap from '../geo/GeoMap';

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
      {/* ── Metric Cards ── */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <MetricCard
          icon="ph-duotone ph-heartbeat"
          iconColor={health.data?.summary.all_ok ? 'text-emerald-500' : 'text-amber-500'}
          label="System Health"
          value={health.data ? `${health.data.summary.ok}/${health.data.summary.total}` : '...'}
          sub={health.data?.summary.all_ok ? 'All systems operational' : `${(health.data?.summary.total ?? 0) - (health.data?.summary.ok ?? 0)} issue(s)`}
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
        <MetricCard
          icon="ph-duotone ph-wifi-high"
          iconColor="text-cyan-500"
          label="Network"
          value={sysPerf.data ? `${Math.round(sysPerf.data.host.cpu_percent)}%` : '...'}
          sub={sysPerf.data ? `Mem ${Math.round(sysPerf.data.host.memory.percent)}%` : ''}
        />
      </div>

      {/* ── Main Grid: Globe + Right Stack ── */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        {/* Globe (3 cols) */}
        <div className="lg:col-span-3 bg-slate-950 rounded-xl overflow-hidden border border-slate-200 dark:border-white/[0.05]" style={{ minHeight: 400 }}>
          <GeoMap initialDirection="inbound" compact />
        </div>

        {/* Right stack (2 cols) */}
        <div className="lg:col-span-2 flex flex-col gap-4">
          {/* Donut Row */}
          <DonutRow events={events.data ?? []} />
          {/* IoT Fleet Summary */}
          <IotSummaryPanel
            total={fleet.data?.total_devices ?? 0}
            online={onlineCount}
            anomalies={fleet.data?.anomaly_devices ?? 0}
            topTalker={fleet.data?.top_talker ?? null}
            totalBytes={fleet.data?.total_bytes_24h ?? 0}
          />
        </div>
      </div>

      {/* ── Sankey ── */}
      <SankeyFlow events={events.data ?? []} />

      {/* ── Bottom Grid: Health + Network Perf + IPS + Privacy ── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <HealthGrid services={health.data?.services ?? []} />
        <NetworkPerfPanel data={netPerf.data?.data ?? []} />
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
// DonutRow — AI + Cloud traffic donuts
// ---------------------------------------------------------------------------
function DonutRow({ events }: { events: DashEvent[] }) {
  const { aiData, cloudData, aiTotal, cloudTotal } = useMemo(() => {
    const ai: Record<string, number> = {};
    const cloud: Record<string, number> = {};
    events.forEach(e => {
      if (e.category === 'ai') ai[e.ai_service] = (ai[e.ai_service] || 0) + 1;
      else if (e.category === 'cloud') cloud[e.ai_service] = (cloud[e.ai_service] || 0) + 1;
    });
    return {
      aiData: Object.entries(ai).map(([name, value]) => ({ name: serviceName(name), value, key: name })),
      cloudData: Object.entries(cloud).map(([name, value]) => ({ name: serviceName(name), value, key: name })),
      aiTotal: Object.values(ai).reduce((s, v) => s + v, 0),
      cloudTotal: Object.values(cloud).reduce((s, v) => s + v, 0),
    };
  }, [events]);

  return (
    <div className="grid grid-cols-2 gap-3">
      <MiniDonut label="AI Traffic" data={aiData} total={aiTotal} category="ai" />
      <MiniDonut label="Cloud Traffic" data={cloudData} total={cloudTotal} category="cloud" />
    </div>
  );
}

function MiniDonut({ label, data, total, category }: {
  label: string; data: { name: string; value: number; key: string }[];
  total: number; category: string;
}) {
  const COLORS = useMemo(() => {
    if (!data.length) return ['#e2e8f0'];
    const baseHue = category === 'ai' ? 245 : 217;
    return data.map((_, i) => `hsl(${baseHue + i * 25}, 65%, ${50 + i * 5}%)`);
  }, [data, category]);

  const displayData = data.length ? data : [{ name: 'None', value: 1, key: '_empty' }];

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-3">
      <p className="text-[11px] text-slate-400 dark:text-slate-500 font-medium mb-1">{label}</p>
      <div className="flex items-center gap-2">
        <div style={{ width: 72, height: 72 }}>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={displayData} dataKey="value" cx="50%" cy="50%"
                innerRadius={22} outerRadius={34} strokeWidth={0} paddingAngle={1}>
                {displayData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-lg font-bold tabular-nums text-slate-700 dark:text-slate-100">{formatNumber(total)}</p>
          <p className="text-[10px] text-slate-400">events today</p>
          {data.slice(0, 3).map(d => (
            <p key={d.key} className="text-[10px] text-slate-500 dark:text-slate-400 truncate">{d.name}: {d.value}</p>
          ))}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// IoT Fleet Summary
// ---------------------------------------------------------------------------
function IotSummaryPanel({ total, online, anomalies, topTalker, totalBytes }: {
  total: number; online: number; anomalies: number; topTalker: string | null; totalBytes: number;
}) {
  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4 flex-1">
      <div className="flex items-center gap-2 mb-3">
        <i className="ph-duotone ph-cpu text-lg text-teal-500" />
        <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">IoT Fleet</span>
      </div>
      <div className="grid grid-cols-3 gap-3 mb-3">
        <div className="text-center">
          <p className="text-xl font-bold tabular-nums text-slate-700 dark:text-slate-100">{total}</p>
          <p className="text-[10px] text-slate-400">devices</p>
        </div>
        <div className="text-center">
          <p className="text-xl font-bold tabular-nums text-emerald-600 dark:text-emerald-400">{online}</p>
          <p className="text-[10px] text-slate-400">online</p>
        </div>
        <div className="text-center">
          <p className={`text-xl font-bold tabular-nums ${anomalies > 0 ? 'text-amber-500' : 'text-slate-700 dark:text-slate-100'}`}>{anomalies}</p>
          <p className="text-[10px] text-slate-400">anomalies</p>
        </div>
      </div>
      <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 border-t border-slate-100 dark:border-white/[0.05] pt-2">
        <span>{formatBytes(totalBytes)} /24h</span>
        {topTalker && <span className="truncate ml-2">Top: {topTalker}</span>}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sankey Flow — ECharts-based device → category flow
// ---------------------------------------------------------------------------
function SankeyFlow({ events }: { events: DashEvent[] }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const chartRef = useRef<any>(null);
  const [modeHits, setModeHits] = useState(false);
  const [excludeTop, setExcludeTop] = useState(false);

  const { nodes, links, rawValues, devFlows, catFlows, topDevName } = useMemo(() => {
    if (!events.length) return { nodes: [], links: [], rawValues: {}, devFlows: {}, catFlows: {}, topDevName: '' };

    const metric = modeHits ? () => 1 : (e: DashEvent) => (e.bytes_transferred || 1);

    // Get device name via window.deviceName if available
    const devName = (ip: string) => {
      if (typeof (window as any).deviceName === 'function') return (window as any).deviceName(ip);
      return ip;
    };

    const devTotals: Record<string, number> = {};
    events.forEach(e => {
      const dev = devName(e.source_ip);
      devTotals[dev] = (devTotals[dev] || 0) + metric(e);
    });
    const topDev = Object.entries(devTotals).sort((a, b) => b[1] - a[1])[0];
    const topDevNameVal = topDev?.[0] ?? '';

    let filtered = events;
    if (excludeTop && topDevNameVal) {
      filtered = events.filter(e => devName(e.source_ip) !== topDevNameVal);
    }

    const flowMap: Record<string, number> = {};
    const dFlows: Record<string, number> = {};
    const cFlows: Record<string, number> = {};

    filtered.forEach(e => {
      const dev = devName(e.source_ip);
      const cat = categoryName(e.category);
      const val = metric(e);
      const key = dev + '\0' + cat;
      flowMap[key] = (flowMap[key] || 0) + val;
      dFlows[dev] = (dFlows[dev] || 0) + val;
      cFlows[cat] = (cFlows[cat] || 0) + val;
    });

    // Top 10 devices
    const top10 = new Set(
      Object.entries(dFlows).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([d]) => d)
    );

    const lnks: any[] = [];
    const rVals: Record<string, number> = {};
    const usedDevs = new Set<string>();
    const usedCats = new Set<string>();

    Object.entries(flowMap).forEach(([key, raw]) => {
      const [dev, cat] = key.split('\0');
      if (!top10.has(dev)) return;
      lnks.push({ source: dev, target: cat, value: Math.max(1, Math.sqrt(raw)) });
      rVals[`${dev} \u2192 ${cat}`] = raw;
      usedDevs.add(dev);
      usedCats.add(cat);
    });

    const nds: any[] = [];
    usedDevs.forEach(d => nds.push({ name: d, isDevice: true }));
    usedCats.forEach(c => nds.push({ name: c, isDevice: false }));

    return { nodes: nds, links: lnks, rawValues: rVals, devFlows: dFlows, catFlows: cFlows, topDevName: topDevNameVal };
  }, [events, modeHits, excludeTop]);

  useEffect(() => {
    if (!containerRef.current) return;

    // Dynamically load echarts
    const echarts = (window as any).echarts;
    if (!echarts) return;

    if (chartRef.current) chartRef.current.dispose();
    if (!nodes.length) { containerRef.current.style.display = 'none'; return; }
    containerRef.current.style.display = '';

    const dark = document.documentElement.classList.contains('dark');
    const textColor = dark ? '#94a3b8' : '#475569';
    const unit = modeHits ? 'hits' : null;

    const CATEGORY_COLORS: Record<string, string> = {
      AI: '#6366f1', Cloud: '#3b82f6', Streaming: '#e50914', Gaming: '#10b981',
      Social: '#f59e0b', Tracking: '#ef4444', Shopping: '#8b5cf6', News: '#06b6d4',
      Adult: '#64748b', Communication: '#0ea5e9',
    };

    const inst = echarts.init(containerRef.current, null, { renderer: 'canvas' });
    chartRef.current = inst;

    inst.setOption({
      tooltip: {
        trigger: 'item',
        triggerOn: 'mousemove',
        backgroundColor: dark ? '#1e293b' : '#fff',
        borderColor: dark ? 'rgba(255,255,255,0.08)' : '#e2e8f0',
        textStyle: { color: dark ? '#e2e8f0' : '#1e293b', fontSize: 12, fontFamily: 'Inter' },
        formatter: (params: any) => {
          if (params.dataType === 'edge') {
            const raw = rawValues[`${params.data.source} \u2192 ${params.data.target}`] || 0;
            const display = unit ? raw.toLocaleString() + ' ' + unit : formatBytes(raw);
            return `${params.data.source} \u2192 ${params.data.target}<br/><b>${display}</b>`;
          }
          const raw = devFlows[params.name] || catFlows[params.name] || 0;
          const display = unit ? raw.toLocaleString() + ' ' + unit : formatBytes(raw);
          return `<b>${params.name}</b><br/>${display}`;
        },
      },
      series: [{
        type: 'sankey',
        layout: 'none',
        emphasis: { focus: 'adjacency' },
        nodeAlign: 'justify',
        layoutIterations: 32,
        nodeGap: 12,
        nodeWidth: 20,
        data: nodes.map((n: any) => ({
          name: n.name,
          itemStyle: {
            color: n.isDevice ? '#3b82f6' : (CATEGORY_COLORS[n.name] || '#6366f1'),
            borderColor: 'transparent',
          },
          label: { color: textColor, fontSize: 11, fontFamily: 'Inter' },
        })),
        links,
        lineStyle: { color: 'gradient', curveness: 0.5, opacity: dark ? 0.25 : 0.35 },
        label: { position: 'right', color: textColor, fontSize: 11, fontFamily: 'Inter' },
        left: 40, right: 100, top: 10, bottom: 10,
      }],
    });

    const ro = new ResizeObserver(() => inst?.resize());
    ro.observe(containerRef.current);
    return () => { ro.disconnect(); inst.dispose(); chartRef.current = null; };
  }, [nodes, links, rawValues, devFlows, catFlows, modeHits]);

  if (!events.length) return null;

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
      <div className="flex items-center justify-between mb-3">
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
      <div ref={containerRef} style={{ height: 320, width: '100%' }} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Health Grid
// ---------------------------------------------------------------------------
function HealthGrid({ services }: { services: HealthService[] }) {
  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
      <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5 mb-3">
        <i className="ph-duotone ph-heartbeat text-emerald-500" /> System Health
      </h3>
      {services.length === 0 ? (
        <p className="text-xs text-slate-400 py-4 text-center">Loading...</p>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {services.map(s => (
            <div key={s.service} className="flex items-center gap-2.5 px-3 py-2 rounded-lg bg-slate-50 dark:bg-white/[0.02]">
              <span className="text-base">{s.icon}</span>
              <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
                s.status === 'ok' ? 'bg-emerald-500' : s.status === 'warning' ? 'bg-amber-500' : 'bg-red-500'
              }`} />
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium text-slate-700 dark:text-slate-200 truncate">{s.service}</p>
                <p className="text-[10px] text-slate-400 truncate">{s.details}</p>
              </div>
              <span className="text-[10px] tabular-nums text-slate-400 flex-shrink-0">{Math.round(s.response_ms)}ms</span>
            </div>
          ))}
        </div>
      )}
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
      rx: (d.br_rx_bps ?? 0) / 1024 / 1024, // Mbps
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
        <Sparkline label="DNS Latency" value={`${lastDns.toFixed(1)} ms`} data={sparkData} dataKey="dns" color="#06b6d4" />
        <Sparkline label="Packet Loss" value={`${lastLoss.toFixed(2)}%`} data={sparkData} dataKey="loss" color={lastLoss > 1 ? '#ef4444' : '#10b981'} />
        <Sparkline label="Throughput" value={`${lastRx.toFixed(1)} Mbps`} data={sparkData} dataKey="rx" color="#3b82f6" />
      </div>
    </div>
  );
}

function Sparkline({ label, value, data, dataKey, color }: {
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
  // Top 5 attacker countries
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

      {/* Blocked ratio bar */}
      <div className="mb-3">
        <div className="flex items-center justify-between text-[10px] text-slate-400 mb-1">
          <span>Blocked: {blockedPct}%</span>
          <span>{formatNumber(blocked)} / {formatNumber(attacks)}</span>
        </div>
        <div className="w-full bg-slate-100 dark:bg-white/[0.04] rounded-full h-2">
          <div className="h-2 rounded-full bg-emerald-500 transition-all" style={{ width: `${blockedPct}%` }} />
        </div>
      </div>

      {/* Top attacker countries */}
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

      {/* AdGuard */}
      <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 mb-2">
        <span>AdGuard DNS blocked</span>
        <span className="font-medium">{formatNumber(adguardBlocked)} ({adguardPct.toFixed(1)}%)</span>
      </div>

      {/* Security events 7-day sparkline */}
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

      {/* Top trackers */}
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
