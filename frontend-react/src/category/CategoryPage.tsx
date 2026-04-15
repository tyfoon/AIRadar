/**
 * Shared Category page component — used for both AI and Cloud pages.
 *
 * AI page adds an "Adoption" tab.
 * Cloud page adds a "Top Data Exporters" panel.
 */
import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
} from 'recharts';
import { fetchEvents, fetchTimeline, exportCsvUrl } from './api';
import type { FilterParams } from './api';
import type {
  DetectionEvent, TimelineBucket,
  AdoptionMetrics, DeviceBreakdown, ServiceBreakdown, UploaderEntry,
} from './types';
import { SvcLogo, SvcBadge, svcColor, svcDisplayName, svcLogoUrl } from './serviceHelpers';
import { formatBytes } from '../colors';

// ---------------------------------------------------------------------------
// Time period options
// ---------------------------------------------------------------------------
const PERIODS = [
  { label: '1h', minutes: 60 },
  { label: '24h', minutes: 1440 },
  { label: '7d', minutes: 10080 },
  { label: 'All', minutes: 0 },
] as const;

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------
export default function CategoryPage({ category }: { category: 'ai' | 'cloud' }) {
  const [period, setPeriod] = useState(1440);
  const [service, setService] = useState('');
  const [heartbeats, setHeartbeats] = useState(false);
  const [aiTab, setAiTab] = useState<'radar' | 'adoption'>('radar');

  const filterParams: FilterParams = useMemo(() => ({
    category,
    service: service || undefined,
    periodMinutes: period || undefined,
    includeHeartbeats: heartbeats ? true : false,
  }), [category, service, period, heartbeats]);

  const { data: events = [], isLoading: evLoading } = useQuery({
    queryKey: ['cat-events', filterParams],
    queryFn: () => fetchEvents(filterParams),
    staleTime: 30_000,
  });

  const { data: timeline = [], isLoading: tlLoading } = useQuery({
    queryKey: ['cat-timeline', filterParams],
    queryFn: () => fetchTimeline(filterParams),
    staleTime: 30_000,
  });

  const isLoading = evLoading || tlLoading;

  // Derived stats
  const stats = useMemo(() => {
    const services = new Set(events.map(e => e.ai_service));
    const sources = new Set(events.map(e => e.source_ip));
    const uploads = events.filter(e => e.possible_upload).length;
    return {
      total: events.length,
      services: services.size,
      sources: sources.size,
      uploads,
      serviceList: [...services].sort(),
    };
  }, [events]);

  const isAi = category === 'ai';
  const title = isAi ? 'AI Services' : 'Cloud Services';

  return (
    <div className="space-y-5 p-1">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h2 className="text-lg font-semibold text-slate-800 dark:text-slate-100">
          {title}
        </h2>
        <div className="flex items-center gap-2 flex-wrap">
          {/* Period toggle */}
          <div className="flex bg-slate-100 dark:bg-white/[0.06] rounded-lg p-0.5">
            {PERIODS.map(p => (
              <button key={p.minutes} onClick={() => setPeriod(p.minutes)}
                className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                  period === p.minutes
                    ? 'bg-white dark:bg-white/10 text-slate-800 dark:text-white shadow-sm'
                    : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
                }`}>
                {p.label}
              </button>
            ))}
          </div>

          {/* Service filter */}
          <select value={service} onChange={e => setService(e.target.value)}
            className="text-xs bg-white dark:bg-white/[0.06] border border-slate-200 dark:border-white/10 rounded-lg px-2 py-1.5 text-slate-600 dark:text-slate-300">
            <option value="">All services</option>
            {stats.serviceList.map(s => (
              <option key={s} value={s}>{svcDisplayName(s)}</option>
            ))}
          </select>

          {/* Heartbeat toggle */}
          <label className="flex items-center gap-1.5 text-[11px] text-slate-500 cursor-pointer">
            <input type="checkbox" checked={heartbeats} onChange={e => setHeartbeats(e.target.checked)}
              className="rounded border-slate-300 dark:border-slate-600 text-blue-600 focus:ring-blue-500 w-3.5 h-3.5" />
            Show pings
          </label>

          {/* Export CSV */}
          <a href={exportCsvUrl(filterParams)} download
            className="text-xs px-2.5 py-1.5 rounded-lg bg-slate-100 dark:bg-white/[0.06] text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-white/10 transition-colors">
            <i className="ph-duotone ph-export text-sm" /> CSV
          </a>
        </div>
      </div>

      {/* AI tab toggle */}
      {isAi && (
        <div className="flex gap-1 bg-slate-100 dark:bg-white/[0.06] rounded-lg p-0.5 w-fit">
          {(['radar', 'adoption'] as const).map(t => (
            <button key={t} onClick={() => setAiTab(t)}
              className={`px-4 py-1.5 rounded-md text-xs font-medium transition-colors ${
                aiTab === t
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
              }`}>
              {t === 'radar' ? 'Overview' : 'Adoption'}
            </button>
          ))}
        </div>
      )}

      {/* Stats cards */}
      <StatsRow stats={stats} isLoading={isLoading} />

      {/* Main content — either radar (overview) or adoption */}
      {(!isAi || aiTab === 'radar') ? (
        <>
          {/* Charts row: donut + timeline */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <ServiceDonut events={events} isLoading={isLoading} />
            <div className="lg:col-span-2">
              <TimelineChart timeline={timeline} isLoading={isLoading} />
            </div>
          </div>

          {/* Cloud: Top uploaders */}
          {!isAi && <TopUploaders events={events} />}

          {/* Events table */}
          <EventsTable events={events} isLoading={isLoading} />
        </>
      ) : (
        <AdoptionPanel events={events} />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Stats cards
// ---------------------------------------------------------------------------
function StatsRow({ stats, isLoading }: { stats: { total: number; services: number; sources: number; uploads: number }; isLoading: boolean }) {
  const cards = [
    { label: 'Events', value: stats.total, icon: 'ph-pulse' },
    { label: 'Services', value: stats.services, icon: 'ph-cube' },
    { label: 'Devices', value: stats.sources, icon: 'ph-devices' },
    { label: 'Uploads', value: stats.uploads, icon: 'ph-upload-simple', warn: stats.uploads > 0 },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      {cards.map(c => (
        <div key={c.label} className={`bg-white dark:bg-white/[0.03] border rounded-xl p-4 ${
          c.warn ? 'border-orange-300 dark:border-orange-700/40' : 'border-slate-200 dark:border-white/[0.05]'
        }`}>
          <div className="flex items-center gap-2 text-slate-400 mb-1">
            <i className={`ph-duotone ${c.icon} text-base`} />
            <span className="text-[11px] font-medium uppercase tracking-wide">{c.label}</span>
          </div>
          {isLoading ? (
            <div className="h-7 w-16 bg-slate-200 dark:bg-slate-700 rounded animate-pulse" />
          ) : (
            <p className={`text-xl font-bold tabular-nums ${c.warn ? 'text-orange-500' : 'text-slate-800 dark:text-white'}`}>
              {c.value.toLocaleString()}
            </p>
          )}
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Service donut
// ---------------------------------------------------------------------------
function ServiceDonut({ events, isLoading }: { events: DetectionEvent[]; isLoading: boolean }) {
  const data = useMemo(() => {
    const counts: Record<string, number> = {};
    events.forEach(e => { counts[e.ai_service] = (counts[e.ai_service] || 0) + 1; });
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .map(([svc, count]) => ({ svc, count, color: svcColor(svc) }));
  }, [events]);

  if (isLoading) {
    return <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4 h-64 animate-pulse" />;
  }

  if (data.length === 0) {
    return (
      <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4 flex items-center justify-center h-64 text-sm text-slate-400">
        No events
      </div>
    );
  }

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4">
      <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">By Service</h3>
      <div className="flex items-center gap-3">
        <div className="w-36 h-36 flex-shrink-0">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={data} dataKey="count" nameKey="svc" cx="50%" cy="50%"
                innerRadius="55%" outerRadius="90%" paddingAngle={1} stroke="none">
                {data.map(d => <Cell key={d.svc} fill={d.color} />)}
              </Pie>
              <Tooltip
                content={({ payload }) => {
                  if (!payload?.[0]) return null;
                  const d = payload[0].payload;
                  return (
                    <div className="bg-black/90 text-white text-xs px-2 py-1 rounded shadow">
                      {svcDisplayName(d.svc)}: {d.count}
                    </div>
                  );
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="flex-1 space-y-1 overflow-hidden">
          {data.slice(0, 8).map(d => (
            <div key={d.svc} className="flex items-center gap-1.5 text-[11px]">
              <SvcLogo svc={d.svc} size={12} />
              <span className="truncate text-slate-600 dark:text-slate-300" style={{ color: d.color }}>
                {svcDisplayName(d.svc)}
              </span>
              <span className="ml-auto tabular-nums text-slate-400 flex-shrink-0">{d.count}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Timeline stacked bar chart
// ---------------------------------------------------------------------------
function TimelineChart({ timeline, isLoading }: { timeline: TimelineBucket[]; isLoading: boolean }) {
  const { chartData, serviceKeys } = useMemo(() => {
    const svcs = new Set<string>();
    timeline.forEach(b => Object.keys(b.services).forEach(s => svcs.add(s)));
    const keys = [...svcs].sort();
    const cd = timeline.map(b => {
      const d: Record<string, any> = {
        time: formatBucket(b.bucket),
        uploads: b.uploads,
      };
      keys.forEach(s => { d[s] = b.services[s] || 0; });
      return d;
    });
    return { chartData: cd, serviceKeys: keys };
  }, [timeline]);

  if (isLoading) {
    return <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4 h-64 animate-pulse" />;
  }

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4">
      <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">Timeline</h3>
      {/* Legend */}
      <div className="flex flex-wrap gap-1.5 mb-3">
        {serviceKeys.map(s => <SvcBadge key={s} svc={s} />)}
      </div>
      <div className="h-48">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} margin={{ top: 4, right: 4, bottom: 0, left: 0 }}>
            <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} axisLine={false} />
            <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} axisLine={false} width={30} />
            <Tooltip
              contentStyle={{ background: 'rgba(0,0,0,.9)', border: 'none', borderRadius: 8, fontSize: 11 }}
              labelStyle={{ color: '#94a3b8' }}
              formatter={(v: number, name: string) => [v, svcDisplayName(name)]}
            />
            {serviceKeys.map(s => (
              <Bar key={s} dataKey={s} stackId="s" fill={svcColor(s)} radius={[2, 2, 0, 0]} isAnimationActive={false} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function formatBucket(b: string): string {
  const d = new Date(b);
  const hh = d.getHours().toString().padStart(2, '0');
  const mm = d.getMinutes().toString().padStart(2, '0');
  return `${hh}:${mm}`;
}

// ---------------------------------------------------------------------------
// Events table
// ---------------------------------------------------------------------------
function EventsTable({ events, isLoading }: { events: DetectionEvent[]; isLoading: boolean }) {
  const [limit, setLimit] = useState(50);

  if (isLoading) {
    return (
      <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-200 dark:border-white/[0.06]">
              {['Time', 'Service', 'Description', 'Device', 'Size'].map(h => (
                <th key={h} className="text-left py-3 px-4 text-xs font-medium text-slate-500 uppercase tracking-wide">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {Array.from({ length: 5 }).map((_, i) => (
              <tr key={i} className="border-b border-slate-100 dark:border-white/[0.04]">
                {Array.from({ length: 5 }).map((_, j) => (
                  <td key={j} className="py-3 px-4"><div className="h-3 bg-slate-200 dark:bg-slate-700 rounded animate-pulse" /></td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  // Collapse consecutive identical events
  const collapsed = collapseEvents(events);
  const visible = collapsed.slice(0, limit);

  if (events.length === 0) {
    return (
      <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-8 text-center text-sm text-slate-400">
        <i className="ph-duotone ph-empty text-3xl block mb-2 opacity-40" />
        No events in this time window
      </div>
    );
  }

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-slate-200 dark:border-white/[0.06]">
            {['Time', 'Service', 'Description', 'Device', 'Size'].map(h => (
              <th key={h} className="text-left py-3 px-4 text-xs font-medium text-slate-500 uppercase tracking-wide">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {visible.map((e, i) => {
            const isUpload = e.possible_upload;
            return (
              <tr key={i} className={`border-b transition-colors ${
                isUpload
                  ? 'border-orange-200 dark:border-orange-700/30 bg-orange-50/30 dark:bg-orange-900/10 border-l-[3px] border-l-orange-400'
                  : 'border-slate-100 dark:border-white/[0.04] hover:bg-slate-50 dark:hover:bg-slate-700/20'
              }`}>
                <td className="py-3 px-4 tabular-nums text-slate-400 dark:text-slate-500 text-xs whitespace-nowrap">
                  {fmtTime(e.timestamp)}
                  {(e as any)._count > 1 && (
                    <span className="ml-1 text-[10px] bg-slate-200 dark:bg-slate-700 rounded px-1">
                      ×{(e as any)._count}
                    </span>
                  )}
                </td>
                <td className="py-3 px-4">
                  <SvcBadge svc={e.ai_service} />
                </td>
                <td className="py-3 px-4 text-xs text-slate-600 dark:text-slate-300 max-w-[200px] truncate">
                  {e.description || e.detection_type}
                </td>
                <td className="py-3 px-4 text-xs text-slate-500 hidden sm:table-cell">
                  {e.source_ip}
                </td>
                <td className="py-3 px-4 text-right tabular-nums text-xs hidden sm:table-cell">
                  {e.bytes_transferred > 0 ? formatBytes(e.bytes_transferred) : '—'}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {collapsed.length > limit && (
        <div className="text-center py-3 border-t border-slate-100 dark:border-white/[0.04]">
          <button onClick={() => setLimit(l => l + 50)}
            className="text-xs text-blue-500 hover:text-blue-400 font-medium">
            Show more ({collapsed.length - limit} remaining)
          </button>
        </div>
      )}
    </div>
  );
}

function fmtTime(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

/** Collapse consecutive events with same service+device into a single row with count. */
function collapseEvents(events: DetectionEvent[]): DetectionEvent[] {
  if (events.length === 0) return [];
  const result: (DetectionEvent & { _count?: number })[] = [];
  let prev = { ...events[0], _count: 1 };
  for (let i = 1; i < events.length; i++) {
    const e = events[i];
    if (e.ai_service === prev.ai_service && e.source_ip === prev.source_ip && e.detection_type === prev.detection_type) {
      prev._count!++;
    } else {
      result.push(prev);
      prev = { ...e, _count: 1 };
    }
  }
  result.push(prev);
  return result;
}

// ---------------------------------------------------------------------------
// Top Data Exporters (Cloud page)
// ---------------------------------------------------------------------------
function TopUploaders({ events }: { events: DetectionEvent[] }) {
  const uploaders = useMemo<UploaderEntry[]>(() => {
    const byIp: Record<string, { bytes: number; events: number; services: Set<string> }> = {};
    events.forEach(e => {
      if (!e.possible_upload || !e.bytes_transferred) return;
      if (!byIp[e.source_ip]) byIp[e.source_ip] = { bytes: 0, events: 0, services: new Set() };
      byIp[e.source_ip].bytes += e.bytes_transferred;
      byIp[e.source_ip].events += 1;
      byIp[e.source_ip].services.add(e.ai_service);
    });
    return Object.entries(byIp)
      .map(([ip, a]) => ({
        ip, name: ip, mac: null,
        bytes: a.bytes, events: a.events,
        services: [...a.services],
      }))
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, 10);
  }, [events]);

  const grandTotal = uploaders.reduce((s, u) => s + u.bytes, 0);
  const maxBytes = uploaders[0]?.bytes || 1;

  if (uploaders.length === 0) return null;

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide">
          Top Data Exporters
        </h3>
        <span className="text-xs text-slate-400 tabular-nums">
          Total: {formatBytes(grandTotal)}
        </span>
      </div>
      <div className="space-y-2.5">
        {uploaders.map((u, i) => {
          const pct = Math.max(3, (u.bytes / maxBytes) * 100);
          const barColor = i === 0 ? 'from-red-500 to-orange-500'
            : i < 3 ? 'from-orange-500 to-amber-500'
            : 'from-blue-500 to-blue-700';
          return (
            <div key={u.ip}>
              <div className="flex items-center justify-between gap-3 mb-0.5">
                <div className="flex items-center gap-2 min-w-0 flex-1">
                  <span className="text-[11px] tabular-nums text-slate-400 w-5 text-right flex-shrink-0">
                    #{i + 1}
                  </span>
                  <span className="text-xs font-medium text-slate-700 dark:text-slate-200 truncate">
                    {u.name}
                  </span>
                </div>
                <span className="text-xs tabular-nums font-semibold text-slate-800 dark:text-slate-100 flex-shrink-0">
                  {formatBytes(u.bytes)}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <div className="flex-1 h-1.5 rounded-full bg-slate-100 dark:bg-white/[0.04] overflow-hidden">
                  <div className={`h-full rounded-full bg-gradient-to-r ${barColor} transition-all`}
                    style={{ width: `${pct}%` }} />
                </div>
                <span className="text-[10px] text-slate-400 tabular-nums w-24 text-right flex-shrink-0">
                  {u.events} ev · {u.services.slice(0, 2).map(s => svcDisplayName(s)).join(', ')}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Adoption panel (AI page only)
// ---------------------------------------------------------------------------
function AdoptionPanel({ events }: { events: DetectionEvent[] }) {
  const metrics = useMemo<AdoptionMetrics>(() => {
    // Group by source IP (rough device proxy)
    const deviceEvents: Record<string, DetectionEvent[]> = {};
    events.forEach(e => {
      const key = e.source_ip;
      if (!deviceEvents[key]) deviceEvents[key] = [];
      deviceEvents[key].push(e);
    });

    const aiDeviceCount = Object.keys(deviceEvents).length;
    const totalDevices = Math.max(aiDeviceCount, 1); // approximate

    // Time span in days
    let spanDays = 1;
    if (events.length > 1) {
      const times = events.map(e => new Date(e.timestamp).getTime());
      spanDays = Math.max(1, (Math.max(...times) - Math.min(...times)) / 86_400_000);
    }

    const avgQueriesPerDay = aiDeviceCount > 0 ? events.length / aiDeviceCount / spanDays : 0;

    // Active today
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    const todayIps = new Set(events.filter(e => new Date(e.timestamp) >= todayStart).map(e => e.source_ip));

    // Avg services per device
    const svcPerDev = Object.values(deviceEvents).map(evts => new Set(evts.map(e => e.ai_service)).size);
    const avgSvc = svcPerDev.length > 0 ? svcPerDev.reduce((a, b) => a + b, 0) / svcPerDev.length : 0;

    // Power users (>50 queries/day)
    let powerUsers = 0;
    Object.values(deviceEvents).forEach(evts => {
      if (evts.length / spanDays > 50) powerUsers++;
    });

    // Top service
    const svcCounts: Record<string, number> = {};
    events.forEach(e => { svcCounts[e.ai_service] = (svcCounts[e.ai_service] || 0) + 1; });
    const topEntry = Object.entries(svcCounts).sort((a, b) => b[1] - a[1])[0];

    return {
      adoptionPct: Math.round((aiDeviceCount / totalDevices) * 100),
      aiDeviceCount,
      totalDevices,
      avgQueriesPerDay,
      activeToday: todayIps.size,
      avgServicesPerUser: avgSvc,
      powerUsers,
      topService: topEntry?.[0] || null,
    };
  }, [events]);

  const { deviceRows, serviceRows } = useMemo(() => {
    // Group by source IP
    const devEvts: Record<string, DetectionEvent[]> = {};
    events.forEach(e => {
      if (!devEvts[e.source_ip]) devEvts[e.source_ip] = [];
      devEvts[e.source_ip].push(e);
    });

    const dr: DeviceBreakdown[] = Object.entries(devEvts).map(([ip, evts]) => ({
      mac: ip,
      name: ip,
      icon: '💻',
      count: evts.length,
      services: [...new Set(evts.map(e => e.ai_service))],
      uploads: evts.filter(e => e.possible_upload).length,
    })).sort((a, b) => b.count - a.count);

    const svcCounts: Record<string, { count: number; users: Set<string> }> = {};
    events.forEach(e => {
      if (!svcCounts[e.ai_service]) svcCounts[e.ai_service] = { count: 0, users: new Set() };
      svcCounts[e.ai_service].count++;
      svcCounts[e.ai_service].users.add(e.source_ip);
    });
    const totalEv = events.length || 1;
    const sr: ServiceBreakdown[] = Object.entries(svcCounts)
      .map(([svc, { count, users }]) => ({
        service: svc, count, share: Math.round((count / totalEv) * 100), users: users.size,
      }))
      .sort((a, b) => b.count - a.count);

    return { deviceRows: dr, serviceRows: sr };
  }, [events]);

  const maxDevCount = deviceRows[0]?.count || 1;
  const maxSvcCount = serviceRows[0]?.count || 1;

  return (
    <div className="space-y-5">
      {/* KPI cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <KpiCard label="Adoption" value={`${metrics.adoptionPct}%`} sub={`${metrics.aiDeviceCount} of ${metrics.totalDevices} devices`} />
        <KpiCard label="Avg queries/day" value={metrics.avgQueriesPerDay < 10 ? metrics.avgQueriesPerDay.toFixed(1) : Math.round(metrics.avgQueriesPerDay).toString()} />
        <KpiCard label="Active today" value={metrics.activeToday.toString()} />
        <KpiCard label="Avg svcs/user" value={metrics.avgServicesPerUser.toFixed(1)} />
        <KpiCard label="Power users" value={metrics.powerUsers.toString()} sub=">50 queries/day" />
        <KpiCard label="Top service" value={metrics.topService ? svcDisplayName(metrics.topService) : '—'}
          icon={metrics.topService ? <SvcLogo svc={metrics.topService} size={16} /> : undefined} />
      </div>

      {/* Adoption progress bar */}
      <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4">
        <div className="flex justify-between text-xs text-slate-500 mb-1.5">
          <span>AI Adoption Rate</span>
          <span className="font-semibold text-blue-500">{metrics.adoptionPct}%</span>
        </div>
        <div className="w-full h-2.5 bg-slate-100 dark:bg-white/[0.04] rounded-full overflow-hidden">
          <div className="h-full rounded-full bg-gradient-to-r from-blue-500 to-indigo-500 transition-all"
            style={{ width: `${metrics.adoptionPct}%` }} />
        </div>
      </div>

      {/* Per-device breakdown */}
      <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4">
        <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
          Per Device Breakdown
        </h3>
        <div className="space-y-1.5">
          {deviceRows.slice(0, 15).map(d => (
            <div key={d.mac} className="flex items-center gap-2 text-[11px]">
              <span className="w-[140px] truncate flex-shrink-0 text-slate-600 dark:text-slate-300" title={d.name}>
                {d.name}
              </span>
              <div className="flex-1 h-4 rounded bg-slate-100 dark:bg-slate-800 overflow-hidden relative">
                <div className="h-full rounded bg-gradient-to-r from-blue-500/80 to-blue-700/80 transition-all"
                  style={{ width: `${Math.round((d.count / maxDevCount) * 100)}%` }} />
                <span className={`absolute inset-0 flex items-center px-2 text-[10px] font-medium tabular-nums ${
                  d.count / maxDevCount > 0.4 ? 'text-white' : 'text-slate-500 dark:text-slate-400'
                }`}>{d.count}</span>
              </div>
              <span className="flex items-center gap-0.5 flex-shrink-0">
                {d.services.slice(0, 5).map(s => <SvcLogo key={s} svc={s} size={12} />)}
              </span>
              {d.uploads > 0 && (
                <span className="text-[10px] px-1 py-0.5 rounded bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400">
                  {d.uploads}▲
                </span>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Service popularity */}
      <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4">
        <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
          Service Popularity
        </h3>
        <div className="space-y-1.5">
          {serviceRows.map(s => (
            <div key={s.service} className="flex items-center gap-3 text-[11px]">
              <span className="w-[120px] flex-shrink-0 flex items-center gap-1.5">
                <SvcLogo svc={s.service} size={14} />
                <span className="truncate text-slate-600 dark:text-slate-300">{svcDisplayName(s.service)}</span>
              </span>
              <div className="flex-1 h-5 rounded bg-slate-100 dark:bg-slate-800 overflow-hidden relative">
                <div className="h-full rounded bg-gradient-to-r from-blue-500/70 to-blue-700/70"
                  style={{ width: `${Math.round((s.count / maxSvcCount) * 100)}%` }} />
                <span className={`absolute inset-0 flex items-center px-2 text-[10px] font-medium tabular-nums ${
                  s.count / maxSvcCount > 0.3 ? 'text-white' : 'text-slate-500 dark:text-slate-400'
                }`}>
                  {s.count} queries · {s.share}% share · {s.users} {s.users !== 1 ? 'users' : 'user'}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function KpiCard({ label, value, sub, icon }: { label: string; value: string; sub?: string; icon?: React.ReactNode }) {
  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-3">
      <p className="text-[10px] text-slate-400 uppercase tracking-wide mb-1">{label}</p>
      <div className="flex items-center gap-1.5">
        {icon}
        <p className="text-lg font-bold text-slate-800 dark:text-white truncate">{value}</p>
      </div>
      {sub && <p className="text-[10px] text-slate-400 mt-0.5">{sub}</p>}
    </div>
  );
}
