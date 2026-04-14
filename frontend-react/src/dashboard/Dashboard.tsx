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
import { fetchGeoTraffic } from '../geo/api';
import { FleetCard } from '../iot/FleetCard';
import type { FleetDevice } from '../iot/types';

// ---------------------------------------------------------------------------
// Dashboard — System Overview
// ---------------------------------------------------------------------------
export default function Dashboard() {
  const [hours, setHours] = useState(24);

  const health = useQuery({ queryKey: ['dash-health'], queryFn: fetchHealth, refetchInterval: 30_000 });
  const sysPerf = useQuery({ queryKey: ['dash-sys-perf'], queryFn: fetchSystemPerf, refetchInterval: 60_000 });
  const netPerf = useQuery({ queryKey: ['dash-net-perf', hours], queryFn: () => fetchNetworkPerf(hours), refetchInterval: 60_000 });
  const privacy = useQuery({ queryKey: ['dash-privacy', hours], queryFn: () => fetchPrivacyStats(hours), refetchInterval: 60_000 });
  const ips = useQuery({ queryKey: ['dash-ips'], queryFn: fetchIpsStatus, refetchInterval: 30_000 });
  const fleet = useQuery({ queryKey: ['dash-fleet'], queryFn: fetchFleetSummary, refetchInterval: 60_000 });
  const events = useQuery({ queryKey: ['dash-events', hours], queryFn: () => fetchDashEvents(hours), refetchInterval: 30_000 });
  const geoOut = useQuery({ queryKey: ['dash-geo-out', hours], queryFn: () => fetchGeoTraffic('outbound', String(hours * 60)), refetchInterval: 60_000 });
  const geoIn = useQuery({ queryKey: ['dash-geo-in', hours], queryFn: () => fetchGeoTraffic('inbound', String(hours * 60)), refetchInterval: 60_000 });

  const deviceCount = fleet.data?.total_devices ?? 0;
  const onlineCount = fleet.data?.devices?.filter(d => d.online).length ?? 0;

  const PERIOD_OPTIONS = [
    { value: 1, label: '1h' },
    { value: 24, label: '24h' },
    { value: 168, label: '7d' },
  ] as const;

  return (
    <div className="space-y-4">
      {/* ── Header row: title + period toggle ── */}
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-slate-700 dark:text-slate-200">System Overview</h2>
        <div className="flex items-center gap-1 bg-slate-100 dark:bg-white/[0.04] rounded-lg p-0.5">
          {PERIOD_OPTIONS.map(o => (
            <button
              key={o.value}
              onClick={() => setHours(o.value)}
              className={`text-[11px] px-3 py-1 rounded-md font-medium transition-colors ${
                hours === o.value
                  ? 'bg-blue-600 text-white shadow-sm'
                  : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200'
              }`}
            >
              {o.label}
            </button>
          ))}
        </div>
      </div>

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
          label={`Events ${hours >= 168 ? '7d' : hours + 'h'}`}
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

      {/* ── Globe + Category Donut Cards ── */}
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_1fr] gap-4">
        {/* Globe */}
        <div className="bg-slate-950 rounded-xl overflow-hidden border border-slate-200 dark:border-white/[0.05]" style={{ minHeight: 380 }}>
          <GeoMap initialDirection="inbound" compact />
        </div>

        {/* Donut cards grid — fills full space next to globe */}
        <DonutCardGrid
          events={events.data ?? []}
          privacy={privacy.data}
          geoOutCountries={geoOut.data?.countries ?? []}
          geoInCountries={geoIn.data?.countries ?? []}
        />
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
// Service logo helpers — favicon-based icons matching app.js SERVICE_LOGO_*
// ---------------------------------------------------------------------------
const SERVICE_LOGO_DOMAIN: Record<string, string> = {
  openai:'openai.com', anthropic_claude:'claude.ai', google_gemini:'gemini.google.com',
  microsoft_copilot:'copilot.microsoft.com', perplexity:'perplexity.ai', huggingface:'huggingface.co',
  mistral:'mistral.ai', dropbox:'dropbox.com', wetransfer:'wetransfer.com',
  google_drive:'drive.google.com', google_device_sync:'android.com', google_generic_cdn:'cloud.google.com',
  google_api:'developers.google.com', onedrive:'onedrive.live.com', icloud:'icloud.com',
  box:'box.com', mega:'mega.nz', google_ads:'ads.google.com', google_analytics:'analytics.google.com',
  google_telemetry:'firebase.google.com', meta_tracking:'meta.com', apple_ads:'searchads.apple.com',
  microsoft_ads:'ads.microsoft.com', hotjar:'hotjar.com', datadog:'datadoghq.com',
  facebook:'facebook.com', instagram:'instagram.com', tiktok:'tiktok.com', twitter:'x.com',
  snapchat:'snapchat.com', pinterest:'pinterest.com', linkedin:'linkedin.com', reddit:'reddit.com',
  tumblr:'tumblr.com', steam:'steampowered.com', epic_games:'epicgames.com', roblox:'roblox.com',
  twitch:'twitch.tv', discord:'discord.com', nintendo:'nintendo.com', playstation:'playstation.com',
  xbox_live:'xbox.com', signal:'signal.org', whatsapp:'whatsapp.com',
  netflix:'netflix.com', youtube:'youtube.com', spotify:'spotify.com', disney_plus:'disneyplus.com',
  hbo_max:'max.com', prime_video:'primevideo.com', apple_tv:'tv.apple.com',
  amazon:'amazon.com', bol:'bol.com', coolblue:'coolblue.nl', mediamarkt:'mediamarkt.nl',
  zalando:'zalando.com', shein:'shein.com', temu:'temu.com', aliexpress:'aliexpress.com',
  marktplaats:'marktplaats.nl', vinted:'vinted.com', ikea:'ikea.com', ebay:'ebay.com', etsy:'etsy.com',
  nos:'nos.nl', nu_nl:'nu.nl', telegraaf:'telegraaf.nl', ad_nl:'ad.nl', nrc:'nrc.nl',
  volkskrant:'volkskrant.nl', bbc:'bbc.com', nytimes:'nytimes.com', reuters:'reuters.com',
  guardian:'theguardian.com', ea_games:'ea.com',
  pornhub:'pornhub.com', xvideos:'xvideos.com', xhamster:'xhamster.com', onlyfans:'onlyfans.com',
  tinder:'tinder.com', bumble:'bumble.com',
};

const SERVICE_LOGO_URL: Record<string, string> = {
  google_drive: 'https://ssl.gstatic.com/images/branding/product/2x/drive_2020q4_48dp.png',
  google_gemini: 'https://ssl.gstatic.com/images/branding/product/2x/gemini_48dp.png',
  google_device_sync: 'https://ssl.gstatic.com/images/branding/product/2x/android_48dp.png',
};

function svcLogoUrl(s: string): string {
  if (SERVICE_LOGO_URL[s]) return SERVICE_LOGO_URL[s];
  const domain = SERVICE_LOGO_DOMAIN[s] || s.replace(/_/g, '') + '.com';
  return `https://www.google.com/s2/favicons?domain=${domain}&sz=64`;
}

function SvcLogo({ svc, size = 14 }: { svc: string; size?: number }) {
  return (
    <img
      src={svcLogoUrl(svc)}
      alt={svc}
      width={size}
      height={size}
      className="rounded-sm"
      style={{ width: size, height: size, objectFit: 'contain' }}
      onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }}
    />
  );
}

// ---------------------------------------------------------------------------
// DonutCardGrid — individual category cards with donut + legend
// ---------------------------------------------------------------------------
const ALL_CATEGORIES = ['ai', 'cloud', 'streaming', 'gaming', 'social', 'shopping', 'news', 'adult', 'communication'] as const;

const SERVICE_COLORS: Record<string, string> = {
  openai:'#10b981', anthropic_claude:'#6366f1', google_gemini:'#f59e0b',
  google_api:'#4285f4', microsoft_copilot:'#0078d4', perplexity:'#22d3ee',
  huggingface:'#ff6f00', mistral:'#7c3aed',
  dropbox:'#0061fe', wetransfer:'#409fff', google_drive:'#22c55e',
  google_device_sync:'#34a853', google_generic_cdn:'#94a3b8',
  onedrive:'#0ea5e9', icloud:'#6b7280', box:'#0075c9', mega:'#d0021b',
  facebook:'#1877f2', instagram:'#e4405f', tiktok:'#010101', snapchat:'#fffc00',
  twitter:'#1da1f2', pinterest:'#e60023', linkedin:'#0a66c2', reddit:'#ff4500',
  tumblr:'#35465c', whatsapp:'#25d366', signal:'#3a76f0', discord:'#5865f2',
  steam:'#1b2838', epic_games:'#2f2d2e', roblox:'#e2231a', twitch:'#9146ff',
  xbox_live:'#107c10', playstation:'#003791', nintendo:'#e60012', ea_games:'#000',
  netflix:'#e50914', youtube:'#ff0000', spotify:'#1db954', disney_plus:'#113ccf',
  hbo_max:'#5822b4', prime_video:'#00a8e1', apple_tv:'#555',
  amazon:'#ff9900', bol:'#0000a4', coolblue:'#0090e3',
  nos:'#ff6600', nu_nl:'#c30000', bbc:'#bb1919', nytimes:'#111',
  google_ads:'#fbbc04', google_analytics:'#e37400', meta_tracking:'#1877f2',
  hotjar:'#fd3a5c', datadog:'#632ca6',
};

function svcColor(s: string): string {
  return SERVICE_COLORS[s] || `hsl(${Math.abs([...s].reduce((h, c) => (Math.imul(31, h) + c.charCodeAt(0)) | 0, 0)) % 360}, 55%, 50%)`;
}

// Country color palette — stable colors for top countries
const COUNTRY_COLORS = ['#3b82f6','#ef4444','#f59e0b','#10b981','#8b5cf6','#ec4899','#06b6d4','#f97316'];

function DonutCardGrid({ events, privacy, geoOutCountries, geoInCountries }: {
  events: DashEvent[]; privacy: any;
  geoOutCountries: { country_code: string; bytes: number; hits: number }[];
  geoInCountries: { country_code: string; bytes: number; hits: number }[];
}) {
  const cards = useMemo(() => {
    const byCat: Record<string, Record<string, number>> = {};
    events.forEach(e => {
      if (!byCat[e.category]) byCat[e.category] = {};
      byCat[e.category][e.ai_service] = (byCat[e.category][e.ai_service] || 0) + 1;
    });

    return ALL_CATEGORIES.map(cat => {
      const m = byCat[cat] || {};
      const entries = Object.entries(m)
        .map(([key, value]) => ({ key, name: serviceName(key), value, color: svcColor(key) }))
        .sort((a, b) => b.value - a.value);
      const total = entries.reduce((s, d) => s + d.value, 0);
      return { cat, entries, total };
    });
  }, [events]);

  // Tracker card from privacy data
  const trackerEntries = useMemo(() => {
    const topT = (privacy?.trackers?.top_trackers ?? []).slice(0, 6);
    return topT.map((t: any) => ({
      key: t.service, name: serviceName(t.service), value: t.hits, color: svcColor(t.service),
    }));
  }, [privacy]);
  const trackerTotal = privacy?.trackers?.total_detected ?? 0;

  // Country donut data
  const outCountries = useMemo(() => {
    const top = [...geoOutCountries].sort((a, b) => b.bytes - a.bytes).slice(0, 6);
    const total = top.reduce((s, c) => s + c.bytes, 0);
    return { entries: top.map((c, i) => ({ cc: c.country_code, value: c.bytes, color: COUNTRY_COLORS[i % COUNTRY_COLORS.length] })), total };
  }, [geoOutCountries]);

  const inCountries = useMemo(() => {
    const top = [...geoInCountries].sort((a, b) => b.bytes - a.bytes).slice(0, 6);
    const total = top.reduce((s, c) => s + c.bytes, 0);
    return { entries: top.map((c, i) => ({ cc: c.country_code, value: c.bytes, color: COUNTRY_COLORS[i % COUNTRY_COLORS.length] })), total };
  }, [geoInCountries]);

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-2 xl:grid-cols-3 gap-2 content-start">
      {cards.map(c => (
        <DonutCard key={c.cat} label={categoryName(c.cat)} entries={c.entries} total={c.total} accent={categoryColor(c.cat)} />
      ))}
      <DonutCard label="Trackers" entries={trackerEntries} total={trackerTotal} accent={categoryColor('tracking')} />
      <CountryDonutCard label="Outbound" entries={outCountries.entries} total={outCountries.total} accent="#3b82f6" icon="ph-arrow-up-right" />
      <CountryDonutCard label="Inbound" entries={inCountries.entries} total={inCountries.total} accent="#ef4444" icon="ph-arrow-down-left" />
    </div>
  );
}

function DonutCard({ label, entries, total, accent }: {
  label: string;
  entries: { key: string; name: string; value: number; color: string }[];
  total: number;
  accent: string;
}) {
  const [active, setActive] = useState<number | null>(null);
  const displayData = entries.length ? entries.slice(0, 6) : [{ key: '_empty', name: 'None', value: 1, color: '#334155' }];
  const isEmpty = !entries.length;
  const toggle = (i: number) => setActive(prev => prev === i ? null : i);

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-3 flex flex-col">
      <div className="flex items-center gap-1.5 mb-1">
        <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: accent }} />
        <span className="text-[11px] font-semibold text-slate-600 dark:text-slate-300">{label}</span>
        <span className="ml-auto text-xs font-bold tabular-nums text-slate-700 dark:text-slate-100">{formatNumber(total)}</span>
      </div>

      <div className="flex items-start gap-2 flex-1">
        <div style={{ width: 60, height: 60, flexShrink: 0 }}>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={displayData} dataKey="value" cx="50%" cy="50%"
                innerRadius={17} outerRadius={28} strokeWidth={0} paddingAngle={1}
                onClick={(_, i) => { if (!isEmpty) toggle(i); }}
                style={{ cursor: isEmpty ? 'default' : 'pointer', outline: 'none' }}
              >
                {displayData.map((d, i) => (
                  <Cell key={i}
                    fill={isEmpty ? '#334155' : d.color}
                    opacity={active !== null && active !== i ? 0.3 : 1}
                    stroke={active === i ? d.color : 'none'}
                    strokeWidth={active === i ? 2 : 0}
                    style={{ transition: 'opacity 150ms', outline: 'none' }}
                  />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="flex-1 min-w-0 space-y-0.5 pt-0.5">
          {entries.length === 0 && (
            <p className="text-[10px] text-slate-500 italic">No events</p>
          )}
          {entries.slice(0, 4).map((e, i) => (
            <div key={e.key}
              className="flex items-center gap-1 min-w-0 cursor-pointer rounded px-0.5 -mx-0.5 transition-opacity"
              style={{ opacity: active !== null && active !== i ? 0.35 : 1 }}
              onClick={() => toggle(i)}
            >
              <SvcLogo svc={e.key} size={12} />
              <span className="text-[10px] font-medium truncate flex-1" style={{ color: e.color }}>{e.name}</span>
              <span className="text-[10px] font-semibold tabular-nums flex-shrink-0" style={{ color: e.color }}>{e.value}</span>
            </div>
          ))}
          {entries.length > 4 && (
            <p className="text-[9px] text-slate-400">+{entries.length - 4} more</p>
          )}
        </div>
      </div>
    </div>
  );
}

function CountryDonutCard({ label, entries, total, accent, icon }: {
  label: string;
  entries: { cc: string; value: number; color: string }[];
  total: number;
  accent: string;
  icon: string;
}) {
  const [active, setActive] = useState<number | null>(null);
  const displayData = entries.length ? entries : [{ cc: '_empty', value: 1, color: '#334155' }];
  const isEmpty = !entries.length;
  const toggle = (i: number) => setActive(prev => prev === i ? null : i);

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-3 flex flex-col">
      <div className="flex items-center gap-1.5 mb-1">
        <i className={`ph-duotone ${icon} text-xs`} style={{ color: accent }} />
        <span className="text-[11px] font-semibold text-slate-600 dark:text-slate-300">{label}</span>
        <span className="ml-auto text-xs font-bold tabular-nums text-slate-700 dark:text-slate-100">{formatBytes(total)}</span>
      </div>
      <div className="flex items-start gap-2 flex-1">
        <div style={{ width: 60, height: 60, flexShrink: 0 }}>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={displayData} dataKey="value" cx="50%" cy="50%"
                innerRadius={17} outerRadius={28} strokeWidth={0} paddingAngle={1}
                onClick={(_, i) => { if (!isEmpty) toggle(i); }}
                style={{ cursor: isEmpty ? 'default' : 'pointer', outline: 'none' }}
              >
                {displayData.map((d, i) => (
                  <Cell key={i}
                    fill={isEmpty ? '#334155' : d.color}
                    opacity={active !== null && active !== i ? 0.3 : 1}
                    stroke={active === i ? d.color : 'none'}
                    strokeWidth={active === i ? 2 : 0}
                    style={{ transition: 'opacity 150ms', outline: 'none' }}
                  />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="flex-1 min-w-0 space-y-0.5 pt-0.5">
          {isEmpty && <p className="text-[10px] text-slate-500 italic">No data</p>}
          {entries.slice(0, 4).map((e, i) => (
            <div key={e.cc}
              className="flex items-center gap-1 min-w-0 cursor-pointer rounded px-0.5 -mx-0.5 transition-opacity"
              style={{ opacity: active !== null && active !== i ? 0.35 : 1 }}
              onClick={() => toggle(i)}
            >
              <span className={`${flagClass(e.cc)} text-[11px]`} />
              <span className="text-[10px] font-medium truncate flex-1" style={{ color: e.color }}>{countryName(e.cc)}</span>
              <span className="text-[10px] font-semibold tabular-nums flex-shrink-0" style={{ color: e.color }}>{formatBytes(e.value)}</span>
            </div>
          ))}
          {entries.length > 4 && (
            <p className="text-[9px] text-slate-400">+{entries.length - 4} more</p>
          )}
        </div>
      </div>
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

    // Compact height — reduced for dashboard overview
    const H = Math.max(150, Math.max(devList.length, catList.length) * 24);
    const nodeW = 10;
    const padL = 4;
    const padR = 4;
    const gap = 3;

    const totalDevVal = devList.reduce((s, d) => s + Math.sqrt(dFlows[d] || 0), 0);
    const devAvailH = H - gap * (devList.length - 1);
    let dy = 0;
    const devNodes: SankeyNode[] = devList.map(d => {
      const h = Math.max(8, (Math.sqrt(dFlows[d] || 0) / totalDevVal) * devAvailH);
      const node: SankeyNode = { name: d, isDevice: true, value: dFlows[d] || 0, y: dy, h };
      dy += h + gap;
      return node;
    });

    const totalCatVal = catList.reduce((s, c) => s + Math.sqrt(cFlows[c] || 0), 0);
    const catAvailH = H - gap * (catList.length - 1);
    let cy = 0;
    const catNodes: SankeyNode[] = catList.map(c => {
      const h = Math.max(8, (Math.sqrt(cFlows[c] || 0) / totalCatVal) * catAvailH);
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
  const labelW = 100;
  const svgW = width;
  const leftX = padL + labelW;
  const rightX = svgW - padR - labelW - nodeW;
  const svgH = height + 10;

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
            const y0s = l.sy + 5;
            const y0e = l.sy + l.sh + 5;
            const y1s = l.ty + 5;
            const y1e = l.ty + l.th + 5;
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
                <rect x={leftX} y={n.y + 5} width={nodeW} height={n.h} rx={3}
                  fill="#3b82f6"
                  opacity={isDim ? 0.3 : 1}
                  className="transition-opacity duration-200" />
                <text x={leftX - 6} y={n.y + 5 + n.h / 2} textAnchor="end" dominantBaseline="central"
                  className="text-[10px] fill-slate-600 dark:fill-slate-300 font-medium"
                  style={{ fontFamily: 'Inter, system-ui, sans-serif' }}
                  opacity={isDim ? 0.4 : 1}>
                  {n.name.length > 16 ? n.name.slice(0, 15) + '…' : n.name}
                </text>
                {isHigh && (
                  <text x={leftX - 6} y={n.y + 5 + n.h / 2 + 12} textAnchor="end" dominantBaseline="central"
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
                <rect x={rightX} y={n.y + 5} width={nodeW} height={n.h} rx={3}
                  fill={color}
                  opacity={isDim ? 0.3 : 1}
                  className="transition-opacity duration-200" />
                <text x={rightX + nodeW + 6} y={n.y + 5 + n.h / 2} dominantBaseline="central"
                  className="text-[10px] fill-slate-600 dark:fill-slate-300 font-medium"
                  style={{ fontFamily: 'Inter, system-ui, sans-serif' }}
                  opacity={isDim ? 0.4 : 1}>
                  {n.name}
                </text>
                {isHigh && (
                  <text x={rightX + nodeW + 6} y={n.y + 5 + n.h / 2 + 12} dominantBaseline="central"
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
