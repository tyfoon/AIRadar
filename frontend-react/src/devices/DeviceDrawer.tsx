import { useState, useEffect, useCallback, useRef } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import type { DeviceEvent, DeviceMap, ReportData, Connection } from './types';
import type { Device } from '../utils/devices';
import { detectDeviceType, isDeviceOnline, bestDeviceName, latestIp, saveFriendlyName } from '../utils/devices';
import { getCategoryGroups, categorizeService } from '../utils/categories';
import { svcDisplayName, svcColor } from '../utils/services';
import { fmtBytes, fmtDuration, fmtDurationSec, fmtTime, formatNumber, todayLocalISO, formatLocalDateLabel } from '../utils/format';
import { t, getLocale } from '../utils/i18n';
import { fetchConnections, fetchActivity, fetchReport, fetchCachedReport, fetchIotProfile, renameDevice } from './api';
import SvcLogo from './SvcLogo';
import PhIcon from './PhIcon';
import ScreenTime from '../ScreenTime';

interface Props {
  mac: string | null;
  deviceMap: DeviceMap;
  allEvents: DeviceEvent[];
  svcCategoryMap: Record<string, string>;
  onClose: () => void;
  onDevicesRefetch: () => void;
}

type TabKey = 'report' | 'summary' | 'connections' | 'activity' | 'screentime' | 'ai' | 'cloud' | 'tracking' | 'other';

const SESSION_GAP_MS = 5 * 60 * 1000;
const MIN_SESSION_MS = 60 * 1000;

function estimateActiveTime(timestamps: string[]): number {
  if (!timestamps.length) return 0;
  const sorted = timestamps.map(t => new Date(t).getTime()).sort((a, b) => a - b);
  let total = 0;
  let start = sorted[0], end = sorted[0];
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i] - end <= SESSION_GAP_MS) {
      end = sorted[i];
    } else {
      total += Math.max(end - start, MIN_SESSION_MS);
      start = sorted[i]; end = sorted[i];
    }
  }
  total += Math.max(end - start, MIN_SESSION_MS);
  return total;
}

export default function DeviceDrawer({ mac, deviceMap, allEvents, svcCategoryMap, onClose, onDevicesRefetch }: Props) {
  const [activeTab, setActiveTab] = useState<TabKey>('report');
  const [serviceFilter, setServiceFilter] = useState<string | null>(null);
  const [isRenaming, setIsRenaming] = useState(false);
  const [renameValue, setRenameValue] = useState('');
  const scrollRef = useRef<HTMLDivElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);

  const device = mac ? deviceMap[mac] || null : null;

  // Collect events for this device
  const deviceEvents = mac ? (() => {
    const devIps = new Set<string>();
    if (device?.ips) device.ips.forEach(ip => devIps.add(ip.ip));
    else if (mac) devIps.add(mac.replace('_ip_', ''));
    return allEvents.filter(e => devIps.has(e.source_ip)).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  })() : [];

  // Tab counts for category tabs
  const cats = getCategoryGroups();
  const tabCounts: Record<string, number> = {};
  cats.forEach(c => { tabCounts[c.key] = deviceEvents.filter(e => e._cat === c.key).length; });

  // Reset tab on mac change
  useEffect(() => {
    if (mac) {
      setActiveTab('report');
      setServiceFilter(null);
      setIsRenaming(false);
      if (scrollRef.current) scrollRef.current.scrollTop = 0;
    }
  }, [mac]);

  // Escape key + back button
  useEffect(() => {
    if (!mac) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    const onPop = () => { onClose(); };
    window.addEventListener('keydown', onKey);
    window.addEventListener('popstate', onPop);
    history.pushState({ drawer: mac }, '', location.href);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('popstate', onPop);
    };
  }, [mac, onClose]);

  // Swipe to close (mobile)
  useEffect(() => {
    const panel = panelRef.current;
    if (!panel || !mac) return;
    let startX = 0, swiping = false;
    const onStart = (e: TouchEvent) => { if (e.touches.length === 1) { startX = e.touches[0].clientX; swiping = true; } };
    const onMove = (e: TouchEvent) => {
      if (!swiping) return;
      const dx = e.touches[0].clientX - startX;
      if (dx > 60) panel.style.transform = `translateX(${Math.min(dx - 60, 200)}px)`;
    };
    const onEnd = (e: TouchEvent) => {
      if (!swiping) return;
      swiping = false;
      const dx = (e.changedTouches[0]?.clientX || 0) - startX;
      if (dx > 120) onClose();
      panel.style.transform = '';
    };
    panel.addEventListener('touchstart', onStart, { passive: true });
    panel.addEventListener('touchmove', onMove, { passive: true });
    panel.addEventListener('touchend', onEnd, { passive: true });
    return () => {
      panel.removeEventListener('touchstart', onStart);
      panel.removeEventListener('touchmove', onMove);
      panel.removeEventListener('touchend', onEnd);
    };
  }, [mac, onClose]);

  const handleRename = async () => {
    if (!mac || !renameValue.trim()) return;
    saveFriendlyName(mac, renameValue.trim());
    try { await renameDevice(mac, renameValue.trim()); } catch { /* localStorage already saved */ }
    setIsRenaming(false);
    onDevicesRefetch();
  };

  if (!mac) return null;

  const dt = detectDeviceType(device);
  const name = bestDeviceName(mac, device);
  const online = device ? isDeviceOnline(device) : false;
  const metaParts = [dt.type];
  if (device) {
    const ip = latestIp(device);
    if (ip) metaParts.push(ip);
    if (device.vendor) metaParts.push(device.vendor);
  }

  const tabBase = 'relative inline-flex items-center justify-center w-9 h-9 rounded-md text-base transition-colors flex-shrink-0';
  const tabActive = `${tabBase} bg-blue-700 text-white shadow-sm`;
  const tabInactive = `${tabBase} text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300 hover:bg-slate-100 dark:hover:bg-white/5`;

  const builtInTabs: { key: TabKey; icon: string; label: string }[] = [
    { key: 'report', icon: 'ph-sparkle', label: t('dev.drawerReportTab') || 'AI Recap' },
    { key: 'summary', icon: 'ph-chart-bar', label: t('dev.drawerSummaryTab') || 'Summary' },
    { key: 'connections', icon: 'ph-swap', label: t('dev.drawerConnectionsTab') || 'Connections' },
    { key: 'activity', icon: 'ph-hourglass-medium', label: t('dev.drawerActivityTab') || 'Activity' },
    { key: 'screentime', icon: 'ph-timer', label: 'Sessions' },
  ];

  return (
    <>
      {/* Backdrop */}
      <div className={`drawer-backdrop ${mac ? 'open' : ''}`} onClick={onClose} />
      {/* Panel */}
      <div ref={panelRef} className={`drawer-panel ${mac ? 'open' : ''}`}>
        {/* Header */}
        <div className="flex items-center gap-3 px-5 py-4 border-b border-slate-200 dark:border-white/[0.06]">
          <span className={`text-2xl ${online ? 'text-emerald-500' : 'text-slate-400'}`}>
            <PhIcon icon={dt.icon} />
          </span>
          <div className="flex-1 min-w-0">
            {isRenaming ? (
              <div className="flex items-center gap-2">
                <input
                  autoFocus
                  value={renameValue}
                  onChange={e => setRenameValue(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') handleRename(); if (e.key === 'Escape') setIsRenaming(false); }}
                  className="flex-1 px-2 py-1 text-sm rounded border border-slate-300 dark:border-white/[0.1] bg-white dark:bg-white/[0.05] text-slate-700 dark:text-slate-200 outline-none"
                />
                <button onClick={handleRename} className="text-emerald-500 hover:text-emerald-600"><i className="ph-bold ph-check text-sm" /></button>
                <button onClick={() => setIsRenaming(false)} className="text-slate-400 hover:text-slate-600"><i className="ph-bold ph-x text-sm" /></button>
              </div>
            ) : (
              <h2
                className="text-base font-semibold text-slate-800 dark:text-white truncate cursor-pointer hover:text-indigo-500"
                onClick={() => { setRenameValue(name); setIsRenaming(true); }}
              >
                {name}
              </h2>
            )}
            <p className="text-[11px] text-slate-400 dark:text-slate-500 truncate">{metaParts.join(' · ')}</p>
            {device?.os_name && (
              <p className="text-[10px] text-indigo-500 dark:text-indigo-400 mt-0.5">
                🔍 p0f: {device.os_name}{device.os_version ? ` ${device.os_version}` : ''}{device.device_class ? ` · ${device.device_class}` : ''}{device.network_distance != null ? ` · ${device.network_distance} hop${device.network_distance !== 1 ? 's' : ''}` : ''}
              </p>
            )}
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300">
            <i className="ph-bold ph-x text-lg" />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex items-center gap-1 px-5 py-2 border-b border-slate-100 dark:border-white/[0.04] overflow-x-auto">
          {builtInTabs.map(tab => (
            <button
              key={tab.key}
              className={activeTab === tab.key ? tabActive : tabInactive}
              onClick={() => { setActiveTab(tab.key); setServiceFilter(null); }}
              title={tab.label}
            >
              <i className={`ph-duotone ${tab.icon}`} />
            </button>
          ))}
          {cats.filter(c => tabCounts[c.key] > 0).map(c => (
            <button
              key={c.key}
              className={activeTab === c.key ? tabActive : tabInactive}
              onClick={() => { setActiveTab(c.key as TabKey); setServiceFilter(null); }}
              title={`${c.label} (${tabCounts[c.key]})`}
            >
              <i className={`ph-duotone ${c.icon}`} />
              {tabCounts[c.key] > 0 && (
                <span className="absolute -top-1 -right-1 min-w-[16px] h-4 px-1 rounded-full bg-slate-700 dark:bg-slate-200 text-white dark:text-slate-900 text-[9px] font-semibold leading-4 text-center tabular-nums">
                  {tabCounts[c.key] > 999 ? '999+' : tabCounts[c.key]}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Content */}
        <div ref={scrollRef} className="flex-1 overflow-y-auto">
          {activeTab === 'report' && <ReportTab mac={mac} />}
          {activeTab === 'summary' && <SummaryTab events={deviceEvents} mac={mac} />}
          {activeTab === 'connections' && <ConnectionsTab mac={mac} />}
          {activeTab === 'activity' && <ActivityTab mac={mac} />}
          {activeTab === 'screentime' && <div className="p-0"><ScreenTime macAddress={mac} /></div>}
          {['ai', 'cloud', 'tracking', 'other'].includes(activeTab) && (
            <EventsTab events={deviceEvents} category={activeTab} serviceFilter={serviceFilter} />
          )}
        </div>
      </div>
    </>
  );
}

// --- Report Tab ---
function ReportTab({ mac }: { mac: string }) {
  const lang = getLocale();
  const [forceLoading, setForceLoading] = useState(false);

  const cachedQuery = useQuery({
    queryKey: ['deviceReport', mac, lang],
    queryFn: () => fetchCachedReport(mac, lang),
    staleTime: 60_000,
  });

  const generateMutation = useMutation({
    mutationFn: () => fetchReport(mac, true, lang),
    onMutate: () => setForceLoading(true),
    onSettled: () => setForceLoading(false),
  });

  const data = generateMutation.data || cachedQuery.data;
  const loading = forceLoading || (cachedQuery.isLoading && !data);

  return (
    <div className="p-5">
      {data && (
        <button
          onClick={() => generateMutation.mutate()}
          className="mb-3 px-3 py-1.5 text-[11px] font-medium rounded-lg border border-indigo-200 dark:border-indigo-800 text-indigo-600 dark:text-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-900/20 transition-colors"
        >
          <i className="ph-duotone ph-arrows-clockwise text-xs mr-1" />
          {t('dev.regenerateReport') || 'Regenerate'}
        </button>
      )}
      {loading && (
        <div className="flex items-center gap-3 text-indigo-500 dark:text-indigo-400 py-6">
          <i className="ph-duotone ph-circle-notch animate-spin text-lg" />
          <span className="text-sm">{t('dev.geminiAnalyzing') || 'Analyzing...'}</span>
        </div>
      )}
      {!loading && data && <ReportContent data={data} />}
      {!loading && !data && (
        <div className="py-10 text-center">
          <p className="text-xs text-slate-400 dark:text-slate-500 mb-4">{t('dev.reportEmptyHint') || 'Generate an AI recap for this device'}</p>
          <button
            onClick={() => generateMutation.mutate()}
            className="px-4 py-2 text-xs font-medium rounded-lg bg-gradient-to-r from-indigo-500 to-purple-500 text-white hover:from-indigo-600 hover:to-purple-600 transition-all shadow-sm hover:shadow-md"
          >
            ✨ {t('dev.generateReport') || 'Generate Report'}
          </button>
        </div>
      )}
      {generateMutation.isError && (
        <p className="text-sm text-red-500 mt-2">{(generateMutation.error as Error)?.message}</p>
      )}
    </div>
  );
}

function ReportContent({ data }: { data: ReportData }) {
  // Flags
  const flags = (() => {
    if (!data.flags) return [];
    try {
      const f = typeof data.flags === 'string' ? JSON.parse(data.flags) : data.flags;
      const out: { cls: string; icon: string; label: string }[] = [];
      if (f.vpn_detected) out.push({ cls: 'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300', icon: 'ph-shield-check', label: 'VPN' });
      if (f.ai_usage_present) out.push({ cls: 'bg-indigo-100 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300', icon: 'ph-sparkle', label: 'AI' });
      if (f.ad_tracker_heavy) out.push({ cls: 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300', icon: 'ph-eye', label: 'Trackers' });
      if (f.unexpected_services) out.push({ cls: 'bg-rose-100 dark:bg-rose-900/30 text-rose-700 dark:text-rose-300', icon: 'ph-warning', label: 'Unexpected' });
      if (f.upload_anomaly) out.push({ cls: 'bg-rose-100 dark:bg-rose-900/30 text-rose-700 dark:text-rose-300', icon: 'ph-arrow-up', label: 'Upload' });
      if (f.activity_level) {
        const colors: Record<string, string> = {
          idle: 'bg-slate-200 dark:bg-white/[0.06] text-slate-500', light: 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700',
          moderate: 'bg-sky-100 dark:bg-sky-900/30 text-sky-700', active: 'bg-orange-100 dark:bg-orange-900/30 text-orange-700',
        };
        out.push({ cls: colors[f.activity_level as string] || colors.light, icon: 'ph-activity', label: f.activity_level as string });
      }
      return out;
    } catch { return []; }
  })();

  // Pricing
  const pricing: Record<string, { input: number; output: number; thinking: number }> = {
    'gemini-2.5-flash-lite': { input: 0.10, output: 0.40, thinking: 0 },
    'gemini-2.5-flash': { input: 0.30, output: 2.50, thinking: 3.50 },
    'gemini-2.0-flash': { input: 0.10, output: 0.40, thinking: 0 },
    'gemini-2.0-flash-lite': { input: 0.075, output: 0.30, thinking: 0 },
    'gemini-3-flash-preview': { input: 0.30, output: 2.50, thinking: 0 },
  };
  const modelName = data.model || 'gemini-2.5-flash-lite';
  const p = pricing[modelName] || pricing['gemini-2.5-flash-lite'];
  const tok = data.tokens || {};
  const totalCost = (tok.prompt_tokens || 0) * p.input / 1e6 + (tok.response_tokens || 0) * p.output / 1e6 + (tok.thinking_tokens || 0) * p.thinking / 1e6;
  const costLabel = totalCost >= 0.01 ? `${(totalCost * 100).toFixed(2)}¢` : `${(totalCost * 1000).toFixed(3)}m¢`;

  return (
    <>
      {flags.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 mb-3">
          {flags.map((f, i) => (
            <span key={i} className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium ${f.cls}`}>
              <i className={`ph-duotone ${f.icon}`} />{f.label}
            </span>
          ))}
        </div>
      )}
      <div
        className="prose prose-sm dark:prose-invert max-w-none text-sm leading-relaxed"
        dangerouslySetInnerHTML={{ __html: renderSimpleMarkdown(data.report) }}
      />
      {data.generated_at && (
        <div className="mt-3 flex items-center gap-2 text-[10px] text-slate-400 dark:text-slate-500">
          <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] uppercase tracking-wider font-medium ${data.cached ? 'bg-slate-200/60 dark:bg-white/[0.05] text-slate-500' : 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600'}`}>
            {data.cached ? 'Cached' : 'Fresh'}
          </span>
          <span>{fmtTime(data.generated_at)}</span>
        </div>
      )}
      <div className="mt-2 pt-3 border-t border-indigo-200/30 dark:border-indigo-700/20 flex items-center justify-between text-[10px] text-indigo-400/70 dark:text-indigo-500/50">
        <span>{modelName} · {formatNumber(tok.total_tokens || 0)} tokens</span>
        <span>{costLabel}</span>
      </div>
    </>
  );
}

function renderSimpleMarkdown(md: string): string {
  if (!md) return '';
  let html = md
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/^### (.+)$/gm, '<h4 class="text-sm font-semibold mt-4 mb-1 text-slate-800 dark:text-slate-200">$1</h4>')
    .replace(/^## (.+)$/gm, '<h3 class="text-base font-semibold mt-5 mb-2 text-slate-800 dark:text-slate-200">$1</h3>')
    .replace(/^# (.+)$/gm, '<h2 class="text-lg font-bold mt-5 mb-2 text-slate-800 dark:text-slate-200">$1</h2>')
    .replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>')
    .replace(/\*\*(.+?)\*\*/g, '<strong class="text-slate-800 dark:text-slate-100">$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/`([^`]+)`/g, '<code class="px-1.5 py-0.5 rounded bg-slate-200/70 dark:bg-slate-700/50 text-xs font-mono">$1</code>')
    .replace(/^- (.+)$/gm, '<li class="ml-4 list-disc text-sm leading-relaxed">$1</li>')
    .replace(/^\* (.+)$/gm, '<li class="ml-4 list-disc text-sm leading-relaxed">$1</li>')
    .replace(/^---$/gm, '<hr class="my-3 border-indigo-200/50 dark:border-indigo-700/30">')
    .replace(/\n\n/g, '</p><p class="mb-2">')
    .replace(/\n/g, '<br>');
  html = html.replace(/(<li[^>]*>.*?<\/li>(?:\s*<br>?\s*<li[^>]*>.*?<\/li>)*)/gs, '<ul class="my-2 space-y-0.5">$1</ul>');
  html = html.replace(/<ul([^>]*)>([\s\S]*?)<\/ul>/g, (_, attrs, inner) => `<ul${attrs}>${inner.replace(/<br>/g, '')}</ul>`);
  return `<p class="mb-2">${html}</p>`;
}

// --- Summary Tab ---
function SummaryTab({ events, mac }: { events: DeviceEvent[]; mac: string }) {
  const iotQuery = useQuery({
    queryKey: ['iotProfile', mac],
    queryFn: () => fetchIotProfile(mac),
    staleTime: 60_000,
  });

  if (events.length === 0) {
    return <div className="py-12 text-center text-sm text-slate-400 dark:text-slate-500">{t('dev.noActivity') || 'No activity'}</div>;
  }

  const svcAgg: Record<string, { bytes: number; hits: number; cat: string; timestamps: string[]; activeMs: number }> = {};
  events.forEach(e => {
    if (!svcAgg[e.ai_service]) svcAgg[e.ai_service] = { bytes: 0, hits: 0, cat: e._cat, timestamps: [], activeMs: 0 };
    svcAgg[e.ai_service].bytes += e.bytes_transferred || 0;
    svcAgg[e.ai_service].hits += 1;
    svcAgg[e.ai_service].timestamps.push(e.timestamp);
  });
  for (const info of Object.values(svcAgg)) {
    info.activeMs = estimateActiveTime(info.timestamps);
  }

  const totalTime = Object.values(svcAgg).reduce((s, v) => s + v.activeMs, 0);
  const totalBytes = Object.values(svcAgg).reduce((s, v) => s + v.bytes, 0);
  const rows = Object.entries(svcAgg).sort((a, b) => b[1].activeMs - a[1].activeMs || b[1].bytes - a[1].bytes).slice(0, 15);
  const maxTime = rows.length ? rows[0][1].activeMs : 0;

  const baseline = iotQuery.data as Record<string, unknown> | null;
  const bl = baseline?.baseline as Record<string, unknown> | undefined;

  return (
    <div className="p-5">
      <div className="mb-4 flex items-baseline justify-between gap-3">
        <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">{t('dev.summaryTitle') || 'Top Services'}</h3>
      </div>
      <div className="space-y-1.5">
        {rows.map(([svc, info]) => (
          <div key={svc} className="flex items-center gap-3 py-1.5 px-2 rounded-lg hover:bg-slate-50 dark:hover:bg-white/[0.03] transition-colors">
            <SvcLogo service={svc} size={20} />
            <div className="flex-1 min-w-0">
              <div className="flex items-baseline justify-between gap-2">
                <span className="text-sm font-medium text-slate-700 dark:text-slate-200 truncate">{svcDisplayName(svc)}</span>
                <span className="text-xs tabular-nums flex-shrink-0 flex items-center gap-2">
                  <span className="text-blue-600 dark:text-blue-400 font-semibold"><i className="ph-duotone ph-clock text-[10px]" /> {fmtDuration(info.activeMs)}</span>
                  {info.bytes > 0 && <span className="text-slate-400 dark:text-slate-500">{fmtBytes(info.bytes)}</span>}
                </span>
              </div>
              <div className="mt-1 h-1.5 rounded-full bg-slate-100 dark:bg-white/[0.05] overflow-hidden">
                <div className="h-full bg-gradient-to-r from-blue-500 to-blue-700" style={{ width: `${maxTime > 0 ? (info.activeMs / maxTime * 100) : 0}%` }} />
              </div>
            </div>
          </div>
        ))}
      </div>
      <div className="mt-4 pt-3 border-t border-slate-100 dark:border-white/[0.05] flex items-center justify-between text-[11px] text-slate-400 dark:text-slate-500">
        <span>{Object.keys(svcAgg).length} services</span>
        <span className="tabular-nums flex items-center gap-2">
          <span><i className="ph-duotone ph-clock text-[10px]" /> {fmtDuration(totalTime)}</span>
          {totalBytes > 0 && <span>{fmtBytes(totalBytes)}</span>}
        </span>
      </div>

      {/* IoT baseline */}
      {bl && (
        <div className="mt-4 pt-3 border-t border-slate-100 dark:border-white/[0.05]">
          <h4 className="text-[10px] uppercase tracking-wider text-slate-400 dark:text-slate-500 font-semibold mb-2">7-day Baseline</h4>
          <div className="grid grid-cols-3 gap-3 text-center">
            <div>
              <div className="text-sm font-semibold text-slate-700 dark:text-slate-200">{fmtBytes(bl.avg_bytes_hour as number)}<span className="text-[10px] text-slate-400 font-normal">/h</span></div>
              <div className="text-[10px] text-slate-400">Avg traffic</div>
            </div>
            <div>
              <div className="text-sm font-semibold text-slate-700 dark:text-slate-200">{bl.avg_connections_hour as number}</div>
              <div className="text-[10px] text-slate-400">Conn/h</div>
            </div>
            <div>
              <div className="text-sm font-semibold text-slate-700 dark:text-slate-200">{bl.avg_unique_destinations as number}</div>
              <div className="text-[10px] text-slate-400">Destinations</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// --- Connections Tab ---
function ConnectionsTab({ mac }: { mac: string }) {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['deviceConnections', mac],
    queryFn: () => fetchConnections(mac),
    staleTime: 30_000,
  });

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-slate-400 py-6 justify-center">
        <i className="ph-duotone ph-circle-notch animate-spin text-lg" />
        <span className="text-sm">{t('dev.loadingConnections') || 'Loading connections...'}</span>
      </div>
    );
  }

  if (isError) return <p className="text-sm text-red-500 text-center py-4">{(error as Error)?.message}</p>;

  const conns = data?.connections || [];
  if (conns.length === 0) {
    return <div className="py-8 text-center text-xs text-slate-400 dark:text-slate-500">{t('dev.noConnections') || 'No connections recorded.'}</div>;
  }

  const totalBytes = conns.reduce((s, c) => s + (c.bytes || 0), 0);
  const totalHits = conns.reduce((s, c) => s + (c.hits || 0), 0);

  return (
    <div className="p-5">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">{t('dev.connectionsTitle') || 'Network Connections'}</h3>
        <span className="text-[11px] text-slate-400 dark:text-slate-500 tabular-nums">{conns.length} dest. · {fmtBytes(totalBytes)} · {formatNumber(totalHits)} conn.</span>
      </div>
      <div className="space-y-1">
        {conns.map((c, i) => (
          <div key={i} className="flex items-center gap-2 py-1.5 px-2 rounded-lg hover:bg-slate-50 dark:hover:bg-white/[0.03]">
            <span className="flex-shrink-0">
              {c.direction === 'outbound'
                ? <i className="ph-duotone ph-arrow-up-right text-xs text-blue-500" title="Outbound" />
                : <i className="ph-duotone ph-arrow-down-left text-xs text-emerald-500" title="Inbound" />
              }
            </span>
            <span className="flex-shrink-0 text-sm">
              {c.country_code?.length === 2
                ? <span className={`fi fi-${c.country_code.toLowerCase()} rounded-sm shadow-sm inline-block`} style={{ fontSize: '1.1em' }} />
                : <i className="ph-duotone ph-globe text-slate-400" />
              }
            </span>
            <div className="flex-1 min-w-0">
              {c.ptr ? (
                <span className="text-xs font-medium text-slate-700 dark:text-slate-200 truncate block">{c.ptr}</span>
              ) : c.asn_org ? (
                <span className="text-xs font-medium text-slate-700 dark:text-slate-200 truncate block">AS{c.asn} · {c.asn_org}</span>
              ) : c.service && c.service !== 'unknown' ? (
                <span className="text-xs font-medium text-slate-700 dark:text-slate-200">{svcDisplayName(c.service)}</span>
              ) : (
                <span className="text-xs font-mono text-slate-500 dark:text-slate-400">{c.resp_ip}</span>
              )}
              {(c.ptr || c.asn_org) && (
                <div className="text-[10px] font-mono text-slate-400 dark:text-slate-500 truncate">{c.resp_ip}</div>
              )}
            </div>
            <div className="flex-shrink-0 text-right">
              <div className="text-xs tabular-nums font-medium text-slate-700 dark:text-slate-200">{fmtBytes(c.bytes)}</div>
              <div className="text-[10px] tabular-nums text-slate-400 dark:text-slate-500">{c.hits} conn.</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// --- Activity Tab ---
function ActivityTab({ mac }: { mac: string }) {
  const [date, setDate] = useState(todayLocalISO);
  const [showSessions, setShowSessions] = useState(false);
  const isToday = date === todayLocalISO();

  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['deviceActivity', mac, date],
    queryFn: () => fetchActivity(mac, date),
    staleTime: 30_000,
  });

  const shiftDate = (delta: number) => {
    setDate(prev => {
      const d = new Date(`${prev}T12:00:00`);
      d.setDate(d.getDate() + delta);
      const today = new Date(); today.setHours(23, 59, 59, 999);
      if (d > today) return prev;
      return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
    });
    setShowSessions(false);
  };

  const sessions = data?.sessions || [];
  const totalsCat = data?.totals_by_category || [];
  const totalsSvc = data?.totals_by_service || [];
  const label = formatLocalDateLabel(date, getLocale());

  return (
    <div className="p-5 space-y-4">
      {/* Date nav */}
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">{t('dev.activityTitle') || 'Daily usage'}</h3>
        <div className="flex items-center gap-1">
          <button onClick={() => shiftDate(-1)} className="w-7 h-7 flex items-center justify-center rounded-md hover:bg-slate-100 dark:hover:bg-white/[0.06] text-slate-500">
            <i className="ph-bold ph-caret-left text-sm" />
          </button>
          <span className="text-xs font-medium text-slate-600 dark:text-slate-300 min-w-[80px] text-center tabular-nums">{label}</span>
          <button onClick={() => shiftDate(1)} disabled={isToday} className="w-7 h-7 flex items-center justify-center rounded-md hover:bg-slate-100 dark:hover:bg-white/[0.06] text-slate-500 disabled:opacity-30">
            <i className="ph-bold ph-caret-right text-sm" />
          </button>
          <button onClick={() => { setDate(todayLocalISO()); setShowSessions(false); }} disabled={isToday} className={`ml-1 px-2 h-7 text-[11px] font-medium rounded-md ${isToday ? 'text-slate-400 cursor-default' : 'text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20'}`}>
            {t('dev.activityToday') || 'Today'}
          </button>
        </div>
      </div>

      {isLoading && (
        <div className="flex items-center gap-2 text-slate-400 py-6 justify-center">
          <i className="ph-duotone ph-circle-notch animate-spin text-lg" />
          <span className="text-sm">Loading...</span>
        </div>
      )}

      {isError && <p className="text-sm text-red-500 text-center py-6">{(error as Error)?.message}</p>}

      {data && !isLoading && sessions.length === 0 && (
        <div className="py-12 text-center text-sm text-slate-400 dark:text-slate-500">
          <i className="ph-duotone ph-hourglass text-3xl mb-2 block" />
          {t('dev.activityEmpty') || 'No usage recorded on this day.'}
        </div>
      )}

      {data && !isLoading && sessions.length > 0 && (
        <>
          {/* Grand total */}
          <div className="flex items-baseline justify-between">
            <div>
              <span className="text-xs text-slate-500 dark:text-slate-400">{t('dev.activityTotal') || 'Total usage'}</span>
              <span className="ml-2 text-base font-semibold text-slate-700 dark:text-slate-200 tabular-nums">{fmtDurationSec(data.grand_total_seconds)}</span>
            </div>
            <span className="text-[11px] text-slate-400 dark:text-slate-500 tabular-nums">{sessions.length} sessions</span>
          </div>

          {/* Timeline */}
          <div className="space-y-1.5">
            <div className="flex justify-between text-[9px] text-slate-400 dark:text-slate-500 px-1 tabular-nums select-none">
              <span>00</span><span>06</span><span>12</span><span>18</span><span>24</span>
            </div>
            {totalsCat.map(catTotal => {
              const cat = catTotal.category;
              const catSessions = sessions.filter(s => s.category === cat);
              return (
                <div key={cat} className="flex items-center gap-2 mb-1.5">
                  <div className="w-16 flex-shrink-0 text-[10px] font-medium text-slate-600 dark:text-slate-400 truncate">
                    {cat.charAt(0).toUpperCase() + cat.slice(1)}
                  </div>
                  <div className="flex-1 relative h-6 rounded bg-slate-100 dark:bg-white/[0.04] overflow-hidden">
                    {[6, 12, 18].map(h => (
                      <div key={h} className="absolute top-0 bottom-0 border-l border-slate-200 dark:border-white/[0.08]" style={{ left: `${(h / 24) * 100}%` }} />
                    ))}
                    {catSessions.map((s, i) => {
                      const start = new Date(s.start);
                      const end = new Date(s.end);
                      const startMin = start.getHours() * 60 + start.getMinutes() + start.getSeconds() / 60;
                      const endMin = end.getHours() * 60 + end.getMinutes() + end.getSeconds() / 60;
                      const left = (startMin / 1440) * 100;
                      const width = Math.max(((endMin - startMin) / 1440) * 100, 0.4);
                      const color = svcColor(s.service);
                      return (
                        <div
                          key={i}
                          className="absolute top-0 bottom-0 hover:ring-2 ring-white/50 cursor-default rounded-sm"
                          style={{ left: `${left}%`, width: `${width}%`, background: color }}
                          title={`${svcDisplayName(s.service)} · ${start.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}–${end.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} · ${fmtDurationSec(s.duration_seconds)}`}
                        />
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Service chips */}
          <div className="flex flex-wrap gap-1.5">
            {totalsSvc.map(svc => {
              const color = svcColor(svc.service);
              return (
                <div key={svc.service} className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md bg-slate-50 dark:bg-white/[0.03] text-[11px]">
                  <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: color }} />
                  <span className="font-medium text-slate-600 dark:text-slate-300">{svcDisplayName(svc.service)}</span>
                  <span className="tabular-nums text-slate-500 dark:text-slate-400">{fmtDurationSec(svc.duration_seconds)}</span>
                </div>
              );
            })}
          </div>

          {/* Collapsible session list */}
          <div className="border-t border-slate-200 dark:border-white/[0.05] pt-3">
            <button onClick={() => setShowSessions(s => !s)} className="w-full flex items-center justify-between text-[11px] font-medium text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200">
              <span>{showSessions ? 'Hide sessions' : 'Show all sessions'}</span>
              <i className={`ph-bold ${showSessions ? 'ph-caret-up' : 'ph-caret-down'}`} />
            </button>
            {showSessions && (
              <div className="mt-3 space-y-1">
                {sessions.map((s, i) => (
                  <div key={i} className="flex items-center gap-2 py-1.5 px-2 rounded-md hover:bg-slate-50 dark:hover:bg-white/[0.03]">
                    <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: svcColor(s.service) }} />
                    <span className="text-[11px] tabular-nums text-slate-500 dark:text-slate-400 w-24 flex-shrink-0">
                      {new Date(s.start).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}–{new Date(s.end).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                    <span className="text-xs font-medium text-slate-700 dark:text-slate-200 truncate flex-1">{svcDisplayName(s.service)}</span>
                    <span className="text-[11px] tabular-nums text-slate-500 dark:text-slate-400 flex-shrink-0">{fmtDurationSec(s.duration_seconds)}</span>
                    {s.bytes > 0 && <span className="text-[10px] tabular-nums text-slate-400 dark:text-slate-500 w-14 text-right flex-shrink-0">{fmtBytes(s.bytes)}</span>}
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

// --- Events Tab (per category) ---
const PAGE_SIZE = 50;
const COLLAPSE_WINDOW_SEC = 60;

function collapseEvents(events: DeviceEvent[], keyFn: (e: DeviceEvent) => string): DeviceEvent[] {
  if (!events.length) return [];
  const sorted = [...events].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  const out: DeviceEvent[] = [];
  let cur: DeviceEvent | null = null;
  for (const e of sorted) {
    const k = keyFn(e);
    const ts = new Date(e.timestamp).getTime();
    if (cur && cur._key === k && ((cur._oldest_ms || 0) - ts) <= COLLAPSE_WINDOW_SEC * 1000) {
      cur._count = (cur._count || 1) + 1;
      cur.bytes_transferred = (cur.bytes_transferred || 0) + (e.bytes_transferred || 0);
      cur.possible_upload = cur.possible_upload || !!e.possible_upload;
      cur._oldest_ts = e.timestamp;
      cur._oldest_ms = ts;
    } else {
      cur = { ...e, _key: k, _count: 1, _newest_ts: e.timestamp, _oldest_ts: e.timestamp, _newest_ms: ts, _oldest_ms: ts };
      out.push(cur);
    }
  }
  return out;
}

function EventsTab({ events, category, serviceFilter }: { events: DeviceEvent[]; category: string; serviceFilter: string | null }) {
  const [visible, setVisible] = useState(PAGE_SIZE);

  let filtered = events.filter(e => e._cat === category);
  if (serviceFilter) filtered = filtered.filter(e => e.ai_service === serviceFilter);

  const collapsed = collapseEvents(filtered, e => `${e.ai_service}|${e.detection_type}`);

  useEffect(() => setVisible(PAGE_SIZE), [category, serviceFilter]);

  if (collapsed.length === 0) {
    return <div className="py-12 text-center text-sm text-slate-400 dark:text-slate-500">{t('dev.noActivity') || 'No events'}</div>;
  }

  const shown = collapsed.slice(0, visible);

  return (
    <div className="p-0">
      <table className="w-full text-left striped-rows">
        <tbody>
          {shown.map((e, i) => (
            <tr key={i} className={`border-b border-slate-100 dark:border-white/[0.04] ${e.possible_upload ? 'bg-orange-50/50 dark:bg-orange-900/10' : ''}`}>
              <td className="py-2.5 px-4 text-xs tabular-nums text-slate-400 dark:text-slate-500 whitespace-nowrap">
                {fmtTime(e._newest_ts || e.timestamp)}
                {(e._count || 0) > 1 && (
                  <span className="text-[10px] text-slate-400 dark:text-slate-500"> – {fmtTime(e._oldest_ts || e.timestamp)}</span>
                )}
              </td>
              <td className="py-2.5 px-4 truncate">
                <span className="inline-flex items-center gap-2 min-w-0">
                  <SvcLogo service={e.ai_service} size={24} showUploadDot={!!e.possible_upload} />
                  <span className="text-xs font-medium text-slate-700 dark:text-slate-200 truncate">{svcDisplayName(e.ai_service)}</span>
                  {(e._count || 0) > 1 && (
                    <span className="ml-1 px-1.5 py-0.5 rounded text-[10px] font-semibold tabular-nums bg-slate-200/70 dark:bg-white/[0.08] text-slate-600 dark:text-slate-300">
                      ×{e._count}
                    </span>
                  )}
                </span>
              </td>
              <td className="py-2.5 px-4 text-xs text-right tabular-nums whitespace-nowrap">
                {e.bytes_transferred ? fmtBytes(e.bytes_transferred) : '0 B'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {visible < collapsed.length && (
        <div className="py-3 text-center">
          <button onClick={() => setVisible(v => v + PAGE_SIZE)} className="px-4 py-1.5 text-xs font-medium rounded-lg border border-slate-200 dark:border-white/[0.06] text-slate-500 hover:text-slate-700 hover:bg-slate-50 dark:hover:bg-white/[0.03] transition-colors">
            Load more ({collapsed.length - visible} remaining)
          </button>
        </div>
      )}
    </div>
  );
}
