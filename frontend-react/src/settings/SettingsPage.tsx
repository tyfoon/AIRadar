// Settings page — React thin-shell.
//
// Same pattern as IpsPage / RulesPage / SummaryPage: React renders the entire
// static chrome (tabs, killswitch card, health cards, perf charts containers,
// notification form, reputation keys, about panel) with matching IDs so the
// existing vanilla code (loadKillswitchState / switchSettingsTab /
// loadSystemPerformance / refreshPerformance / loadNotificationSettings /
// loadReputationSettings / renderLegalComponents / loadDataSources / ...)
// can keep populating and mutating those nodes unchanged.
//
// Why thin-shell: Settings is >500 lines of static HTML with ~15 distinct
// onclick handlers, five tabs, Chart.js canvases, polling timers, and a
// killswitch state machine that talks to /api/killswitch. Re-implementing
// all that in React would be a multi-day rewrite with zero visible user
// benefit. We render the IDs and delegate actions to window.* helpers.
//
// On mount we:
//   1. Call loadKillswitchState() so the killswitch card reflects server state
//   2. Call _initThemeSelect() so the theme <select> shows the right value
//   3. Call loadSystemPerformance() so the perf tab has a snapshot ready
//   4. Call renderLegalComponents() to populate the about tab (normally runs
//      on DOMContentLoaded, but the target DOM didn't exist yet then)
//   5. Derive tab from :tab URL param and call switchSettingsTab() so the
//      right panel shows immediately after mount — supports deep links like
//      /#/settings/reputation
//
// Unlike IpsPage/RulesPage we don't poll — settings state changes on user
// action, and the killswitch badge is already refreshed by AppShell's 5s
// badge poll via window._killswitchActive.

import { useEffect } from 'react';
import { useParams } from 'react-router-dom';

declare global {
  interface Window {
    switchSettingsTab?: (tab: string) => void;
    toggleKillswitch?: () => void;
    loadKillswitchState?: () => Promise<void>;
    _initThemeSelect?: () => void;
    setThemeFromSelect?: (v: string) => void;
    setLocale?: (v: string) => void;
    runHealthCheck?: () => Promise<void>;
    adminCleanupRun?: () => Promise<void>;
    loadDataSources?: () => Promise<void>;
    loadSystemPerformance?: () => Promise<void>;
    refreshPerformance?: () => void;
    loadNotificationSettings?: () => Promise<void>;
    saveNotificationSettings?: () => Promise<void>;
    testHaNotification?: () => Promise<void>;
    loadReputationSettings?: () => Promise<void>;
    saveReputationSettings?: () => Promise<void>;
    testReputationKeys?: () => Promise<void>;
    renderLegalComponents?: () => void;
  }
}

const TABS: { id: string; labelKey: string; label: string; icon: string }[] = [
  { id: 'protection',    labelKey: 'settings.tabProtection',    label: 'Protection',    icon: 'ph-shield-check' },
  { id: 'system',        labelKey: 'settings.tabSystem',        label: 'System',        icon: 'ph-gear' },
  { id: 'notifications', labelKey: 'settings.tabNotifications', label: 'Notifications', icon: 'ph-bell' },
  { id: 'performance',   labelKey: 'settings.tabPerformance',   label: 'Performance',   icon: 'ph-gauge' },
  { id: 'reputation',    labelKey: '',                          label: 'Reputation',    icon: 'ph-shield-check' },
  { id: 'about',         labelKey: 'settings.tabAbout',         label: 'About',         icon: 'ph-info' },
];

const ACTIVE_TAB_CLS = 'bg-blue-700 text-white shadow-sm';
const INACTIVE_TAB_CLS = 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300';

export default function SettingsPage() {
  const { tab } = useParams<{ tab?: string }>();

  // One-time vanilla bootstrap. We intentionally do NOT depend on `tab`;
  // switchSettingsTab() is cheap to call from the second useEffect below.
  useEffect(() => {
    window.loadKillswitchState?.();
    window._initThemeSelect?.();
    window.loadSystemPerformance?.();
    // renderLegalComponents normally runs on DOMContentLoaded, but #legal-components
    // only exists after this component mounts, so call it here too.
    window.renderLegalComponents?.();
  }, []);

  // Tab sync — runs on mount AND whenever the URL tab segment changes
  // (e.g. user clicks a sidebar link to /settings/reputation).
  useEffect(() => {
    const wanted = tab || 'protection';
    window.switchSettingsTab?.(wanted);
  }, [tab]);

  return (
    <section id="page-settings" className="page active space-y-6">

      {/* Tab navigation */}
      <div className="flex items-center gap-1 bg-slate-100 dark:bg-white/[0.04] rounded-lg p-1 w-fit">
        {TABS.map((t, i) => (
          <button
            key={t.id}
            id={`settings-tab-btn-${t.id}`}
            onClick={() => window.switchSettingsTab?.(t.id)}
            className={`px-4 py-1.5 rounded-md text-xs font-medium transition-colors ${i === 0 ? ACTIVE_TAB_CLS : INACTIVE_TAB_CLS}`}
          >
            <span className="inline-flex items-center gap-1.5">
              <i className={`ph-duotone ${t.icon} text-sm`}></i>
              {t.labelKey
                ? <span data-i18n={t.labelKey}>{t.label}</span>
                : <span>{t.label}</span>}
            </span>
          </button>
        ))}
      </div>

      {/* ── PROTECTION TAB ── */}
      <div id="settings-tab-protection" className="space-y-6">
        <p className="text-sm text-slate-500 dark:text-slate-400" data-i18n="settings.ksExplainer">
          The Emergency Killswitch immediately disables all network filtering and protection. Use this if the network stops working correctly.
        </p>

        <div id="killswitch-card" className="bg-white dark:bg-white/[0.03] border-2 border-slate-200 dark:border-white/[0.05] rounded-xl p-5 transition-all duration-300">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div id="ks-icon" className="w-10 h-10 rounded-xl bg-emerald-100 dark:bg-emerald-900/30 flex items-center justify-center transition-colors">
                <i className="ph-duotone ph-shield-check text-xl"></i>
              </div>
              <div>
                <h3 className="text-lg font-semibold text-slate-700 dark:text-slate-300" data-i18n="settings.killswitch">Emergency Killswitch</h3>
                <p id="ks-subtitle" className="text-[11px] text-slate-400 dark:text-slate-500" data-i18n="settings.ksOperational">All systems operational</p>
              </div>
            </div>
            <button id="ks-toggle-btn" onClick={() => window.toggleKillswitch?.()}
              className="relative px-5 py-2.5 rounded-xl font-semibold text-sm transition-all duration-300 active:scale-95 bg-red-600 hover:bg-red-500 text-white shadow-lg shadow-red-600/20">
              <span data-i18n="settings.ksActivate">Activate Killswitch</span>
            </button>
          </div>

          <div id="ks-status-bar" className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-4">
            <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-50 dark:bg-white/[0.02]">
              <span id="ks-dot-adguard" className="w-2 h-2 rounded-full bg-emerald-500"></span>
              <span className="text-xs text-slate-500 dark:text-slate-400" data-i18n="settings.ksAdguard">Ad &amp; Tracker Blocking</span>
              <span id="ks-label-adguard" className="ml-auto text-[10px] font-medium text-emerald-600 dark:text-emerald-400" data-i18n="settings.ksFiltering">Active</span>
            </div>
            <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-50 dark:bg-white/[0.02]">
              <span id="ks-dot-ips" className="w-2 h-2 rounded-full bg-emerald-500"></span>
              <span className="text-xs text-slate-500 dark:text-slate-400" data-i18n="settings.ksIps">Intrusion Prevention</span>
              <span id="ks-label-ips" className="ml-auto text-[10px] font-medium text-emerald-600 dark:text-emerald-400" data-i18n="settings.ksActive">Active</span>
            </div>
            <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-50 dark:bg-white/[0.02]">
              <span id="ks-dot-rules" className="w-2 h-2 rounded-full bg-emerald-500"></span>
              <span className="text-xs text-slate-500 dark:text-slate-400" data-i18n="settings.ksBlockRules">Custom Block Rules</span>
              <span id="ks-label-rules" className="ml-auto text-[10px] font-medium text-emerald-600 dark:text-emerald-400" data-i18n="settings.ksEnforced">Enforced</span>
            </div>
          </div>

          <div id="ks-log" className="hidden mt-4 p-3 rounded-lg bg-slate-900 dark:bg-black/40 text-xs font-mono text-slate-300 space-y-1 max-h-40 overflow-y-auto"></div>

          <div id="ks-failsafe-info" className="hidden mt-3 px-3 py-2 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-700/30">
            <p className="text-xs text-amber-700 dark:text-amber-400">
              <span className="font-semibold"><i className="ph-duotone ph-lightning"></i> Auto-failsafe:</span>
              <span id="ks-failsafe-text" data-i18n="settings.ksAutoText">Activated automatically because the ad blocker became unreachable. Network protection has been paused to keep your internet working.</span>
            </p>
          </div>
        </div>
      </div>

      {/* ── SYSTEM TAB ── */}
      <div id="settings-tab-system" className="space-y-6 hidden">

        {/* Language & Theme */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-slate-700 dark:text-slate-300" data-i18n="settings.language">Language</h3>
                <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-1" data-i18n="settings.langDesc">Choose your preferred language</p>
              </div>
              <select id="locale-select" onChange={e => window.setLocale?.(e.target.value)} className="text-sm rounded-lg border border-slate-200 dark:border-white/[0.1] bg-white dark:bg-white/[0.06] text-slate-700 dark:text-slate-200 px-3 py-1.5" defaultValue="en">
                <option value="en">English</option>
                <option value="nl">Nederlands</option>
              </select>
            </div>
          </div>
          <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-slate-700 dark:text-slate-300" data-i18n="settings.theme">Theme</h3>
                <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-1" data-i18n="settings.themeDesc">Choose your preferred appearance</p>
              </div>
              <select id="theme-select" onChange={e => window.setThemeFromSelect?.(e.target.value)} className="text-sm rounded-lg border border-slate-200 dark:border-white/[0.1] bg-white dark:bg-white/[0.06] text-slate-700 dark:text-slate-200 px-3 py-1.5" defaultValue="dark">
                <option value="dark" data-i18n="settings.themeDark">Dark</option>
                <option value="light" data-i18n="settings.themeLight">Light</option>
              </select>
            </div>
          </div>
        </div>

        {/* Health Check */}
        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-slate-700 dark:text-slate-300" data-i18n="settings.health">System Health</h3>
            <button id="health-run-btn" onClick={() => window.runHealthCheck?.()} className="px-3 py-1.5 rounded-lg bg-blue-700 hover:bg-blue-600 text-white text-xs font-medium transition-colors active:scale-95" data-i18n="settings.runCheck">Run Check</button>
          </div>
          <div id="health-cards" className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <p className="col-span-full text-center text-sm text-slate-400 dark:text-slate-500 py-8" data-i18n="settings.pressRunCheck">
              Press <span className="text-indigo-500 font-medium">Run Check</span> to test all services.
            </p>
          </div>
        </div>

        {/* Health details table */}
        <div id="health-details" className="hidden bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
          <h3 className="text-lg font-semibold text-slate-700 dark:text-slate-300 mb-4" data-i18n="settings.detailedResults">Detailed Results</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400 font-medium border-b border-slate-200 dark:border-white/[0.05]">
                <tr>
                  <th className="py-3 px-4 font-medium" data-i18n="settings.thService">Service</th>
                  <th className="py-3 px-4 font-medium" data-i18n="settings.thStatus">Status</th>
                  <th className="py-3 px-4 font-medium" data-i18n="settings.thResponse">Response</th>
                  <th className="py-3 px-4 font-medium" data-i18n="settings.thDetails">Details</th>
                </tr>
              </thead>
              <tbody id="health-tbody" className="text-slate-600 dark:text-slate-300 striped-rows"></tbody>
            </table>
          </div>
        </div>

        {/* Appliance Config */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-slate-700 dark:text-slate-300" data-i18n="settings.network">Network Configuration</h3>
              <span className="inline-flex items-center gap-1 text-[10px] text-slate-400 dark:text-slate-500">
                <i className="ph-duotone ph-lock text-xs"></i>
                <span data-i18n="settings.readOnly">Read-only</span>
              </span>
            </div>
            <div className="space-y-3 text-sm">
              <div className="flex justify-between items-center py-2 border-b border-slate-100 dark:border-slate-700/30">
                <span className="text-slate-500 dark:text-slate-400" data-i18n="settings.dnsServer">DNS Server</span>
                <span className="font-mono text-slate-700 dark:text-slate-200">127.0.0.1</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-slate-100 dark:border-slate-700/30">
                <span className="text-slate-500 dark:text-slate-400" data-i18n="settings.adguardHome">AdGuard Home</span>
                <a href="http://localhost:80" target="_blank" rel="noopener noreferrer" className="text-indigo-500 hover:underline font-mono">localhost:80</a>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-slate-100 dark:border-slate-700/30">
                <span className="text-slate-500 dark:text-slate-400" data-i18n="settings.apiBackend">API Backend</span>
                <span className="font-mono text-slate-700 dark:text-slate-200">localhost:8000</span>
              </div>
              <div className="flex justify-between items-center py-2">
                <span className="text-slate-500 dark:text-slate-400" data-i18n="settings.sensor">Sensor</span>
                <span className="font-mono text-slate-700 dark:text-slate-200">Zeek + zeek_tailer.py</span>
              </div>
            </div>
          </div>

          <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-slate-700 dark:text-slate-300" data-i18n="settings.dataRetention">Data Retention</h3>
            </div>
            <div className="space-y-3 text-sm">
              <div className="flex justify-between items-center py-2 border-b border-slate-100 dark:border-slate-700/30">
                <span className="text-slate-500 dark:text-slate-400" data-i18n="settings.retentionPeriod">Retention Period</span>
                <span className="text-slate-700 dark:text-slate-200" data-i18n="settings.retentionValue">7 days</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-slate-100 dark:border-slate-700/30">
                <span className="text-slate-500 dark:text-slate-400" data-i18n="settings.maxEvents">Max Events</span>
                <span className="text-slate-700 dark:text-slate-200" data-i18n="settings.maxEventsValue">50,000</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-slate-100 dark:border-slate-700/30">
                <span className="text-slate-500 dark:text-slate-400" data-i18n="settings.cleanupInterval">Cleanup Interval</span>
                <span className="text-slate-700 dark:text-slate-200" data-i18n="settings.cleanupValue">Every 60 min</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-slate-100 dark:border-slate-700/30">
                <span className="text-slate-500 dark:text-slate-400" data-i18n="settings.dbCompaction">DB Compaction</span>
                <span className="text-slate-700 dark:text-slate-200" data-i18n="settings.dbCompactionValue">Auto VACUUM on cleanup</span>
              </div>
            </div>
            <div className="mt-4 pt-4 border-t border-slate-200 dark:border-white/[0.06]">
              <div className="flex items-start justify-between gap-3 mb-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium text-slate-700 dark:text-slate-200" data-i18n="settings.manualCleanup">Clean up stale data</p>
                  <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5" data-i18n="settings.manualCleanupHint">Wipes all VPN events (old and new), dead-protocol stealth tunnels, and orphaned TLS fingerprints. Then VACUUMs the database. Device names, services, and policies are untouched.</p>
                </div>
                <button id="btn-admin-cleanup" onClick={() => window.adminCleanupRun?.()} className="flex-shrink-0 px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-medium transition-colors whitespace-nowrap">
                  <span data-i18n="settings.runCleanup">Run cleanup</span>
                </button>
              </div>
              <div id="admin-cleanup-result" className="hidden text-[11px]"></div>
            </div>
          </div>
        </div>

        {/* Data Sources */}
        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-slate-700 dark:text-slate-300" data-i18n="settings.dataSources">Data Sources</h3>
            <button onClick={() => window.loadDataSources?.()} className="px-3 py-1.5 rounded-lg bg-blue-700 hover:bg-blue-600 text-white text-xs font-medium transition-colors active:scale-95" data-i18n="settings.refresh">Refresh</button>
          </div>
          <p className="text-xs text-slate-400 dark:text-slate-500 mb-4" data-i18n="settings.dataSourcesDesc">External lists and databases used for service classification, geo-location, and threat detection.</p>
          <div id="data-sources-list" className="space-y-2">
            <p className="text-xs text-slate-400 dark:text-slate-500 text-center py-4" data-i18n="settings.pressRefresh">Press Refresh to load data source info.</p>
          </div>
        </div>
      </div>

      {/* ── PERFORMANCE TAB ── */}
      <div id="settings-tab-performance" className="space-y-6 hidden">

        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-slate-700 dark:text-slate-300" data-i18n="settings.performance">System Performance</h3>
            <div className="flex items-center gap-2">
              <label className="flex items-center gap-1.5 text-[11px] text-slate-500 dark:text-slate-400 cursor-pointer select-none">
                <input type="checkbox" id="perf-autorefresh" className="rounded border-slate-300 dark:border-slate-600" />
                <span data-i18n="settings.autoRefresh">Auto-refresh</span>
              </label>
              <button id="perf-refresh-btn" onClick={() => window.loadSystemPerformance?.()} className="px-3 py-1.5 rounded-lg bg-blue-700 hover:bg-blue-600 text-white text-xs font-medium transition-colors active:scale-95" data-i18n="settings.refresh">Refresh</button>
            </div>
          </div>

          <div id="perf-host-grid" className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-5">
            <p className="col-span-full text-center text-sm text-slate-400 dark:text-slate-500 py-6" data-i18n="settings.perfLoading">Loading performance data...</p>
          </div>

          <div id="perf-container-section" className="hidden">
            <h4 className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400 font-medium mb-2" data-i18n="settings.containers">Containers</h4>
            <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-white/[0.05]">
              <table className="w-full text-sm text-left">
                <thead className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400 font-medium border-b border-slate-200 dark:border-white/[0.05] bg-slate-50 dark:bg-white/[0.02]">
                  <tr>
                    <th className="py-2.5 px-4 font-medium" data-i18n="settings.thContainer">Container</th>
                    <th className="py-2.5 px-4 font-medium" data-i18n="settings.thState">State</th>
                    <th className="py-2.5 px-4 font-medium" data-i18n="settings.thCpu">CPU</th>
                    <th className="py-2.5 px-4 font-medium" data-i18n="settings.thMemory">Memory</th>
                  </tr>
                </thead>
                <tbody id="perf-container-tbody" className="text-slate-600 dark:text-slate-300 striped-rows"></tbody>
              </table>
            </div>
            <p id="perf-docker-error" className="hidden mt-2 text-[11px] text-amber-500 dark:text-amber-400"></p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-500 dark:text-slate-400 font-medium" data-i18n="perf.timeRange">Time range</span>
          <select id="perf-hours" onChange={() => window.refreshPerformance?.()} className="text-xs rounded-lg border border-slate-200 dark:border-white/[0.08] bg-white dark:bg-white/[0.03] text-slate-600 dark:text-slate-300 px-3 py-1.5" defaultValue="24">
            <option value="1" data-i18n="perf.1h">Last hour</option>
            <option value="6" data-i18n="perf.6h">Last 6 hours</option>
            <option value="24" data-i18n="perf.24h">Last 24 hours</option>
            <option value="72" data-i18n="perf.72h">Last 3 days</option>
            <option value="168" data-i18n="perf.168h">Last 7 days</option>
          </select>
          <label className="ml-auto flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400 cursor-pointer">
            <input type="checkbox" id="perf-auto" defaultChecked className="rounded border-slate-300 dark:border-slate-600" />
            <span data-i18n="perf.autoRefresh">Auto-refresh</span>
          </label>
        </div>

        <div id="perf-snapshot" className="grid grid-cols-2 lg:grid-cols-4 gap-4"></div>

        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3" data-i18n="perf.latencyTitle">DNS &amp; Ping Latency</h3>
          <div style={{ position: 'relative', height: 250 }}><canvas id="perf-chart-latency"></canvas></div>
        </div>

        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3" data-i18n="perf.throughputTitle">Bridge Throughput</h3>
          <div style={{ position: 'relative', height: 250 }}><canvas id="perf-chart-throughput"></canvas></div>
        </div>

        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3" data-i18n="perf.systemTitle">CPU &amp; Memory</h3>
          <div style={{ position: 'relative', height: 250 }}><canvas id="perf-chart-system"></canvas></div>
        </div>

        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3" data-i18n="perf.errorsTitle">Errors &amp; Drops</h3>
          <div style={{ position: 'relative', height: 250 }}><canvas id="perf-chart-errors"></canvas></div>
        </div>
      </div>

      {/* ── NOTIFICATIONS TAB ── */}
      <div id="settings-tab-notifications" className="space-y-6 hidden">
        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-lg bg-blue-100 dark:bg-blue-900/30 flex items-center justify-center">
              <i className="ph-duotone ph-house text-xl text-blue-600 dark:text-blue-400"></i>
            </div>
            <div>
              <h3 className="text-lg font-semibold text-slate-700 dark:text-slate-300">Home Assistant</h3>
              <p className="text-xs text-slate-400 dark:text-slate-500" data-i18n="notify.haDesc">Push alerts to your Home Assistant instance</p>
            </div>
            <label className="toggle ml-auto">
              <input type="checkbox" id="notify-ha-enabled" onChange={() => window.saveNotificationSettings?.()} />
              <span className="slider"></span>
            </label>
          </div>

          <div className="space-y-3 mb-5">
            <div>
              <label className="text-xs text-slate-500 dark:text-slate-400 font-medium block mb-1">Home Assistant URL</label>
              <input type="url" id="notify-ha-url" placeholder="http://homeassistant.local:8123" className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 text-sm text-slate-700 dark:text-slate-200" />
            </div>
            <div>
              <label className="text-xs text-slate-500 dark:text-slate-400 font-medium block mb-1">
                Long-Lived Access Token
                <span className="ml-1 text-slate-400 cursor-help" title="Create a Long-Lived Access Token in Home Assistant under your profile settings (bottom of the page)."><i className="ph-duotone ph-info text-xs"></i></span>
              </label>
              <input type="password" id="notify-ha-token" placeholder="eyJhbGciOiJIUzI1NiIs..." className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 text-sm text-slate-700 dark:text-slate-200 font-mono" />
            </div>
            <div>
              <label className="text-xs text-slate-500 dark:text-slate-400 font-medium block mb-1">
                Notify Service (target device)
                <span className="ml-1 text-slate-400 cursor-help" title="The HA notify service to call, e.g. 'mobile_app_iphone_van_goswijn'. Find yours in HA → Developer Tools → Services → search 'notify'. Leave empty to notify ALL devices."><i className="ph-duotone ph-info text-xs"></i></span>
              </label>
              <input type="text" id="notify-ha-service" placeholder="mobile_app_iphone_van_goswijn" className="w-full px-3 py-2 rounded-lg border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 text-sm text-slate-700 dark:text-slate-200 font-mono" />
              <p className="text-[10px] text-slate-400 dark:text-slate-500 mt-1" data-i18n="notify.serviceHint">Find your device service in HA → Developer Tools → Services → search "notify"</p>
            </div>
          </div>

          <div className="mb-5">
            <p className="text-xs text-slate-500 dark:text-slate-400 font-medium mb-2" data-i18n="notify.categories">Alert categories to notify</p>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2" id="notify-categories">
              <label className="flex items-center gap-2 p-2 rounded-lg bg-slate-50 dark:bg-white/[0.02] hover:bg-slate-100 dark:hover:bg-white/[0.04] cursor-pointer">
                <input type="checkbox" value="security" defaultChecked className="rounded border-slate-300 dark:border-slate-600" />
                <span className="text-xs text-slate-600 dark:text-slate-300"><i className="ph-duotone ph-siren text-sm text-red-500"></i> Security</span>
              </label>
              <label className="flex items-center gap-2 p-2 rounded-lg bg-slate-50 dark:bg-white/[0.02] hover:bg-slate-100 dark:hover:bg-white/[0.04] cursor-pointer">
                <input type="checkbox" value="new_device" defaultChecked className="rounded border-slate-300 dark:border-slate-600" />
                <span className="text-xs text-slate-600 dark:text-slate-300"><i className="ph-duotone ph-wifi-high text-sm text-blue-500"></i> New devices</span>
              </label>
              <label className="flex items-center gap-2 p-2 rounded-lg bg-slate-50 dark:bg-white/[0.02] hover:bg-slate-100 dark:hover:bg-white/[0.04] cursor-pointer">
                <input type="checkbox" value="ai" className="rounded border-slate-300 dark:border-slate-600" />
                <span className="text-xs text-slate-600 dark:text-slate-300"><i className="ph-duotone ph-brain text-sm text-indigo-500"></i> AI uploads</span>
              </label>
              <label className="flex items-center gap-2 p-2 rounded-lg bg-slate-50 dark:bg-white/[0.02] hover:bg-slate-100 dark:hover:bg-white/[0.04] cursor-pointer">
                <input type="checkbox" value="cloud" className="rounded border-slate-300 dark:border-slate-600" />
                <span className="text-xs text-slate-600 dark:text-slate-300"><i className="ph-duotone ph-cloud text-sm text-sky-500"></i> Cloud storage</span>
              </label>
              <label className="flex items-center gap-2 p-2 rounded-lg bg-slate-50 dark:bg-white/[0.02] hover:bg-slate-100 dark:hover:bg-white/[0.04] cursor-pointer">
                <input type="checkbox" value="gaming" className="rounded border-slate-300 dark:border-slate-600" />
                <span className="text-xs text-slate-600 dark:text-slate-300"><i className="ph-duotone ph-game-controller text-sm text-indigo-500"></i> Gaming</span>
              </label>
              <label className="flex items-center gap-2 p-2 rounded-lg bg-slate-50 dark:bg-white/[0.02] hover:bg-slate-100 dark:hover:bg-white/[0.04] cursor-pointer">
                <input type="checkbox" value="social" className="rounded border-slate-300 dark:border-slate-600" />
                <span className="text-xs text-slate-600 dark:text-slate-300"><i className="ph-duotone ph-chat-circle-text text-sm text-pink-500"></i> Social media</span>
              </label>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button onClick={() => window.saveNotificationSettings?.()} className="px-4 py-2 rounded-lg bg-blue-700 hover:bg-blue-600 text-white text-xs font-semibold shadow-sm transition-colors active:scale-95">
              <span className="inline-flex items-center gap-1.5"><i className="ph-duotone ph-floppy-disk text-sm"></i> <span data-i18n="notify.save">Save</span></span>
            </button>
            <button onClick={() => window.testHaNotification?.()} className="px-4 py-2 rounded-lg bg-slate-200 dark:bg-white/[0.06] hover:bg-slate-300 dark:hover:bg-white/[0.1] text-xs font-medium text-slate-600 dark:text-slate-300 transition-colors">
              <span className="inline-flex items-center gap-1.5"><i className="ph-duotone ph-paper-plane-tilt text-sm"></i> <span data-i18n="notify.test">Test HA Notification</span></span>
            </button>
            <span id="notify-status" className="text-[11px] text-slate-400 dark:text-slate-500"></span>
          </div>
        </div>
      </div>

      {/* ── REPUTATION TAB ── */}
      <div id="settings-tab-reputation" className="space-y-6 hidden">
        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl overflow-hidden card-hover">
          <div className="p-5 border-b border-slate-100 dark:border-white/[0.05]">
            <div className="flex items-center gap-3">
              <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-indigo-100 dark:bg-indigo-900/30">
                <i className="ph-duotone ph-shield-check text-xl text-indigo-600 dark:text-indigo-400"></i>
              </div>
              <div>
                <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">IP &amp; Domain Reputation</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">Threat intelligence from URLhaus, ThreatFox, AbuseIPDB &amp; VirusTotal</p>
              </div>
            </div>
          </div>
          <div className="p-5 space-y-4">
            <div className="space-y-3">
              <h4 className="text-xs font-bold text-slate-600 dark:text-slate-300">Layer 1 — Proactive (abuse.ch)</h4>
              <p className="text-xs text-slate-400">URLhaus (malware) + ThreatFox (C2 servers) — checked automatically for every new IP.</p>
              <div>
                <label className="block text-xs text-slate-500 dark:text-slate-400 mb-1">abuse.ch Auth-Key</label>
                <input type="password" id="rep-abusech-key" placeholder="Enter Auth-Key..." className="w-full text-xs px-3 py-2 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 font-mono" />
                <p className="text-[10px] text-slate-400 mt-1">Free registration · <a href="https://auth.abuse.ch/" target="_blank" rel="noopener noreferrer" className="text-indigo-400 hover:underline">Get free key at auth.abuse.ch</a></p>
              </div>
            </div>
            <hr className="border-slate-200 dark:border-slate-700" />
            <div className="space-y-3">
              <h4 className="text-xs font-bold text-slate-600 dark:text-slate-300">Layer 2 — On-Demand (click to check)</h4>
              <div>
                <label className="block text-xs text-slate-500 dark:text-slate-400 mb-1">AbuseIPDB API Key</label>
                <input type="password" id="rep-abuseipdb-key" placeholder="Enter API key..." className="w-full text-xs px-3 py-2 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 font-mono" />
                <p className="text-[10px] text-slate-400 mt-1">Free: 1,000 checks/day · <a href="https://www.abuseipdb.com/account/api" target="_blank" rel="noopener noreferrer" className="text-indigo-400 hover:underline">Get free key</a></p>
              </div>
              <div>
                <label className="block text-xs text-slate-500 dark:text-slate-400 mb-1">VirusTotal API Key</label>
                <input type="password" id="rep-virustotal-key" placeholder="Enter API key..." className="w-full text-xs px-3 py-2 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 font-mono" />
                <p className="text-[10px] text-slate-400 mt-1">Free: 500 checks/day · <a href="https://www.virustotal.com/gui/my-apikey" target="_blank" rel="noopener noreferrer" className="text-indigo-400 hover:underline">Get free key</a></p>
              </div>
            </div>
            <div className="flex gap-2 pt-2">
              <button onClick={() => window.saveReputationSettings?.()} className="px-4 py-2 text-xs font-medium rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white transition">Save Keys</button>
              <button onClick={() => window.testReputationKeys?.()} className="px-4 py-2 text-xs font-medium rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-200 transition">Test Connection</button>
            </div>
            <div id="rep-test-result" className="hidden text-xs p-3 rounded-lg"></div>
          </div>
        </div>
      </div>

      {/* ── ABOUT TAB ── */}
      <div id="settings-tab-about" className="space-y-6 hidden">
        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl overflow-hidden card-hover">
          <div className="p-5 border-b border-slate-200 dark:border-white/[0.05]">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-indigo-100 dark:bg-indigo-900/30 flex items-center justify-center">
                  <span className="text-indigo-600 dark:text-indigo-400 font-bold text-sm">AR</span>
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">AI-Radar</h3>
                  <p className="text-[11px] text-slate-400 dark:text-slate-500">Version 1.0.0</p>
                </div>
              </div>
              <button
                onClick={() => document.getElementById('legal-panel')?.classList.toggle('hidden')}
                className="px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300 text-xs font-medium transition-colors"
                data-i18n="settings.about"
              >
                About &amp; Legal
              </button>
            </div>
            <p className="text-[12px] text-slate-400 dark:text-slate-500 mt-3" data-i18n="settings.appDesc">Network intelligence appliance for monitoring AI &amp; Cloud service usage, privacy protection, and intrusion prevention.</p>
          </div>

          <div id="legal-panel" className="hidden">
            <div className="p-5 border-b border-slate-100 dark:border-white/[0.04]">
              <p className="text-[11px] text-slate-400 dark:text-slate-500 mb-4" data-i18n="settings.legalIntro">AI-Radar integrates the following independent open-source components via their official APIs. No source code of these projects has been modified or redistributed.</p>
              <div id="legal-components" className="space-y-2"></div>
            </div>
            <div className="px-5 py-3">
              <p className="text-[10px] text-slate-400 dark:text-slate-500" data-i18n="settings.legalFooter">All trademarks and registered trademarks are the property of their respective owners. This software is provided "as is" without warranty of any kind.</p>
            </div>
          </div>
        </div>
      </div>

    </section>
  );
}
