// Rules / Access Control page — React thin-shell.
//
// Same pattern as SummaryPage and IpsPage: React renders the static layout
// (tabs, scope selector, static category headers, toggle cards, blocks list
// container) and vanilla keeps ownership of the dynamic content + all state.
//
// Why thin-shell: the vanilla Rules code spans ~1200 lines across
// loadAccessControl, loadGlobalFilterStatus, loadAdguardProtectionState,
// loadActiveBlockRules, renderServiceCard, the schedule modal, and the
// scope state machine (_rulesScopeMode / _rulesScopeMac / _rulesScopeGroupId).
// All of those talk to this page's DOM by ID; re-implementing them in React
// would be a multi-day rewrite with zero visible benefit. Instead, React
// renders the IDs and wires onclick to window.* helpers so the existing
// vanilla code keeps running unchanged.
//
// Refresh: refreshRules() is called on mount and every 30s. Navigating away
// unmounts this component and clears the interval.

import { useEffect, useRef } from 'react';

declare global {
  interface Window {
    refreshRules?: () => Promise<void>;
    switchRulesTab?: (tab: 'outbound' | 'inbound' | 'active') => void;
    switchRulesScope?: (mode: 'global' | 'device' | 'group') => void;
    onRulesDeviceSelected?: (mac: string) => void;
    onRulesGroupSelected?: (groupId: string) => void;
    toggleAdguardProtection?: (el: HTMLInputElement) => void;
    toggleGlobalFilter?: (type: string, el: HTMLInputElement) => void;
    toggleIps?: (el: HTMLInputElement) => void;
    openScheduleModal?: (filterKey: string) => void;
  }
}

const CATEGORY_SECTIONS: { id: string; title: string; desc: string }[] = [
  { id: 'ai',        title: 'AI Services',       desc: 'Control which AI platforms can be accessed from your network.' },
  { id: 'cloud',     title: 'Cloud Services',    desc: 'Control which cloud storage services can be accessed from your network.' },
  { id: 'social',    title: 'Social Media',      desc: 'Control access to social media platforms.' },
  { id: 'gaming',    title: 'Gaming',            desc: 'Control access to gaming platforms and services.' },
  { id: 'streaming', title: 'Streaming',         desc: 'Control access to streaming services.' },
  { id: 'shopping',  title: 'Shopping',          desc: 'Control access to online shops and marketplaces.' },
  { id: 'news',      title: 'News',              desc: 'Control access to news sites.' },
  { id: 'dating',    title: 'Dating',            desc: 'Control access to dating apps and sites.' },
  { id: 'adult',     title: 'Adult',             desc: 'Control access to adult content. Keep in mind a household DNS block is easily bypassed on mobile data.' },
];

export default function RulesPage() {
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    // Kick off the initial data load — refreshRules() calls every loader
    // in parallel (global filters, IPS status, access control, adguard
    // state, active block rules).
    window.refreshRules?.();
    timerRef.current = window.setInterval(() => {
      window.refreshRules?.();
    }, 30_000);

    return () => {
      if (timerRef.current != null) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    };
  }, []);

  return (
    <section className="space-y-6">
      {/* Tab navigation */}
      <div className="flex items-center gap-1 bg-slate-100 dark:bg-white/[0.04] rounded-lg p-1 w-fit">
        <button
          id="rules-tab-btn-outbound"
          onClick={() => window.switchRulesTab?.('outbound')}
          className="px-4 py-1.5 rounded-md text-xs font-medium transition-colors bg-blue-700 text-white shadow-sm"
        >
          <span className="inline-flex items-center gap-1.5">
            <i className="ph-duotone ph-arrow-up-right text-sm" />
            <span data-i18n="rules.outbound">Outbound</span>
          </span>
        </button>
        <button
          id="rules-tab-btn-inbound"
          onClick={() => window.switchRulesTab?.('inbound')}
          className="px-4 py-1.5 rounded-md text-xs font-medium transition-colors text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300"
        >
          <span className="inline-flex items-center gap-1.5">
            <i className="ph-duotone ph-arrow-down-left text-sm" />
            <span data-i18n="rules.inbound">Inbound</span>
          </span>
        </button>
        <button
          id="rules-tab-btn-active"
          onClick={() => window.switchRulesTab?.('active')}
          className="px-4 py-1.5 rounded-md text-xs font-medium transition-colors text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300"
        >
          <span className="inline-flex items-center gap-1.5">
            <i className="ph-duotone ph-prohibit text-sm" />
            <span data-i18n="rules.activeBlocks">Active Blocks</span>
            <span id="rules-active-count" className="ml-0.5 px-1.5 py-0.5 text-[10px] rounded-full bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 hidden">0</span>
          </span>
        </button>
      </div>

      {/* ── OUTBOUND TAB ── */}
      <div id="rules-tab-outbound" className="space-y-6">

        {/* Scope selector */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-1 bg-slate-100 dark:bg-white/[0.04] rounded-lg p-1 w-fit">
            <button
              id="rules-scope-btn-global"
              onClick={() => window.switchRulesScope?.('global')}
              className="px-4 py-1.5 rounded-md text-xs font-medium transition-colors bg-blue-700 text-white shadow-sm"
            >
              <span className="inline-flex items-center gap-1.5">
                <i className="ph-duotone ph-globe text-sm" />
                <span data-i18n="rules.scopeGlobal">Global</span>
              </span>
            </button>
            <button
              id="rules-scope-btn-device"
              onClick={() => window.switchRulesScope?.('device')}
              className="px-4 py-1.5 rounded-md text-xs font-medium transition-colors text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300"
            >
              <span className="inline-flex items-center gap-1.5">
                <i className="ph-duotone ph-device-mobile text-sm" />
                <span data-i18n="rules.scopePerDevice">Per device</span>
              </span>
            </button>
            <button
              id="rules-scope-btn-group"
              onClick={() => window.switchRulesScope?.('group')}
              className="px-4 py-1.5 rounded-md text-xs font-medium transition-colors text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300"
            >
              <span className="inline-flex items-center gap-1.5">
                <i className="ph-duotone ph-users-three text-sm" />
                <span data-i18n="rules.scopePerGroup">Per group</span>
              </span>
            </button>
          </div>
          <select
            id="rules-scope-device-select"
            onChange={(e) => window.onRulesDeviceSelected?.(e.target.value)}
            className="hidden text-sm rounded-lg border border-slate-200 dark:border-white/[0.1] bg-white dark:bg-white/[0.06] text-slate-700 dark:text-slate-200 px-3 py-1.5 max-w-[260px]"
            defaultValue=""
          >
            <option value="" data-i18n="rules.selectDevice">Select a device...</option>
          </select>
          <select
            id="rules-scope-group-select"
            onChange={(e) => window.onRulesGroupSelected?.(e.target.value)}
            className="hidden text-sm rounded-lg border border-slate-200 dark:border-white/[0.1] bg-white dark:bg-white/[0.06] text-slate-700 dark:text-slate-200 px-3 py-1.5 max-w-[260px]"
            defaultValue=""
          >
            <option value="" data-i18n="rules.selectGroup">Select a group...</option>
          </select>
          <span id="rules-scope-label" className="hidden text-xs text-blue-600 dark:text-blue-400 font-medium" />
        </div>

        {/* Global Filters — hidden in device/group scope */}
        <div id="rules-global-filters-section">
          <div>
            <h3 className="text-lg font-semibold text-slate-700 dark:text-slate-300 mb-4" data-i18n="rules.globalFilters">Global Office Filters</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-2 xl:grid-cols-4 gap-4">

              {/* AdGuard DNS blocking */}
              <div id="adguard-protection-card" className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
                <div className="flex items-center justify-between mb-1">
                  <p className="text-sm font-medium text-slate-700 dark:text-slate-200" data-i18n="rules.adguardFiltering">DNS Blocking Engine</p>
                  <div className="flex items-center gap-2">
                    <span id="adguard-protection-state" className="text-xs font-medium text-slate-400" data-i18n="svc.off">Off</span>
                    <label className="toggle">
                      <input
                        type="checkbox"
                        id="toggle-adguard-protection"
                        onChange={(e) => window.toggleAdguardProtection?.(e.target)}
                      />
                      <span className="slider" />
                    </label>
                  </div>
                </div>
                <p className="text-sm text-slate-500 dark:text-slate-400 mb-3" data-i18n="rules.adguardFilteringDesc">
                  Enables DNS-level blocking for services you set to "Block" below. Only your explicit block rules apply — no ads, trackers or other content is affected. Turns on automatically when you block a service.
                </p>
                <div id="adguard-active-blocks" className="text-[10px] text-slate-400 dark:text-slate-500" />
              </div>

              <FilterCard
                id="parental" titleKey="rules.safeWork" titleEn="Safe Work Environment"
                descKey="rules.safeWorkDesc" descEn="Blocks NSFW content, gambling sites, and enables SafeSearch"
                chips={[
                  { label: 'NSFW', cls: 'bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400' },
                  { label: 'Gambling', cls: 'bg-amber-100 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400' },
                  { label: 'SafeSearch', cls: 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400' },
                ]}
              />

              <FilterCard
                id="social" titleKey="rules.blockSocial" titleEn="Block Social Media"
                descKey="rules.blockSocialDesc" descEn="Blocks Facebook, Instagram, TikTok, X, and Snapchat for all devices"
                chips={[
                  { label: 'Facebook',  cls: 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400' },
                  { label: 'Instagram', cls: 'bg-pink-100 dark:bg-pink-900/30 text-pink-600 dark:text-pink-400' },
                  { label: 'TikTok',    cls: 'bg-slate-100 dark:bg-slate-700/50 text-slate-600 dark:text-slate-300' },
                  { label: 'X',         cls: 'bg-sky-100 dark:bg-sky-900/30 text-sky-600 dark:text-sky-400' },
                  { label: 'Snapchat',  cls: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-600 dark:text-yellow-400' },
                ]}
              />

              <FilterCard
                id="gaming" titleKey="rules.blockGaming" titleEn="Block Gaming"
                descKey="rules.blockGamingDesc" descEn="Blocks Steam, Epic Games, Roblox, Twitch, and Discord for all devices"
                chips={[
                  { label: 'Steam',   cls: 'bg-slate-100 dark:bg-slate-700/50 text-slate-600 dark:text-slate-300' },
                  { label: 'Epic',    cls: 'bg-slate-100 dark:bg-slate-700/50 text-slate-600 dark:text-slate-300' },
                  { label: 'Roblox',  cls: 'bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400' },
                  { label: 'Twitch',  cls: 'bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400' },
                  { label: 'Discord', cls: 'bg-indigo-100 dark:bg-indigo-900/30 text-indigo-600 dark:text-indigo-400' },
                ]}
              />

            </div>
          </div>
        </div>{/* /rules-global-filters-section */}

        {/* Granular app control — vanilla fills #access-control-{id} */}
        {CATEGORY_SECTIONS.map(({ id, title, desc }) => (
          <div key={id}>
            <h3 className="text-lg font-semibold text-slate-700 dark:text-slate-300 mb-1" data-i18n={`rules.${id}Services`}>
              {title}
            </h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 mb-4" data-i18n={`rules.${id}ServicesDesc`}>
              {desc}
            </p>
            <div id={`access-control-${id}`} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
              {id === 'ai' || id === 'cloud' ? (
                <p className="text-slate-400 dark:text-slate-500 text-sm col-span-full text-center py-4">Loading...</p>
              ) : null}
            </div>
          </div>
        ))}

      </div>{/* /rules-tab-outbound */}

      {/* ── INBOUND TAB ── */}
      <div id="rules-tab-inbound" className="space-y-6 hidden">

        <div>
          <h3 className="text-lg font-semibold text-slate-700 dark:text-slate-300 mb-4" data-i18n="rules.ipsTitle">Intrusion Prevention (CrowdSec)</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

            <div id="filter-ips-card" className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
              <div className="flex items-center justify-between mb-2">
                <div>
                  <p className="text-sm font-medium text-slate-700 dark:text-slate-200" data-i18n="rules.crowdsecEngine">CrowdSec Engine</p>
                  <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5" data-i18n="rules.crowdsecDesc">Community-driven threat intelligence</p>
                </div>
                <label className="toggle">
                  <input type="checkbox" id="toggle-ips" onChange={(e) => window.toggleIps?.(e.target)} />
                  <span className="slider" />
                </label>
              </div>
              <p className="text-[10px] text-slate-400 dark:text-slate-500 mb-2" data-i18n="rules.crowdsecDetail">
                Automatically blocks known malicious IPs, botnets, and hackers using CrowdSec's real-time threat database.
              </p>
              <div className="flex items-center gap-2">
                <span id="ips-threats-badge" className="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400 font-medium">
                  <i className="ph-duotone ph-shield-check text-xs" />
                  <span id="ips-threats-count">0</span> threats blocked
                </span>
                <span id="ips-status-dot" className="w-2 h-2 rounded-full bg-slate-300 dark:bg-slate-600" title="CrowdSec offline" />
              </div>
            </div>

            <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
              <p className="text-sm font-medium text-slate-700 dark:text-slate-200 mb-2" data-i18n="rules.howItWorks">How it works</p>
              <ul className="space-y-2 text-[11px] text-slate-500 dark:text-slate-400">
                <li className="flex items-start gap-2"><span className="text-emerald-500 mt-0.5">1.</span> <span data-i18n="rules.howStep1">CrowdSec analyses Zeek network logs for suspicious patterns</span></li>
                <li className="flex items-start gap-2"><span className="text-emerald-500 mt-0.5">2.</span> <span data-i18n="rules.howStep2">Detected attackers are matched against a global reputation database</span></li>
                <li className="flex items-start gap-2"><span className="text-emerald-500 mt-0.5">3.</span> <span data-i18n="rules.howStep3">Confirmed threats are automatically blocked at the network level</span></li>
                <li className="flex items-start gap-2"><span className="text-emerald-500 mt-0.5">4.</span> <span data-i18n="rules.howStep4">Your network contributes back to the community intelligence</span></li>
              </ul>
            </div>

          </div>
        </div>

        <div>
          <h3 className="text-lg font-semibold text-slate-700 dark:text-slate-300 mb-4" data-i18n="rules.threatSources">Threat Intelligence Sources</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <ThreatSourceCard icon="ph-warning" iconCls="text-red-500" bgCls="bg-red-500/10 dark:bg-red-500/20"
              titleKey="rules.botnetDetection" title="Botnet Detection"
              descKey="rules.botnetDesc" desc="Blocks traffic from known botnets, command-and-control servers, and zombie networks." />
            <ThreatSourceCard icon="ph-key" iconCls="text-amber-500" bgCls="bg-amber-500/10 dark:bg-amber-500/20"
              titleKey="rules.bruteForce" title="Brute Force Protection"
              descKey="rules.bruteForceDesc" desc="Detects and blocks automated password-guessing attacks on SSH, web apps, and other services." />
            <ThreatSourceCard icon="ph-magnifying-glass" iconCls="text-purple-500" bgCls="bg-purple-500/10 dark:bg-purple-500/20"
              titleKey="rules.scannerExploit" title="Scanner & Exploit"
              descKey="rules.scannerDesc" desc="Identifies port scanners, vulnerability probes, and known exploit attempts targeting your network." />
          </div>
        </div>

      </div>{/* /rules-tab-inbound */}

      {/* ── ACTIVE BLOCKS TAB ── */}
      <div id="rules-tab-active" className="space-y-6 hidden">
        <div>
          <p className="text-sm text-slate-500 dark:text-slate-400 mb-4" data-i18n="rules.activeBlocksDesc">
            All currently active block rules across all services and devices. Rules with a timer show their expiration time.
          </p>
          <div id="active-blocks-list" className="space-y-3">
            <p className="text-slate-400 dark:text-slate-500 text-sm text-center py-8" data-i18n="rules.noActiveBlockRules">
              No active block rules.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Filter card — the parental / social / gaming toggle cards share the same
// shape, only the id/copy/chips vary. The IDs (filter-{id}-card,
// filter-{id}-state, toggle-{id}, filter-{id}-schedule(-text)) are what
// vanilla's loadGlobalFilterStatus / openScheduleModal target.
// ---------------------------------------------------------------------------
function FilterCard({
  id, titleKey, titleEn, descKey, descEn, chips,
}: {
  id: string; titleKey: string; titleEn: string;
  descKey: string; descEn: string;
  chips: { label: string; cls: string }[];
}) {
  return (
    <div id={`filter-${id}-card`} className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
      <div className="flex items-center justify-between mb-1">
        <p className="text-sm font-medium text-slate-700 dark:text-slate-200" data-i18n={titleKey}>{titleEn}</p>
        <div className="flex items-center gap-2">
          <span id={`filter-${id}-state`} className="text-xs font-medium text-slate-400" data-i18n="svc.off">Off</span>
          <label className="toggle">
            <input type="checkbox" id={`toggle-${id}`} onChange={(e) => window.toggleGlobalFilter?.(id, e.target)} />
            <span className="slider" />
          </label>
        </div>
      </div>
      <p className="text-sm text-slate-500 dark:text-slate-400 mb-3" data-i18n={descKey}>{descEn}</p>
      <div className="flex flex-wrap items-center gap-1">
        {chips.map(c => (
          <span key={c.label} className={`text-[10px] px-1.5 py-0.5 rounded ${c.cls}`}>{c.label}</span>
        ))}
        <button
          onClick={() => window.openScheduleModal?.(id)}
          className="ml-auto p-1 rounded-md hover:bg-slate-100 dark:hover:bg-white/[0.06] text-slate-400 hover:text-indigo-500 transition-colors"
          title="Schedule"
        >
          <i className="ph-duotone ph-clock text-sm" />
        </button>
      </div>
      <div id={`filter-${id}-schedule`} className="hidden mt-2 text-[10px] text-indigo-500 dark:text-indigo-400 flex items-center gap-1">
        <i className="ph-duotone ph-clock text-xs" />
        <span id={`filter-${id}-schedule-text`} />
      </div>
    </div>
  );
}

function ThreatSourceCard({ icon, iconCls, bgCls, titleKey, title, descKey, desc }: {
  icon: string; iconCls: string; bgCls: string;
  titleKey: string; title: string; descKey: string; desc: string;
}) {
  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
      <div className="flex items-center gap-2 mb-2">
        <div className={`w-8 h-8 rounded-lg ${bgCls} flex items-center justify-center`}>
          <i className={`ph-duotone ${icon} text-base ${iconCls}`} />
        </div>
        <p className="text-sm font-medium text-slate-700 dark:text-slate-200" data-i18n={titleKey}>{title}</p>
      </div>
      <p className="text-[10px] text-slate-400 dark:text-slate-500" data-i18n={descKey}>{desc}</p>
    </div>
  );
}
