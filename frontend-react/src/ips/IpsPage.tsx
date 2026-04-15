// IPS / Attacks page — React shell, vanilla alert rendering.
//
// Architecture mirrors SummaryPage: React owns the tabs, stat cards, filter
// bar, and blocklist table; vanilla keeps ownership of the alert-card HTML
// because _renderAlertCard (and the _card* action handlers it spawns) close
// over module-local state in app.js (_ipsInboundAlerts, _beaconAlerts,
// _reputationCache). Re-implementing those in React would duplicate hundreds
// of lines for no visible benefit.
//
// Data flow: React Query fetches both endpoints on a 30s cadence. On every
// successful response we call window._renderIpsThreats(data) (populates
// #ips-inbound-container + #ips-blocklist-body + syncs _ipsInboundAlerts)
// and window.renderBeaconAlerts / renderSecurityStats for the outbound tab.
// Tab switching is pure React — we toggle `.hidden` on the panels instead
// of unmounting, so vanilla-injected HTML survives a tab change.

import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchIpsStatus, fetchPrivacyStatsForIps } from './api';
import type { IpsStatus, PrivacyStatsPayload } from './types';

declare global {
  interface Window {
    _renderIpsThreats?: (data: IpsStatus) => void;
    renderBeaconAlerts?: (alerts: unknown[], status: unknown) => void;
    renderSecurityStats?: (stats: unknown, countId: string, weekId: string, sparkId: string) => void;
    _filterIpsTable?: () => void;
    _fetchReputationBulk?: (targets: string[]) => Promise<unknown>;
    _navIpsCount?: number;
  }
}

type Tab = 'alerts' | 'outbound' | 'blocklist';

function formatNumber(n: number | undefined): string {
  if (!n) return '0';
  return new Intl.NumberFormat('nl-NL').format(n);
}

export default function IpsPage() {
  const [tab, setTab] = useState<Tab>('alerts');

  const { data: ips } = useQuery<IpsStatus>({
    queryKey: ['ips-status'],
    queryFn: fetchIpsStatus,
    refetchInterval: 30_000,
    staleTime: 15_000,
  });

  const { data: priv } = useQuery<PrivacyStatsPayload>({
    queryKey: ['ips-privacy-stats'],
    queryFn: fetchPrivacyStatsForIps,
    refetchInterval: 30_000,
    staleTime: 15_000,
  });

  // Hand IPS data to the vanilla renderer — it populates #ips-inbound-container
  // and #ips-blocklist-body, and keeps the module-local _ipsInboundAlerts in
  // sync so the onclick handlers in each card resolve correctly.
  useEffect(() => {
    if (!ips) return;
    window._renderIpsThreats?.(ips);
    // Mirror nav-badge count (AppShell polls window._navIpsCount every 5s)
    window._navIpsCount = ips.inbound_attacks_24h || 0;
  }, [ips]);

  // Beaconing + security events live on the Outbound tab
  useEffect(() => {
    if (!priv) return;
    window.renderBeaconAlerts?.(priv.beaconing_alerts || [], priv.beaconing_status || null);
    window.renderSecurityStats?.(priv.security || {}, 'security-stat-count', 'security-stat-7d', 'security-spark');
  }, [priv]);

  // Tab-pill counts: computed from data, not scraped from the DOM
  const inboundCount = (ips?.inbound_attacks as unknown[] | undefined)?.length ?? 0;
  const blocklistCount = ips?.blocklist_count ?? 0;
  const outboundCount = useMemo(() => {
    const activeBeacons = ((priv?.beaconing_alerts as { dismissed?: boolean }[] | undefined) || [])
      .filter(a => !a.dismissed).length;
    const secEvents = priv?.security?.total_24h || 0;
    return activeBeacons + secEvents;
  }, [priv]);

  const showSetupGuide = ips && !ips.crowdsec_running;

  return (
    <section className="space-y-6">
      {/* Direction tabs */}
      <div className="flex items-center gap-1 bg-slate-100 dark:bg-white/[0.04] rounded-lg p-1 w-fit">
        <TabButton active={tab === 'alerts'} onClick={() => setTab('alerts')} icon="ph-arrow-down-left" count={inboundCount}>Inbound</TabButton>
        <TabButton active={tab === 'outbound'} onClick={() => setTab('outbound')} icon="ph-arrow-up-right" count={outboundCount}>Outbound</TabButton>
        <TabButton active={tab === 'blocklist'} onClick={() => setTab('blocklist')} icon="ph-list-bullets" count={blocklistCount}>Blocklist</TabButton>
      </div>

      {/* Inbound panel */}
      <div className={tab === 'alerts' ? 'space-y-4' : 'hidden'}>
        <div className="stat-grid grid grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Attempts with blocked/connected breakdown */}
          <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
            <p className="text-xs text-slate-500 dark:text-slate-400 font-medium">Inbound Attempts (24h)</p>
            <p className="text-2xl font-bold mt-2 tabular-nums text-slate-700 dark:text-slate-200">
              {formatNumber(ips?.inbound_attacks_24h)}
            </p>
            <div className="flex items-center gap-3 mt-2 text-xs">
              <span className="flex items-center gap-1">
                <span className="inline-block w-2 h-2 rounded-full bg-emerald-500" />
                <span className="text-emerald-600 dark:text-emerald-400 font-medium">{formatNumber(ips?.inbound_blocked_24h)}</span>
                <span className="text-slate-400">blocked</span>
              </span>
              {(ips?.inbound_connected_24h ?? 0) > 0 && (
                <span className="flex items-center gap-1">
                  <span className="inline-block w-2 h-2 rounded-full bg-red-500" />
                  <span className="text-red-500 dark:text-red-400 font-medium">{formatNumber(ips?.inbound_connected_24h)}</span>
                  <span className="text-slate-400">connected</span>
                </span>
              )}
            </div>
          </div>

          <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
            <p className="text-xs text-slate-500 dark:text-slate-400 font-medium">Known Threats (24h)</p>
            <p className="text-2xl font-bold mt-2 tabular-nums text-red-500 dark:text-red-400">
              {formatNumber(ips?.inbound_threats_24h)}
            </p>
            <p className="text-xs text-slate-400 mt-2">matched on CrowdSec blocklist</p>
          </div>

          <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
            <p className="text-xs text-slate-500 dark:text-slate-400 font-medium">Unique Attackers (24h)</p>
            <p className="text-2xl font-bold mt-2 tabular-nums text-slate-700 dark:text-slate-200">
              {formatNumber(ips?.inbound_unique_ips_24h)}
            </p>
            <p className="text-xs text-slate-400 mt-2">distinct source IPs</p>
          </div>

          <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
            <p className="text-xs text-slate-500 dark:text-slate-400 font-medium">CrowdSec Blocklist</p>
            <p className="text-2xl font-bold mt-2 tabular-nums text-slate-500 dark:text-slate-400">
              {formatNumber(ips?.blocklist_count)}
            </p>
            <p className="text-xs text-slate-400 mt-2">IPs actively blocked</p>
          </div>
        </div>

        {/* Inbound alert cards — React owns the shell + filter, vanilla fills the container */}
        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl overflow-hidden card-hover">
          <div className="px-5 py-3 flex items-center justify-between border-b border-slate-100 dark:border-white/[0.05]">
            <p className="text-xs text-slate-400 dark:text-slate-500">Probes, scans, and rejected connections from external IPs.</p>
            <select
              id="ips-severity-filter"
              onChange={() => window._filterIpsTable?.()}
              className="text-xs border border-slate-200 dark:border-white/[0.1] rounded-md px-2 py-1 bg-white dark:bg-white/[0.05] text-slate-600 dark:text-slate-300"
              defaultValue="all"
            >
              <option value="all">All</option>
              <option value="threat">Known threats</option>
              <option value="blocked">Probes only</option>
            </select>
          </div>
          <div id="ips-inbound-container" className="space-y-2 p-2">
            <div className="py-8 text-center text-slate-400 dark:text-slate-500 text-sm">
              <div className="flex flex-col items-center gap-2">
                <i className="ph-duotone ph-shield-check text-2xl" />
                <span>No inbound connection attempts detected yet.</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Outbound panel */}
      <div className={tab === 'outbound' ? 'space-y-4' : 'hidden'}>
        <div className="stat-grid grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="bg-white dark:bg-red-900/10 border border-slate-200 dark:border-red-700/30 rounded-xl p-5 card-hover">
            <p className="text-xs text-red-500 dark:text-red-400 font-medium">Outbound Security Events</p>
            <p id="security-stat-count" className="text-2xl font-bold mt-2 tabular-nums text-red-500 dark:text-red-400">0</p>
            <div className="flex items-end justify-between mt-1 gap-2">
              <p className="text-[10px] text-slate-400 dark:text-slate-500">
                Last 7 days: <span id="security-stat-7d" className="tabular-nums font-medium">0</span>
              </p>
              <svg id="security-spark" className="h-5 w-16" viewBox="0 0 64 20" preserveAspectRatio="none" />
            </div>
          </div>
        </div>

        {/* Beaconing / C2 detection — vanilla fills #beacon-body + #beacon-badge */}
        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl overflow-hidden card-hover">
          <div className="p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2.5">
                <div className="w-9 h-9 rounded-lg bg-red-100 dark:bg-red-900/30 flex items-center justify-center flex-shrink-0">
                  <i className="ph-duotone ph-siren text-xl text-red-500 dark:text-red-400" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300">Beaconing Detection</h3>
                  <p className="text-[11px] text-slate-400 dark:text-slate-500">Periodic outbound patterns that may indicate malware C2 or app heartbeats</p>
                </div>
              </div>
              <span id="beacon-badge" className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400 font-medium">
                Scanning
              </span>
            </div>
            <div id="beacon-body">
              <p className="text-sm text-slate-400 dark:text-slate-500 italic">Waiting for data...</p>
            </div>
          </div>
        </div>
      </div>

      {/* Blocklist panel — vanilla fills #ips-blocklist-body */}
      <div className={tab === 'blocklist' ? '' : 'hidden'}>
        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl overflow-hidden card-hover">
          <div className="px-5 py-3 bg-slate-50 dark:bg-slate-800/30 border-b border-slate-200 dark:border-white/[0.05]">
            <p className="text-xs text-slate-400 dark:text-slate-500">
              Known malicious IPs shared by the CrowdSec community. Preventive blocklist entries, not attacks on your network.
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400 font-medium border-b border-slate-200 dark:border-white/[0.05] bg-slate-50 dark:bg-[#0B0C10]">
                <tr>
                  <th className="py-3 px-4 font-medium">IP Address</th>
                  <th className="py-3 px-4 font-medium">Reason</th>
                  <th className="py-3 px-4 font-medium">Duration</th>
                </tr>
              </thead>
              <tbody id="ips-blocklist-body" className="text-slate-600 dark:text-slate-300 striped-rows">
                <tr>
                  <td colSpan={3} className="py-8 text-center text-slate-400 dark:text-slate-500 text-sm">
                    Loading blocklist...
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Setup guide — only shown while CrowdSec isn't reachable */}
      {showSetupGuide && (
        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5 card-hover">
          <h3 className="text-lg font-semibold text-slate-700 dark:text-slate-300 mb-3">Setup Guide</h3>
          <div className="space-y-2 text-[12px] text-slate-400 dark:text-slate-500 font-mono">
            <p className="text-slate-500 dark:text-slate-400 font-sans text-sm mb-3">Install CrowdSec to enable Active Protect:</p>
            <div className="bg-slate-50 dark:bg-slate-800/50 rounded-lg p-3 space-y-1">
              <p><span className="text-emerald-500">$</span> curl -s https://install.crowdsec.net | sudo bash</p>
              <p><span className="text-emerald-500">$</span> sudo apt install crowdsec crowdsec-firewall-bouncer-iptables</p>
              <p><span className="text-emerald-500">$</span> sudo cscli collections install crowdsecurity/linux</p>
            </div>
            <p className="font-sans text-[11px] mt-2">
              Once installed, CrowdSec will automatically connect to the community threat intelligence network and begin protecting your network.
            </p>
          </div>
        </div>
      )}
    </section>
  );
}

function TabButton({
  active, onClick, icon, count, children,
}: {
  active: boolean; onClick: () => void; icon: string; count: number; children: React.ReactNode;
}) {
  const base = 'px-4 py-1.5 rounded-md text-xs font-medium transition-colors';
  const cls = active
    ? `${base} bg-blue-700 text-white shadow-sm`
    : `${base} text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300`;
  const pillCls = active
    ? 'ml-1 px-1.5 py-0.5 text-[10px] rounded-full bg-white/20 text-white'
    : 'ml-1 px-1.5 py-0.5 text-[10px] rounded-full bg-slate-200 dark:bg-white/[0.08] text-slate-500 dark:text-slate-400';
  return (
    <button onClick={onClick} className={cls}>
      <span className="inline-flex items-center gap-1.5">
        <i className={`ph-duotone ${icon} text-sm`} />
        {children}
        <span className={pillCls}>{count}</span>
      </span>
    </button>
  );
}
