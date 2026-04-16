// IPS / Attacks page — fully React, using shared AlertCard.
//
// Inbound tab: stat cards + AlertCard list for each inbound attack
// Outbound tab: security stats + beaconing AlertCards
// Blocklist tab: table of CrowdSec blocked IPs

import { useMemo, useState, useCallback } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { fetchIpsStatus, fetchPrivacyStatsForIps } from './api';
import type { IpsStatus, InboundAttack, PrivacyStatsPayload, BeaconAlert } from './types';
import AlertCard from '../shared/AlertCard';
import type { AlertData } from '../shared/AlertCard';
import { formatBytes } from '../colors';

function formatNumber(n: number | undefined): string {
  if (!n) return '0';
  return new Intl.NumberFormat('nl-NL').format(n);
}

// ---------------------------------------------------------------------------
// Inbound attack → AlertData mapper
// ---------------------------------------------------------------------------
function inboundToAlertData(a: InboundAttack): AlertData {
  const isThreat = a.severity === 'threat';
  const portLabel = a.target_port ? `Port ${a.target_port}` : '';
  const connLabel = a.conn_state === 'SF' || a.conn_state === 'S1' ? 'connected' : 'blocked';

  let description = `from ${a.source_ip}`;
  if (a.asn_org) description += ` (${a.asn_org})`;
  if (portLabel) description += ` \u2192 ${portLabel}`;
  description += ` \u00b7 ${a.hit_count} attempt${a.hit_count !== 1 ? 's' : ''} \u00b7 ${connLabel}`;
  if (a.crowdsec_reason) description += ` \u00b7 ${a.crowdsec_reason}`;

  return {
    alert_id: `ips-${a.source_ip}-${a.target_port}-${a.last_seen}`,
    mac_address: '',  // inbound attacks don't have a local MAC
    alert_type: isThreat ? 'inbound_threat' : 'inbound_port_scan',
    service_or_dest: a.source_ip,
    device_name: a.target_name || a.target_ip || 'Network',
    description,
    country_code: a.country_code || undefined,
    severity: isThreat ? 'HIGH' : undefined,
    timestamp: a.last_seen,
    hits: a.hit_count,
  };
}

// ---------------------------------------------------------------------------
// Beacon → AlertData mapper (same as Privacy page)
// ---------------------------------------------------------------------------
function beaconToAlertData(a: BeaconAlert): AlertData {
  const dest = a.dest_sni || a.dest_ptr || a.dest_ip;
  let description = dest;
  if (a.dest_asn_org) description += ` (${a.dest_asn_org})`;
  if (a.score) description += ` \u00b7 Score: ${a.score}`;

  return {
    alert_id: `beacon-${a.mac_address || a.source_ip}-${a.dest_ip}`,
    mac_address: a.mac_address || '',
    alert_type: 'beaconing_threat',
    service_or_dest: a.dest_sni || a.dest_ip,
    device_name: a.display_name || a.hostname || a.source_ip,
    description,
    country_code: a.dest_country || undefined,
    severity: a.score >= 70 ? 'Critical' : a.score >= 40 ? 'HIGH' : undefined,
    timestamp: a.last_seen,
    hits: a.total_hits || a.hits,
    total_bytes: a.total_bytes || 0,
    beacon_score: a.score,
    is_dismissed: a.dismissed,
  };
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------
type Tab = 'alerts' | 'outbound' | 'blocklist';

export default function IpsPage() {
  const [tab, setTab] = useState<Tab>('alerts');
  const [severityFilter, setSeverityFilter] = useState<'all' | 'threat' | 'blocked'>('all');
  const queryClient = useQueryClient();

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

  // Mirror nav-badge count
  (window as any)._navIpsCount = ips?.inbound_attacks_24h || 0;

  const handleAlertAction = useCallback((_id: string, _action: string) => {
    queryClient.invalidateQueries({ queryKey: ['ips-status'] });
    queryClient.invalidateQueries({ queryKey: ['ips-privacy-stats'] });
  }, [queryClient]);

  // Filtered inbound attacks
  const inboundAlerts = useMemo(() => {
    const attacks = (ips?.inbound_attacks ?? []) as InboundAttack[];
    if (severityFilter === 'all') return attacks;
    return attacks.filter(a => {
      if (severityFilter === 'threat') return a.severity === 'threat';
      return a.severity !== 'threat'; // blocked = probes
    });
  }, [ips?.inbound_attacks, severityFilter]);

  // Beaconing alerts
  const beaconAlerts = (priv?.beaconing_alerts ?? []) as BeaconAlert[];
  const activeBeacons = beaconAlerts.filter(a => !a.dismissed);
  const dismissedBeacons = beaconAlerts.filter(a => a.dismissed);

  // Security stats
  const security = priv?.security;

  // Tab counts
  const inboundCount = (ips?.inbound_attacks as unknown[] | undefined)?.length ?? 0;
  const blocklistCount = ips?.blocklist_count ?? 0;
  const outboundCount = useMemo(() => {
    return activeBeacons.length + (security?.total_24h || 0);
  }, [activeBeacons, security]);

  const showSetupGuide = ips && !ips.crowdsec_running;

  return (
    <section className="space-y-6">
      {/* Direction tabs */}
      <div className="flex items-center gap-1 bg-slate-100 dark:bg-white/[0.04] rounded-lg p-1 w-fit">
        <TabButton active={tab === 'alerts'} onClick={() => setTab('alerts')} icon="ph-arrow-down-left" count={inboundCount}>Inbound</TabButton>
        <TabButton active={tab === 'outbound'} onClick={() => setTab('outbound')} icon="ph-arrow-up-right" count={outboundCount}>Outbound</TabButton>
        <TabButton active={tab === 'blocklist'} onClick={() => setTab('blocklist')} icon="ph-list-bullets" count={blocklistCount}>Blocklist</TabButton>
      </div>

      {/* ================================================================ */}
      {/* Inbound panel                                                    */}
      {/* ================================================================ */}
      {tab === 'alerts' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard label="Inbound Attempts (24h)" value={formatNumber(ips?.inbound_attacks_24h)}>
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
            </StatCard>
            <StatCard label="Known Threats (24h)" value={formatNumber(ips?.inbound_threats_24h)} color="red">
              <p className="text-xs text-slate-400 mt-2">matched on CrowdSec blocklist</p>
            </StatCard>
            <StatCard label="Unique Attackers (24h)" value={formatNumber(ips?.inbound_unique_ips_24h)}>
              <p className="text-xs text-slate-400 mt-2">distinct source IPs</p>
            </StatCard>
            <StatCard label="CrowdSec Blocklist" value={formatNumber(ips?.blocklist_count)} color="slate">
              <p className="text-xs text-slate-400 mt-2">IPs actively blocked</p>
            </StatCard>
          </div>

          {/* Inbound alert cards */}
          <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl overflow-hidden">
            <div className="px-5 py-3 flex items-center justify-between border-b border-slate-100 dark:border-white/[0.05]">
              <p className="text-xs text-slate-400 dark:text-slate-500">Probes, scans, and rejected connections from external IPs.</p>
              <select
                value={severityFilter}
                onChange={e => setSeverityFilter(e.target.value as any)}
                className="text-xs border border-slate-200 dark:border-white/[0.1] rounded-md px-2 py-1 bg-white dark:bg-white/[0.05] text-slate-600 dark:text-slate-300"
              >
                <option value="all">All</option>
                <option value="threat">Known threats</option>
                <option value="blocked">Probes only</option>
              </select>
            </div>
            <div className="space-y-2 p-2">
              {inboundAlerts.length === 0 ? (
                <div className="py-8 text-center text-slate-400 dark:text-slate-500 text-sm">
                  <div className="flex flex-col items-center gap-2">
                    <i className="ph-duotone ph-shield-check text-2xl" />
                    <span>No inbound connection attempts detected yet.</span>
                  </div>
                </div>
              ) : (
                inboundAlerts.map((a, i) => (
                  <AlertCard
                    key={`ips-${a.source_ip}-${a.target_port}-${i}`}
                    alert={inboundToAlertData(a)}
                    compact
                    onAction={handleAlertAction}
                  />
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* ================================================================ */}
      {/* Outbound panel                                                   */}
      {/* ================================================================ */}
      {tab === 'outbound' && (
        <div className="space-y-4">
          {/* Security stats card */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="bg-white dark:bg-red-900/10 border border-slate-200 dark:border-red-700/30 rounded-xl p-5">
              <p className="text-xs text-red-500 dark:text-red-400 font-medium">Outbound Security Events</p>
              <div className="flex items-end gap-3 mt-2">
                <p className="text-2xl font-bold tabular-nums text-red-500 dark:text-red-400">
                  {security?.total_24h ?? 0}
                </p>
                {security?.sparkline_7d && (
                  <Sparkline data={security.sparkline_7d} color={security.total_24h ? '#ef4444' : '#94a3b8'} />
                )}
              </div>
              <p className="text-[10px] text-slate-400 dark:text-slate-500 mt-1">
                Last 7 days: <span className="tabular-nums font-medium">{security?.total_7d ?? 0}</span>
              </p>
            </div>
          </div>

          {/* Beaconing / C2 detection */}
          <div className={`bg-white border rounded-xl p-5 ${
            activeBeacons.length > 0
              ? 'border-red-500/30 dark:border-red-700/40 dark:bg-red-900/5'
              : 'border-slate-200 dark:border-white/[0.05] dark:bg-white/[0.03]'
          }`}>
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
              <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
                activeBeacons.length > 0
                  ? 'bg-red-500 text-white font-bold animate-pulse'
                  : 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400'
              }`}>
                {activeBeacons.length > 0 ? `${activeBeacons.length} threats` : 'All clear'}
              </span>
            </div>

            {activeBeacons.length > 0 && (
              <div className="mb-3 px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700/40 flex items-start gap-2">
                <i className="ph-duotone ph-warning text-base mt-0.5 text-red-500 flex-shrink-0" />
                <p className="text-xs text-red-700 dark:text-red-300">
                  <span className="font-semibold">Warning:</span>{' '}
                  One or more devices are exhibiting highly periodic outbound connection patterns consistent with malware command & control traffic.
                </p>
              </div>
            )}

            {beaconAlerts.length === 0 ? (
              <div className="flex items-center gap-2.5 text-emerald-600 dark:text-emerald-400">
                <i className="ph-duotone ph-shield-check text-xl flex-shrink-0" />
                <span className="text-sm font-medium">No suspicious malware beacons detected.</span>
              </div>
            ) : (
              <div className="space-y-2">
                {activeBeacons.map((a, i) => (
                  <AlertCard key={`beacon-active-${i}`} alert={beaconToAlertData(a)} onAction={handleAlertAction} />
                ))}
                {dismissedBeacons.map((a, i) => (
                  <AlertCard key={`beacon-dismissed-${i}`} alert={beaconToAlertData(a)} showTrash onAction={handleAlertAction} />
                ))}
              </div>
            )}

            {/* Scanner status footer */}
            {priv?.beaconing_status && <BeaconStatusFooter status={priv.beaconing_status} />}
          </div>
        </div>
      )}

      {/* ================================================================ */}
      {/* Blocklist panel                                                  */}
      {/* ================================================================ */}
      {tab === 'blocklist' && (
        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl overflow-hidden">
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
              <tbody className="text-slate-600 dark:text-slate-300">
                {(ips?.blocklist ?? []).length === 0 ? (
                  <tr>
                    <td colSpan={3} className="py-8 text-center text-slate-400 dark:text-slate-500 text-sm">
                      {ips ? 'No blocklist entries.' : 'Loading blocklist...'}
                    </td>
                  </tr>
                ) : (
                  (ips!.blocklist as { ip: string; reason: string; duration: string }[]).map((b, i) => (
                    <tr key={i} className="border-b border-slate-100 dark:border-white/[0.04] hover:bg-slate-50 dark:hover:bg-white/[0.02]">
                      <td className="py-2.5 px-4 font-mono text-xs">{b.ip}</td>
                      <td className="py-2.5 px-4 text-xs">{b.reason}</td>
                      <td className="py-2.5 px-4 text-xs text-slate-400">{b.duration}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Setup guide — only shown while CrowdSec isn't reachable */}
      {showSetupGuide && (
        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
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

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

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

function StatCard({ label, value, color, children }: {
  label: string; value: string; color?: 'red' | 'slate'; children?: React.ReactNode;
}) {
  const valueCls = color === 'red' ? 'text-red-500 dark:text-red-400' : color === 'slate' ? 'text-slate-500 dark:text-slate-400' : 'text-slate-700 dark:text-slate-200';
  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
      <p className="text-xs text-slate-500 dark:text-slate-400 font-medium">{label}</p>
      <p className={`text-2xl font-bold mt-2 tabular-nums ${valueCls}`}>{value}</p>
      {children}
    </div>
  );
}

function Sparkline({ data, color }: { data: number[]; color: string }) {
  const max = Math.max(1, ...data);
  return (
    <svg viewBox="0 0 64 20" className="w-16 h-5 flex-shrink-0">
      {data.map((v, i) => {
        const barW = 64 / 7;
        const gap = 1.5;
        const h = Math.max(2, (v / max) * 18);
        const x = i * barW + gap / 2;
        return (
          <rect key={i} x={x} y={20 - h} width={barW - gap} height={h} rx={0.5}
            fill={color} opacity={v > 0 ? 0.9 : 0.35} />
        );
      })}
    </svg>
  );
}

function BeaconStatusFooter({ status }: { status: any }) {
  if (!status) return null;
  return (
    <div className="mt-3 pt-3 border-t border-slate-100 dark:border-white/[0.05] flex items-center gap-3 text-[10px] text-slate-400 dark:text-slate-500">
      <span className="flex items-center gap-1">
        <span className={`w-2 h-2 rounded-full ${status.running ? 'bg-emerald-500 animate-pulse' : 'bg-slate-400'}`} />
        {status.running ? 'Scanner active' : 'Scanner stopped'}
      </span>
      {status.scans_completed > 0 && <span>{status.scans_completed} scans completed</span>}
      {status.last_scan_at && <span>Last: {new Date(status.last_scan_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>}
      {status.last_error && <span className="text-red-400">{status.last_error}</span>}
    </div>
  );
}
