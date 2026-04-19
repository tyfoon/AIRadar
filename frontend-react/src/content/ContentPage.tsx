import { useState, useMemo, useCallback, useEffect, useRef } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { fetchFamilyMeta, fetchFamilyOverview, fetchFamilyCategory, fetchGroups } from './api';
import type {
  OverviewCard, CategoryService, CategoryDevice, CategoryPolicy,
  HonestyInfo,
} from './types';
import { SvcLogo, svcDisplayName } from '../category/serviceHelpers';
import { detectDeviceType } from '../utils/devices';
import { upsertPolicy, fetchDeviceGroups } from '../shared/alertApi';
import type { DeviceGroup as SharedDeviceGroup } from '../shared/alertApi';

// ---------------------------------------------------------------------------
// Constants & helpers
// ---------------------------------------------------------------------------
const CATEGORY_META: Record<string, { icon: string; color: string }> = {
  social:        { icon: 'ph-chat-circle-text', color: 'pink' },
  gaming:        { icon: 'ph-game-controller',  color: 'indigo' },
  streaming:     { icon: 'ph-play-circle',      color: 'purple' },
  shopping:      { icon: 'ph-shopping-bag',     color: 'amber' },
  news:          { icon: 'ph-newspaper',        color: 'sky' },
  dating:        { icon: 'ph-heart',            color: 'rose' },
  adult:         { icon: 'ph-warning-circle',   color: 'red' },
  gambling:      { icon: 'ph-dice-five',        color: 'rose' },
  communication: { icon: 'ph-phone-call',       color: 'sky' },
};

const CHIP_CAP = 3;
const DIM_BYTES = 1_048_576; // 1 MB
const DIM_HITS = 10;

const LS_GROUP_KEY = 'airadar-family-group-id';

function fmtBytes(b: number): string {
  if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB';
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB';
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB';
  return b + ' B';
}

function catLabel(key: string): string {
  return key.charAt(0).toUpperCase() + key.slice(1);
}

/** Render a device-type icon with online dot, using the shared detectDeviceType logic */
function DeviceTypeIcon({ hostname, vendor, deviceClass, online, size = 'text-base' }: {
  hostname?: string | null;
  vendor?: string | null;
  deviceClass?: string | null;
  online?: boolean;
  size?: string;
}) {
  const dt = detectDeviceType({
    mac_address: '', hostname: hostname ?? undefined,
    vendor: vendor ?? undefined, device_class: deviceClass ?? undefined, ips: [],
  } as any);
  const colorCls = online ? 'text-emerald-500 dark:text-emerald-400' : 'text-slate-400 dark:text-slate-600';
  return (
    <span className={`relative inline-flex items-center justify-center w-5 h-5 ${size} leading-none flex-shrink-0 ${colorCls}`} title={`${dt.type}${online ? ' · online' : ' · offline'}`}>
      <i className={`ph-duotone ${dt.icon}`} />
      {online && (
        <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-emerald-400 border border-white dark:border-[#0B0C10]" />
      )}
    </span>
  );
}

declare global {
  interface Window {
    showToast?: (msg: string, type?: string) => void;
  }
}

// Policy panel context — which service/device is currently showing its inline policy controls
interface PolicyTarget {
  serviceName?: string | null;
  category: string;
  macAddress?: string | null;
  deviceName?: string;
  defaultScope: 'global' | 'device';
  defaultAction: 'allow' | 'alert' | 'block';
}

// ---------------------------------------------------------------------------
// Policy helpers (same logic as vanilla _findServiceHeadlinePolicy etc)
// ---------------------------------------------------------------------------
function findServiceHeadlinePolicy(
  policies: CategoryPolicy[], service: string, category: string,
): CategoryPolicy | null {
  const byStrength = (a: CategoryPolicy, b: CategoryPolicy) =>
    (a.action === 'block' ? 0 : 1) - (b.action === 'block' ? 0 : 1);
  const globalSvc = policies
    .filter(p => p.scope === 'global' && p.service_name === service)
    .sort(byStrength);
  if (globalSvc.length) return globalSvc[0];
  const globalCat = policies
    .filter(p => p.scope === 'global' && p.service_name === null && p.category === category)
    .sort(byStrength);
  if (globalCat.length) return globalCat[0];
  return null;
}

function findDeviceHeadlinePolicy(
  policies: CategoryPolicy[], mac: string, category: string,
): CategoryPolicy | null {
  const candidates = policies.filter(p =>
    p.scope === 'device' && p.mac_address === mac && (
      (p.service_name === null && p.category === category) ||
      p.service_name !== null
    ),
  );
  if (!candidates.length) return null;
  candidates.sort((a, b) => {
    const catA = a.service_name === null ? 0 : 1;
    const catB = b.service_name === null ? 0 : 1;
    if (catA !== catB) return catA - catB;
    return (a.action === 'block' ? 0 : 1) - (b.action === 'block' ? 0 : 1);
  });
  return candidates[0];
}

// Nested policy: exact match on (device scope, mac, service). This is what
// the user sets by clicking a device-chip inside a service row (or a
// service-chip inside a device row) — "block THIS service for THIS device".
// Falls back to a device+category rule (blocks every service in the
// category for the device) so that chip still shows the policy dot.
function findNestedPolicy(
  policies: CategoryPolicy[], mac: string, service: string, category: string,
): CategoryPolicy | null {
  const exact = policies.find(p =>
    p.scope === 'device' && p.mac_address === mac && p.service_name === service,
  );
  if (exact) return exact;
  const catWide = policies.find(p =>
    p.scope === 'device' && p.mac_address === mac && p.service_name === null && p.category === category,
  );
  return catWide || null;
}

function PolicyIcon({ policy }: { policy: CategoryPolicy | null }) {
  if (!policy) return null;
  if (policy.action === 'block') {
    return <i className="ph-duotone ph-prohibit text-red-500 text-sm" title={`Blocked (${policy.scope})`} />;
  }
  if (policy.action === 'alert') {
    return <i className="ph-duotone ph-bell-ringing text-amber-500 text-sm" title={`Alerting (${policy.scope})`} />;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------
export default function ContentPage() {
  // Group filter — persisted in localStorage
  const [groupId, setGroupId] = useState<number | null>(() => {
    const v = localStorage.getItem(LS_GROUP_KEY);
    return v && v !== 'null' ? parseInt(v, 10) : null;
  });
  const [activeCategory, setActiveCategory] = useState<string | null>(null);

  // Expanded rows
  const [expandedServices, setExpandedServices] = useState<Set<string>>(new Set());
  const [expandedDevices, setExpandedDevices] = useState<Set<string>>(new Set());

  // Inline policy panel
  const [policyTarget, setPolicyTarget] = useState<PolicyTarget | null>(null);
  const queryClient = useQueryClient();

  // Data queries
  const { data: _meta } = useQuery({
    queryKey: ['family-meta'],
    queryFn: fetchFamilyMeta,
    staleTime: 300_000, // static, 5min
  });

  const { data: groups } = useQuery({
    queryKey: ['family-groups'],
    queryFn: fetchGroups,
    staleTime: 60_000,
  });

  const { data: overview, isLoading: overviewLoading } = useQuery({
    queryKey: ['family-overview', groupId],
    queryFn: () => fetchFamilyOverview(24, groupId),
    refetchInterval: 30_000,
    staleTime: 15_000,
  });

  // Auto-pick most active category
  useEffect(() => {
    if (!overview?.cards?.length) return;
    if (activeCategory && overview.cards.some(c => c.key === activeCategory)) return;
    const sorted = [...overview.cards].sort((a, b) => (b.bytes || 0) - (a.bytes || 0));
    setActiveCategory(sorted[0]?.key ?? null);
  }, [overview?.cards, activeCategory]);

  const { data: catData, isLoading: catLoading } = useQuery({
    queryKey: ['family-category', activeCategory, groupId],
    queryFn: () => fetchFamilyCategory(activeCategory!, 24, groupId),
    enabled: !!activeCategory,
    refetchInterval: 30_000,
    staleTime: 15_000,
  });

  const handleGroupChange = useCallback((value: string) => {
    const parsed = value === '' ? null : parseInt(value, 10);
    const val = Number.isNaN(parsed) ? null : parsed;
    setGroupId(val);
    if (val == null) localStorage.removeItem(LS_GROUP_KEY);
    else localStorage.setItem(LS_GROUP_KEY, String(val));
  }, []);

  const handleCategorySelect = useCallback((key: string) => {
    setActiveCategory(key);
    setExpandedServices(new Set());
    setExpandedDevices(new Set());
  }, []);

  const toggleExpand = useCallback((kind: 'service' | 'device', key: string) => {
    const setter = kind === 'service' ? setExpandedServices : setExpandedDevices;
    setter(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }, []);

  if (overviewLoading && !overview) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  const cards = overview?.cards ?? [];
  const sorted = [...cards].sort((a, b) => (b.bytes || 0) - (a.bytes || 0));
  const policies = catData?.policies ?? [];

  return (
    <div className="space-y-6">
      {/* Group filter */}
      <div className="flex flex-wrap items-center justify-end gap-3">
        <div className="flex items-center gap-2">
          <label className="text-xs text-slate-500 dark:text-slate-400">Group</label>
          <select
            value={groupId != null ? String(groupId) : ''}
            onChange={e => handleGroupChange(e.target.value)}
            className="text-sm rounded-lg border border-slate-200 dark:border-white/[0.1] bg-white dark:bg-white/[0.06] text-slate-700 dark:text-slate-200 px-3 py-1.5 max-w-[240px]"
          >
            <option value="">All devices</option>
            {(groups ?? []).map(g => (
              <option key={g.id} value={g.id}>
                {g.name}{g.member_count != null ? ` (${g.member_count})` : ''}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Category chip strip */}
      <CategoryChipStrip cards={sorted} activeKey={activeCategory} onSelect={handleCategorySelect} />

      {/* Two kader panels */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Services kader */}
        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200 flex items-center gap-2">
              <i className="ph-duotone ph-squares-four text-base text-slate-500" />
              <span>Services</span>
              {catData?.services?.length ? (
                <span className="text-[10px] font-normal text-slate-400 dark:text-slate-500">({catData.services.length})</span>
              ) : null}
            </h3>
            <p className="text-[10px] text-slate-400 dark:text-slate-500">Click to set a rule</p>
          </div>
          {catLoading && !catData ? (
            <p className="text-slate-400 dark:text-slate-500 text-center py-6 text-xs">Loading...</p>
          ) : (
            <ServicesKader
              services={catData?.services ?? []}
              category={activeCategory ?? ''}
              policies={policies}
              expandedSet={expandedServices}
              onToggleExpand={(k) => toggleExpand('service', k)}
              onOpenPolicy={(svc) => setPolicyTarget({
                serviceName: svc, category: activeCategory ?? '',
                defaultScope: 'global', defaultAction: 'block',
              })}
              onOpenNestedPolicy={(mac, deviceName, svc) => setPolicyTarget({
                serviceName: svc, macAddress: mac, deviceName,
                category: activeCategory ?? '',
                defaultScope: 'device', defaultAction: 'block',
              })}
              activePolicyService={policyTarget?.serviceName && !policyTarget?.macAddress ? policyTarget.serviceName : undefined}
              activeNested={policyTarget?.macAddress && policyTarget?.serviceName
                ? { mac: policyTarget.macAddress, service: policyTarget.serviceName } : undefined}
            />
          )}
        </div>

        {/* Devices kader */}
        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200 flex items-center gap-2">
              <i className="ph-duotone ph-devices text-base text-slate-500" />
              <span>Devices</span>
              {catData?.devices?.length ? (
                <span className="text-[10px] font-normal text-slate-400 dark:text-slate-500">({catData.devices.length})</span>
              ) : null}
            </h3>
            <p className="text-[10px] text-slate-400 dark:text-slate-500">Click to set a rule</p>
          </div>
          {catLoading && !catData ? (
            <p className="text-slate-400 dark:text-slate-500 text-center py-6 text-xs">Loading...</p>
          ) : (
            <DevicesKader
              devices={catData?.devices ?? []}
              category={activeCategory ?? ''}
              policies={policies}
              expandedSet={expandedDevices}
              onToggleExpand={(k) => toggleExpand('device', k)}
              onOpenPolicy={(mac, name) => setPolicyTarget({
                category: activeCategory ?? '', macAddress: mac, deviceName: name,
                defaultScope: 'device', defaultAction: 'block',
              })}
              onOpenNestedPolicy={(mac, deviceName, svc) => setPolicyTarget({
                serviceName: svc, macAddress: mac, deviceName,
                category: activeCategory ?? '',
                defaultScope: 'device', defaultAction: 'block',
              })}
              activePolicyMac={policyTarget?.macAddress && !policyTarget?.serviceName ? policyTarget.macAddress : undefined}
              activeNested={policyTarget?.macAddress && policyTarget?.serviceName
                ? { mac: policyTarget.macAddress, service: policyTarget.serviceName } : undefined}
            />
          )}
        </div>
      </div>

      {/* Inline policy panel */}
      {policyTarget && (
        <InlinePolicyPanel
          target={policyTarget}
          onClose={() => setPolicyTarget(null)}
          onApplied={() => {
            setPolicyTarget(null);
            queryClient.invalidateQueries({ queryKey: ['family-category'] });
          }}
        />
      )}

      {/* Honesty block */}
      {overview?.honesty && <HonestyBlock honesty={overview.honesty} />}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function CategoryChipStrip({ cards, activeKey, onSelect }: {
  cards: OverviewCard[];
  activeKey: string | null;
  onSelect: (key: string) => void;
}) {
  if (!cards.length) {
    return <p className="text-xs text-slate-400 dark:text-slate-500">No family usage yet.</p>;
  }

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2">
      {cards.map(c => {
        const m = CATEGORY_META[c.key] || { icon: 'ph-squares-four', color: 'slate' };
        const isActive = c.key === activeKey;
        const dim = (c.bytes || 0) < DIM_BYTES && !isActive ? 'opacity-60' : '';

        return (
          <button
            key={c.key}
            type="button"
            onClick={() => onSelect(c.key)}
            className={`relative group flex flex-col items-start justify-between gap-2 p-3 rounded-lg border transition-colors text-left min-h-[92px] ${
              isActive
                ? 'bg-blue-50 dark:bg-blue-500/10 border-blue-400 dark:border-blue-500/60 shadow-sm'
                : `bg-white/60 dark:bg-white/[0.02] border-slate-200 dark:border-white/[0.06] hover:bg-white dark:hover:bg-white/[0.05] hover:border-slate-300 dark:hover:border-white/[0.12] ${dim}`
            }`}
          >
            {c.blocked && (
              <span className="absolute top-2 right-2 w-1.5 h-1.5 rounded-full bg-red-500" title="Has active blocks" />
            )}
            <div className="flex items-center gap-2 w-full min-w-0">
              <i className={`ph-duotone ${m.icon} text-xl flex-shrink-0 ${
                isActive ? 'text-blue-600 dark:text-blue-300' : 'text-slate-500 dark:text-slate-400'
              }`} />
              <span className={`font-semibold text-xs truncate ${
                isActive ? 'text-blue-800 dark:text-blue-100' : 'text-slate-700 dark:text-slate-200'
              }`} title={catLabel(c.key)}>
                {catLabel(c.key)}
              </span>
            </div>
            <div className="flex flex-col gap-0.5 w-full">
              <span className="text-[10px] text-slate-500 dark:text-slate-400 truncate">
                {c.services} services · {c.devices} devices
              </span>
              <span className="tabular-nums text-[11px] font-semibold text-slate-700 dark:text-slate-200">
                {fmtBytes(c.bytes || 0)}
              </span>
            </div>
          </button>
        );
      })}
    </div>
  );
}

function ServicesKader({ services, category, policies, expandedSet, onToggleExpand, onOpenPolicy, onOpenNestedPolicy, activePolicyService, activeNested }: {
  services: CategoryService[];
  category: string;
  policies: CategoryPolicy[];
  expandedSet: Set<string>;
  onToggleExpand: (key: string) => void;
  onOpenPolicy: (serviceName: string) => void;
  onOpenNestedPolicy: (mac: string, deviceName: string, serviceName: string) => void;
  activePolicyService?: string;
  activeNested?: { mac: string; service: string };
}) {
  if (!services.length) {
    return <p className="text-slate-400 dark:text-slate-500 text-center py-6 text-xs">No services seen in this category.</p>;
  }
  const maxBytes = Math.max(...services.map(s => s.total_bytes || 0), 1);

  return (
    <div className="space-y-2">
      {services.map(s => {
        const isPhantom = !!s.phantom;
        const dim = !isPhantom && (s.total_bytes || 0) < DIM_BYTES && (s.total_hits || 0) < DIM_HITS;
        const pct = Math.max(3, Math.round(((s.total_bytes || 0) / maxBytes) * 100));
        const expanded = expandedSet.has(s.service_name);
        const allDevs = s.top_devices || [];
        const shown = expanded ? allDevs : allDevs.slice(0, CHIP_CAP);
        const hidden = Math.max(0, allDevs.length - shown.length);
        const headlinePol = findServiceHeadlinePolicy(policies, s.service_name, category);

        return (
          <div
            key={s.service_name}
            className={`p-2.5 rounded-lg hover:bg-slate-50 dark:hover:bg-white/[0.02] cursor-pointer transition-colors ${dim ? 'opacity-50' : ''} ${activePolicyService === s.service_name ? 'ring-1 ring-blue-500/50 bg-blue-50/5' : ''}`}
            onClick={() => onOpenPolicy(s.service_name)}
          >
            <div className="flex items-center gap-2 mb-1.5">
              <SvcLogo svc={s.service_name} size={20} />
              <span className="font-medium text-slate-700 dark:text-slate-200 truncate flex-1 text-xs" title={svcDisplayName(s.service_name)}>
                {svcDisplayName(s.service_name)}
              </span>
              <PolicyIcon policy={headlinePol} />
              {s.blocked && (
                <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-red-100 dark:bg-red-950/40 text-red-600 dark:text-red-400 font-semibold">Blocked</span>
              )}
              {isPhantom && (
                <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-slate-100 dark:bg-white/[0.06] text-slate-500 dark:text-slate-400 font-medium" title="Rule only — no recent traffic">
                  rule only
                </span>
              )}
              <span className="text-[10px] tabular-nums text-slate-400 dark:text-slate-500">
                {isPhantom ? '—' : fmtBytes(s.total_bytes || 0)}
              </span>
            </div>
            <div className="h-1 w-full bg-slate-100 dark:bg-white/[0.06] rounded-full overflow-hidden mb-2">
              <div className="h-full bg-blue-500/70 dark:bg-blue-400/70 rounded-full" style={{ width: `${pct}%` }} />
            </div>
            <div className="flex flex-wrap gap-1.5">
              {shown.map(d => {
                const nestedPol = findNestedPolicy(policies, d.mac_address, s.service_name, category);
                const isActive = activeNested?.mac === d.mac_address && activeNested?.service === s.service_name;
                return (
                  <DeviceChip
                    key={d.mac_address}
                    dev={d}
                    policy={nestedPol}
                    active={isActive}
                    onClick={() => onOpenNestedPolicy(
                      d.mac_address,
                      d.display_name || d.hostname || d.mac_address,
                      s.service_name,
                    )}
                  />
                );
              })}
              {hidden > 0 && (
                <button
                  type="button"
                  onClick={e => { e.stopPropagation(); onToggleExpand(s.service_name); }}
                  className="text-[10px] px-2 py-1 rounded-lg bg-slate-100 dark:bg-white/[0.06] hover:bg-slate-200 dark:hover:bg-white/[0.10] text-slate-500 dark:text-slate-400 transition-colors"
                >
                  +{hidden} more
                </button>
              )}
              {expanded && allDevs.length > CHIP_CAP && hidden === 0 && (
                <button
                  type="button"
                  onClick={e => { e.stopPropagation(); onToggleExpand(s.service_name); }}
                  className="text-[10px] px-2 py-1 rounded-lg bg-slate-100 dark:bg-white/[0.06] hover:bg-slate-200 dark:hover:bg-white/[0.10] text-slate-500 dark:text-slate-400 transition-colors"
                >
                  show less
                </button>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function DevicesKader({ devices, category, policies, expandedSet, onToggleExpand, onOpenPolicy, onOpenNestedPolicy, activePolicyMac, activeNested }: {
  devices: CategoryDevice[];
  category: string;
  policies: CategoryPolicy[];
  expandedSet: Set<string>;
  onToggleExpand: (key: string) => void;
  onOpenPolicy: (mac: string, name: string) => void;
  onOpenNestedPolicy: (mac: string, deviceName: string, serviceName: string) => void;
  activePolicyMac?: string;
  activeNested?: { mac: string; service: string };
}) {
  if (!devices.length) {
    return <p className="text-slate-400 dark:text-slate-500 text-center py-6 text-xs">No devices seen in this category.</p>;
  }
  const maxBytes = Math.max(...devices.map(d => d.total_bytes || 0), 1);

  return (
    <div className="space-y-2">
      {devices.map(d => {
        const dim = (d.total_bytes || 0) < DIM_BYTES && (d.total_hits || 0) < DIM_HITS;
        const pct = Math.max(3, Math.round(((d.total_bytes || 0) / maxBytes) * 100));
        const expanded = expandedSet.has(d.mac_address);
        const allSvcs = d.top_services || [];
        const shown = expanded ? allSvcs : allSvcs.slice(0, CHIP_CAP);
        const hidden = Math.max(0, allSvcs.length - shown.length);
        const name = d.display_name || d.hostname || d.mac_address || '?';
        const headlinePol = findDeviceHeadlinePolicy(policies, d.mac_address, category);

        return (
          <div
            key={d.mac_address}
            className={`p-2.5 rounded-lg hover:bg-slate-50 dark:hover:bg-white/[0.02] cursor-pointer transition-colors ${dim ? 'opacity-50' : ''} ${activePolicyMac === d.mac_address ? 'ring-1 ring-blue-500/50 bg-blue-50/5' : ''}`}
            onClick={() => onOpenPolicy(d.mac_address, d.display_name || d.hostname || d.mac_address)}
          >
            <div className="flex items-center gap-2 mb-1.5">
              <DeviceTypeIcon hostname={d.hostname} vendor={d.vendor} deviceClass={d.device_class} online={d.online} />
              <span className="font-medium text-slate-700 dark:text-slate-200 truncate flex-1 text-xs" title={name}>
                {name}
              </span>
              <PolicyIcon policy={headlinePol} />
              <span className="text-[10px] tabular-nums text-slate-400 dark:text-slate-500">
                {fmtBytes(d.total_bytes || 0)}
              </span>
            </div>
            <div className="h-1 w-full bg-slate-100 dark:bg-white/[0.06] rounded-full overflow-hidden mb-2">
              <div className="h-full bg-emerald-500/70 dark:bg-emerald-400/70 rounded-full" style={{ width: `${pct}%` }} />
            </div>
            <div className="flex flex-wrap gap-1.5">
              {shown.map(s => {
                const nestedPol = findNestedPolicy(policies, d.mac_address, s.service_name, category);
                const isActive = activeNested?.mac === d.mac_address && activeNested?.service === s.service_name;
                return (
                  <ServiceChip
                    key={s.service_name}
                    svc={s}
                    policy={nestedPol}
                    active={isActive}
                    onClick={() => onOpenNestedPolicy(
                      d.mac_address,
                      d.display_name || d.hostname || d.mac_address,
                      s.service_name,
                    )}
                  />
                );
              })}
              {hidden > 0 && (
                <button
                  type="button"
                  onClick={e => { e.stopPropagation(); onToggleExpand(d.mac_address); }}
                  className="text-[10px] px-2 py-1 rounded-lg bg-slate-100 dark:bg-white/[0.06] hover:bg-slate-200 dark:hover:bg-white/[0.10] text-slate-500 dark:text-slate-400 transition-colors"
                >
                  +{hidden} more
                </button>
              )}
              {expanded && allSvcs.length > CHIP_CAP && hidden === 0 && (
                <button
                  type="button"
                  onClick={e => { e.stopPropagation(); onToggleExpand(d.mac_address); }}
                  className="text-[10px] px-2 py-1 rounded-lg bg-slate-100 dark:bg-white/[0.06] hover:bg-slate-200 dark:hover:bg-white/[0.10] text-slate-500 dark:text-slate-400 transition-colors"
                >
                  show less
                </button>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// Chip — clickable to open a nested (device + service) policy. Shows an
// existing-policy icon when a rule already covers this pair.
function DeviceChip({ dev, policy, active, onClick }: {
  dev: { mac_address: string; display_name: string; hostname: string | null; vendor: string | null; device_class: string | null; online: boolean; bytes: number };
  policy?: CategoryPolicy | null;
  active?: boolean;
  onClick?: () => void;
}) {
  const name = dev.display_name || dev.hostname || dev.mac_address || '?';
  const dt = detectDeviceType({
    mac_address: dev.mac_address, hostname: dev.hostname ?? undefined,
    vendor: dev.vendor ?? undefined, device_class: dev.device_class ?? undefined, ips: [],
  } as any);
  return (
    <button
      type="button"
      onClick={e => { e.stopPropagation(); onClick?.(); }}
      className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-lg bg-slate-50 dark:bg-white/[0.04] border transition-colors max-w-[140px] ${
        active
          ? 'border-blue-400 dark:border-blue-500/60 ring-1 ring-blue-400/50'
          : 'border-slate-200 dark:border-white/[0.06] hover:bg-slate-100 dark:hover:bg-white/[0.08]'
      }`}
      title={`${name} — ${fmtBytes(dev.bytes || 0)}${policy ? ` · ${policy.action} (${policy.scope})` : ''}`}
    >
      <i className={`ph-duotone ${dt.icon} text-xs ${dev.online ? 'text-emerald-500' : 'text-slate-400'}`} />
      <span className="truncate text-[11px] text-slate-600 dark:text-slate-300">{name}</span>
      {policy && <PolicyIcon policy={policy} />}
    </button>
  );
}

function ServiceChip({ svc, policy, active, onClick }: {
  svc: { service_name: string; bytes: number };
  policy?: CategoryPolicy | null;
  active?: boolean;
  onClick?: () => void;
}) {
  const name = svcDisplayName(svc.service_name);
  return (
    <button
      type="button"
      onClick={e => { e.stopPropagation(); onClick?.(); }}
      className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-lg bg-slate-50 dark:bg-white/[0.04] border transition-colors max-w-[140px] ${
        active
          ? 'border-blue-400 dark:border-blue-500/60 ring-1 ring-blue-400/50'
          : 'border-slate-200 dark:border-white/[0.06] hover:bg-slate-100 dark:hover:bg-white/[0.08]'
      }`}
      title={`${name} — ${fmtBytes(svc.bytes || 0)}${policy ? ` · ${policy.action} (${policy.scope})` : ''}`}
    >
      <SvcLogo svc={svc.service_name} size={14} />
      <span className="truncate text-[11px] text-slate-600 dark:text-slate-300">{name}</span>
      {policy && <PolicyIcon policy={policy} />}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Policy Modal — centered popup for setting global/group/device rules.
// Replaces the previous inline panel which rendered below both kaders
// and was often off-screen when opened from a chip in the upper area.
// ---------------------------------------------------------------------------
type Scope = 'global' | 'group' | 'device';
type PolicyAction = 'allow' | 'alert' | 'block';

function InlinePolicyPanel({ target, onClose, onApplied }: {
  target: PolicyTarget;
  onClose: () => void;
  onApplied: () => void;
}) {
  const [scope, setScope] = useState<Scope>(target.defaultScope);
  const [action, setAction] = useState<PolicyAction>(target.defaultAction);
  const [pending, setPending] = useState(false);
  const [showCustom, setShowCustom] = useState(false);
  const dtRef = useRef<HTMLInputElement>(null);

  // Re-sync scope/action when the target changes (e.g. user clicks a
  // different chip while the panel is open). Without this, the panel
  // keeps the previous selection — confusing because the title
  // updated but the controls didn't.
  const targetKey = `${target.macAddress || ''}|${target.serviceName || ''}|${target.category}`;
  useEffect(() => {
    setScope(target.defaultScope);
    setAction(target.defaultAction);
    setShowCustom(false);
  }, [targetKey, target.defaultScope, target.defaultAction]);

  // Escape to close — matches the other modals in the app
  // (ReputationModal, CountryDrawer, DeviceDrawer).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  // Fetch groups for the device (if device scope)
  const { data: groups = [] } = useQuery<SharedDeviceGroup[]>({
    queryKey: ['device-groups', target.macAddress],
    queryFn: () => fetchDeviceGroups(target.macAddress!),
    enabled: !!target.macAddress,
    staleTime: 120_000,
  });
  const firstGroup = groups[0];

  const applyPolicy = useCallback(async (expiresAt?: string | null) => {
    setPending(true);
    try {
      await upsertPolicy({
        scope,
        mac_address: scope === 'device' ? (target.macAddress || null) : null,
        group_id: scope === 'group' && firstGroup ? firstGroup.id : null,
        service_name: target.serviceName || null,
        category: !target.serviceName ? (target.category || null) : null,
        action,
        expires_at: expiresAt ?? null,
      });
      const targetLabel = target.serviceName
        ? svcDisplayName(target.serviceName)
        : target.deviceName || target.category;
      const scopeLabel = scope === 'global' ? 'globally' : scope === 'group' ? `for ${firstGroup?.name || 'group'}` : `for ${target.deviceName || 'device'}`;
      window.showToast?.(`${targetLabel}: ${action} ${scopeLabel}`, 'success');
      onApplied();
    } catch (err) {
      window.showToast?.(`Failed: ${(err as Error).message}`, 'error');
    } finally {
      setPending(false);
    }
  }, [scope, action, target, firstGroup, onApplied]);

  const snoozeExpiry = (hours: number) => new Date(Date.now() + hours * 3600_000).toISOString();

  // Build a more descriptive title for the nested case so it's obvious
  // what exactly is being policed (e.g. "TikTok on Robin iPhone").
  const titleNode = target.serviceName && target.macAddress && target.deviceName
    ? <>{svcDisplayName(target.serviceName)} <span className="text-slate-400">on</span> {target.deviceName}</>
    : <>{target.serviceName ? svcDisplayName(target.serviceName) : (target.deviceName || target.category)}</>;

  return (
    <div
      className="fixed inset-0 z-[120] flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" />
      <div
        className="relative w-full max-w-md bg-white dark:bg-slate-800 border border-blue-400/40 dark:border-blue-500/30 rounded-xl p-5 shadow-2xl shadow-blue-500/10 max-h-[90vh] overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2 min-w-0">
          <i className="ph-duotone ph-shield-warning text-base text-blue-500 flex-shrink-0" />
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200 truncate">
            Set policy for <span className="text-blue-500">{titleNode}</span>
          </h3>
        </div>
        <button
          onClick={onClose}
          aria-label="Close"
          className="w-7 h-7 flex items-center justify-center rounded-lg hover:bg-slate-100 dark:hover:bg-white/[0.08] text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 transition-colors text-lg leading-none flex-shrink-0"
        >
          ×
        </button>
      </div>

      <p className="text-[10px] text-slate-500 mb-3">Block or allow this {target.serviceName ? 'service' : 'category'} — affects actual network traffic.</p>

      {/* Scope + Action — stacks vertically on mobile */}
      <div className="flex flex-col sm:flex-row sm:items-start gap-3 mb-3">
        <div className="min-w-0">
          <span className="text-[10px] text-slate-500 block mb-1.5">Apply to</span>
          <div className="flex items-center gap-1 bg-white/[0.04] dark:bg-white/[0.04] rounded-lg p-0.5 border border-slate-200 dark:border-white/[0.06]">
            <ScopeBtn active={scope === 'global'} onClick={() => setScope('global')} icon="ph-globe" label="Global" tooltip="Apply to all devices" />
            {firstGroup && (
              <ScopeBtn active={scope === 'group'} onClick={() => setScope('group')} icon="ph-users-three" label="Group" tooltip={`Apply to all devices in '${firstGroup.name}'`} />
            )}
            {target.macAddress && (
              <ScopeBtn active={scope === 'device'} onClick={() => setScope('device')} icon="ph-device-mobile" label="Device" tooltip={`Apply only to ${target.deviceName || 'this device'}`} />
            )}
          </div>
        </div>
        <div className="min-w-0">
          <span className="text-[10px] text-slate-500 block mb-1.5">Action</span>
          <div className="flex gap-1 bg-white/[0.04] dark:bg-white/[0.04] rounded-lg p-0.5 border border-slate-200 dark:border-white/[0.06]">
            <ActionBtn active={action === 'allow'} onClick={() => setAction('allow')} icon="ph-check" label="Allow" tooltip="Explicitly allow" color="emerald" />
            <ActionBtn active={action === 'alert'} onClick={() => setAction('alert')} icon="ph-warning" label="Alert" tooltip="Allow but warn" color="amber" />
            <ActionBtn active={action === 'block'} onClick={() => setAction('block')} icon="ph-x" label="Block" tooltip="Block all traffic" color="red" />
          </div>
        </div>
      </div>

      {/* Duration */}
      <div>
        <span className="text-[10px] text-slate-500 block mb-1.5">Duration</span>
        {!showCustom ? (
          <div className="flex flex-wrap gap-1.5">
            {[1, 4, 8, 24].map(h => (
              <button key={h} disabled={pending} onClick={() => applyPolicy(snoozeExpiry(h))}
                className="px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-blue-500/15 border border-slate-200 dark:border-white/[0.06] hover:border-blue-500/20 text-slate-500 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-300 text-xs font-medium transition-colors disabled:opacity-50"
                title={`${action} for ${h} hours`}
              >{h}h</button>
            ))}
            <button onClick={() => setShowCustom(true)}
              className="px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-slate-200 dark:border-white/[0.06] text-slate-500 dark:text-slate-400 text-xs font-medium transition-colors"
              title="Pick a custom date and time"
            >
              <i className="ph-duotone ph-clock-countdown text-xs" /> Custom...
            </button>
            <span className="w-px bg-slate-200 dark:bg-white/[0.06] mx-0.5" />
            <button disabled={pending} onClick={() => applyPolicy(null)}
              className="px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-slate-200 dark:border-white/[0.06] text-slate-500 dark:text-slate-400 text-xs font-medium transition-colors disabled:opacity-50"
              title={`${action} permanently`}
            >Permanent</button>
          </div>
        ) : (
          <div className="flex flex-wrap items-center gap-2">
            <input ref={dtRef} type="datetime-local"
              className="flex-1 min-w-[180px] bg-white dark:bg-white/[0.06] border border-slate-200 dark:border-white/[0.08] rounded-lg px-3 py-1.5 text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-1 focus:ring-blue-500" />
            <button disabled={pending} onClick={() => { const v = dtRef.current?.value; if (v) applyPolicy(new Date(v).toISOString()); }}
              className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-colors disabled:opacity-50">Set</button>
            <button onClick={() => setShowCustom(false)}
              className="px-3 py-1.5 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] text-slate-400 text-xs font-medium transition-colors">Cancel</button>
          </div>
        )}
      </div>
      </div>
    </div>
  );
}

function ScopeBtn({ active, onClick, icon, label, tooltip }: { active: boolean; onClick: () => void; icon: string; label: string; tooltip: string }) {
  return (
    <button onClick={onClick} title={tooltip}
      className={`flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors ${
        active ? 'bg-blue-600 text-white shadow-sm' : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300'
      }`}>
      <i className={`ph-duotone ${icon} text-xs`} /> {label}
    </button>
  );
}

function ActionBtn({ active, onClick, icon, label, tooltip, color }: { active: boolean; onClick: () => void; icon: string; label: string; tooltip: string; color: string }) {
  const activeCls = color === 'red' ? 'bg-red-500 text-white shadow-sm font-semibold'
    : color === 'amber' ? 'bg-amber-500 text-white shadow-sm font-semibold'
    : 'bg-emerald-500 text-white shadow-sm font-semibold';
  return (
    <button onClick={onClick} title={tooltip}
      className={`flex items-center gap-1 px-3 py-1 rounded-md text-[11px] font-medium transition-colors ${active ? activeCls : 'text-slate-500 dark:text-slate-400'}`}>
      <i className={`ph-duotone ${icon} text-xs`} /> {label}
    </button>
  );
}

function HonestyBlock({ honesty }: { honesty: HonestyInfo }) {
  const total = (honesty.known_bytes || 0) + (honesty.unknown_bytes || 0);
  const knownPct = total > 0 ? Math.round((honesty.known_bytes / total) * 100) : 0;
  const unknownPct = 100 - knownPct;

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
      <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200 mb-3 flex items-center gap-2">
        <i className="ph-duotone ph-eye-slash text-base text-slate-500" />
        <span>What we can and can't see</span>
      </h3>
      <div className="text-xs text-slate-500 dark:text-slate-400 space-y-1.5">
        <div className="flex items-center gap-2">
          <i className="ph-duotone ph-check-circle text-emerald-500" />
          <span>
            Classified traffic: <strong className="text-slate-700 dark:text-slate-200">{fmtBytes(honesty.known_bytes || 0)}</strong> ({knownPct}%)
          </span>
        </div>
        <div className="flex items-center gap-2">
          <i className="ph-duotone ph-question text-amber-500" />
          <span>
            Encrypted / unknown: <strong className="text-slate-700 dark:text-slate-200">{fmtBytes(honesty.unknown_bytes || 0)}</strong> ({unknownPct}%)
          </span>
        </div>
        <p className="text-[11px] text-slate-400 dark:text-slate-500 pt-1 leading-relaxed">
          AI-Radar only reports what it can positively identify. Traffic over QUIC/ECH or unknown SNIs is counted but not attributed to a service.
        </p>
      </div>
    </div>
  );
}
