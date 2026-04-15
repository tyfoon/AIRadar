import { useState, useMemo, useCallback, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchFamilyMeta, fetchFamilyOverview, fetchFamilyCategory, fetchGroups } from './api';
import type {
  OverviewCard, CategoryService, CategoryDevice, CategoryPolicy,
  HonestyInfo, DeviceGroup,
} from './types';
import { SvcLogo, svcDisplayName } from '../category/serviceHelpers';
import { detectDeviceType } from '../utils/devices';

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

/** Open the vanilla alert-action modal (still shared across vanilla + React) */
function openModal(opts: Record<string, any>) {
  const fn = (window as any).openAlertActionModal;
  if (typeof fn === 'function') fn(opts);
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
            />
          )}
        </div>
      </div>

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

function ServicesKader({ services, category, policies, expandedSet, onToggleExpand }: {
  services: CategoryService[];
  category: string;
  policies: CategoryPolicy[];
  expandedSet: Set<string>;
  onToggleExpand: (key: string) => void;
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
            className={`p-2.5 rounded-lg hover:bg-slate-50 dark:hover:bg-white/[0.02] cursor-pointer transition-colors ${dim ? 'opacity-50' : ''}`}
            onClick={() => openModal({
              mode: 'content', service_or_dest: s.service_name, category,
              mac_address: null, default_scope: 'global', default_action: 'block', alert_type: 'content_rule',
            })}
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
              {shown.map(d => (
                <DeviceChip key={d.mac_address} dev={d} serviceName={s.service_name} category={category} />
              ))}
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

function DevicesKader({ devices, category, policies, expandedSet, onToggleExpand }: {
  devices: CategoryDevice[];
  category: string;
  policies: CategoryPolicy[];
  expandedSet: Set<string>;
  onToggleExpand: (key: string) => void;
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
            className={`p-2.5 rounded-lg hover:bg-slate-50 dark:hover:bg-white/[0.02] cursor-pointer transition-colors ${dim ? 'opacity-50' : ''}`}
            onClick={() => openModal({
              mode: 'content', service_or_dest: null, category,
              mac_address: d.mac_address, hostname: d.hostname, vendor: d.vendor,
              display_name: d.display_name,
              default_scope: 'device', default_action: 'block', alert_type: 'content_rule',
            })}
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
              {shown.map(s => (
                <ServiceChip key={s.service_name} svc={s} mac={d.mac_address} category={category} />
              ))}
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

function DeviceChip({ dev, serviceName, category }: {
  dev: { mac_address: string; display_name: string; hostname: string | null; vendor: string | null; device_class: string | null; online: boolean; bytes: number };
  serviceName: string;
  category: string;
}) {
  const name = dev.display_name || dev.hostname || dev.mac_address || '?';
  const dt = detectDeviceType({
    mac_address: dev.mac_address, hostname: dev.hostname ?? undefined,
    vendor: dev.vendor ?? undefined, device_class: dev.device_class ?? undefined, ips: [],
  } as any);
  return (
    <button
      type="button"
      onClick={e => {
        e.stopPropagation();
        const dm = (window as any).deviceMap?.[dev.mac_address] || {};
        openModal({
          mode: 'content', service_or_dest: serviceName, category,
          mac_address: dev.mac_address, hostname: dm.hostname, vendor: dm.vendor,
          display_name: dm.display_name || dev.display_name,
          default_scope: 'device', default_action: 'block', alert_type: 'content_rule',
        });
      }}
      className="inline-flex items-center gap-1.5 px-2 py-1 rounded-lg bg-slate-50 dark:bg-white/[0.04] hover:bg-slate-100 dark:hover:bg-white/[0.08] border border-slate-200 dark:border-white/[0.06] transition-colors max-w-[140px]"
      title={`${name} — ${fmtBytes(dev.bytes || 0)}`}
    >
      <i className={`ph-duotone ${dt.icon} text-xs ${dev.online ? 'text-emerald-500' : 'text-slate-400'}`} />
      <span className="truncate text-[11px] text-slate-600 dark:text-slate-300">{name}</span>
    </button>
  );
}

function ServiceChip({ svc, mac, category }: {
  svc: { service_name: string; bytes: number };
  mac: string;
  category: string;
}) {
  const name = svcDisplayName(svc.service_name);
  return (
    <button
      type="button"
      onClick={e => {
        e.stopPropagation();
        const dm = (window as any).deviceMap?.[mac] || {};
        openModal({
          mode: 'content', service_or_dest: svc.service_name, category,
          mac_address: mac, hostname: dm.hostname, vendor: dm.vendor, display_name: dm.display_name,
          default_scope: 'device', default_action: 'block', alert_type: 'content_rule',
        });
      }}
      className="inline-flex items-center gap-1.5 px-2 py-1 rounded-lg bg-slate-50 dark:bg-white/[0.04] hover:bg-slate-100 dark:hover:bg-white/[0.08] border border-slate-200 dark:border-white/[0.06] transition-colors max-w-[140px]"
      title={`${name} — ${fmtBytes(svc.bytes || 0)}`}
    >
      <SvcLogo svc={svc.service_name} size={14} />
      <span className="truncate text-[11px] text-slate-600 dark:text-slate-300">{name}</span>
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
