import { useState, useMemo } from 'react';
import type { DeviceMatrix as MatrixData, DeviceMap, DeviceEvent } from './types';
import { detectDeviceType, isDeviceOnline, bestDeviceName, latestIp, ipSummary, TYPE_TO_GROUP, type Device } from '../utils/devices';
import { getCategoryGroups, categorizeService } from '../utils/categories';
import { svcDisplayName, svcColor } from '../utils/services';
import { fmtBytes } from '../utils/format';
import { t } from '../utils/i18n';
import SvcLogo from './SvcLogo';
import PhIcon from './PhIcon';

interface Props {
  matrix: MatrixData;
  deviceMap: DeviceMap;
  policyByService: Record<string, string>;
  onOpenDrawer: (mac: string, service?: string, category?: string) => void;
  onRename: (mac: string) => void;
  onRefresh: (mac: string) => void;
  onNavigateRules: (mac: string) => void;
  onGenerateReport: (mac: string) => void;
}

type SortCol = 'name' | 'total' | string;
type SortDir = 'asc' | 'desc';

export default function DeviceMatrix({
  matrix, deviceMap, policyByService,
  onOpenDrawer, onRename, onRefresh, onNavigateRules, onGenerateReport,
}: Props) {
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [hideInactive, setHideInactive] = useState(false);
  const [sortCol, setSortCol] = useState<SortCol>('total');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());

  const { matrix: matrixData, svcCategoryMap, allServices, deviceMacs, globalMax } = matrix;

  const groups = useMemo(() =>
    getCategoryGroups().map(g => {
      const svcs = [...allServices].filter(s => categorizeService(s, svcCategoryMap) === g.key).sort();
      return { ...g, services: svcs };
    }).filter(g => g.services.length > 0),
    [allServices, svcCategoryMap]
  );

  // Type chip counts
  const groupCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    deviceMacs.forEach(mac => {
      const dev = deviceMap[mac] || null;
      const dt = detectDeviceType(dev);
      const group = TYPE_TO_GROUP[dt.type] || 'Other';
      counts[group] = (counts[group] || 0) + 1;
    });
    return counts;
  }, [deviceMacs, deviceMap]);

  // Filter + sort
  const filteredMacs = useMemo(() => {
    let macs = [...deviceMacs];

    if (typeFilter !== 'all') {
      macs = macs.filter(mac => {
        const dev = deviceMap[mac] || null;
        const dt = detectDeviceType(dev);
        return (TYPE_TO_GROUP[dt.type] || 'Other') === typeFilter;
      });
    }

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      macs = macs.filter(mac => {
        const dev = deviceMap[mac] || null;
        const name = bestDeviceName(mac, dev).toLowerCase();
        const hostname = (dev?.hostname || '').toLowerCase();
        const ip = dev ? latestIp(dev).toLowerCase() : mac.replace('_ip_', '');
        const dt = detectDeviceType(dev);
        const vendor = (dev?.vendor || '').toLowerCase();
        return name.includes(q) || hostname.includes(q) || ip.includes(q) || dt.type.toLowerCase().includes(q) || vendor.includes(q);
      });
    }

    if (hideInactive) {
      macs = macs.filter(mac => {
        const row = matrixData[mac] || {};
        return Object.values(row).reduce((s, v) => s + v.count, 0) > 0;
      });
    }

    // Sort
    macs.sort((a, b) => {
      const devA = deviceMap[a] || null;
      const devB = deviceMap[b] || null;
      const rowA = matrixData[a] || {};
      const rowB = matrixData[b] || {};
      let cmp = 0;
      if (sortCol === 'name') {
        cmp = bestDeviceName(a, devA).localeCompare(bestDeviceName(b, devB));
      } else if (sortCol.startsWith('grp_')) {
        const grpKey = sortCol.slice(4);
        const grpSvcs = [...allServices].filter(s => categorizeService(s, svcCategoryMap) === grpKey);
        const gA = grpSvcs.reduce((s, svc) => s + (rowA[svc]?.count || 0), 0);
        const gB = grpSvcs.reduce((s, svc) => s + (rowB[svc]?.count || 0), 0);
        cmp = gA - gB;
      } else {
        const tA = Object.values(rowA).reduce((s, v) => s + v.count, 0);
        const tB = Object.values(rowB).reduce((s, v) => s + v.count, 0);
        cmp = tA - tB;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });

    return macs;
  }, [deviceMacs, deviceMap, matrixData, allServices, svcCategoryMap, typeFilter, searchQuery, hideInactive, sortCol, sortDir]);

  const toggleSort = (col: SortCol) => {
    if (sortCol === col) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortCol(col);
      setSortDir(col === 'name' ? 'asc' : 'desc');
    }
  };

  const toggleGroup = (key: string) => {
    setExpandedGroups(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  };

  const sortArrow = (col: string) => {
    if (sortCol !== col) return <span className="text-[10px] opacity-30 ml-0.5">↕</span>;
    return sortDir === 'asc'
      ? <span className="text-[10px] text-indigo-400 ml-0.5">↑</span>
      : <span className="text-[10px] text-indigo-400 ml-0.5">↓</span>;
  };

  // Stats
  const totalDevices = deviceMacs.length;
  const totalEvents = Object.values(matrixData).reduce((s, row) => s + Object.values(row).reduce((ss, v) => ss + v.count, 0), 0);
  const totalUploads = Object.values(matrixData).reduce((s, row) => s + Object.values(row).reduce((ss, v) => ss + v.uploads, 0), 0);
  const violationMacs = Object.entries(matrixData).filter(([, svcs]) =>
    Object.keys(svcs).some(svc => policyByService[svc] === 'alert' || policyByService[svc] === 'block')
  ).length;

  return (
    <div className="space-y-4">
      {/* Stats bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard label={t('dev.totalDevices') || 'Devices'} value={totalDevices} />
        <StatCard label={t('dev.violations') || 'Violations'} value={violationMacs} warn={violationMacs > 0} />
        <StatCard label={t('dev.events') || 'Events'} value={totalEvents.toLocaleString()} />
        <StatCard label={t('dev.uploads') || 'Uploads'} value={totalUploads} warn={totalUploads > 0} />
      </div>

      {/* Search + filters */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
        <div className="relative flex-1 w-full sm:w-auto">
          <input
            type="text"
            placeholder={t('dev.searchPlaceholder') || 'Search devices...'}
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full sm:w-64 px-3 py-2 text-sm rounded-lg border border-slate-200 dark:border-white/[0.06] bg-white dark:bg-white/[0.03] text-slate-700 dark:text-slate-200 placeholder:text-slate-400 outline-none focus:ring-2 focus:ring-indigo-500/30"
          />
          {searchQuery && (
            <button onClick={() => setSearchQuery('')} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600">
              <i className="ph-bold ph-x text-xs" />
            </button>
          )}
        </div>
        <label className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400 cursor-pointer">
          <input type="checkbox" checked={hideInactive} onChange={e => setHideInactive(e.target.checked)} className="rounded border-slate-300 dark:border-slate-600" />
          {t('dev.hideInactive') || 'Hide inactive'}
        </label>
      </div>

      {/* Type chips */}
      <div className="flex flex-wrap gap-1.5">
        <TypeChip label={t('dev.filterAll') || 'All'} count={totalDevices} active={typeFilter === 'all'} onClick={() => setTypeFilter('all')} />
        {Object.keys(groupCounts).sort().map(grp => (
          <TypeChip key={grp} label={grp} count={groupCounts[grp]} active={typeFilter === grp} onClick={() => setTypeFilter(grp)} />
        ))}
      </div>

      {/* Matrix table */}
      <div className="overflow-x-auto rounded-xl border border-slate-200 dark:border-white/[0.05] bg-white dark:bg-white/[0.02]">
        <table className="w-full text-left">
          <thead className="bg-slate-50 dark:bg-[#0B0C10] text-xs text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-white/[0.06]">
            <tr>
              <th
                className="py-3 px-4 font-medium sticky left-0 bg-slate-50 dark:bg-[#0B0C10] z-10 min-w-[240px] cursor-pointer select-none hover:text-indigo-400 transition-colors"
                onClick={() => toggleSort('name')}
              >
                <span className="inline-flex items-center">{t('dev.device') || 'Device'} {sortArrow('name')}</span>
              </th>
              {groups.map(g => (
                <th
                  key={g.key}
                  className="py-3 px-3 font-medium text-center min-w-[180px] cursor-pointer select-none hover:text-indigo-400 transition-colors border-l border-slate-200 dark:border-white/[0.06] hidden sm:table-cell"
                  onClick={e => e.shiftKey ? toggleGroup(g.key) : toggleSort(`grp_${g.key}`)}
                  title={`Click to sort · Shift+click to ${expandedGroups.has(g.key) ? 'collapse' : 'expand'}`}
                >
                  <span className="inline-flex items-center gap-1 justify-center">
                    <i className={`ph-duotone ${g.icon} text-base`} /> {g.label} {sortArrow(`grp_${g.key}`)}
                    <span className="text-[10px] opacity-60">{expandedGroups.has(g.key) ? '▾' : '▸'}</span>
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filteredMacs.length === 0 ? (
              <tr>
                <td colSpan={1 + groups.length} className="py-12 text-center text-slate-400 dark:text-slate-500 text-sm">
                  {t('dev.noActivity') || 'No devices found'}
                </td>
              </tr>
            ) : filteredMacs.map(mac => (
              <DeviceRow
                key={mac}
                mac={mac}
                device={deviceMap[mac] || null}
                row={matrixData[mac] || {}}
                groups={groups}
                expandedGroups={expandedGroups}
                globalMax={globalMax}
                svcCategoryMap={svcCategoryMap}
                policyByService={policyByService}
                onOpenDrawer={onOpenDrawer}
                onRename={onRename}
                onRefresh={onRefresh}
                onNavigateRules={onNavigateRules}
                onGenerateReport={onGenerateReport}
              />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// --- Sub components ---

function StatCard({ label, value, warn }: { label: string; value: number | string; warn?: boolean }) {
  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl px-4 py-3">
      <div className={`text-2xl font-bold tabular-nums ${warn ? 'text-amber-600 dark:text-amber-400' : 'text-slate-700 dark:text-slate-100'}`}>
        {value}
      </div>
      <div className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">{label}</div>
    </div>
  );
}

function TypeChip({ label, count, active, onClick }: { label: string; count: number; active: boolean; onClick: () => void }) {
  const cls = active
    ? 'bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300 border-blue-300 dark:border-blue-600'
    : 'bg-slate-50 dark:bg-white/[0.04] text-slate-500 dark:text-slate-400 border-slate-200 dark:border-white/[0.06] hover:bg-slate-100 dark:hover:bg-white/[0.08]';
  return (
    <button onClick={onClick} className={`px-2.5 py-1 rounded-md text-[11px] font-medium border transition-colors ${cls}`}>
      {label} <span className="ml-0.5 text-[10px] opacity-60">{count}</span>
    </button>
  );
}

interface DeviceRowProps {
  mac: string;
  device: Device | null;
  row: Record<string, { count: number; uploads: number }>;
  groups: { key: string; label: string; icon: string; services: string[] }[];
  expandedGroups: Set<string>;
  globalMax: number;
  svcCategoryMap: Record<string, string>;
  policyByService: Record<string, string>;
  onOpenDrawer: (mac: string, service?: string, category?: string) => void;
  onRename: (mac: string) => void;
  onRefresh: (mac: string) => void;
  onNavigateRules: (mac: string) => void;
  onGenerateReport: (mac: string) => void;
}

function DeviceRow({
  mac, device, row, groups, expandedGroups, globalMax, svcCategoryMap, policyByService,
  onOpenDrawer, onRename, onRefresh, onNavigateRules, onGenerateReport,
}: DeviceRowProps) {
  const total = Object.values(row).reduce((s, v) => s + v.count, 0);
  const isQuiet = total === 0;
  const dt = detectDeviceType(device);
  const online = device ? isDeviceOnline(device) : false;
  const name = bestDeviceName(mac, device);
  const ipInfo = device ? ipSummary(device) : { primary: mac.replace('_ip_', ''), extra: 0 };

  return (
    <tr className={`border-b border-slate-100 dark:border-white/[0.04] hover:bg-slate-50 dark:hover:bg-slate-700/20 transition-colors group ${isQuiet ? 'opacity-50' : ''}`}>
      <td className="py-3 px-4 sticky left-0 bg-white dark:bg-[#0B0C10] z-10">
        <div className="flex items-center gap-1">
          <span
            className="device-name cursor-pointer hover:text-indigo-500 transition-colors text-sm font-medium truncate max-w-[180px]"
            onClick={() => onOpenDrawer(mac)}
            title={name}
          >
            {name}
          </span>
          <button onClick={() => onRename(mac)} className="opacity-0 group-hover:opacity-100 ml-1 text-slate-400 hover:text-blue-500 transition-all" title={t('dev.editName') || 'Edit name'}>
            <i className="ph-duotone ph-pencil-simple text-sm" />
          </button>
          {device && (
            <>
              <button onClick={() => onRefresh(mac)} className="opacity-0 group-hover:opacity-100 ml-0.5 text-slate-400 hover:text-blue-500 transition-all" title="Refresh">
                <i className="ph-duotone ph-arrows-clockwise text-sm" />
              </button>
              <button onClick={() => onNavigateRules(mac)} className="opacity-0 group-hover:opacity-100 ml-0.5 text-slate-400 hover:text-blue-500 transition-all" title={t('rules.manageRules') || 'Rules'}>
                <i className="ph-duotone ph-shield-check text-sm" />
              </button>
              <button
                onClick={() => onGenerateReport(mac)}
                className="opacity-0 group-hover:opacity-100 ml-2 px-1.5 py-0.5 text-[10px] font-semibold rounded bg-gradient-to-r from-indigo-500/80 to-purple-500/80 text-white hover:from-indigo-500 hover:to-purple-500 transition-all leading-none whitespace-nowrap"
                title={t('dev.aiRecap') || 'AI Recap'}
              >
                ✨ AI
              </button>
            </>
          )}
        </div>
        <p className="text-[10px] text-slate-400 dark:text-slate-500 font-mono">
          {ipInfo.primary}{ipInfo.extra > 0 && <span className="text-[10px] text-slate-400 dark:text-slate-500"> (+{ipInfo.extra} other{ipInfo.extra > 1 ? 's' : ''})</span>}
        </p>
        {/* Device type tag */}
        <span className="inline-flex items-center flex-wrap gap-x-1.5 gap-y-0 text-[10px] text-slate-400 dark:text-slate-500">
          <span className={`relative inline-flex items-center justify-center w-5 h-5 text-base leading-none flex-shrink-0 ${online ? 'text-emerald-500 dark:text-emerald-400' : 'text-slate-400 dark:text-slate-600'}`} title={`${dt.type}${online ? ' · online' : ' · offline'}`}>
            <PhIcon icon={dt.icon} className="text-base" />
            {online && <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-emerald-400 border border-white dark:border-[#0B0C10]" />}
          </span>
          {' '}{dt.type}{device?.vendor ? ` · ${device.vendor}` : ''}
          {device?.os_name && (
            <span className="ml-1 px-1.5 py-0.5 rounded-full bg-indigo-50 dark:bg-indigo-950/30 text-indigo-600 dark:text-indigo-400 text-[10px] font-medium">
              {device.os_name}{device.os_version ? ` ${device.os_version}` : ''}
            </span>
          )}
        </span>
      </td>
      {groups.map(g => (
        <CategoryCells
          key={g.key}
          mac={mac}
          group={g}
          row={row}
          expanded={expandedGroups.has(g.key)}
          globalMax={globalMax}
          policyByService={policyByService}
          onOpenDrawer={onOpenDrawer}
        />
      ))}
    </tr>
  );
}

function CategoryCells({
  mac, group, row, expanded, globalMax, policyByService, onOpenDrawer,
}: {
  mac: string;
  group: { key: string; services: string[] };
  row: Record<string, { count: number; uploads: number }>;
  expanded: boolean;
  globalMax: number;
  policyByService: Record<string, string>;
  onOpenDrawer: (mac: string, service?: string, category?: string) => void;
}) {
  const items = group.services
    .map(s => ({ s, count: row[s]?.count || 0, uploads: row[s]?.uploads || 0 }))
    .filter(x => x.count > 0)
    .sort((a, b) => b.count - a.count);

  return (
    <>
      <td className="py-2.5 px-2 text-center border-l border-slate-100 dark:border-white/[0.04] hidden sm:table-cell">
        {items.length === 0 ? (
          <span className="inline-block py-1 text-[10px] text-slate-300 dark:text-slate-600">—</span>
        ) : (
          <div className="flex items-center justify-center gap-1.5 flex-wrap">
            {items.slice(0, 5).map(({ s, uploads }) => (
              <span
                key={s}
                className="cursor-pointer hover:scale-110 transition-transform"
                title={`${svcDisplayName(s)}${uploads > 0 ? ` (${uploads}↑)` : ''}`}
                onClick={e => { e.stopPropagation(); onOpenDrawer(mac, s, group.key); }}
              >
                <SvcLogo service={s} size={24} showUploadDot={uploads > 0} />
              </span>
            ))}
            {items.length > 5 && (
              <span
                className="text-[10px] font-semibold text-slate-500 dark:text-slate-400 px-1 cursor-pointer hover:text-blue-500"
                onClick={e => { e.stopPropagation(); onOpenDrawer(mac, undefined, group.key); }}
              >
                +{items.length - 5}
              </span>
            )}
          </div>
        )}
      </td>
      {expanded && group.services.map(s => {
        const v = row[s];
        const policy = policyByService[s] || null;
        return (
          <td key={s} className="py-2.5 px-2 text-center cursor-pointer hidden sm:table-cell" onClick={() => onOpenDrawer(mac, s)}>
            <HeatCell count={v?.count || 0} uploads={v?.uploads || 0} globalMax={globalMax} policyAction={policy} />
          </td>
        );
      })}
    </>
  );
}

function HeatCell({ count, uploads, globalMax, policyAction }: { count: number; uploads: number; globalMax: number; policyAction: string | null }) {
  if (!count) return <span className="inline-block w-full py-1 rounded text-[10px] text-slate-300 dark:text-slate-600">—</span>;

  const intensity = Math.min(count / (globalMax || 1), 1);
  let bg: string, text: string;
  let icon = '';

  if (policyAction === 'block') {
    if (intensity < 0.3) { bg = 'bg-red-100 dark:bg-red-900/30'; text = 'text-red-700 dark:text-red-300'; }
    else if (intensity < 0.6) { bg = 'bg-red-300 dark:bg-red-700/50'; text = 'text-red-900 dark:text-red-100'; }
    else { bg = 'bg-red-400 dark:bg-red-600/70'; text = 'text-white dark:text-red-100'; }
    icon = 'ph-prohibit';
  } else if (policyAction === 'alert') {
    if (intensity < 0.3) { bg = 'bg-amber-100 dark:bg-amber-900/30'; text = 'text-amber-700 dark:text-amber-300'; }
    else if (intensity < 0.6) { bg = 'bg-amber-200 dark:bg-amber-800/50'; text = 'text-amber-800 dark:text-amber-200'; }
    else { bg = 'bg-amber-300 dark:bg-amber-700/60'; text = 'text-amber-900 dark:text-amber-100'; }
    icon = 'ph-warning';
  } else {
    if (intensity < 0.15) { bg = 'bg-blue-100 dark:bg-blue-900/40'; text = 'text-blue-700 dark:text-blue-300'; }
    else if (intensity < 0.4) { bg = 'bg-blue-200 dark:bg-blue-800/50'; text = 'text-blue-800 dark:text-blue-200'; }
    else if (intensity < 0.7) { bg = 'bg-blue-300 dark:bg-blue-700/60'; text = 'text-blue-900 dark:text-blue-100'; }
    else { bg = 'bg-blue-400 dark:bg-blue-600/70'; text = 'text-white dark:text-blue-100'; }
  }

  return (
    <span className={`inline-block w-full py-1 rounded text-[11px] font-medium tabular-nums ${bg} ${text}`}>
      {count}
      {icon && <i className={`ph-duotone ${icon} text-[10px] ml-0.5`} />}
      {uploads > 0 && <span className="text-orange-500 ml-0.5" title={`${uploads} upload(s)`}>▲</span>}
    </span>
  );
}
