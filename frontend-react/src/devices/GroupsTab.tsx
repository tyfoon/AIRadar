import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import type { Group, DeviceMap } from './types';
import { fetchGroups, createGroup, deleteGroup, fetchGroupMembers, addGroupMember, removeGroupMember } from './api';
import { bestDeviceName } from '../utils/devices';
import { t } from '../utils/i18n';

declare global {
  interface Window {
    navigate?: (page: string) => void;
    showToast?: (msg: string, type?: string) => void;
    styledConfirm?: (title: string, msg: string) => Promise<boolean>;
  }
}

interface Props {
  deviceMap: DeviceMap;
}

// ---------------------------------------------------------------------------
// Groups tab — unified list of suggested + user-created groups.
// There is only ONE kind of group. Policies attach to any of them.
// The ✨ / 🛠️ indicators are informational only.
// ---------------------------------------------------------------------------

type FilterKey = 'all' | 'suggested' | 'modified' | 'user';

function groupState(g: Group): 'suggested' | 'modified' | 'user' {
  if (g.origin === 'suggested' && !g.modified_at) return 'suggested';
  if (g.origin === 'suggested') return 'modified';
  return 'user';
}

export default function GroupsTab({ deviceMap }: Props) {
  const [newName, setNewName] = useState('');
  const [filter, setFilter] = useState<FilterKey>('all');
  const [openGroupId, setOpenGroupId] = useState<number | null>(null);
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ['groups'],
    queryFn: fetchGroups,
    staleTime: 30_000,
  });

  const createMut = useMutation({
    mutationFn: (name: string) => createGroup(name),
    onSuccess: () => {
      setNewName('');
      queryClient.invalidateQueries({ queryKey: ['groups'] });
      window.showToast?.(t('groups.created') || 'Group created', 'success');
    },
    onError: (err: Error) => window.showToast?.(`Failed: ${err.message}`, 'error'),
  });

  const deleteMut = useMutation({
    mutationFn: (id: number) => deleteGroup(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['groups'] });
      window.showToast?.(t('groups.deleted') || 'Group deleted', 'success');
    },
  });

  const groups = data?.groups || [];
  const counts = useMemo(() => {
    const c = { all: groups.length, suggested: 0, modified: 0, user: 0 };
    groups.forEach(g => { c[groupState(g)] += 1; });
    return c;
  }, [groups]);

  const filtered = useMemo(() => {
    if (filter === 'all') return groups;
    return groups.filter(g => groupState(g) === filter);
  }, [groups, filter]);

  const handleDelete = async (group: Group) => {
    const isSuggested = groupState(group) !== 'user';
    const msg = isSuggested
      ? `"${group.name}" is een voorstel van AI-Radar. Verwijderen betekent ook de bijbehorende policies kwijt — hij komt niet automatisch terug.`
      : `Dit verwijdert de groep, alle lidmaatschappen en alle policies die eraan hangen.`;
    const ok = window.styledConfirm
      ? await window.styledConfirm('Groep verwijderen', msg)
      : confirm(`Groep "${group.name}" verwijderen?`);
    if (ok) deleteMut.mutate(group.id);
  };

  return (
    <div className="space-y-4">
      {/* Header row: title + filter chips + new group button */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2 flex-wrap">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-200">Groepen</h2>
          {!isLoading && <span className="text-[11px] text-slate-500">{counts.all} totaal</span>}
          {/* Filter chips — only show if there are any suggested groups at all */}
          {(counts.suggested > 0 || counts.modified > 0) && (
            <div className="flex items-center gap-1 ml-2 flex-wrap">
              <FilterChip active={filter === 'all'} onClick={() => setFilter('all')} label={`Alles · ${counts.all}`} />
              {counts.suggested > 0 && (
                <FilterChip
                  active={filter === 'suggested'}
                  onClick={() => setFilter('suggested')}
                  label={<><i className="ph-fill ph-sparkle text-[10px] text-indigo-400/80 mr-1" />Voorgesteld · {counts.suggested}</>}
                />
              )}
              {counts.modified > 0 && (
                <FilterChip
                  active={filter === 'modified'}
                  onClick={() => setFilter('modified')}
                  label={<><i className="ph-duotone ph-pencil text-[10px] text-amber-400/80 mr-1" />Aangepast · {counts.modified}</>}
                />
              )}
              {counts.user > 0 && (
                <FilterChip
                  active={filter === 'user'}
                  onClick={() => setFilter('user')}
                  label={`Eigen · ${counts.user}`}
                />
              )}
            </div>
          )}
        </div>

        {/* Create group inline */}
        <div className="flex items-center gap-2">
          <input
            type="text"
            placeholder={t('groups.newGroupPlaceholder') || 'Nieuwe groepsnaam...'}
            value={newName}
            onChange={e => setNewName(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && newName.trim()) createMut.mutate(newName.trim()); }}
            className="px-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-white/[0.06] bg-white dark:bg-white/[0.03] text-slate-700 dark:text-slate-200 outline-none focus:ring-2 focus:ring-indigo-500/30 w-56"
          />
          <button
            onClick={() => newName.trim() && createMut.mutate(newName.trim())}
            disabled={!newName.trim()}
            className="px-3 py-1.5 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 disabled:opacity-40 transition-colors whitespace-nowrap"
          >
            <i className="ph-bold ph-plus text-[10px] mr-1" />Nieuwe groep
          </button>
        </div>
      </div>

      {isLoading && (
        <div className="py-8 text-center text-sm text-slate-400">
          <i className="ph-duotone ph-circle-notch animate-spin text-lg" />
        </div>
      )}

      {!isLoading && filtered.length === 0 && (
        <p className="text-slate-400 dark:text-slate-500 text-sm text-center py-8">
          {filter === 'all'
            ? (t('groups.noGroups') || 'Nog geen groepen.')
            : 'Geen groepen in dit filter.'}
        </p>
      )}

      {/* Unified grid */}
      {filtered.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
          {filtered.map(g => (
            <GroupCard
              key={g.id}
              group={g}
              onOpen={() => setOpenGroupId(g.id)}
              onDelete={() => handleDelete(g)}
            />
          ))}
        </div>
      )}

      {/* Inline legend — only shown when there's a mix of origins */}
      {!isLoading && (counts.suggested > 0 || counts.modified > 0) && counts.user > 0 && (
        <div className="flex items-center gap-4 pt-3 border-t border-slate-200 dark:border-white/[0.04] text-[11px] text-slate-500">
          <span className="inline-flex items-center gap-1"><i className="ph-fill ph-sparkle text-indigo-400/80" />Voorgesteld door AI-Radar</span>
          <span className="inline-flex items-center gap-1"><i className="ph-duotone ph-pencil text-amber-400/80" />Voorgesteld, door jou aangepast</span>
          <span className="text-slate-600">(geen icoon = zelf gemaakt)</span>
        </div>
      )}

      {/* Members modal — same for any origin */}
      {openGroupId != null && (() => {
        const g = groups.find(x => x.id === openGroupId);
        if (!g) return null;
        return (
          <MembersModal
            group={g}
            deviceMap={deviceMap}
            onClose={() => setOpenGroupId(null)}
          />
        );
      })()}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function FilterChip({ active, onClick, label }: { active: boolean; onClick: () => void; label: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`text-[11px] px-2.5 py-1 rounded-full font-medium transition-colors ${
        active
          ? 'bg-blue-600 text-white'
          : 'bg-white/[0.04] dark:bg-white/[0.04] hover:bg-white/[0.08] text-slate-500 dark:text-slate-400'
      }`}
    >{label}</button>
  );
}

function GroupCard({ group, onOpen, onDelete }: {
  group: Group;
  onOpen: () => void;
  onDelete: () => void;
}) {
  const state = groupState(group);
  const color = group.color || 'blue';
  const icon = group.icon || 'users-three';
  const mc = group.member_counts;

  // Subtle extra border for customized suggestions
  const customBorder = state === 'modified' ? 'border-amber-500/15' : 'border-slate-200 dark:border-white/[0.04]';

  return (
    <div className={`group relative flex items-center gap-3 p-3 rounded-xl bg-white dark:bg-white/[0.02] border ${customBorder} hover:bg-slate-50 dark:hover:bg-white/[0.04] transition-colors cursor-pointer`}
      onClick={onOpen}
    >
      <div
        className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0`}
        style={{ backgroundColor: colorBg(color) }}
      >
        <i className={`ph-duotone ph-${icon} text-xl`} style={{ color: colorFg(color) }} />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1">
          <p className="text-sm font-semibold text-slate-700 dark:text-slate-200 truncate">{group.name}</p>
          {state === 'suggested' && (
            <i className="ph-fill ph-sparkle text-[10px] text-indigo-400/70" title="Voorgesteld door AI-Radar · onveranderd" />
          )}
          {state === 'modified' && (
            <i className="ph-duotone ph-pencil text-[10px] text-amber-400/80" title="Voorgesteld · door jou aangepast" />
          )}
        </div>
        <p className="text-[11px] text-slate-500 dark:text-slate-400">
          {formatMemberCount(group.member_count, mc)}
        </p>
      </div>

      {/* Hover-revealed actions */}
      <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
        <button
          onClick={e => { e.stopPropagation(); window.navigate?.('rules'); window.showToast?.(t('groups.rulesHint') || 'Kies "Per groep" op de Rules page', 'info'); }}
          className="p-1.5 rounded hover:bg-slate-100 dark:hover:bg-white/[0.06] text-slate-400 hover:text-blue-500"
          title="Policies beheren"
        >
          <i className="ph-duotone ph-shield-check text-sm" />
        </button>
        <button
          onClick={e => { e.stopPropagation(); onDelete(); }}
          className="p-1.5 rounded hover:bg-slate-100 dark:hover:bg-white/[0.06] text-slate-400 hover:text-red-500"
          title="Verwijderen"
        >
          <i className="ph-duotone ph-trash text-sm" />
        </button>
      </div>
    </div>
  );
}

function formatMemberCount(total: number, counts?: Group['member_counts']): string {
  const noun = total === 1 ? 'lid' : 'leden';
  if (!counts || (counts.auto === 0 && counts.manual === 0)) {
    return `${total} ${noun}`;
  }
  // Show auto/manual split when interesting
  if (counts.auto > 0 && counts.manual > 0) {
    return `${total} ${noun} · ${counts.auto} via regels + ${counts.manual} handmatig`;
  }
  if (counts.auto > 0) return `${total} ${noun} · via regels`;
  return `${total} ${noun} · handmatig`;
}

// ---------------------------------------------------------------------------
// Color palette — maps our Phosphor color strings to bg/fg pairs.
// Tailwind's dynamic class purging doesn't pick up bg-${color}-900/30 from a
// template string, so we resolve to inline styles. Keep in sync with the
// palette used in the mockup / default group seeds.
// ---------------------------------------------------------------------------

const COLORS: Record<string, { bg: string; fg: string }> = {
  rose:    { bg: 'rgba(136,19,55,0.3)',   fg: '#fb7185' },
  purple:  { bg: 'rgba(88,28,135,0.3)',   fg: '#c084fc' },
  pink:    { bg: 'rgba(131,24,67,0.3)',   fg: '#f472b6' },
  orange:  { bg: 'rgba(124,45,18,0.3)',   fg: '#fb923c' },
  sky:     { bg: 'rgba(12,74,110,0.3)',   fg: '#38bdf8' },
  blue:    { bg: 'rgba(30,58,138,0.3)',   fg: '#60a5fa' },
  amber:   { bg: 'rgba(120,53,15,0.3)',   fg: '#fbbf24' },
  slate:   { bg: 'rgb(30,41,59)',         fg: '#94a3b8' },
  teal:    { bg: 'rgba(19,78,74,0.3)',    fg: '#2dd4bf' },
  indigo:  { bg: 'rgba(49,46,129,0.3)',   fg: '#818cf8' },
  emerald: { bg: 'rgba(6,78,59,0.3)',     fg: '#34d399' },
  stone:   { bg: 'rgb(41,37,36)',         fg: '#a8a29e' },
  red:     { bg: 'rgba(127,29,29,0.3)',   fg: '#f87171' },
  green:   { bg: 'rgba(20,83,45,0.3)',    fg: '#4ade80' },
  yellow:  { bg: 'rgba(113,63,18,0.3)',   fg: '#facc15' },
};

function colorBg(color: string): string { return COLORS[color]?.bg || COLORS.blue.bg; }
function colorFg(color: string): string { return COLORS[color]?.fg || COLORS.blue.fg; }

// ---------------------------------------------------------------------------
// Members modal — unchanged API shape but now shows source per member
// ---------------------------------------------------------------------------

function MembersModal({ group, deviceMap, onClose }: {
  group: Group;
  deviceMap: DeviceMap;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const { data: membersData } = useQuery({
    queryKey: ['groupMembers', group.id],
    queryFn: () => fetchGroupMembers(group.id),
  });

  const bySourceByMac = useMemo(() => {
    const m: Record<string, 'auto' | 'manual' | 'exclude'> = {};
    (membersData?.members || []).forEach(x => {
      m[x.mac_address] = (x as any).source || 'manual';
    });
    return m;
  }, [membersData]);

  const rows = useMemo(() => {
    return Object.values(deviceMap).map(d => ({
      mac: d.mac_address,
      name: bestDeviceName(d.mac_address, d),
      source: bySourceByMac[d.mac_address],
      lastSeen: d.last_seen ? new Date(d.last_seen).getTime() : 0,
    })).sort((a, b) => {
      // Members first, then excluded, then the rest
      const rank = (s: string | undefined) => s === 'manual' ? 0 : s === 'auto' ? 1 : s === 'exclude' ? 2 : 3;
      if (rank(a.source) !== rank(b.source)) return rank(a.source) - rank(b.source);
      return b.lastSeen - a.lastSeen;
    });
  }, [deviceMap, bySourceByMac]);

  const toggleInclude = async (mac: string, add: boolean) => {
    try {
      if (add) await addGroupMember(group.id, mac);
      else await removeGroupMember(group.id, mac);
      queryClient.invalidateQueries({ queryKey: ['groupMembers', group.id] });
      queryClient.invalidateQueries({ queryKey: ['groups'] });
    } catch (err) {
      window.showToast?.(`Failed: ${(err as Error).message}`, 'error');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4" onClick={onClose}>
      <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl shadow-2xl w-full max-w-lg max-h-[80vh] flex flex-col" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-slate-700">
          <div className="flex items-center gap-2 min-w-0">
            <div
              className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
              style={{ backgroundColor: colorBg(group.color || 'blue') }}
            >
              <i className={`ph-duotone ph-${group.icon || 'users-three'} text-base`} style={{ color: colorFg(group.color || 'blue') }} />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-1">
                <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200 truncate">{group.name}</h3>
                {groupState(group) === 'suggested' && <i className="ph-fill ph-sparkle text-[10px] text-indigo-400/70" />}
                {groupState(group) === 'modified' && <i className="ph-duotone ph-pencil text-[10px] text-amber-400/80" />}
              </div>
              <p className="text-[10px] text-slate-400">{formatMemberCount(group.member_count, group.member_counts)}</p>
            </div>
          </div>
          <button onClick={onClose} className="w-7 h-7 rounded-lg hover:bg-slate-100 dark:hover:bg-white/[0.06] text-slate-400 flex items-center justify-center"><i className="ph-bold ph-x" /></button>
        </div>
        <div className="flex-1 overflow-y-auto p-2">
          {rows.map(r => (
            <MemberRow key={r.mac} row={r} onToggle={toggleInclude} />
          ))}
        </div>
      </div>
    </div>
  );
}

function MemberRow({ row, onToggle }: {
  row: { mac: string; name: string; source?: 'auto' | 'manual' | 'exclude' };
  onToggle: (mac: string, add: boolean) => void;
}) {
  const isMember = row.source === 'auto' || row.source === 'manual';
  const isExcluded = row.source === 'exclude';

  return (
    <label className="flex items-center gap-2 py-1.5 px-2 rounded hover:bg-slate-50 dark:hover:bg-white/[0.03] cursor-pointer">
      <input
        type="checkbox"
        checked={isMember}
        onChange={e => onToggle(row.mac, e.target.checked)}
        className="rounded border-slate-300 dark:border-slate-600 w-4 h-4"
      />
      <span className={`text-sm flex-1 truncate ${isExcluded ? 'text-slate-400 line-through' : 'text-slate-700 dark:text-slate-200'}`}>{row.name}</span>
      {row.source === 'auto' && (
        <span className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded-full bg-indigo-500/15 text-indigo-300 font-medium">
          <i className="ph-fill ph-sparkle text-[8px]" />via regel
        </span>
      )}
      {row.source === 'manual' && (
        <span className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded-full bg-amber-500/15 text-amber-300 font-medium">
          <i className="ph-fill ph-user text-[8px]" />handmatig
        </span>
      )}
      {row.source === 'exclude' && (
        <span className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded-full bg-slate-500/15 text-slate-400 font-medium">
          <i className="ph-fill ph-prohibit text-[8px]" />uitgesloten
        </span>
      )}
    </label>
  );
}
