import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import type { Group, DeviceMap, GroupMember } from './types';
import {
  fetchGroups, createGroup, deleteGroup, updateGroup,
  fetchGroupMembers, addGroupMember, removeGroupMember,
} from './api';
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
// Groups tab — vertical tree with inline-expand on click.
//
// Nesting (parent_id) is rendered as an indented block below each parent,
// sharing a vertical connector rail. Top-level groups without children go
// below a separator at the bottom. Click a card to expand it in place and
// see/manage: match rules, sub-groups, members (with source badges), parent.
//
// There is only ONE kind of group. The ✨ / 🛠️ indicators are purely
// informational (origin = 'suggested' / 'user', modified_at for pencil).
// ---------------------------------------------------------------------------

type FilterKey = 'all' | 'suggested' | 'modified' | 'user';

function groupState(g: Group): 'suggested' | 'modified' | 'user' {
  if (g.origin === 'suggested' && !g.modified_at) return 'suggested';
  if (g.origin === 'suggested') return 'modified';
  return 'user';
}

// Build parent → children tree from the flat list, preserving API order.
function buildTree(groups: Group[]): { group: Group; children: Group[] }[] {
  const byId = new Map<number, Group>();
  groups.forEach(g => byId.set(g.id, g));
  const childrenByParent = new Map<number, Group[]>();
  groups.forEach(g => {
    if (g.parent_id != null && byId.has(g.parent_id)) {
      const arr = childrenByParent.get(g.parent_id) ?? [];
      arr.push(g);
      childrenByParent.set(g.parent_id, arr);
    }
  });
  return groups
    .filter(g => g.parent_id == null || !byId.has(g.parent_id))
    .map(g => ({ group: g, children: childrenByParent.get(g.id) ?? [] }));
}

export default function GroupsTab({ deviceMap }: Props) {
  const [filter, setFilter] = useState<FilterKey>('all');
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [showCreate, setShowCreate] = useState<{ parentId: number | null } | null>(null);
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ['groups'],
    queryFn: fetchGroups,
    staleTime: 30_000,
  });

  const groups = data?.groups || [];

  const counts = useMemo(() => {
    const c = { all: groups.length, suggested: 0, modified: 0, user: 0 };
    groups.forEach(g => { c[groupState(g)] += 1; });
    return c;
  }, [groups]);

  // Apply filter but keep tree relationships: if a child matches and its
  // parent doesn't, lift the child to top-level for display.
  const filtered = useMemo(() => {
    if (filter === 'all') return groups;
    return groups.filter(g => groupState(g) === filter);
  }, [groups, filter]);

  const tree = useMemo(() => buildTree(filtered), [filtered]);

  // Split into "nested" (parent with children) and "flat" (top-level without).
  const nested = tree.filter(n => n.children.length > 0);
  const flat = tree.filter(n => n.children.length === 0);

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['groups'] });
  };

  const handleDelete = async (group: Group) => {
    const isSuggested = groupState(group) !== 'user';
    const msg = isSuggested
      ? `"${group.name}" is een voorstel van AI-Radar. Verwijderen betekent ook de bijbehorende policies kwijt — hij komt niet automatisch terug.`
      : `Dit verwijdert de groep, alle lidmaatschappen en alle policies die eraan hangen.`;
    const ok = window.styledConfirm
      ? await window.styledConfirm('Groep verwijderen', msg)
      : confirm(`Groep "${group.name}" verwijderen?`);
    if (!ok) return;
    try {
      await deleteGroup(group.id);
      invalidate();
      window.showToast?.(t('groups.deleted') || 'Group deleted', 'success');
      if (expandedId === group.id) setExpandedId(null);
    } catch (err) {
      window.showToast?.(`Failed: ${(err as Error).message}`, 'error');
    }
  };

  return (
    <div className="space-y-4">
      {/* Header row */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2 flex-wrap">
          <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-200">Groepen</h2>
          {!isLoading && (
            <span className="text-[11px] text-slate-500">
              {counts.all} totaal
              {nested.length > 0 && ` · ${tree.length} top-level · ${counts.all - tree.length} genest`}
            </span>
          )}
          {(counts.suggested > 0 || counts.modified > 0) && (
            <div className="flex items-center gap-1 ml-2 flex-wrap">
              <FilterChip active={filter === 'all'} onClick={() => setFilter('all')} label={`Alles · ${counts.all}`} />
              {counts.suggested > 0 && (
                <FilterChip active={filter === 'suggested'} onClick={() => setFilter('suggested')}
                  label={<><i className="ph-fill ph-sparkle text-[10px] text-indigo-400/80 mr-1" />Voorgesteld · {counts.suggested}</>} />
              )}
              {counts.modified > 0 && (
                <FilterChip active={filter === 'modified'} onClick={() => setFilter('modified')}
                  label={<><i className="ph-duotone ph-pencil text-[10px] text-amber-400/80 mr-1" />Aangepast · {counts.modified}</>} />
              )}
              {counts.user > 0 && (
                <FilterChip active={filter === 'user'} onClick={() => setFilter('user')} label={`Eigen · ${counts.user}`} />
              )}
            </div>
          )}
        </div>

        <button
          onClick={() => setShowCreate({ parentId: null })}
          className="px-3 py-1.5 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors whitespace-nowrap"
        >
          <i className="ph-bold ph-plus text-[10px] mr-1" />Nieuwe groep
        </button>
      </div>

      {isLoading && (
        <div className="py-8 text-center text-sm text-slate-400">
          <i className="ph-duotone ph-circle-notch animate-spin text-lg" />
        </div>
      )}

      {!isLoading && tree.length === 0 && (
        <p className="text-slate-400 dark:text-slate-500 text-sm text-center py-8">
          {filter === 'all' ? 'Nog geen groepen.' : 'Geen groepen in dit filter.'}
        </p>
      )}

      {/* Tree container — max 3xl so cards stay scannable on wide screens */}
      <div className="space-y-2 max-w-3xl">
        {/* Nested parents with their children */}
        {nested.map(node => (
          <TreeBranch
            key={node.group.id}
            parent={node.group}
            children={node.children}
            expandedId={expandedId}
            setExpandedId={setExpandedId}
            deviceMap={deviceMap}
            groups={groups}
            onDelete={handleDelete}
            onCreateSub={(parentId) => setShowCreate({ parentId })}
            onInvalidate={invalidate}
          />
        ))}

        {/* Separator + flat top-level groups */}
        {nested.length > 0 && flat.length > 0 && (
          <div className="pt-4 mt-4 border-t border-slate-200 dark:border-white/[0.04]" />
        )}

        {flat.map(node => (
          <GroupCard
            key={node.group.id}
            group={node.group}
            isExpanded={expandedId === node.group.id}
            onToggle={() => setExpandedId(expandedId === node.group.id ? null : node.group.id)}
            deviceMap={deviceMap}
            groups={groups}
            onDelete={() => handleDelete(node.group)}
            onCreateSub={() => setShowCreate({ parentId: node.group.id })}
            onInvalidate={invalidate}
            subgroupCount={0}
          />
        ))}
      </div>

      {/* Create modal */}
      {showCreate && (
        <CreateGroupModal
          allGroups={groups}
          initialParentId={showCreate.parentId}
          onClose={() => setShowCreate(null)}
          onCreated={() => { invalidate(); setShowCreate(null); }}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tree rendering
// ---------------------------------------------------------------------------

function TreeBranch({ parent, children, expandedId, setExpandedId, deviceMap, groups, onDelete, onCreateSub, onInvalidate }: {
  parent: Group;
  children: Group[];
  expandedId: number | null;
  setExpandedId: (id: number | null) => void;
  deviceMap: DeviceMap;
  groups: Group[];
  onDelete: (g: Group) => void;
  onCreateSub: (parentId: number) => void;
  onInvalidate: () => void;
}) {
  const parentColor = parent.color || 'blue';
  const railColor = COLORS[parentColor]?.fg || COLORS.blue.fg;

  return (
    <div className="space-y-2">
      <GroupCard
        group={parent}
        isExpanded={expandedId === parent.id}
        onToggle={() => setExpandedId(expandedId === parent.id ? null : parent.id)}
        deviceMap={deviceMap}
        groups={groups}
        onDelete={() => onDelete(parent)}
        onCreateSub={() => onCreateSub(parent.id)}
        onInvalidate={onInvalidate}
        subgroupCount={children.length}
        isParent
      />

      {/* Children indented with shared vertical rail */}
      <div className="relative pl-8 space-y-2">
        <span
          className="absolute left-[18px] top-0 bottom-4 w-px opacity-30"
          style={{ backgroundColor: railColor }}
        />
        {children.map(child => (
          <div key={child.id} className="relative">
            <span
              className="absolute -left-[14px] top-6 w-3.5 h-px opacity-30"
              style={{ backgroundColor: railColor }}
            />
            <GroupCard
              group={child}
              isExpanded={expandedId === child.id}
              onToggle={() => setExpandedId(expandedId === child.id ? null : child.id)}
              deviceMap={deviceMap}
              groups={groups}
              onDelete={() => onDelete(child)}
              onCreateSub={() => onCreateSub(child.id)}
              onInvalidate={onInvalidate}
              subgroupCount={0}
              isChild
            />
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Group card — collapsed (title + meta) or expanded (full in-place editor).
// ---------------------------------------------------------------------------

function GroupCard({ group, isExpanded, onToggle, deviceMap, groups, onDelete, onCreateSub, onInvalidate, subgroupCount, isParent = false, isChild = false }: {
  group: Group;
  isExpanded: boolean;
  onToggle: () => void;
  deviceMap: DeviceMap;
  groups: Group[];
  onDelete: () => void;
  onCreateSub: () => void;
  onInvalidate: () => void;
  subgroupCount: number;
  isParent?: boolean;
  isChild?: boolean;
}) {
  const state = groupState(group);
  const color = group.color || 'blue';
  const icon = group.icon || 'users-three';
  const mc = group.member_counts;
  const fg = COLORS[color]?.fg || COLORS.blue.fg;

  // Colored left border for parent cards; subtle amber for customized suggestions.
  const borderClasses = isExpanded
    ? 'border border-teal-500/30'
    : isParent
      ? `border-y border-r border-l-[3px] border-slate-200 dark:border-white/[0.04]`
      : state === 'modified'
        ? 'border border-amber-500/15'
        : 'border border-slate-200 dark:border-white/[0.04]';

  const parentBorderStyle = isParent && !isExpanded ? { borderLeftColor: fg + '80' } : undefined;

  return (
    <div
      className={`rounded-xl bg-white dark:bg-white/[0.02] ${borderClasses} transition-colors overflow-hidden`}
      style={parentBorderStyle}
    >
      {/* Header (always visible) */}
      <div
        onClick={onToggle}
        className="flex items-center gap-3 p-3 cursor-pointer hover:bg-slate-50 dark:hover:bg-white/[0.04] transition-colors"
      >
        <div
          className={`${isChild ? 'w-9 h-9' : 'w-10 h-10'} rounded-lg flex items-center justify-center flex-shrink-0`}
          style={{ backgroundColor: colorBg(color) }}
        >
          <i className={`ph-duotone ph-${icon} ${isChild ? 'text-lg' : 'text-xl'}`} style={{ color: fg }} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <p className="text-sm font-semibold text-slate-700 dark:text-slate-200 truncate">{group.name}</p>
            {state === 'suggested' && (
              <i className="ph-fill ph-sparkle text-[10px] text-indigo-400/70" title="Voorgesteld door AI-Radar · onveranderd" />
            )}
            {state === 'modified' && (
              <i className="ph-duotone ph-pencil text-[10px] text-amber-400/80" title="Voorgesteld · door jou aangepast" />
            )}
            {subgroupCount > 0 && (
              <span className="text-[10px] px-1.5 py-0.5 rounded ml-1" style={{ backgroundColor: colorBg(color), color: fg }}>
                {subgroupCount} {subgroupCount === 1 ? 'subgroep' : 'subgroepen'}
              </span>
            )}
            {isExpanded && (
              <span className="text-[10px] text-teal-300/90 px-1.5 py-0.5 rounded bg-teal-500/10 ml-1">open</span>
            )}
          </div>
          <p className="text-[11px] text-slate-500 dark:text-slate-400">
            {formatMemberCount(group.member_count, mc)}
          </p>
        </div>
        <i className={`ph-bold ${isExpanded ? 'ph-caret-up' : 'ph-caret-down'} text-slate-500 text-sm`} />
      </div>

      {/* Expanded body */}
      {isExpanded && (
        <ExpandedBody
          group={group}
          groups={groups}
          deviceMap={deviceMap}
          onDelete={onDelete}
          onCreateSub={onCreateSub}
          onInvalidate={onInvalidate}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Expanded body — rules summary, sub-groups section, member list with +Device.
// ---------------------------------------------------------------------------

function ExpandedBody({ group, groups, deviceMap, onDelete, onCreateSub, onInvalidate }: {
  group: Group;
  groups: Group[];
  deviceMap: DeviceMap;
  onDelete: () => void;
  onCreateSub: () => void;
  onInvalidate: () => void;
}) {
  const queryClient = useQueryClient();
  const { data: membersData } = useQuery({
    queryKey: ['groupMembers', group.id],
    queryFn: () => fetchGroupMembers(group.id),
  });

  const members = membersData?.members || [];
  const memberMacs = new Set(
    members.filter(m => m.source !== 'exclude').map(m => m.mac_address)
  );
  const subgroups = groups.filter(g => g.parent_id === group.id);

  const [deviceSearch, setDeviceSearch] = useState('');
  const [showDeviceAdder, setShowDeviceAdder] = useState(false);

  const addableDevices = useMemo(() => {
    const q = deviceSearch.trim().toLowerCase();
    const list = Object.values(deviceMap)
      .filter(d => !memberMacs.has(d.mac_address))
      .map(d => ({ mac: d.mac_address, name: bestDeviceName(d.mac_address, d) }))
      .filter(d => q === '' || d.name.toLowerCase().includes(q) || d.mac.toLowerCase().includes(q))
      .slice(0, 20);
    return list;
  }, [deviceMap, memberMacs, deviceSearch]);

  const changeParent = async (newParentId: number | null) => {
    try {
      await updateGroup(group.id, { parent_id: newParentId });
      onInvalidate();
    } catch (err) {
      window.showToast?.(`Failed: ${(err as Error).message}`, 'error');
    }
  };

  const addMember = async (mac: string) => {
    try {
      await addGroupMember(group.id, mac);
      queryClient.invalidateQueries({ queryKey: ['groupMembers', group.id] });
      onInvalidate();
      setDeviceSearch('');
    } catch (err) {
      window.showToast?.(`Failed: ${(err as Error).message}`, 'error');
    }
  };

  const removeMember = async (mac: string) => {
    try {
      await removeGroupMember(group.id, mac);
      queryClient.invalidateQueries({ queryKey: ['groupMembers', group.id] });
      onInvalidate();
    } catch (err) {
      window.showToast?.(`Failed: ${(err as Error).message}`, 'error');
    }
  };

  const rulesSummary = useMemo(() => renderRulesSummary(group.auto_match_rules), [group.auto_match_rules]);

  return (
    <div className="px-3 pb-3 pt-0 space-y-3 border-t border-white/[0.04] dark:border-white/[0.04] border-slate-200">

      {/* Rules preview */}
      {rulesSummary && (
        <div className="pt-3">
          <p className="text-[10px] uppercase tracking-wider font-semibold text-slate-500 mb-1.5">Auto-match regels</p>
          <div className="text-[11px] text-slate-600 dark:text-slate-300 leading-relaxed font-mono">
            {rulesSummary}
          </div>
        </div>
      )}
      {!rulesSummary && (
        <div className="pt-3">
          <p className="text-[10px] uppercase tracking-wider font-semibold text-slate-500 mb-1.5">Auto-match regels</p>
          <p className="text-[11px] italic text-slate-500">Geen regels — deze groep wordt alleen handmatig gevuld.</p>
        </div>
      )}

      {/* Sub-groups */}
      <div>
        <div className="flex items-center justify-between mb-1.5">
          <p className="text-[10px] uppercase tracking-wider font-semibold text-slate-500">
            Sub-groepen · {subgroups.length}
          </p>
          {/* No nesting beyond 2 levels: only allow sub-groep on top-level */}
          {group.parent_id == null && (
            <button
              onClick={onCreateSub}
              className="text-[11px] text-blue-400 hover:text-blue-300"
            >
              <i className="ph-bold ph-plus text-[10px] mr-0.5" />Sub-groep maken
            </button>
          )}
        </div>
        {subgroups.length === 0 ? (
          <p className="text-[11px] italic text-slate-500">
            {group.parent_id != null
              ? 'Dit is een sub-groep (max 2 niveaus diep).'
              : 'Nog geen sub-groepen onder deze groep.'}
          </p>
        ) : (
          <div className="space-y-1">
            {subgroups.map(sg => (
              <div key={sg.id} className="flex items-center gap-2 text-[12px] text-slate-600 dark:text-slate-300 py-0.5">
                <i className={`ph-duotone ph-${sg.icon || 'folder'} text-sm`} style={{ color: colorFg(sg.color || 'blue') }} />
                <span>{sg.name}</span>
                <span className="text-[10px] text-slate-500">· {sg.member_count} leden</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Members */}
      <div>
        <div className="flex items-center justify-between mb-1.5">
          <p className="text-[10px] uppercase tracking-wider font-semibold text-slate-500">
            Leden · {group.member_count}
          </p>
          <button
            onClick={() => setShowDeviceAdder(v => !v)}
            className="text-[11px] text-blue-400 hover:text-blue-300"
          >
            <i className={`ph-bold ${showDeviceAdder ? 'ph-x' : 'ph-plus'} text-[10px] mr-0.5`} />
            {showDeviceAdder ? 'Sluiten' : 'Device toevoegen'}
          </button>
        </div>

        {showDeviceAdder && (
          <div className="mb-2 p-2 rounded-lg bg-slate-50 dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.04]">
            <input
              type="text"
              value={deviceSearch}
              onChange={e => setDeviceSearch(e.target.value)}
              placeholder="Zoek device op naam of MAC..."
              autoFocus
              className="w-full px-2 py-1 text-[11px] rounded bg-white dark:bg-white/[0.04] border border-slate-200 dark:border-white/[0.06] text-slate-700 dark:text-slate-200 outline-none focus:ring-1 focus:ring-blue-500/30 mb-1.5"
            />
            <div className="max-h-36 overflow-y-auto space-y-0.5">
              {addableDevices.length === 0 && (
                <p className="text-[11px] italic text-slate-500 py-1 text-center">Geen matches</p>
              )}
              {addableDevices.map(d => (
                <button
                  key={d.mac}
                  onClick={() => addMember(d.mac)}
                  className="w-full flex items-center gap-2 py-1 px-2 rounded hover:bg-blue-500/10 text-left"
                >
                  <i className="ph-duotone ph-plus-circle text-sm text-blue-400" />
                  <span className="text-[12px] text-slate-700 dark:text-slate-200 truncate flex-1">{d.name}</span>
                  <span className="text-[10px] text-slate-500 font-mono">{d.mac.slice(-8)}</span>
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="space-y-0.5 max-h-48 overflow-y-auto pr-1">
          {members.length === 0 && (
            <p className="text-[11px] italic text-slate-500 py-1">Nog geen leden.</p>
          )}
          {members.map(m => (
            <MemberRow
              key={m.mac_address}
              member={m}
              name={bestDeviceName(m.mac_address, deviceMap[m.mac_address])}
              onRemove={() => removeMember(m.mac_address)}
            />
          ))}
        </div>
      </div>

      {/* Footer: parent picker + delete */}
      <div className="flex items-center justify-between pt-2 border-t border-slate-200 dark:border-white/[0.04]">
        <div className="flex items-center gap-1.5 text-[11px] text-slate-500">
          <span>Parent:</span>
          <ParentPicker
            group={group}
            groups={groups}
            onChange={changeParent}
          />
        </div>
        <button
          onClick={onDelete}
          className="text-[11px] text-slate-500 hover:text-rose-400"
          title="Groep verwijderen"
        >
          <i className="ph-duotone ph-trash text-sm mr-1" />Verwijderen
        </button>
      </div>
    </div>
  );
}

function MemberRow({ member, name, onRemove }: { member: GroupMember; name: string; onRemove: () => void }) {
  const isExcluded = member.source === 'exclude';
  const badge = member.source === 'auto' ? (
    <span className="text-[9px] px-1.5 py-0.5 rounded bg-indigo-500/15 text-indigo-300 font-medium">
      <i className="ph-fill ph-sparkle text-[7px] mr-0.5" />via regel
    </span>
  ) : member.source === 'manual' ? (
    <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 font-medium">
      <i className="ph-fill ph-user text-[7px] mr-0.5" />handmatig
    </span>
  ) : (
    <span className="text-[9px] px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-300 font-medium">
      <i className="ph-bold ph-x text-[7px] mr-0.5" />uitgesloten
    </span>
  );

  const actionLabel = member.source === 'auto' ? 'Uitsluiten'
    : member.source === 'manual' ? 'Verwijderen'
    : 'Terugzetten';

  return (
    <div className={`flex items-center gap-2 py-1 px-2 rounded hover:bg-slate-50 dark:hover:bg-white/[0.03] ${isExcluded ? 'opacity-60' : ''}`}>
      <i className="ph-duotone ph-desktop text-sm text-slate-400" />
      <span className={`text-[12px] truncate flex-1 ${isExcluded ? 'text-slate-500 line-through' : 'text-slate-700 dark:text-slate-200'}`}>
        {name}
      </span>
      {badge}
      <button
        onClick={onRemove}
        className="text-[10px] text-slate-500 hover:text-rose-400 px-1.5"
      >
        {actionLabel}
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Parent picker — dropdown to rehome a group under another top-level parent.
// Only shows candidates that are themselves top-level (no nesting >2 deep).
// ---------------------------------------------------------------------------

function ParentPicker({ group, groups, onChange }: {
  group: Group;
  groups: Group[];
  onChange: (parentId: number | null) => void;
}) {
  const [open, setOpen] = useState(false);
  const current = group.parent_id != null ? groups.find(g => g.id === group.parent_id) : null;

  // Candidates: groups other than self, that are top-level, and don't
  // currently have this group as parent.
  const candidates = groups.filter(g =>
    g.id !== group.id
    && g.parent_id == null
    && group.parent_id !== g.id
    // can't assign a parent to a group that has its own children (would be 3-deep)
  );
  const canHaveParent = groups.filter(g => g.parent_id === group.id).length === 0;

  if (!canHaveParent && current == null) {
    return <span className="italic text-slate-500">(heeft zelf sub-groepen)</span>;
  }

  return (
    <div className="relative">
      <button
        onClick={() => setOpen(o => !o)}
        className="px-2 py-0.5 rounded bg-white/[0.04] hover:bg-white/[0.08] inline-flex items-center gap-1 text-[11px]"
      >
        {current ? (
          <>
            <i className={`ph-duotone ph-${current.icon || 'folder'} text-[11px]`} style={{ color: colorFg(current.color || 'blue') }} />
            {current.name}
          </>
        ) : (
          <span className="italic text-slate-500">geen</span>
        )}
        <i className="ph-bold ph-caret-down text-[8px] ml-0.5" />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div className="absolute z-20 bottom-full mb-1 left-0 min-w-[180px] bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg shadow-xl py-1 max-h-56 overflow-y-auto">
            <button
              onClick={() => { onChange(null); setOpen(false); }}
              className="w-full text-left px-3 py-1.5 text-[12px] hover:bg-slate-100 dark:hover:bg-white/[0.06] italic text-slate-500"
            >
              (geen parent — top-level)
            </button>
            {candidates.map(c => (
              <button
                key={c.id}
                onClick={() => { onChange(c.id); setOpen(false); }}
                className="w-full text-left px-3 py-1.5 text-[12px] hover:bg-slate-100 dark:hover:bg-white/[0.06] flex items-center gap-2"
              >
                <i className={`ph-duotone ph-${c.icon || 'folder'} text-sm`} style={{ color: colorFg(c.color || 'blue') }} />
                {c.name}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Create group modal — name, icon, color, optional parent.
// ---------------------------------------------------------------------------

const ICON_CHOICES = [
  'users-three', 'house-line', 'cpu', 'video-camera', 'television-simple',
  'speaker-high', 'device-mobile', 'laptop', 'thermometer', 'printer',
  'washing-machine', 'monitor-play', 'wifi-high', 'shield-check', 'folder',
];
const COLOR_CHOICES = [
  'blue', 'purple', 'pink', 'rose', 'orange', 'amber', 'emerald', 'teal', 'sky', 'indigo',
];

function CreateGroupModal({ allGroups, initialParentId, onClose, onCreated }: {
  allGroups: Group[];
  initialParentId: number | null;
  onClose: () => void;
  onCreated: () => void;
}) {
  const [name, setName] = useState('');
  const [parentId, setParentId] = useState<number | null>(initialParentId);
  const [icon, setIcon] = useState('users-three');
  const [color, setColor] = useState('blue');
  const [busy, setBusy] = useState(false);

  const parentCandidates = allGroups.filter(g => g.parent_id == null);

  const mutation = useMutation({
    mutationFn: async () => {
      await createGroup({ name: name.trim(), parent_id: parentId, icon, color });
    },
    onMutate: () => setBusy(true),
    onSuccess: () => {
      window.showToast?.(t('groups.created') || 'Group created', 'success');
      onCreated();
    },
    onError: (err: Error) => {
      window.showToast?.(`Failed: ${err.message}`, 'error');
      setBusy(false);
    },
  });

  const submit = () => {
    if (!name.trim() || busy) return;
    mutation.mutate();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4" onClick={onClose}>
      <div
        onClick={e => e.stopPropagation()}
        className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl shadow-2xl w-full max-w-md"
      >
        <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-slate-700">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">Nieuwe groep</h3>
          <button onClick={onClose} className="w-7 h-7 rounded-lg hover:bg-slate-100 dark:hover:bg-white/[0.06] text-slate-400 flex items-center justify-center">
            <i className="ph-bold ph-x" />
          </button>
        </div>
        <div className="p-4 space-y-4">
          {/* Name */}
          <div>
            <label className="block text-[11px] uppercase tracking-wider font-semibold text-slate-500 mb-1">Naam</label>
            <input
              type="text"
              autoFocus
              value={name}
              onChange={e => setName(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') submit(); }}
              placeholder="bijv. Gasten, Kantoor, Kids..."
              className="w-full px-3 py-2 text-sm rounded-lg border border-slate-200 dark:border-white/[0.06] bg-white dark:bg-white/[0.03] text-slate-700 dark:text-slate-200 outline-none focus:ring-2 focus:ring-blue-500/30"
            />
          </div>

          {/* Parent */}
          <div>
            <label className="block text-[11px] uppercase tracking-wider font-semibold text-slate-500 mb-1">Parent (optioneel)</label>
            <select
              value={parentId ?? ''}
              onChange={e => setParentId(e.target.value === '' ? null : Number(e.target.value))}
              className="w-full px-3 py-2 text-sm rounded-lg border border-slate-200 dark:border-white/[0.06] bg-white dark:bg-white/[0.03] text-slate-700 dark:text-slate-200 outline-none focus:ring-2 focus:ring-blue-500/30"
            >
              <option value="">(geen — top-level)</option>
              {parentCandidates.map(p => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
          </div>

          {/* Icon */}
          <div>
            <label className="block text-[11px] uppercase tracking-wider font-semibold text-slate-500 mb-1">Icoon</label>
            <div className="flex flex-wrap gap-1">
              {ICON_CHOICES.map(ic => (
                <button
                  key={ic}
                  onClick={() => setIcon(ic)}
                  className={`w-9 h-9 rounded-lg flex items-center justify-center transition-colors ${icon === ic ? 'ring-2 ring-blue-500' : 'hover:bg-slate-100 dark:hover:bg-white/[0.06]'}`}
                  style={{ backgroundColor: colorBg(color) }}
                  title={ic}
                >
                  <i className={`ph-duotone ph-${ic} text-base`} style={{ color: colorFg(color) }} />
                </button>
              ))}
            </div>
          </div>

          {/* Color */}
          <div>
            <label className="block text-[11px] uppercase tracking-wider font-semibold text-slate-500 mb-1">Kleur</label>
            <div className="flex flex-wrap gap-1.5">
              {COLOR_CHOICES.map(c => (
                <button
                  key={c}
                  onClick={() => setColor(c)}
                  className={`w-7 h-7 rounded-lg transition-all ${color === c ? 'ring-2 ring-offset-2 ring-offset-slate-800 ring-blue-500' : ''}`}
                  style={{ backgroundColor: colorBg(c) }}
                  title={c}
                >
                  <span className="block w-full h-full rounded-lg" style={{ backgroundColor: colorFg(c), opacity: 0.3 }} />
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="flex items-center justify-end gap-2 p-4 border-t border-slate-200 dark:border-slate-700">
          <button
            onClick={onClose}
            className="px-3 py-1.5 text-xs font-medium rounded-lg text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-white/[0.06]"
          >
            Annuleren
          </button>
          <button
            onClick={submit}
            disabled={!name.trim() || busy}
            className="px-3 py-1.5 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-500 disabled:opacity-40"
          >
            {busy ? 'Bezig...' : 'Aanmaken'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
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

function formatMemberCount(total: number, counts?: Group['member_counts']): string {
  const noun = total === 1 ? 'lid' : 'leden';
  if (!counts || (counts.auto === 0 && counts.manual === 0)) {
    return `${total} ${noun}`;
  }
  if (counts.auto > 0 && counts.manual > 0) {
    return `${total} ${noun} · ${counts.auto} via regels + ${counts.manual} handmatig`;
  }
  if (counts.auto > 0) return `${total} ${noun} · via regels`;
  return `${total} ${noun} · handmatig`;
}

// Render auto_match_rules JSON as a short human-readable summary.
// The rule format mirrors auto_groups.py: OR of rule-groups, each an AND of
// { field, op, value|values } clauses. We render as a single line per rule
// separated by " · ".
function renderRulesSummary(rulesJson: string | null | undefined): React.ReactNode {
  if (!rulesJson) return null;
  try {
    const parsed = JSON.parse(rulesJson);
    const rules = Array.isArray(parsed) ? parsed : (parsed?.rules || []);
    if (!rules || rules.length === 0) return null;
    const clauses = rules.flatMap((r: any) =>
      (r.clauses || r.match_rules || []).map((c: any) => {
        const field = c.field ?? '?';
        const op = c.op ?? 'equals';
        const value = c.value ?? c.values;
        const vals = Array.isArray(value) ? value : [value];
        return (
          <span key={`${field}-${op}-${vals.join(',')}`} className="block">
            <span className="bg-slate-100 dark:bg-white/[0.04] px-1 rounded">{field}</span>
            {' '}{humanOp(op)}{' '}
            {vals.map((v, i) => (
              <span key={i} className="bg-teal-500/10 text-teal-600 dark:text-teal-300 px-1 rounded mr-0.5">{String(v)}</span>
            ))}
          </span>
        );
      })
    );
    return <>{clauses}</>;
  } catch {
    return <span className="italic text-slate-500">(kon regels niet parsen)</span>;
  }
}

function humanOp(op: string): string {
  switch (op) {
    case 'equals': return '=';
    case 'equals_any': return 'is een van';
    case 'contains': return 'bevat';
    case 'contains_any': return 'bevat één van';
    case 'startswith': return 'start met';
    case 'matches': return 'matcht';
    case 'is_empty': return 'is leeg';
    default: return op;
  }
}

// ---------------------------------------------------------------------------
// Color palette — see comment in old file; keep in sync with auto_groups seeds.
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
