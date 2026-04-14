import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import type { Group, DeviceMap } from './types';
import { fetchGroups, createGroup, deleteGroup, fetchGroupMembers, fetchDevices, addGroupMember, removeGroupMember } from './api';
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

export default function GroupsTab({ deviceMap }: Props) {
  const [newName, setNewName] = useState('');
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
  const childrenOf: Record<number, Group[]> = {};
  const topLevel: Group[] = [];
  groups.forEach(g => {
    if (g.parent_id) {
      (childrenOf[g.parent_id] = childrenOf[g.parent_id] || []).push(g);
    } else {
      topLevel.push(g);
    }
  });

  const handleDelete = async (id: number) => {
    const ok = window.styledConfirm
      ? await window.styledConfirm(t('groups.deleteTitle') || 'Delete group', t('groups.deleteConfirm') || 'This will remove the group. Continue?')
      : confirm('Delete this group?');
    if (ok) deleteMut.mutate(id);
  };

  return (
    <div className="space-y-4">
      {/* Create group */}
      <div className="flex items-center gap-2">
        <input
          type="text"
          placeholder={t('groups.newGroupPlaceholder') || 'New group name...'}
          value={newName}
          onChange={e => setNewName(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter' && newName.trim()) createMut.mutate(newName.trim()); }}
          className="flex-1 px-3 py-2 text-sm rounded-lg border border-slate-200 dark:border-white/[0.06] bg-white dark:bg-white/[0.03] text-slate-700 dark:text-slate-200 outline-none focus:ring-2 focus:ring-indigo-500/30"
        />
        <button
          onClick={() => newName.trim() && createMut.mutate(newName.trim())}
          disabled={!newName.trim()}
          className="px-4 py-2 text-xs font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-40 transition-colors"
        >
          {t('groups.create') || 'Create'}
        </button>
      </div>

      {isLoading && (
        <div className="py-8 text-center text-sm text-slate-400">
          <i className="ph-duotone ph-circle-notch animate-spin text-lg" />
        </div>
      )}

      {!isLoading && groups.length === 0 && (
        <p className="text-slate-400 dark:text-slate-500 text-sm text-center py-8">{t('groups.noGroups') || 'No groups created yet.'}</p>
      )}

      {topLevel.map(group => (
        <GroupCard
          key={group.id}
          group={group}
          children={childrenOf[group.id] || []}
          deviceMap={deviceMap}
          onDelete={handleDelete}
        />
      ))}
    </div>
  );
}

function GroupCard({ group, children, deviceMap, onDelete }: {
  group: Group;
  children: Group[];
  deviceMap: DeviceMap;
  onDelete: (id: number) => void;
}) {
  const [showMembers, setShowMembers] = useState(false);

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-lg bg-${group.color || 'blue'}-100 dark:bg-${group.color || 'blue'}-900/30 flex items-center justify-center`}>
            <i className={`ph-duotone ph-${group.icon || 'users-three'} text-xl text-${group.color || 'blue'}-600 dark:text-${group.color || 'blue'}-400`} />
          </div>
          <div>
            <h3 className="text-base font-semibold text-slate-800 dark:text-white">{group.name}</h3>
            <p className="text-[11px] text-slate-400 dark:text-slate-500">
              {group.member_count} {t('groups.members') || 'members'}{children.length > 0 ? ` · ${children.length} subgroups` : ''}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-1">
          <button onClick={() => setShowMembers(true)} className="p-1.5 rounded hover:bg-slate-100 dark:hover:bg-white/[0.06] text-slate-400 hover:text-blue-500 transition-colors" title={t('groups.manageMembers') || 'Manage members'}>
            <i className="ph-duotone ph-user-plus text-base" />
          </button>
          <button onClick={() => { window.navigate?.('rules'); window.showToast?.(t('groups.rulesHint') || 'Select "Per group" on the Rules page', 'info'); }} className="p-1.5 rounded hover:bg-slate-100 dark:hover:bg-white/[0.06] text-slate-400 hover:text-blue-500 transition-colors">
            <i className="ph-duotone ph-shield-check text-base" />
          </button>
          <button onClick={() => onDelete(group.id)} className="p-1.5 rounded hover:bg-slate-100 dark:hover:bg-white/[0.06] text-slate-400 hover:text-red-500 transition-colors">
            <i className="ph-duotone ph-trash text-base" />
          </button>
        </div>
      </div>

      {/* Child groups */}
      {children.length > 0 && (
        <div className="ml-6 mt-2 space-y-2 border-l-2 border-slate-200 dark:border-white/[0.06] pl-3">
          {children.map(c => (
            <div key={c.id} className="flex items-center justify-between p-3 rounded-lg bg-slate-50 dark:bg-white/[0.02] border border-slate-100 dark:border-white/[0.03]">
              <div className="flex items-center gap-2">
                <i className={`ph-duotone ph-${c.icon || 'users-three'} text-lg text-${c.color || 'blue'}-500`} />
                <span className="text-sm font-medium text-slate-700 dark:text-slate-200">{c.name}</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-white/[0.06] text-slate-500">{c.member_count} members</span>
              </div>
              <button onClick={() => onDelete(c.id)} className="p-1.5 rounded hover:bg-slate-100 dark:hover:bg-white/[0.06] text-slate-400 hover:text-red-500 transition-colors">
                <i className="ph-duotone ph-trash text-base" />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Members modal */}
      {showMembers && (
        <MembersModal groupId={group.id} groupName={group.name} deviceMap={deviceMap} onClose={() => setShowMembers(false)} />
      )}
    </div>
  );
}

function MembersModal({ groupId, groupName, deviceMap, onClose }: {
  groupId: number;
  groupName: string;
  deviceMap: DeviceMap;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const { data: membersData } = useQuery({
    queryKey: ['groupMembers', groupId],
    queryFn: () => fetchGroupMembers(groupId),
  });

  const members = new Set((membersData?.members || []).map(m => m.mac_address));

  const devices = Object.values(deviceMap)
    .map(d => ({
      mac: d.mac_address,
      name: bestDeviceName(d.mac_address, d),
      isMember: members.has(d.mac_address),
      lastSeen: d.last_seen ? new Date(d.last_seen).getTime() : 0,
    }))
    .sort((a, b) => {
      if (a.isMember !== b.isMember) return a.isMember ? -1 : 1;
      return b.lastSeen - a.lastSeen;
    });

  const toggle = async (mac: string, add: boolean) => {
    try {
      if (add) await addGroupMember(groupId, mac);
      else await removeGroupMember(groupId, mac);
      queryClient.invalidateQueries({ queryKey: ['groupMembers', groupId] });
      queryClient.invalidateQueries({ queryKey: ['groups'] });
    } catch (err) {
      window.showToast?.(`Failed: ${(err as Error).message}`, 'error');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={onClose}>
      <div className="bg-white dark:bg-slate-800 rounded-xl shadow-xl p-5 w-full max-w-md mx-4" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">{groupName} — Members</h3>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600"><i className="ph-bold ph-x" /></button>
        </div>
        <div className="max-h-[300px] overflow-y-auto space-y-0.5">
          {devices.map(d => (
            <label key={d.mac} className="flex items-center gap-2 py-1.5 px-2 rounded hover:bg-slate-50 dark:hover:bg-white/[0.03] cursor-pointer">
              <input
                type="checkbox"
                checked={d.isMember}
                onChange={e => toggle(d.mac, e.target.checked)}
                className="rounded border-slate-300 dark:border-slate-600 w-4 h-4"
              />
              <span className="text-sm text-slate-700 dark:text-slate-200">{d.name}</span>
            </label>
          ))}
        </div>
      </div>
    </div>
  );
}
