import type { Device, DeviceEvent, Policy, Connection, Group, GroupMember, ReportData, AskResponse } from './types';
import type { ActivityResponse } from '../types';

const browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone;

async function json<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

// Devices
export async function fetchDevices(): Promise<Device[]> {
  return json<Device[]>('/api/devices');
}

export async function renameDevice(mac: string, displayName: string): Promise<void> {
  await fetch(`/api/devices/${encodeURIComponent(mac)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ display_name: displayName }),
  });
}

export async function refreshDeviceMetadata(mac: string): Promise<void> {
  const res = await fetch(`/api/devices/${encodeURIComponent(mac)}/refresh`, { method: 'POST' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
}

// Events
export async function fetchEvents(category: string, startIso: string, limit = 1000): Promise<DeviceEvent[]> {
  const params = new URLSearchParams({ category, limit: String(limit), start: startIso });
  return json<DeviceEvent[]>(`/api/events?${params}`);
}

// Policies
export async function fetchPolicies(): Promise<Policy[]> {
  try {
    return await json<Policy[]>('/api/policies?scope=global');
  } catch {
    return [];
  }
}

// Connections
export async function fetchConnections(mac: string): Promise<{ connections: Connection[] }> {
  return json<{ connections: Connection[] }>(`/api/devices/${encodeURIComponent(mac)}/connections`);
}

// Activity
export async function fetchActivity(mac: string, date: string): Promise<ActivityResponse> {
  return json<ActivityResponse>(
    `/api/devices/${encodeURIComponent(mac)}/activity?date=${date}&tz=${encodeURIComponent(browserTz)}`
  );
}

// Report
export async function fetchReport(mac: string, force: boolean, lang: string): Promise<ReportData> {
  const params = new URLSearchParams({ lang });
  if (force) params.set('force', 'true');
  return json<ReportData>(`/api/devices/${encodeURIComponent(mac)}/report?${params}`);
}

export async function fetchCachedReport(mac: string, lang: string): Promise<ReportData | null> {
  try {
    const res = await fetch(`/api/devices/${encodeURIComponent(mac)}/report?lang=${encodeURIComponent(lang)}`);
    if (!res.ok) return null;
    const data: ReportData = await res.json();
    if (!data.cached || !data.report) return null;
    return data;
  } catch {
    return null;
  }
}

// IoT baseline
export async function fetchIotProfile(mac: string): Promise<Record<string, unknown> | null> {
  try {
    const res = await fetch(`/api/iot/device/${encodeURIComponent(mac)}`);
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

// Groups
export async function fetchGroups(): Promise<{ groups: Group[] }> {
  return json<{ groups: Group[] }>('/api/groups');
}

export async function createGroup(name: string): Promise<void> {
  await json('/api/groups', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  });
}

export async function deleteGroup(groupId: number): Promise<void> {
  await fetch(`/api/groups/${groupId}`, { method: 'DELETE' });
}

export async function fetchGroupMembers(groupId: number): Promise<{ members: GroupMember[] }> {
  return json<{ members: GroupMember[] }>(`/api/groups/${groupId}/members`);
}

export async function addGroupMember(groupId: number, mac: string): Promise<void> {
  await fetch(`/api/groups/${groupId}/members`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mac_address: mac }),
  });
}

export async function removeGroupMember(groupId: number, mac: string): Promise<void> {
  await fetch(`/api/groups/${groupId}/members/${encodeURIComponent(mac)}`, { method: 'DELETE' });
}

// Policies
export async function setServicePolicy(
  serviceName: string,
  action: 'allow' | 'alert' | 'block',
  scope: 'global' | 'device' | 'group' = 'global',
  macAddress?: string,
  groupId?: number,
): Promise<void> {
  const res = await fetch('/api/policies', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      scope,
      mac_address: scope === 'device' ? macAddress : null,
      group_id: scope === 'group' ? groupId : null,
      service_name: serviceName,
      category: null,
      action,
    }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || `HTTP ${res.status}`);
  }
}

// Ask
export async function askNetwork(question: string, lang: string): Promise<AskResponse> {
  return json<AskResponse>('/api/ask', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ question, lang }),
  });
}
