import type { FamilyMetaResponse, OverviewResponse, CategoryResponse, DeviceGroup } from './types';

export async function fetchFamilyMeta(): Promise<FamilyMetaResponse> {
  const res = await fetch('/api/family/meta');
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function fetchFamilyOverview(hours = 24, groupId?: number | null): Promise<OverviewResponse> {
  const q = new URLSearchParams({ hours: String(hours) });
  if (groupId != null) q.set('group_id', String(groupId));
  const res = await fetch('/api/family/overview?' + q.toString());
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function fetchFamilyCategory(
  category: string,
  hours = 24,
  groupId?: number | null,
): Promise<CategoryResponse> {
  const q = new URLSearchParams({ hours: String(hours) });
  if (groupId != null) q.set('group_id', String(groupId));
  const res = await fetch(`/api/family/category/${encodeURIComponent(category)}?${q.toString()}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function fetchGroups(): Promise<DeviceGroup[]> {
  const res = await fetch('/api/groups');
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  return Array.isArray(data?.groups) ? data.groups : [];
}
