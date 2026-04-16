// ---------------------------------------------------------------------------
// Alert API — exceptions (snooze/silence) + policies (block/allow/alert)
// ---------------------------------------------------------------------------

export interface AlertException {
  id: number;
  mac_address: string;
  alert_type: string;
  destination?: string | null;
  expires_at?: string | null;
  dismissed_score?: number | null;
  created_at: string;
}

export interface ServicePolicy {
  id: number;
  scope: 'global' | 'group' | 'device';
  mac_address?: string | null;
  group_id?: number | null;
  service_name?: string | null;
  category?: string | null;
  action: 'allow' | 'alert' | 'block';
  expires_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface DeviceGroup {
  id: number;
  name: string;
  icon?: string;
  color?: string;
}

// ---- Exceptions (alert management: snooze / silence / dismiss) ----

export async function createException(params: {
  mac_address: string;
  alert_type: string;
  destination?: string | null;
  expires_at?: string | null;
  dismissed_score?: number | null;
}): Promise<AlertException> {
  const r = await fetch('/api/exceptions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      mac_address: params.mac_address,
      alert_type: params.alert_type,
      destination: params.destination ?? null,
      expires_at: params.expires_at ?? null,
      dismissed_score: params.dismissed_score ?? null,
    }),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

export async function deleteException(id: number): Promise<void> {
  const r = await fetch(`/api/exceptions/${id}`, { method: 'DELETE' });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
}

// ---- Policies (activity control: block / allow / alert) ----

export async function upsertPolicy(params: {
  scope: 'global' | 'group' | 'device';
  mac_address?: string | null;
  group_id?: number | null;
  service_name?: string | null;
  category?: string | null;
  action: 'allow' | 'alert' | 'block';
  expires_at?: string | null;
}): Promise<ServicePolicy> {
  const r = await fetch('/api/policies', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      scope: params.scope,
      mac_address: params.mac_address ?? null,
      group_id: params.group_id ?? null,
      service_name: params.service_name ?? null,
      category: params.category ?? null,
      action: params.action,
      expires_at: params.expires_at ?? null,
    }),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

export async function deletePolicy(id: number): Promise<void> {
  const r = await fetch(`/api/policies/${id}`, { method: 'DELETE' });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
}

export async function fetchPolicies(params?: {
  scope?: string;
  mac_address?: string;
  service_name?: string;
}): Promise<ServicePolicy[]> {
  const qs = new URLSearchParams();
  if (params?.scope) qs.set('scope', params.scope);
  if (params?.mac_address) qs.set('mac_address', params.mac_address);
  if (params?.service_name) qs.set('service_name', params.service_name);
  const r = await fetch(`/api/policies?${qs}`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

// ---- Device groups (for scope selector) ----

export async function fetchDeviceGroups(mac: string): Promise<DeviceGroup[]> {
  const r = await fetch(`/api/devices/${encodeURIComponent(mac)}/groups`);
  if (!r.ok) return [];
  const data = await r.json();
  return data.groups || [];
}
