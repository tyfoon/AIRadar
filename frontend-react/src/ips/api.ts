import type { IpsStatus, PrivacyStatsPayload } from './types';

export async function fetchIpsStatus(): Promise<IpsStatus> {
  const res = await fetch('/api/ips/status');
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function fetchPrivacyStatsForIps(): Promise<PrivacyStatsPayload> {
  const res = await fetch('/api/privacy/stats');
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}
