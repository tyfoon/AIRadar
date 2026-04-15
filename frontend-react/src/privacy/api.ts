import type { PrivacyStatsResponse } from './types';

export async function fetchPrivacyStats(params?: {
  service?: string;
  source_ip?: string;
  periodMinutes?: number;
}): Promise<PrivacyStatsResponse> {
  const q = new URLSearchParams();
  if (params?.service) q.set('service', params.service);
  if (params?.source_ip) q.set('source_ip', params.source_ip);
  if (params?.periodMinutes) {
    const start = new Date(Date.now() - params.periodMinutes * 60_000).toISOString();
    q.set('start', start);
  }
  const qs = q.toString();
  const res = await fetch(`/api/privacy/stats${qs ? '?' + qs : ''}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export function exportPrivacyCsvUrl(): string {
  return '/api/events/csv?category=tracking';
}
