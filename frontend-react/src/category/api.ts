import type { DetectionEvent, TimelineBucket } from './types';

export interface FilterParams {
  category: string;
  service?: string;
  sourceIp?: string;
  periodMinutes?: number;
  includeHeartbeats?: boolean;
}

function buildParams(f: FilterParams): URLSearchParams {
  const p = new URLSearchParams();
  p.set('category', f.category);
  if (f.service) p.set('service', f.service);
  if (f.sourceIp) p.set('source_ip', f.sourceIp);
  if (f.periodMinutes) {
    p.set('start', new Date(Date.now() - f.periodMinutes * 60_000).toISOString());
  }
  if (f.includeHeartbeats === false) p.set('include_heartbeats', 'false');
  return p;
}

function bucketSize(periodMinutes?: number): string {
  if (periodMinutes && periodMinutes <= 60) return 'minute';
  return 'hour';
}

export async function fetchEvents(f: FilterParams): Promise<DetectionEvent[]> {
  const r = await fetch('/api/events?' + buildParams(f));
  if (!r.ok) throw new Error(`Events API ${r.status}`);
  return r.json();
}

export async function fetchTimeline(f: FilterParams): Promise<TimelineBucket[]> {
  const p = buildParams(f);
  p.set('bucket_size', bucketSize(f.periodMinutes));
  const r = await fetch('/api/timeline?' + p);
  if (!r.ok) throw new Error(`Timeline API ${r.status}`);
  return r.json();
}

export function exportCsvUrl(f: FilterParams): string {
  return '/api/events/export?' + buildParams(f);
}
