import type { GeoTrafficResponse, CountryDetailResponse, Direction, BlockRule } from './types';

export async function fetchGeoTraffic(
  direction: Direction,
  period?: string,
  service?: string,
  device?: string,
): Promise<GeoTrafficResponse> {
  const p = new URLSearchParams();
  p.set('direction', direction);
  if (period) p.set('start', new Date(Date.now() - parseInt(period) * 60000).toISOString());
  if (service) p.set('service', service);
  if (device) p.set('source_ip', device);
  const res = await fetch(`/api/analytics/geo?${p}`);
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

export async function fetchCountryDetail(
  cc: string,
  direction: Direction,
): Promise<CountryDetailResponse> {
  const res = await fetch(`/api/analytics/geo/country/${cc}?direction=${direction}`);
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

export async function fetchBlockRules(): Promise<BlockRule[]> {
  const res = await fetch('/api/geo/block-rules');
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

export async function blockCountry(cc: string, direction: string): Promise<void> {
  const res = await fetch('/api/geo/block-rules', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ country_code: cc, direction }),
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
}

export async function unblockCountry(cc: string): Promise<void> {
  const res = await fetch(`/api/geo/block-rules/${cc}`, { method: 'DELETE' });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
}
