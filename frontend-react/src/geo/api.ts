import type { GeoTrafficResponse, CountryDetailResponse, Direction } from './types';

export async function fetchGeoTraffic(
  direction: Direction,
  period?: string,
  service?: string,
  sourceIp?: string,
): Promise<GeoTrafficResponse> {
  const p = new URLSearchParams();
  p.set('direction', direction);
  if (period) p.set('start', new Date(Date.now() - parseInt(period) * 60000).toISOString());
  if (service) p.set('service', service);
  if (sourceIp) p.set('source_ip', sourceIp);
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
