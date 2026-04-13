import type { ActivityResponse } from './types';

const browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone;

export async function fetchActivity(
  mac: string,
  date: string,
): Promise<ActivityResponse> {
  const url = `/api/devices/${encodeURIComponent(mac)}/activity?date=${date}&tz=${encodeURIComponent(browserTz)}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
