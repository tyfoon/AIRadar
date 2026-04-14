import type { Direction } from './types';

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  if (bytes < 1024 ** 4) return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
  return `${(bytes / 1024 ** 4).toFixed(2)} TB`;
}

export function formatNumber(n: number): string {
  return n.toLocaleString();
}

export function countryName(cc: string): string {
  try {
    const dn = new Intl.DisplayNames(['en'], { type: 'region' });
    return dn.of(cc.toUpperCase()) || cc;
  } catch {
    return cc;
  }
}

export function flagClass(cc: string): string {
  return `fi fi-${cc.toLowerCase()}`;
}

/** Color class for the ratio border: orange=upload heavy, blue=download heavy */
export function ratioColor(
  bytes: number,
  oppositeBytes: number,
  direction: Direction,
): string {
  if (!oppositeBytes || !bytes) return '#94a3b8'; // slate
  const ratio = direction === 'outbound'
    ? bytes / Math.max(1, oppositeBytes)
    : oppositeBytes / Math.max(1, bytes);
  if (ratio > 3) return '#f97316';   // orange — upload heavy
  if (ratio < 0.33) return '#3b82f6'; // blue — download heavy
  return '#94a3b8';                   // slate — balanced
}
