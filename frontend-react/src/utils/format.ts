export function fmtBytes(b: number): string {
  if (!b || b <= 0) return '0 B';
  if (b >= 1073741824) return (b / 1073741824).toFixed(1) + ' GB';
  if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
  if (b >= 1024) return (b / 1024).toFixed(0) + ' KB';
  return b + ' B';
}

export function fmtDuration(ms: number): string {
  if (ms <= 0) return '0m';
  const mins = Math.round(ms / 60000);
  if (mins < 60) return `${mins}m`;
  const h = Math.floor(mins / 60);
  const m = mins % 60;
  return m > 0 ? `${h}h ${m}m` : `${h}h`;
}

export function fmtDurationSec(secs: number): string {
  if (!secs || secs < 0) return '0s';
  if (secs < 60) return `${secs}s`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m`;
  const h = Math.floor(mins / 60);
  const m = mins % 60;
  return m > 0 ? `${h}h ${m}m` : `${h}h`;
}

export function fmtTime(iso: string): string {
  const d = new Date(iso.endsWith('Z') ? iso : iso + 'Z');
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function formatNumber(n: number): string {
  return n.toLocaleString();
}

export function flagEmoji(cc: string): string {
  if (!cc || cc.length !== 2) return '';
  return cc.toLowerCase();
}

export function todayLocalISO(): string {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

export function formatLocalDateLabel(isoDate: string, locale?: string): string {
  const d = new Date(`${isoDate}T12:00:00`);
  const loc = locale === 'nl' ? 'nl-NL' : 'en-US';
  return d.toLocaleDateString(loc, { weekday: 'short', day: 'numeric', month: 'short' });
}
