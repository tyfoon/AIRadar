// Category colors — synced with CATEGORY_COLORS in app.js
const CATEGORY_COLORS: Record<string, string> = {
  ai: '#6366f1',
  cloud: '#3b82f6',
  streaming: '#e50914',
  gaming: '#10b981',
  social: '#f59e0b',
  tracking: '#ef4444',
  shopping: '#8b5cf6',
  news: '#06b6d4',
  adult: '#64748b',
  communication: '#0ea5e9',
};

// Per-service colors: hash the service name to a hue for consistent
// but distinct colors within the same category.
const SERVICE_CACHE: Record<string, string> = {};

function hashCode(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  }
  return Math.abs(h);
}

export function categoryColor(cat: string): string {
  return CATEGORY_COLORS[cat] || '#94a3b8';
}

export function serviceColor(service: string, category: string): string {
  const key = `${service}:${category}`;
  if (SERVICE_CACHE[key]) return SERVICE_CACHE[key];
  const base = CATEGORY_COLORS[category];
  if (!base) {
    const hue = hashCode(service) % 360;
    const c = `hsl(${hue}, 55%, 50%)`;
    SERVICE_CACHE[key] = c;
    return c;
  }
  SERVICE_CACHE[key] = base;
  return base;
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return rm > 0 ? `${h}h ${rm}m` : `${h}h`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function serviceName(s: string): string {
  return s
    .replace(/_/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase());
}
