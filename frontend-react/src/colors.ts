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

const CATEGORY_NAMES: Record<string, string> = {
  ai: 'AI',
  cloud: 'Cloud',
  streaming: 'Streaming',
  gaming: 'Gaming',
  social: 'Social',
  tracking: 'Tracking',
  shopping: 'Shopping',
  news: 'News',
  adult: 'Adult',
  communication: 'Communication',
};

// Per-service distinct colors. Services within the same category get
// different hues so you can tell Spotify from YouTube in the timeline.
const SERVICE_CACHE: Record<string, string> = {};

function hashCode(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  }
  return Math.abs(h);
}

// Parse hex color to HSL, shift hue, return hex
function hexToHSL(hex: string): [number, number, number] {
  const r = parseInt(hex.slice(1, 3), 16) / 255;
  const g = parseInt(hex.slice(3, 5), 16) / 255;
  const b = parseInt(hex.slice(5, 7), 16) / 255;
  const max = Math.max(r, g, b), min = Math.min(r, g, b);
  const l = (max + min) / 2;
  let h = 0, s = 0;
  if (max !== min) {
    const d = max - min;
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
    if (max === r) h = ((g - b) / d + (g < b ? 6 : 0)) / 6;
    else if (max === g) h = ((b - r) / d + 2) / 6;
    else h = ((r - g) / d + 4) / 6;
  }
  return [Math.round(h * 360), Math.round(s * 100), Math.round(l * 100)];
}

export function categoryColor(cat: string): string {
  return CATEGORY_COLORS[cat] || '#94a3b8';
}

export function categoryName(cat: string): string {
  return CATEGORY_NAMES[cat] || cat.charAt(0).toUpperCase() + cat.slice(1);
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

  // Shift hue by a hash-derived offset so each service within the same
  // category gets a visually distinct color
  const [h, s, l] = hexToHSL(base);
  const offset = (hashCode(service) % 60) - 30; // -30 to +30 degrees
  const lShift = (hashCode(service + '_l') % 20) - 10; // -10 to +10 lightness
  const newH = (h + offset + 360) % 360;
  const newL = Math.max(25, Math.min(65, l + lShift));
  const c = `hsl(${newH}, ${Math.max(40, s)}%, ${newL}%)`;
  SERVICE_CACHE[key] = c;
  return c;
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
