import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { categoryColor, categoryName, formatBytes } from '../colors';

// ---------------------------------------------------------------------------
// Traffic Heatmap — devices (Y) × hours (X), color = category, brightness = hits
// Uses server-side aggregation to avoid fetching 10k+ raw events.
// ---------------------------------------------------------------------------

interface HeatmapCell {
  ip: string;
  hour: number;
  hits: number;
  bytes: number;
  category: string;
}

interface HeatmapResponse {
  devices: string[];   // top 20 device IPs, sorted by total hits
  cells: HeatmapCell[];
}

async function fetchHeatmap(hours: number): Promise<HeatmapResponse> {
  const r = await fetch(`/api/events/heatmap?hours=${hours}`);
  return r.json();
}

export default function TrafficHeatmap({ hours }: { hours: number }) {
  const [tip, setTip] = useState<{ text: string; x: number; y: number } | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ['dash-heatmap', hours],
    queryFn: () => fetchHeatmap(hours),
    refetchInterval: 60_000,
    staleTime: 30_000,
  });

  const processed = useMemo(() => {
    if (!data || !data.cells.length) return null;

    const devName = (ip: string) => {
      if (typeof (window as any).deviceName === 'function') return (window as any).deviceName(ip);
      return ip;
    };

    // Build lookup: "ip\0hour" → cell
    const grid: Record<string, HeatmapCell> = {};
    data.cells.forEach(c => { grid[`${c.ip}\0${c.hour}`] = c; });

    // Map IPs to display names
    const devices = data.devices.map(ip => ({ ip, name: devName(ip) }));

    // P95 cap for intensity
    const allHits = data.cells.map(c => c.hits).sort((a, b) => a - b);
    const p95Idx = Math.min(allHits.length - 1, Math.floor(allHits.length * 0.95));
    const maxVal = Math.max(1, allHits[p95Idx]);

    return { grid, devices, maxVal };
  }, [data]);

  if (isLoading) {
    return (
      <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4">
        <div className="h-24 bg-slate-100 dark:bg-white/[0.03] rounded animate-pulse" />
      </div>
    );
  }

  if (!processed) return null;

  const { grid, devices, maxVal } = processed;
  const isDark = document.documentElement.classList.contains('dark');

  // Compact layout
  const cellW = 18;
  const cellH = 11;
  const gap = 1;
  const padLeft = 100;
  const padTop = 2;
  const svgW = padLeft + 24 * (cellW + gap) + 10;
  const svgH = padTop + devices.length * (cellH + gap) + 14;

  function getColor(cell: HeatmapCell | undefined): string {
    if (!cell || cell.hits === 0) return isDark ? 'rgba(148,163,184,0.06)' : 'rgba(148,163,184,0.08)';
    const t = Math.min(1, Math.sqrt(cell.hits / maxVal));
    const base = categoryColor(cell.category);
    const r = parseInt(base.slice(1, 3), 16);
    const g = parseInt(base.slice(3, 5), 16);
    const b = parseInt(base.slice(5, 7), 16);
    if (isDark) {
      return `rgb(${Math.round(15 + t * (r - 15))},${Math.round(20 + t * (g - 20))},${Math.round(30 + t * (b - 30))})`;
    }
    return `rgb(${Math.round(240 + t * (r - 240))},${Math.round(244 + t * (g - 244))},${Math.round(248 + t * (b - 248))})`;
  }

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4">
      <div className="flex items-center justify-between mb-2 flex-wrap gap-2">
        <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
          <i className="ph-duotone ph-chart-bar text-indigo-500" /> Traffic Heatmap
        </h3>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-slate-400">
          {['ai', 'cloud', 'streaming', 'tracking', 'social', 'gaming'].map(cat => (
            <span key={cat} className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-sm inline-block" style={{ backgroundColor: categoryColor(cat) }} />
              {categoryName(cat)}
            </span>
          ))}
        </div>
      </div>

      <div className="relative overflow-x-auto">
        <svg
          width="100%"
          viewBox={`0 0 ${svgW} ${svgH}`}
          preserveAspectRatio="xMinYMin meet"
          className="overflow-visible"
          style={{ minWidth: 480 }}
        >
          {devices.map((dev, di) => {
            const y = padTop + di * (cellH + gap);
            const label = dev.name.length > 14 ? dev.name.slice(0, 13) + '…' : dev.name;
            return (
              <g key={dev.ip}>
                <text
                  x={padLeft - 4}
                  y={y + cellH / 2}
                  textAnchor="end"
                  dominantBaseline="central"
                  fill={isDark ? 'rgba(148,163,184,0.7)' : 'rgba(71,85,105,0.8)'}
                  fontSize={8}
                  fontFamily="Inter, system-ui, sans-serif"
                >
                  {label}
                </text>
                {Array.from({ length: 24 }, (_, hi) => {
                  const cell = grid[`${dev.ip}\0${hi}`];
                  return (
                    <rect
                      key={hi}
                      x={padLeft + hi * (cellW + gap)}
                      y={y}
                      width={cellW}
                      height={cellH}
                      rx={2}
                      ry={2}
                      fill={getColor(cell)}
                      className="cursor-pointer"
                      onMouseEnter={(e) => {
                        (e.target as SVGRectElement).style.stroke = isDark ? 'rgba(255,255,255,0.5)' : 'rgba(0,0,0,0.3)';
                        (e.target as SVGRectElement).style.strokeWidth = '0.5';
                        const rect = (e.target as SVGRectElement).getBoundingClientRect();
                        const val = cell
                          ? `${cell.hits} hits` + (cell.bytes > 0 ? ` · ${formatBytes(cell.bytes)}` : '')
                          : 'No activity';
                        const cat = cell ? ` · ${categoryName(cell.category)}` : '';
                        setTip({
                          text: `${dev.name} @ ${hi}:00–${hi + 1}:00 — ${val}${cat}`,
                          x: rect.x + rect.width / 2,
                          y: rect.y,
                        });
                      }}
                      onMouseLeave={(e) => {
                        (e.target as SVGRectElement).style.stroke = 'none';
                        setTip(null);
                      }}
                    />
                  );
                })}
              </g>
            );
          })}

          {Array.from({ length: 24 }, (_, h) => (
            <text
              key={h}
              x={padLeft + h * (cellW + gap) + cellW / 2}
              y={padTop + devices.length * (cellH + gap) + 9}
              textAnchor="middle"
              fill={isDark ? 'rgba(148,163,184,0.5)' : 'rgba(100,116,139,0.6)'}
              fontSize={7}
              fontFamily="Inter, system-ui, sans-serif"
            >
              {h % 3 === 0 ? `${h}:00` : ''}
            </text>
          ))}
        </svg>

        {tip && (
          <div
            className="fixed bg-slate-900 dark:bg-slate-800 text-slate-200 text-[11px] px-2.5 py-1 rounded-md pointer-events-none whitespace-nowrap z-50 shadow-lg"
            style={{ left: tip.x, top: tip.y - 28, transform: 'translateX(-50%)' }}
          >
            {tip.text}
          </div>
        )}
      </div>
    </div>
  );
}
