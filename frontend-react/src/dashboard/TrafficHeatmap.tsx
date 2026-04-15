import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { categoryColor, categoryName, formatBytes } from '../colors';

// ---------------------------------------------------------------------------
// Traffic Heatmap — devices (Y) × hours (X)
// Default: all categories summed, teal color. Click category to filter.
// ---------------------------------------------------------------------------

interface HeatmapCell {
  ip: string;
  hour: number;
  hits: number;
  bytes: number;
  cats: Record<string, number>;  // category → hits
}

interface HeatmapResponse {
  devices: string[];
  cells: HeatmapCell[];
}

const ALL_COLOR = '#14b8a6'; // teal-500 — not used by any category

const LEGEND_CATS = ['ai', 'cloud', 'streaming', 'tracking', 'social', 'gaming', 'infrastructure', 'communication'];

async function fetchHeatmap(hours: number): Promise<HeatmapResponse> {
  const r = await fetch(`/api/events/heatmap?hours=${hours}`);
  return r.json();
}

export default function TrafficHeatmap({ hours }: { hours: number }) {
  const [tip, setTip] = useState<{ text: string; x: number; y: number } | null>(null);
  const [filter, setFilter] = useState<string | null>(null); // null = all

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

    const grid: Record<string, HeatmapCell> = {};
    data.cells.forEach(c => { grid[`${c.ip}\0${c.hour}`] = c; });

    const devices = data.devices.map(ip => ({ ip, name: devName(ip) }));

    // Collect which categories actually exist in data
    const seenCats = new Set<string>();
    data.cells.forEach(c => { Object.keys(c.cats).forEach(cat => seenCats.add(cat)); });

    return { grid, devices, seenCats };
  }, [data]);

  // Compute maxVal based on filter
  const maxVal = useMemo(() => {
    if (!data) return 1;
    const vals = data.cells.map(c => {
      if (!filter) return c.hits;
      return c.cats[filter] || 0;
    }).filter(v => v > 0).sort((a, b) => a - b);
    if (vals.length === 0) return 1;
    const p95 = Math.min(vals.length - 1, Math.floor(vals.length * 0.95));
    return Math.max(1, vals[p95]);
  }, [data, filter]);

  if (isLoading) {
    return (
      <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4">
        <div className="h-24 bg-slate-100 dark:bg-white/[0.03] rounded animate-pulse" />
      </div>
    );
  }

  if (!processed) return null;

  const { grid, devices, seenCats } = processed;
  const isDark = document.documentElement.classList.contains('dark');

  // Layout — font sizes match Sankey (11px rendered ≈ 4px in viewBox coords)
  const cellW = 8;
  const cellH = 5;
  const gap = 1;
  const padLeft = 58;
  const padRight = 2;
  const padTop = 1;
  const svgW = padLeft + 24 * (cellW + gap) + padRight;
  const svgH = padTop + devices.length * (cellH + gap) + 8;
  const labelFont = 3.5;

  function getCellValue(cell: HeatmapCell | undefined): number {
    if (!cell) return 0;
    if (!filter) return cell.hits;
    return cell.cats[filter] || 0;
  }

  function getColor(cell: HeatmapCell | undefined): string {
    const val = getCellValue(cell);
    if (val === 0) return isDark ? 'rgba(148,163,184,0.06)' : 'rgba(148,163,184,0.08)';
    const t = Math.min(1, Math.sqrt(val / maxVal));
    const base = filter ? categoryColor(filter) : ALL_COLOR;
    const r = parseInt(base.slice(1, 3), 16);
    const g = parseInt(base.slice(3, 5), 16);
    const b = parseInt(base.slice(5, 7), 16);
    if (isDark) {
      return `rgb(${Math.round(15 + t * (r - 15))},${Math.round(20 + t * (g - 20))},${Math.round(30 + t * (b - 30))})`;
    }
    return `rgb(${Math.round(240 + t * (r - 240))},${Math.round(244 + t * (g - 244))},${Math.round(248 + t * (b - 248))})`;
  }

  // Only show categories that exist in data
  const visibleCats = LEGEND_CATS.filter(c => seenCats.has(c));

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4">
      <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5 mb-1.5">
        <i className="ph-duotone ph-chart-bar text-indigo-500" /> Traffic Heatmap
      </h3>
      <div className="flex flex-wrap items-center gap-x-1 gap-y-1 text-[10px] mb-2 relative z-10">
        <button
          onClick={() => setFilter(null)}
          className={`flex items-center gap-1 px-1.5 py-0.5 rounded transition-colors cursor-pointer ${
            filter === null
              ? 'bg-teal-100 dark:bg-teal-900/30 text-teal-700 dark:text-teal-300'
              : 'text-slate-400 hover:text-slate-600 dark:hover:text-slate-300'
          }`}
        >
          <span className="w-2 h-2 rounded-sm inline-block" style={{ backgroundColor: ALL_COLOR }} />
          All
        </button>
        {visibleCats.map(cat => (
          <button
            key={cat}
            onClick={() => setFilter(filter === cat ? null : cat)}
            className={`flex items-center gap-1 px-1.5 py-0.5 rounded transition-colors cursor-pointer ${
              filter === cat
                ? 'bg-slate-200 dark:bg-white/10 text-slate-700 dark:text-slate-200'
                : 'text-slate-400 hover:text-slate-600 dark:hover:text-slate-300'
            }`}
          >
            <span className="w-2 h-2 rounded-sm inline-block" style={{ backgroundColor: categoryColor(cat) }} />
            {categoryName(cat)}
          </button>
        ))}
      </div>

      <div className="relative overflow-x-auto">
        <svg
          viewBox={`0 0 ${svgW} ${svgH}`}
          preserveAspectRatio="none"
          className="overflow-visible"
          style={{ width: '100%', height: devices.length * 7 + 16 }}
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
                  fill={isDark ? '#cbd5e1' : '#475569'}
                  fontSize={labelFont}
                  fontFamily="Inter, system-ui, sans-serif"
                >
                  {label}
                </text>
                {Array.from({ length: 24 }, (_, hi) => {
                  const cell = grid[`${dev.ip}\0${hi}`];
                  const val = getCellValue(cell);
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
                        const valText = val > 0 ? `${val} hits` : 'No activity';
                        const catText = filter ? ` · ${categoryName(filter)}` : '';
                        setTip({
                          text: `${dev.name} @ ${hi}:00–${hi + 1}:00 — ${valText}${catText}`,
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
              y={padTop + devices.length * (cellH + gap) + 7}
              textAnchor="middle"
              fill={isDark ? '#cbd5e1' : '#475569'}
              fontSize={labelFont}
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
