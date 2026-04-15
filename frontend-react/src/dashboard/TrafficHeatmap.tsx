import { useMemo, useState } from 'react';
import type { DashEvent } from './types';
import { categoryColor, categoryName, formatBytes } from '../colors';

// ---------------------------------------------------------------------------
// Traffic Heatmap — devices (Y) × hours (X), brightness = bytes
// ---------------------------------------------------------------------------

interface HeatCell {
  bytes: number;
  hits: number;
  dominantCategory: string;
}

function buildHeatmap(events: DashEvent[]) {
  if (!events.length) return null;

  const devName = (ip: string) => {
    if (typeof (window as any).deviceName === 'function') return (window as any).deviceName(ip);
    return ip;
  };

  // Aggregate per device
  const devTotals: Record<string, number> = {};
  events.forEach(e => {
    const d = devName(e.source_ip);
    devTotals[d] = (devTotals[d] || 0) + (e.bytes_transferred || 0) + 1; // +1 so zero-byte events still rank
  });

  const topDevs = Object.entries(devTotals)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20)
    .map(([d]) => d);
  const topDevSet = new Set(topDevs);

  // Build grid: device × hour
  const grid: Record<string, HeatCell> = {};
  events.forEach(e => {
    const dev = devName(e.source_ip);
    if (!topDevSet.has(dev)) return;
    const hour = new Date(e.timestamp).getHours();
    const cat = e.category || 'other';
    const bytes = e.bytes_transferred || 0;
    const key = `${dev}\0${hour}`;
    if (!grid[key]) grid[key] = { bytes: 0, hits: 0, dominantCategory: 'other' };
    grid[key].bytes += bytes;
    grid[key].hits += 1;
    // Track dominant category by hit count
    if (!grid[key]._catHits) (grid[key] as any)._catHits = {};
    const ch = (grid[key] as any)._catHits;
    ch[cat] = (ch[cat] || 0) + 1;
  });

  // Resolve dominant category per cell
  Object.values(grid).forEach((cell: any) => {
    if (cell._catHits) {
      let topCat = 'other', topN = 0;
      Object.entries(cell._catHits).forEach(([c, n]) => {
        if ((n as number) > topN) { topCat = c; topN = n as number; }
      });
      cell.dominantCategory = topCat;
      delete cell._catHits;
    }
  });

  // Compute intensity metric per cell: use hits (every event counts equally)
  // Bytes have extreme outliers (e.g. 14GB vs 176KB median) that make the
  // heatmap useless. Hits give a much better distribution.
  const allVals = Object.values(grid).map(c => c.hits).filter(v => v > 0).sort((a, b) => a - b);
  if (allVals.length === 0) return null;

  // Cap at P95 so outliers don't wash out everything
  const p95Idx = Math.min(allVals.length - 1, Math.floor(allVals.length * 0.95));
  const maxVal = Math.max(1, allVals[p95Idx]);

  return { grid, devices: topDevs, maxVal };
}

export default function TrafficHeatmap({ events }: { events: DashEvent[] }) {
  const [tip, setTip] = useState<{ text: string; x: number; y: number } | null>(null);

  const data = useMemo(() => buildHeatmap(events), [events]);

  if (!data) return null;

  const { grid, devices, maxVal } = data;

  // Layout — 20 devices
  const cellW = 20;
  const cellH = 22;
  const gap = 2;
  const padLeft = 110;
  const padTop = 4;
  const svgW = padLeft + 24 * (cellW + gap) + 10;
  const svgH = padTop + devices.length * (cellH + gap) + 20;

  // Color intensity — uses category color with varying brightness
  function cellColor(cell: HeatCell | undefined): string {
    if (!cell || cell.hits === 0) return 'rgba(148,163,184,0.06)';
    const t = Math.min(1, Math.sqrt(cell.hits / maxVal)); // capped at 1, sqrt for distribution
    const base = categoryColor(cell.dominantCategory);
    // Parse hex to RGB and interpolate with dark background
    const r = parseInt(base.slice(1, 3), 16);
    const g = parseInt(base.slice(3, 5), 16);
    const b = parseInt(base.slice(5, 7), 16);
    // Lerp from dark (15,20,30) to full color
    const lr = Math.round(15 + t * (r - 15));
    const lg = Math.round(20 + t * (g - 20));
    const lb = Math.round(30 + t * (b - 30));
    return `rgb(${lr},${lg},${lb})`;
  }

  function cellColorLight(cell: HeatCell | undefined): string {
    if (!cell || cell.hits === 0) return 'rgba(148,163,184,0.08)';
    const t = Math.min(1, Math.sqrt(cell.hits / maxVal));
    const base = categoryColor(cell.dominantCategory);
    const r = parseInt(base.slice(1, 3), 16);
    const g = parseInt(base.slice(3, 5), 16);
    const b = parseInt(base.slice(5, 7), 16);
    // Lerp from light background (240,244,248) to full color
    const lr = Math.round(240 + t * (r - 240));
    const lg = Math.round(244 + t * (g - 244));
    const lb = Math.round(248 + t * (b - 248));
    return `rgb(${lr},${lg},${lb})`;
  }

  const isDark = document.documentElement.classList.contains('dark');
  const getColor = isDark ? cellColor : cellColorLight;

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4">
      <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
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
          style={{ minWidth: 500 }}
        >
          {/* Device rows */}
          {devices.map((dev, di) => {
            const y = padTop + di * (cellH + gap);
            const label = dev.length > 14 ? dev.slice(0, 13) + '…' : dev;
            return (
              <g key={dev}>
                {/* Device label */}
                <text
                  x={padLeft - 6}
                  y={y + cellH / 2}
                  textAnchor="end"
                  dominantBaseline="central"
                  fill={isDark ? 'rgba(148,163,184,0.7)' : 'rgba(71,85,105,0.8)'}
                  fontSize={10}
                  fontFamily="Inter, system-ui, sans-serif"
                >
                  {label}
                </text>

                {/* Hour cells */}
                {Array.from({ length: 24 }, (_, hi) => {
                  const key = `${dev}\0${hi}`;
                  const cell = grid[key];
                  return (
                    <rect
                      key={hi}
                      x={padLeft + hi * (cellW + gap)}
                      y={y}
                      width={cellW}
                      height={cellH}
                      rx={3}
                      ry={3}
                      fill={getColor(cell)}
                      className="cursor-pointer transition-opacity duration-150"
                      style={{ stroke: 'transparent', strokeWidth: 1 }}
                      onMouseEnter={(e) => {
                        (e.target as SVGRectElement).style.stroke = isDark ? 'rgba(255,255,255,0.5)' : 'rgba(0,0,0,0.3)';
                        const rect = (e.target as SVGRectElement).getBoundingClientRect();
                        const val = cell
                          ? `${cell.hits} hits` + (cell.bytes > 0 ? ` · ${formatBytes(cell.bytes)}` : '')
                          : 'No activity';
                        const cat = cell?.dominantCategory ? ` · ${categoryName(cell.dominantCategory)}` : '';
                        setTip({
                          text: `${dev} @ ${hi}:00–${hi + 1}:00 — ${val}${cat}`,
                          x: rect.x + rect.width / 2,
                          y: rect.y,
                        });
                      }}
                      onMouseLeave={(e) => {
                        (e.target as SVGRectElement).style.stroke = 'transparent';
                        setTip(null);
                      }}
                    />
                  );
                })}
              </g>
            );
          })}

          {/* Hour labels at bottom */}
          {Array.from({ length: 24 }, (_, h) => (
            <text
              key={h}
              x={padLeft + h * (cellW + gap) + cellW / 2}
              y={padTop + devices.length * (cellH + gap) + 12}
              textAnchor="middle"
              fill={isDark ? 'rgba(148,163,184,0.5)' : 'rgba(100,116,139,0.6)'}
              fontSize={8}
              fontFamily="Inter, system-ui, sans-serif"
            >
              {h % 3 === 0 ? `${h}:00` : ''}
            </text>
          ))}
        </svg>

        {/* Tooltip */}
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
