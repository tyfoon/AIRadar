import { useState, useMemo } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  ComposableMap,
  Geographies,
  Geography,
  ZoomableGroup,
} from 'react-simple-maps';
import { scaleLinear } from 'd3-scale';
import { fetchGeoTraffic, fetchBlockRules, blockCountry, unblockCountry } from './api';
import { formatBytes, formatNumber, countryName, flagClass, ratioColor } from './utils';
import type { Direction, GeoCountry } from './types';

const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

// Map ISO-3166-1 alpha-2 (our data) to ISO-3166-1 numeric (topojson)
// react-simple-maps uses numeric codes in the topojson
// We'll match by country name as fallback

// Access vanilla JS globals for device names and service display
function getDeviceMap(): Record<string, any> {
  return (window as any).deviceMap || {};
}
function svcDisplayName(svc: string): string {
  if (typeof (window as any).svcDisplayName === 'function') {
    return (window as any).svcDisplayName(svc);
  }
  return svc.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}
function bestDeviceName(mac: string, dev: any): string {
  if (typeof (window as any)._bestDeviceName === 'function') {
    return (window as any)._bestDeviceName(mac, dev);
  }
  return dev?.display_name || dev?.hostname || mac;
}

interface Props {
  initialDirection?: Direction;
}

export default function GeoMap({ initialDirection = 'outbound' }: Props) {
  const [direction, setDirection] = useState<Direction>(initialDirection);
  const [period, setPeriod] = useState('1440');
  const [serviceFilter, setServiceFilter] = useState('');
  const [deviceFilter, setDeviceFilter] = useState('');
  const [hoveredCountry, setHoveredCountry] = useState<string | null>(null);
  const [tooltipContent, setTooltipContent] = useState('');
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const queryClient = useQueryClient();

  const { data, isLoading, isError } = useQuery({
    queryKey: ['geo-traffic', direction, period, serviceFilter, deviceFilter],
    queryFn: () => fetchGeoTraffic(
      direction,
      period || undefined,
      serviceFilter || undefined,
      deviceFilter || undefined,
    ),
    staleTime: 30_000,
  });

  const { data: blockRules = [] } = useQuery({
    queryKey: ['geo-block-rules'],
    queryFn: fetchBlockRules,
    staleTime: 60_000,
  });

  // Fetch services list for filter dropdown
  const { data: eventsForServices } = useQuery({
    queryKey: ['events-for-service-list'],
    queryFn: async () => {
      const res = await fetch('/api/events?limit=1000');
      if (!res.ok) return [];
      return res.json();
    },
    staleTime: 120_000,
  });

  const countries = data?.countries || [];
  const blockedSet = useMemo(() => new Set(blockRules.map(r => r.country_code)), [blockRules]);

  // Build service options from events
  const serviceOptions = useMemo(() => {
    if (!eventsForServices || !Array.isArray(eventsForServices)) return [];
    const svcs = new Set<string>();
    eventsForServices.forEach((e: any) => {
      if (e.ai_service && e.ai_service !== 'unknown') svcs.add(e.ai_service);
    });
    return [...svcs].sort();
  }, [eventsForServices]);

  // Build device options from vanilla deviceMap
  const deviceOptions = useMemo(() => {
    const dm = getDeviceMap();
    return Object.entries(dm)
      .map(([mac, dev]: [string, any]) => {
        const name = bestDeviceName(mac, dev);
        // Pick first non-link-local IPv4 or IPv6
        const ip = (dev.ips || [])
          .map((i: any) => i.ip)
          .find((ip: string) => !ip.startsWith('fe80') && !ip.startsWith('fd')) || '';
        return { mac, name, ip };
      })
      .filter(d => d.ip)
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [data]); // re-derive when data refreshes

  // Color scale for map
  const bytesByCC = useMemo(() => {
    const m: Record<string, number> = {};
    countries.forEach(c => { m[c.country_code] = c.bytes; });
    return m;
  }, [countries]);

  const maxBytes = useMemo(() => Math.max(1, ...countries.map(c => c.bytes)), [countries]);

  const colorScale = useMemo(() => {
    const dark = document.documentElement.classList.contains('dark');
    return scaleLinear<string>()
      .domain([0, maxBytes * 0.3, maxBytes])
      .range(dark ? ['#1e293b', '#7c3aed', '#ef4444'] : ['#e2e8f0', '#a78bfa', '#dc2626']);
  }, [maxBytes]);

  async function handleBlock(cc: string) {
    try {
      await blockCountry(cc, 'both');
      queryClient.invalidateQueries({ queryKey: ['geo-block-rules'] });
    } catch (e) { console.error('Block failed:', e); }
  }

  async function handleUnblock(cc: string) {
    try {
      await unblockCountry(cc);
      queryClient.invalidateQueries({ queryKey: ['geo-block-rules'] });
    } catch (e) { console.error('Unblock failed:', e); }
  }

  // Stats
  const totalCountries = countries.length;
  const totalBytes = countries.reduce((s, c) => s + c.bytes, 0);
  const totalHits = countries.reduce((s, c) => s + c.hits, 0);
  const topCountry = countries[0];

  return (
    <div className="space-y-4">
      {/* Direction tabs */}
      <div className="flex items-center gap-1 bg-slate-100 dark:bg-white/[0.04] rounded-lg p-1 w-fit">
        <TabButton active={direction === 'outbound'} onClick={() => setDirection('outbound')} icon="ph-duotone ph-arrow-up-right" label="Outbound" />
        <TabButton active={direction === 'inbound'} onClick={() => setDirection('inbound')} icon="ph-duotone ph-arrow-down-left" label="Inbound" />
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard label="Countries" value={totalCountries} />
        <StatCard label="Bandwidth" value={formatBytes(totalBytes)} />
        <StatCard label="Connections" value={formatNumber(totalHits)} />
        <StatCard
          label="Top Destination"
          value={topCountry ? countryName(topCountry.country_code) : '—'}
          sub={topCountry ? formatBytes(topCountry.bytes) : undefined}
        />
      </div>

      {/* Filter bar */}
      <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl px-4 py-3 flex flex-wrap items-center gap-3">
        <span className="text-xs text-slate-500 dark:text-slate-400 font-medium">Filters</span>
        <select
          value={serviceFilter}
          onChange={e => setServiceFilter(e.target.value)}
          className="text-xs border border-slate-200 dark:border-white/[0.1] rounded-md px-2 py-1.5 bg-white dark:bg-white/[0.05] text-slate-600 dark:text-slate-300"
        >
          <option value="">All services</option>
          {serviceOptions.map(s => (
            <option key={s} value={s}>{svcDisplayName(s)}</option>
          ))}
        </select>
        <select
          value={deviceFilter}
          onChange={e => setDeviceFilter(e.target.value)}
          className="text-xs border border-slate-200 dark:border-white/[0.1] rounded-md px-2 py-1.5 bg-white dark:bg-white/[0.05] text-slate-600 dark:text-slate-300"
        >
          <option value="">All devices</option>
          {deviceOptions.map(d => (
            <option key={d.mac} value={d.ip}>{d.name}</option>
          ))}
        </select>
        <select
          value={period}
          onChange={e => setPeriod(e.target.value)}
          className="text-xs border border-slate-200 dark:border-white/[0.1] rounded-md px-2 py-1.5 bg-white dark:bg-white/[0.05] text-slate-600 dark:text-slate-300"
        >
          <option value="">All time</option>
          <option value="60">Last hour</option>
          <option value="1440">Last 24h</option>
          <option value="10080">Last 7 days</option>
        </select>
      </div>

      {/* Loading */}
      {isLoading && (
        <div className="py-10 text-center text-sm text-slate-400">
          <div className="inline-block w-5 h-5 border-2 border-slate-300 dark:border-slate-600 border-t-indigo-500 rounded-full animate-spin mb-2" />
          <p>Loading geo data...</p>
        </div>
      )}

      {/* Error */}
      {isError && <div className="py-8 text-center text-sm text-red-500">Failed to load geo data</div>}

      {/* Map */}
      {!isLoading && countries.length > 0 && (
        <div className="bg-white dark:bg-white/[0.02] border border-slate-200 dark:border-white/[0.05] rounded-xl overflow-hidden relative">
          {/* Tooltip */}
          {hoveredCountry && tooltipContent && (
            <div
              className="absolute z-10 px-2.5 py-1.5 rounded-lg bg-slate-800 text-white text-xs shadow-lg pointer-events-none"
              style={{ left: tooltipPos.x + 10, top: tooltipPos.y - 10 }}
              dangerouslySetInnerHTML={{ __html: tooltipContent }}
            />
          )}
          <ComposableMap
            projectionConfig={{ scale: 147 }}
            style={{ width: '100%', height: 'auto', maxHeight: 420 }}
          >
            <ZoomableGroup>
              <Geographies geography={GEO_URL}>
                {({ geographies }) =>
                  geographies.map(geo => {
                    const cc = geo.properties?.['ISO_A2'] || '';
                    const bytes = bytesByCC[cc] || 0;
                    const dark = document.documentElement.classList.contains('dark');
                    return (
                      <Geography
                        key={geo.rsmKey}
                        geography={geo}
                        fill={bytes > 0 ? colorScale(bytes) : (dark ? '#1e293b' : '#e2e8f0')}
                        stroke={dark ? '#334155' : '#cbd5e1'}
                        strokeWidth={0.4}
                        style={{
                          hover: { fill: dark ? '#475569' : '#cbd5e1', cursor: 'pointer' },
                        }}
                        onMouseEnter={(evt) => {
                          setHoveredCountry(cc);
                          const c = countries.find(x => x.country_code === cc);
                          if (c) {
                            setTooltipContent(
                              `<b>${countryName(cc)}</b><br/>${formatBytes(c.bytes)} · ${formatNumber(c.hits)} connections`,
                            );
                          } else {
                            setTooltipContent(`<b>${geo.properties?.name || cc}</b><br/>No traffic`);
                          }
                          const rect = (evt.target as SVGElement).closest('svg')?.getBoundingClientRect();
                          if (rect) {
                            setTooltipPos({
                              x: (evt as any).clientX - rect.left,
                              y: (evt as any).clientY - rect.top,
                            });
                          }
                        }}
                        onMouseLeave={() => {
                          setHoveredCountry(null);
                          setTooltipContent('');
                        }}
                        onClick={() => {
                          if (cc && typeof (window as any).openCountryDrawer === 'function') {
                            (window as any).openCountryDrawer(cc);
                          }
                        }}
                      />
                    );
                  })
                }
              </Geographies>
            </ZoomableGroup>
          </ComposableMap>
        </div>
      )}

      {/* Empty state */}
      {!isLoading && !isError && countries.length === 0 && (
        <div className="py-12 text-center text-sm text-slate-400">No geo traffic data for this period.</div>
      )}

      {/* Blocked countries */}
      {blockRules.length > 0 && (
        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
              <i className="ph-duotone ph-shield-warning text-red-500" />
              Blocked Countries
            </h3>
            <span className="text-xs text-slate-400">{blockRules.length} blocked</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {blockRules.map(r => (
              <span key={r.country_code} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400">
                <span className={`${flagClass(r.country_code)} text-sm`} />
                {countryName(r.country_code)}
                <span className="text-[10px] opacity-60">({r.direction})</span>
                <button onClick={() => handleUnblock(r.country_code)} className="ml-0.5 hover:text-red-800 dark:hover:text-red-300" title="Unblock">&times;</button>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Countries table */}
      {countries.length > 0 && (
        <CountriesTable countries={countries} direction={direction} blockedSet={blockedSet} onBlock={handleBlock} onUnblock={handleUnblock} />
      )}
    </div>
  );
}

// --- Sub-components ---

function TabButton({ active, onClick, icon, label }: { active: boolean; onClick: () => void; icon: string; label: string }) {
  return (
    <button
      onClick={onClick}
      className={`px-4 py-1.5 rounded-md text-xs font-medium transition-colors inline-flex items-center gap-1.5 ${
        active ? 'bg-blue-700 text-white shadow-sm' : 'text-slate-500 dark:text-slate-400 hover:text-slate-700'
      }`}
    >
      <i className={`${icon} text-sm`} />
      {label}
    </button>
  );
}

function StatCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4">
      <p className="text-[11px] text-slate-400 dark:text-slate-500 font-medium">{label}</p>
      <p className="text-xl font-bold mt-1 tabular-nums text-slate-700 dark:text-slate-100">{value}</p>
      {sub && <p className="text-[10px] text-slate-400 mt-0.5">{sub}</p>}
    </div>
  );
}

function CountriesTable({ countries, direction, blockedSet, onBlock, onUnblock }: {
  countries: GeoCountry[]; direction: Direction; blockedSet: Set<string>;
  onBlock: (cc: string) => void; onUnblock: (cc: string) => void;
}) {
  const maxBytes = Math.max(1, ...countries.map(c => c.bytes));
  return (
    <div className="bg-white dark:bg-white/[0.02] border border-slate-200 dark:border-white/[0.05] rounded-xl overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-[11px] text-slate-400 dark:text-slate-500 border-b border-slate-100 dark:border-white/[0.04]">
            <th className="py-2.5 px-4 text-left font-medium w-8">#</th>
            <th className="py-2.5 px-4 text-left font-medium">Country</th>
            <th className="py-2.5 px-4 text-right font-medium">Bandwidth</th>
            <th className="py-2.5 px-4 text-right font-medium hidden sm:table-cell">Connections</th>
            <th className="py-2.5 px-4 text-left font-medium hidden lg:table-cell" style={{ width: '25%' }}>Distribution</th>
            <th className="py-2.5 px-4 text-center font-medium w-10"></th>
          </tr>
        </thead>
        <tbody>
          {countries.map((c, i) => {
            const pct = (c.bytes / maxBytes) * 100;
            const color = ratioColor(c.bytes, c.opposite_bytes, direction);
            const isBlocked = blockedSet.has(c.country_code);
            return (
              <tr key={c.country_code} className="border-b border-slate-50 dark:border-white/[0.02] hover:bg-slate-50 dark:hover:bg-white/[0.02] transition-colors">
                <td className="py-2.5 px-4 text-slate-400 tabular-nums text-xs">{i + 1}</td>
                <td className="py-2.5 px-4 cursor-pointer" onClick={() => { if (typeof (window as any).openCountryDrawer === 'function') (window as any).openCountryDrawer(c.country_code); }}>
                  <span className="inline-flex items-center gap-2">
                    <span className={`${flagClass(c.country_code)} text-base`} />
                    <span className="font-medium text-slate-700 dark:text-slate-200">{countryName(c.country_code)}</span>
                    {isBlocked && <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 font-medium">blocked</span>}
                  </span>
                </td>
                <td className="py-2.5 px-4 text-right tabular-nums text-slate-600 dark:text-slate-300">{formatBytes(c.bytes)}</td>
                <td className="py-2.5 px-4 text-right tabular-nums text-slate-400 hidden sm:table-cell">{formatNumber(c.hits)}</td>
                <td className="py-2.5 px-4 hidden lg:table-cell">
                  <div className="w-full bg-slate-100 dark:bg-white/[0.04] rounded-full h-2">
                    <div className="h-2 rounded-full transition-all" style={{ width: `${Math.max(2, pct)}%`, backgroundColor: color, opacity: 0.8 }} />
                  </div>
                </td>
                <td className="py-2.5 px-2 text-center">
                  <button
                    onClick={e => { e.stopPropagation(); isBlocked ? onUnblock(c.country_code) : onBlock(c.country_code); }}
                    className={`p-1.5 rounded-lg transition-colors ${isBlocked ? 'text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20' : 'text-slate-300 dark:text-slate-600 hover:text-red-500 hover:bg-slate-100 dark:hover:bg-white/[0.05]'}`}
                    title={isBlocked ? `Unblock ${countryName(c.country_code)}` : `Block ${countryName(c.country_code)}`}
                  >
                    <i className={`ph-duotone ${isBlocked ? 'ph-shield-slash' : 'ph-shield-warning'} text-base`} />
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
