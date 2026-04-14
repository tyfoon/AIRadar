import { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import Globe from 'react-globe.gl';
import { fetchGeoTraffic, fetchBlockRules, blockCountry, unblockCountry } from './api';
import { formatBytes, formatNumber, countryName, flagClass, ratioColor } from './utils';
import type { Direction, GeoCountry } from './types';

const GEO_JSON_URL =
  'https://raw.githubusercontent.com/vasturiano/react-globe.gl/master/example/datasets/ne_110m_admin_0_countries.geojson';

// Home location (Netherlands) for initial view + arc origin
const HOME = { lat: 52.1, lng: 5.3 };

// Rough country centroids for arc endpoints (top traffic countries)
const CENTROIDS: Record<string, { lat: number; lng: number }> = {
  US: { lat: 39.8, lng: -98.6 }, CA: { lat: 56.1, lng: -106.3 },
  GB: { lat: 54.0, lng: -2.0 }, DE: { lat: 51.2, lng: 10.4 },
  FR: { lat: 46.6, lng: 2.2 }, IE: { lat: 53.4, lng: -8.2 },
  NL: { lat: 52.1, lng: 5.3 }, ES: { lat: 40.5, lng: -3.7 },
  IT: { lat: 41.9, lng: 12.6 }, SE: { lat: 60.1, lng: 18.6 },
  NO: { lat: 60.5, lng: 8.5 }, PL: { lat: 51.9, lng: 19.1 },
  CH: { lat: 46.8, lng: 8.2 }, BE: { lat: 50.5, lng: 4.5 },
  AT: { lat: 47.5, lng: 14.6 }, CZ: { lat: 49.8, lng: 15.5 },
  DK: { lat: 56.3, lng: 9.5 }, FI: { lat: 61.9, lng: 25.7 },
  AU: { lat: -25.3, lng: 133.8 }, JP: { lat: 36.2, lng: 138.3 },
  KR: { lat: 35.9, lng: 127.8 }, CN: { lat: 35.9, lng: 104.2 },
  IN: { lat: 20.6, lng: 79.0 }, SG: { lat: 1.4, lng: 103.8 },
  BR: { lat: -14.2, lng: -51.9 }, RU: { lat: 61.5, lng: 105.3 },
  ZA: { lat: -30.6, lng: 22.9 }, MX: { lat: 23.6, lng: -102.6 },
  HK: { lat: 22.4, lng: 114.1 }, RO: { lat: 45.9, lng: 25.0 },
  BG: { lat: 42.7, lng: 25.5 }, UA: { lat: 48.4, lng: 31.2 },
  PT: { lat: 39.4, lng: -8.2 }, LU: { lat: 49.8, lng: 6.1 },
  SK: { lat: 48.7, lng: 19.7 }, HU: { lat: 47.2, lng: 19.5 },
  KE: { lat: -0.02, lng: 37.9 }, SA: { lat: 23.9, lng: 45.1 },
  AE: { lat: 23.4, lng: 53.8 }, IL: { lat: 31.0, lng: 34.9 },
  TW: { lat: 23.7, lng: 121.0 }, AR: { lat: -38.4, lng: -63.6 },
  CO: { lat: 4.6, lng: -74.3 }, GE: { lat: 42.3, lng: 43.4 },
};

function svcDisplayName(svc: string): string {
  if (typeof (window as any).svcDisplayName === 'function') {
    return (window as any).svcDisplayName(svc);
  }
  return svc.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

interface Props {
  initialDirection?: Direction;
}

export default function GeoMap({ initialDirection = 'outbound' }: Props) {
  const [direction, setDirection] = useState<Direction>(initialDirection);
  const [period, setPeriod] = useState('1440');
  const [serviceFilter, setServiceFilter] = useState('');
  const [deviceFilter, setDeviceFilter] = useState('');
  const queryClient = useQueryClient();
  const globeRef = useRef<any>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [globeSize, setGlobeSize] = useState({ w: 600, h: 380 });
  const [geoJson, setGeoJson] = useState<any>(null);

  // Responsive sizing
  useEffect(() => {
    function measure() {
      if (containerRef.current) {
        const w = containerRef.current.clientWidth;
        setGlobeSize({ w, h: Math.min(380, Math.round(w * 0.5)) });
      }
    }
    measure();
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, []);

  // Fetch GeoJSON
  useEffect(() => {
    fetch(GEO_JSON_URL).then(r => r.json()).then(d => setGeoJson(d.features));
  }, []);

  // Auto-rotate + initial view
  useEffect(() => {
    if (!globeRef.current) return;
    const controls = globeRef.current.controls();
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.3;
    controls.enableZoom = true;
    globeRef.current.pointOfView({ lat: HOME.lat, lng: HOME.lng, altitude: 2.2 }, 0);
  }, [geoJson]);

  const { data, isLoading, isError } = useQuery({
    queryKey: ['geo-traffic', direction, period, serviceFilter, deviceFilter],
    queryFn: () => fetchGeoTraffic(
      direction, period || undefined, serviceFilter || undefined, deviceFilter || undefined,
    ),
    staleTime: 30_000,
  });

  const { data: blockRules = [] } = useQuery({
    queryKey: ['geo-block-rules'],
    queryFn: fetchBlockRules,
    staleTime: 60_000,
  });

  const { data: eventsForServices } = useQuery({
    queryKey: ['events-for-service-list'],
    queryFn: async () => {
      const res = await fetch('/api/events?limit=1000');
      if (!res.ok) return [];
      return res.json();
    },
    staleTime: 120_000,
  });

  const { data: devicesRaw } = useQuery({
    queryKey: ['devices-list'],
    queryFn: async () => {
      const res = await fetch('/api/devices');
      if (!res.ok) return [];
      return res.json();
    },
    staleTime: 60_000,
  });

  const countries = data?.countries || [];
  const blockedSet = useMemo(() => new Set(blockRules.map(r => r.country_code)), [blockRules]);

  const serviceOptions = useMemo(() => {
    if (!eventsForServices || !Array.isArray(eventsForServices)) return [];
    const svcs = new Set<string>();
    eventsForServices.forEach((e: any) => {
      if (e.ai_service && e.ai_service !== 'unknown') svcs.add(e.ai_service);
    });
    return [...svcs].sort();
  }, [eventsForServices]);

  const deviceOptions = useMemo(() => {
    if (!devicesRaw || !Array.isArray(devicesRaw)) return [];
    return devicesRaw
      .map((dev: any) => {
        const name = dev.display_name || dev.hostname || dev.mac_address;
        const ip = (dev.ips || [])
          .map((i: any) => i.ip)
          .find((ip: string) => !ip.startsWith('fe80') && !ip.startsWith('fd')) || '';
        return { mac: dev.mac_address, name, ip };
      })
      .filter(d => d.ip)
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [devicesRaw]);

  // Build bytes lookup and color function
  const bytesByCC = useMemo(() => {
    const m: Record<string, number> = {};
    countries.forEach(c => { m[c.country_code] = c.bytes; });
    return m;
  }, [countries]);

  const maxBytes = useMemo(() => Math.max(1, ...countries.map(c => c.bytes)), [countries]);

  const countryColor = useCallback((cc: string) => {
    const bytes = bytesByCC[cc] || 0;
    if (bytes <= 0) return 'rgba(30, 58, 100, 0.3)';
    const t = Math.log10(bytes + 1) / Math.log10(maxBytes + 1);
    // Blue hue: dim → bright
    const r = Math.round(20 + t * 40);
    const g = Math.round(60 + t * 100);
    const b = Math.round(160 + t * 90);
    return `rgb(${r},${g},${b})`;
  }, [bytesByCC, maxBytes]);

  // Polygon cap color accessor
  const polygonCapColor = useCallback((feat: any) => {
    const cc = feat?.properties?.ISO_A2;
    return countryColor(cc || '');
  }, [countryColor]);

  const polygonLabel = useCallback((feat: any) => {
    const cc = feat?.properties?.ISO_A2 || '';
    const name = feat?.properties?.NAME || cc;
    const c = countries.find(x => x.country_code === cc);
    if (c) {
      return `<div style="background:rgba(0,0,0,0.8);color:#fff;padding:6px 10px;border-radius:6px;font-size:12px;line-height:1.4">
        <b>${name}</b><br/>${formatBytes(c.bytes)} &middot; ${formatNumber(c.hits)} connections
      </div>`;
    }
    return `<div style="background:rgba(0,0,0,0.7);color:#ccc;padding:4px 8px;border-radius:4px;font-size:11px">${name}</div>`;
  }, [countries]);

  const handlePolygonClick = useCallback((feat: any) => {
    const cc = feat?.properties?.ISO_A2;
    if (cc && typeof (window as any).openCountryDrawer === 'function') {
      (window as any).openCountryDrawer(cc);
    }
  }, []);

  // Arcs from home to top countries
  const arcsData = useMemo(() => {
    return countries
      .filter(c => c.country_code !== 'NL' && CENTROIDS[c.country_code])
      .slice(0, 15)
      .map(c => {
        const dest = CENTROIDS[c.country_code];
        const t = Math.log10(c.bytes + 1) / Math.log10(maxBytes + 1);
        return {
          startLat: HOME.lat,
          startLng: HOME.lng,
          endLat: dest.lat,
          endLng: dest.lng,
          color: [`rgba(59,130,246,${0.3 + t * 0.5})`, `rgba(59,130,246,${0.1 + t * 0.2})`],
          stroke: 0.3 + t * 1.5,
          label: `${countryName(c.country_code)}: ${formatBytes(c.bytes)}`,
        };
      });
  }, [countries, maxBytes]);

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

  const totalCountries = countries.length;
  const totalBytes = countries.reduce((s, c) => s + c.bytes, 0);
  const totalHits = countries.reduce((s, c) => s + c.hits, 0);
  const topCountry = countries[0];

  const dark = typeof document !== 'undefined' && document.documentElement.classList.contains('dark');

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
        <select value={serviceFilter} onChange={e => setServiceFilter(e.target.value)}
          className="text-xs border border-slate-200 dark:border-white/[0.1] rounded-md px-2 py-1.5 bg-white dark:bg-white/[0.05] text-slate-600 dark:text-slate-300">
          <option value="">All services</option>
          {serviceOptions.map(s => <option key={s} value={s}>{svcDisplayName(s)}</option>)}
        </select>
        <select value={deviceFilter} onChange={e => setDeviceFilter(e.target.value)}
          className="text-xs border border-slate-200 dark:border-white/[0.1] rounded-md px-2 py-1.5 bg-white dark:bg-white/[0.05] text-slate-600 dark:text-slate-300">
          <option value="">All devices</option>
          {deviceOptions.map(d => <option key={d.mac} value={d.ip}>{d.name}</option>)}
        </select>
        <select value={period} onChange={e => setPeriod(e.target.value)}
          className="text-xs border border-slate-200 dark:border-white/[0.1] rounded-md px-2 py-1.5 bg-white dark:bg-white/[0.05] text-slate-600 dark:text-slate-300">
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

      {isError && <div className="py-8 text-center text-sm text-red-500">Failed to load geo data</div>}

      {/* Globe */}
      {geoJson && !isLoading && (
        <div ref={containerRef}
          className="bg-slate-950 border border-slate-200 dark:border-white/[0.05] rounded-xl overflow-hidden"
        >
          <Globe
            ref={globeRef}
            width={globeSize.w}
            height={globeSize.h}
            backgroundColor="rgba(0,0,0,0)"
            showAtmosphere={true}
            atmosphereColor={dark ? '#1e3a8a' : '#3b82f6'}
            atmosphereAltitude={0.15}
            showGraticules={false}
            polygonsData={geoJson}
            polygonGeoJsonGeometry="geometry"
            polygonCapColor={polygonCapColor}
            polygonSideColor={() => 'rgba(30,58,100,0.15)'}
            polygonStrokeColor={() => 'rgba(100,140,200,0.2)'}
            polygonAltitude={(feat: any) => {
              const cc = feat?.properties?.ISO_A2 || '';
              const bytes = bytesByCC[cc] || 0;
              return bytes > 0 ? 0.005 + (Math.log10(bytes + 1) / Math.log10(maxBytes + 1)) * 0.02 : 0.003;
            }}
            polygonLabel={polygonLabel}
            onPolygonClick={handlePolygonClick}
            arcsData={arcsData}
            arcStartLat="startLat"
            arcStartLng="startLng"
            arcEndLat="endLat"
            arcEndLng="endLng"
            arcColor="color"
            arcStroke="stroke"
            arcDashLength={0.5}
            arcDashGap={0.3}
            arcDashAnimateTime={2000}
            arcLabel="label"
            arcsTransitionDuration={500}
            pointsData={[{ lat: HOME.lat, lng: HOME.lng, size: 0.4, color: '#3b82f6' }]}
            pointLat="lat"
            pointLng="lng"
            pointColor="color"
            pointAltitude={0.03}
            pointRadius="size"
          />
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
    <button onClick={onClick}
      className={`px-4 py-1.5 rounded-md text-xs font-medium transition-colors inline-flex items-center gap-1.5 ${
        active ? 'bg-blue-700 text-white shadow-sm' : 'text-slate-500 dark:text-slate-400 hover:text-slate-700'
      }`}>
      <i className={`${icon} text-sm`} /> {label}
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
