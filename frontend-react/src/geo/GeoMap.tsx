import { useState, useEffect, useMemo, useRef, useCallback, Component } from 'react';
import type { ReactNode, ErrorInfo } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  ComposableMap, Geographies, Geography, ZoomableGroup,
} from 'react-simple-maps';
import Globe from 'react-globe.gl';
import { fetchGeoTraffic, fetchBlockRules, blockCountry, unblockCountry } from './api';
import { formatBytes, formatNumber, countryName, flagClass, ratioColor } from './utils';
import CountryDrawer from './CountryDrawer';
import type { Direction, GeoCountry } from './types';

// ---------------------------------------------------------------------------
// Dispose helper — walk the Three.js scene graph and release GPU resources
// ---------------------------------------------------------------------------
function disposeGlobe(globeRef: React.MutableRefObject<any>) {
  try {
    const inst = globeRef.current;
    if (!inst) return;

    // Pause the internal animation loop first
    if (typeof inst.pauseAnimation === 'function') inst.pauseAnimation();

    // Stop OrbitControls auto-rotate so the rAF callback is a no-op
    try { const c = inst.controls(); if (c) c.autoRotate = false; } catch (_) {}

    // Dispose the Three.js renderer (frees WebGL context + GPU memory)
    try {
      const renderer = inst.renderer();
      if (renderer) {
        renderer.dispose();
        renderer.forceContextLoss();
        // Remove the canvas element so it can be GC'd
        const canvas = renderer.domElement;
        if (canvas?.parentNode) canvas.parentNode.removeChild(canvas);
      }
    } catch (_) {}

    // Walk scene and dispose geometries + materials + textures
    try {
      const scene = inst.scene();
      if (scene) {
        scene.traverse((obj: any) => {
          if (obj.geometry) obj.geometry.dispose();
          if (obj.material) {
            const mats = Array.isArray(obj.material) ? obj.material : [obj.material];
            mats.forEach((m: any) => {
              if (m.map) m.map.dispose();
              if (m.lightMap) m.lightMap.dispose();
              if (m.bumpMap) m.bumpMap.dispose();
              if (m.normalMap) m.normalMap.dispose();
              if (m.specularMap) m.specularMap.dispose();
              if (m.envMap) m.envMap.dispose();
              m.dispose();
            });
          }
        });
      }
    } catch (_) {}

    globeRef.current = null;
  } catch (e) {
    console.warn('Globe dispose error (non-fatal):', e);
  }
}

// ---------------------------------------------------------------------------
// Error boundary — catch WebGL/Three.js crashes and dispose before fallback
// ---------------------------------------------------------------------------
class GlobeBoundary extends Component<
  { children: ReactNode; globeRef: React.MutableRefObject<any> },
  { error: boolean }
> {
  state = { error: false };
  static getDerivedStateFromError() { return { error: true }; }
  componentDidCatch(err: Error, info: ErrorInfo) {
    console.warn('Globe failed (WebGL?):', err, info);
    // Dispose all GPU resources so they don't leak after the fallback renders
    disposeGlobe(this.props.globeRef);
  }
  render() {
    if (this.state.error) {
      return (
        <div className="flex items-center justify-center h-full text-xs text-slate-400 p-4 text-center">
          <div>
            <i className="ph-duotone ph-globe text-2xl mb-2 block opacity-40" />
            3D globe not available<br />
            <span className="text-[10px] opacity-60">(WebGL not supported)</span>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

const TOPO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';
const GEO_JSON_URL =
  'https://raw.githubusercontent.com/vasturiano/react-globe.gl/master/example/datasets/ne_110m_admin_0_countries.geojson';

const HOME = { lat: 52.1, lng: 5.3 };

// ISO-3166-1 numeric → alpha-2 (for the topojson flat map)
const NUM_TO_ALPHA2: Record<string, string> = {
  '004':'AF','008':'AL','012':'DZ','016':'AS','020':'AD','024':'AO','028':'AG','031':'AZ',
  '032':'AR','036':'AU','040':'AT','044':'BS','048':'BH','050':'BD','051':'AM','052':'BB',
  '056':'BE','060':'BM','064':'BT','068':'BO','070':'BA','072':'BW','076':'BR','084':'BZ',
  '090':'SB','096':'BN','100':'BG','104':'MM','108':'BI','112':'BY','116':'KH','120':'CM',
  '124':'CA','140':'CF','144':'LK','148':'TD','152':'CL','156':'CN','158':'TW','170':'CO',
  '174':'KM','178':'CG','180':'CD','188':'CR','191':'HR','192':'CU','196':'CY','203':'CZ',
  '204':'BJ','208':'DK','214':'DO','218':'EC','222':'SV','226':'GQ','231':'ET','232':'ER',
  '233':'EE','242':'FJ','246':'FI','250':'FR','262':'DJ','266':'GA','268':'GE','270':'GM',
  '275':'PS','276':'DE','288':'GH','296':'KI','300':'GR','304':'GL','308':'GD','320':'GT',
  '324':'GN','328':'GY','332':'HT','340':'HN','348':'HU','352':'IS','356':'IN','360':'ID',
  '364':'IR','368':'IQ','372':'IE','376':'IL','380':'IT','384':'CI','388':'JM','392':'JP',
  '398':'KZ','400':'JO','404':'KE','408':'KP','410':'KR','414':'KW','417':'KG','418':'LA',
  '422':'LB','426':'LS','428':'LV','430':'LR','434':'LY','440':'LT','442':'LU','450':'MG',
  '454':'MW','458':'MY','462':'MV','466':'ML','470':'MT','478':'MR','480':'MU','484':'MX',
  '496':'MN','498':'MD','499':'ME','504':'MA','508':'MZ','512':'OM','516':'NA','520':'NR',
  '524':'NP','528':'NL','540':'NC','554':'NZ','558':'NI','562':'NE','566':'NG','578':'NO',
  '586':'PK','591':'PA','598':'PG','600':'PY','604':'PE','608':'PH','616':'PL','620':'PT',
  '624':'GW','626':'TL','634':'QA','642':'RO','643':'RU','646':'RW','682':'SA','686':'SN',
  '688':'RS','694':'SL','702':'SG','703':'SK','704':'VN','705':'SI','706':'SO','710':'ZA',
  '716':'ZW','724':'ES','728':'SS','729':'SD','740':'SR','748':'SZ','752':'SE','756':'CH',
  '760':'SY','762':'TJ','764':'TH','768':'TG','776':'TO','780':'TT','784':'AE','788':'TN',
  '792':'TR','795':'TM','800':'UG','804':'UA','807':'MK','818':'EG','826':'GB','834':'TZ',
  '840':'US','854':'BF','858':'UY','860':'UZ','862':'VE','887':'YE','894':'ZM',
  '010':'AQ','-99':'XK','732':'EH',
};

const CENTROIDS: Record<string, { lat: number; lng: number }> = {
  US:{lat:39.8,lng:-98.6},CA:{lat:56.1,lng:-106.3},GB:{lat:54,lng:-2},DE:{lat:51.2,lng:10.4},
  FR:{lat:46.6,lng:2.2},IE:{lat:53.4,lng:-8.2},NL:{lat:52.1,lng:5.3},ES:{lat:40.5,lng:-3.7},
  IT:{lat:41.9,lng:12.6},SE:{lat:60.1,lng:18.6},NO:{lat:60.5,lng:8.5},PL:{lat:51.9,lng:19.1},
  CH:{lat:46.8,lng:8.2},BE:{lat:50.5,lng:4.5},AT:{lat:47.5,lng:14.6},CZ:{lat:49.8,lng:15.5},
  DK:{lat:56.3,lng:9.5},FI:{lat:61.9,lng:25.7},AU:{lat:-25.3,lng:133.8},JP:{lat:36.2,lng:138.3},
  KR:{lat:35.9,lng:127.8},CN:{lat:35.9,lng:104.2},IN:{lat:20.6,lng:79},SG:{lat:1.4,lng:103.8},
  BR:{lat:-14.2,lng:-51.9},RU:{lat:61.5,lng:105.3},ZA:{lat:-30.6,lng:22.9},MX:{lat:23.6,lng:-102.6},
  HK:{lat:22.4,lng:114.1},RO:{lat:45.9,lng:25},BG:{lat:42.7,lng:25.5},UA:{lat:48.4,lng:31.2},
  PT:{lat:39.4,lng:-8.2},LU:{lat:49.8,lng:6.1},SK:{lat:48.7,lng:19.7},HU:{lat:47.2,lng:19.5},
  KE:{lat:-0.02,lng:37.9},SA:{lat:23.9,lng:45.1},AE:{lat:23.4,lng:53.8},IL:{lat:31,lng:34.9},
  TW:{lat:23.7,lng:121},AR:{lat:-38.4,lng:-63.6},CO:{lat:4.6,lng:-74.3},GE:{lat:42.3,lng:43.4},
};

function svcDisplayName(svc: string): string {
  if (typeof (window as any).svcDisplayName === 'function') {
    return (window as any).svcDisplayName(svc);
  }
  return svc.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

interface Props { initialDirection?: Direction; compact?: boolean }

export default function GeoMap({ initialDirection = 'outbound', compact = false }: Props) {
  const [direction, setDirection] = useState<Direction>(initialDirection);
  const [period, setPeriod] = useState('1440');
  const [serviceFilter, setServiceFilter] = useState('');
  const [deviceFilter, setDeviceFilter] = useState('');
  const [hoveredCC, setHoveredCC] = useState<string | null>(null);
  const [drawerCC, setDrawerCC] = useState<string | null>(null);
  const [tooltip, setTooltip] = useState({ html: '', x: 0, y: 0 });
  const queryClient = useQueryClient();
  const globeRef = useRef<any>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const [globeSize, setGlobeSize] = useState(0);
  const [visible, setVisible] = useState(false);
  const [geoJson, setGeoJson] = useState<any>(null);
  // Callback ref — fires when the globe wrapper DOM node attaches OR detaches.
  // Critical for the non-compact Geo page where the wrapper is conditionally
  // rendered once `countries.length > 0`: a plain useRef + useEffect misses
  // this mount because the effect only runs when `visible` changes, not when
  // the node finally appears. ResizeObserver then handles all subsequent
  // layout settles (aspect-ratio resolution, window resize, sidebar toggle).
  const [globeEl, setGlobeEl] = useState<HTMLDivElement | null>(null);
  const globeWrapRef = useCallback((el: HTMLDivElement | null) => {
    setGlobeEl(el);
  }, []);

  // Expose window.openCountryDrawer so the DeviceDrawer's back button can
  // reopen this drawer when the user clicked out of a country into a device.
  // Only valid while GeoMap is mounted; after navigation it's cleared.
  useEffect(() => {
    (window as any).openCountryDrawer = (cc: string, dir?: Direction) => {
      if (!cc) return;
      if (dir) setDirection(dir);
      setDrawerCC(cc);
    };
    return () => {
      if ((window as any).openCountryDrawer) delete (window as any).openCountryDrawer;
    };
  }, []);

  // Detect when the component becomes visible / hidden (parent toggling
  // hidden class or scrolling off-screen). We track BOTH directions so we
  // can pause the Three.js animation loop when the globe isn't visible,
  // which is the main fix for the "runs forever in the background" leak.
  useEffect(() => {
    const el = rootRef.current;
    if (!el) return;
    const obs = new IntersectionObserver(([entry]) => {
      setVisible(entry.isIntersecting);
    }, { threshold: 0.01 });
    obs.observe(el);
    return () => obs.disconnect();
  }, []);

  // Pause / resume the Globe animation when visibility changes
  useEffect(() => {
    const inst = globeRef.current;
    if (!inst) return;
    try {
      if (visible) {
        if (typeof inst.resumeAnimation === 'function') inst.resumeAnimation();
        const c = inst.controls();
        if (c) c.autoRotate = true;
      } else {
        if (typeof inst.pauseAnimation === 'function') inst.pauseAnimation();
        const c = inst.controls();
        if (c) c.autoRotate = false;
      }
    } catch (_) {}
  }, [visible]);

  // Measure globe container via ResizeObserver — fires on attach, layout
  // settle (e.g. aspect-ratio resolving after siblings lay out), and any
  // later resize. Replaces the previous one-shot setTimeout(50ms) which
  // raced against data load: on the non-compact Geo page the wrapper only
  // mounts after `countries.length > 0`, so the timeout would fire before
  // the div existed and leave globeSize at 0 forever.
  useEffect(() => {
    if (!globeEl) return;
    const measure = () => {
      const w = globeEl.clientWidth;
      if (w > 0) setGlobeSize(w);
    };
    measure(); // synchronous first pass covers the fast path
    const ro = new ResizeObserver(measure);
    ro.observe(globeEl);
    return () => ro.disconnect();
  }, [globeEl]);

  // Fetch GeoJSON with AbortController so we can cancel on unmount
  useEffect(() => {
    const ac = new AbortController();
    fetch(GEO_JSON_URL, { signal: ac.signal })
      .then(r => r.json())
      .then(d => setGeoJson(d.features))
      .catch(e => { if (e.name !== 'AbortError') console.warn('GeoJSON fetch failed:', e); });
    return () => ac.abort();
  }, []);

  // Configure controls once globe + data are ready
  useEffect(() => {
    if (!globeRef.current || !globeSize) return;
    const c = globeRef.current.controls();
    c.autoRotate = true;
    c.autoRotateSpeed = 0.4;
    c.enableZoom = true;
    globeRef.current.pointOfView({ lat: HOME.lat, lng: HOME.lng, altitude: 1.8 }, 1000);
  }, [geoJson, globeSize]);

  // Dispose all Three.js / WebGL resources on unmount
  useEffect(() => {
    return () => disposeGlobe(globeRef);
  }, []);

  // --- Data queries ---
  const { data, isLoading, isError } = useQuery({
    queryKey: ['geo-traffic', direction, period, serviceFilter, deviceFilter],
    queryFn: () => fetchGeoTraffic(direction, period || undefined, serviceFilter || undefined, deviceFilter || undefined),
    staleTime: 30_000,
  });
  const { data: blockRules = [] } = useQuery({ queryKey: ['geo-block-rules'], queryFn: fetchBlockRules, staleTime: 60_000 });
  const { data: eventsForServices } = useQuery({
    queryKey: ['events-for-service-list'],
    queryFn: async () => { const r = await fetch('/api/events?limit=1000'); return r.ok ? r.json() : []; },
    staleTime: 120_000,
  });
  const { data: devicesRaw } = useQuery({
    queryKey: ['devices-list'],
    queryFn: async () => { const r = await fetch('/api/devices'); return r.ok ? r.json() : []; },
    staleTime: 60_000,
  });

  const countries = data?.countries || [];
  const blockedSet = useMemo(() => new Set(blockRules.map(r => r.country_code)), [blockRules]);
  const serviceOptions = useMemo(() => {
    if (!eventsForServices || !Array.isArray(eventsForServices)) return [];
    const s = new Set<string>();
    eventsForServices.forEach((e: any) => { if (e.ai_service && e.ai_service !== 'unknown') s.add(e.ai_service); });
    return [...s].sort();
  }, [eventsForServices]);
  const deviceOptions = useMemo(() => {
    if (!devicesRaw || !Array.isArray(devicesRaw)) return [];
    return devicesRaw.map((d: any) => ({
      mac: d.mac_address,
      name: d.display_name || d.hostname || d.mac_address,
      ip: (d.ips || []).map((i: any) => i.ip).find((ip: string) => !ip.startsWith('fe80') && !ip.startsWith('fd')) || '',
    })).filter(d => d.ip).sort((a, b) => a.name.localeCompare(b.name));
  }, [devicesRaw]);

  // --- Color logic ---
  const bytesByCC = useMemo(() => {
    const m: Record<string, number> = {};
    countries.forEach(c => { m[c.country_code] = c.bytes; });
    return m;
  }, [countries]);
  // Attack IPs per country (inbound only). We use unique attacker IPs as
  // the intensity metric because it's accurate per-period. hit_count is
  // cumulative over the attack row's lifetime and overestimates for any
  // single period window.
  const attackIpsByCC = useMemo(() => {
    const m: Record<string, number> = {};
    countries.forEach(c => { if (c.attack_ips) m[c.country_code] = c.attack_ips; });
    return m;
  }, [countries]);
  const maxBytes = useMemo(() => Math.max(1, ...countries.map(c => c.bytes)), [countries]);
  const maxAttackIps = useMemo(() => Math.max(1, ...countries.map(c => c.attack_ips || 0)), [countries]);
  const logMax = Math.log10(maxBytes + 1);
  const logMaxAtk = Math.log10(maxAttackIps + 1);

  const isAttackCountry = useCallback((cc: string) => {
    return (attackIpsByCC[cc] || 0) > 0;
  }, [attackIpsByCC]);

  const flatColor = useCallback((bytes: number, cc?: string) => {
    const dark = document.documentElement.classList.contains('dark');
    const atkIps = cc ? (attackIpsByCC[cc] || 0) : 0;
    // Red for attack countries (inbound) — intensity from unique attacker IPs
    if (atkIps > 0) {
      const t = Math.log10(atkIps + 1) / logMaxAtk;
      if (dark) return `rgb(${Math.round(80 + t * 175)},${Math.round(20 + t * 10)},${Math.round(20 + t * 10)})`;
      return `rgb(${Math.round(254 - t * 50)},${Math.round(202 - t * 170)},${Math.round(202 - t * 170)})`;
    }
    // Blue for normal traffic
    if (bytes <= 0) return dark ? '#1e293b' : '#e2e8f0';
    const t = Math.log10(bytes + 1) / logMax;
    if (dark) return `rgb(${Math.round(30 + t * 29)},${Math.round(58 + t * 72)},${Math.round(138 + t * 108)})`;
    return `rgb(${Math.round(219 - t * 180)},${Math.round(234 - t * 136)},${Math.round(254 - t * 8)})`;
  }, [logMax, logMaxAtk, attackIpsByCC]);

  const globeColor = useCallback((cc: string) => {
    const atkIps = attackIpsByCC[cc] || 0;
    // Red for attack countries on the 3D globe
    if (atkIps > 0) {
      const t = Math.log10(atkIps + 1) / logMaxAtk;
      return `rgb(${Math.round(80 + t * 175)},${Math.round(20 + t * 20)},${Math.round(20 + t * 15)})`;
    }
    const bytes = bytesByCC[cc] || 0;
    if (bytes <= 0) return 'rgba(30,58,100,0.3)';
    const t = Math.log10(bytes + 1) / logMax;
    return `rgb(${Math.round(20 + t * 40)},${Math.round(60 + t * 100)},${Math.round(160 + t * 90)})`;
  }, [bytesByCC, attackIpsByCC, logMax, logMaxAtk]);

  // --- Globe accessors ---
  const polygonCapColor = useCallback((f: any) => globeColor(f?.properties?.ISO_A2 || ''), [globeColor]);
  const polygonLabel = useCallback((f: any) => {
    const cc = f?.properties?.ISO_A2 || '';
    const name = f?.properties?.NAME || cc;
    const c = countries.find(x => x.country_code === cc);
    if (c) {
      const atkLine = c.attack_ips ? `<br/><span style="color:#f87171">⚠ ${c.attack_ips} attacker IPs</span>` : '';
      return `<div style="background:rgba(0,0,0,.85);color:#fff;padding:6px 10px;border-radius:6px;font-size:12px"><b>${name}</b><br/>${formatBytes(c.bytes)} &middot; ${formatNumber(c.hits)} conn.${atkLine}</div>`;
    }
    return `<div style="background:rgba(0,0,0,.7);color:#ccc;padding:4px 8px;border-radius:4px;font-size:11px">${name}</div>`;
  }, [countries]);
  const handlePolygonClick = useCallback((f: any) => {
    const cc = f?.properties?.ISO_A2;
    if (cc) setDrawerCC(cc);
  }, []);

  const arcsData = useMemo(() => countries
    .filter(c => c.country_code !== 'NL' && CENTROIDS[c.country_code])
    .slice(0, 15)
    .map(c => {
      const d = CENTROIDS[c.country_code];
      const t = Math.log10(c.bytes + 1) / logMax;
      const outbound = direction === 'outbound';
      // Red arcs for attack countries, blue for normal traffic
      const atkIps = c.attack_ips || 0;
      const isAtk = atkIps > 0;
      const r = isAtk ? 239 : 59;
      const g = isAtk ? 68 : 130;
      const b = isAtk ? 68 : 246;
      // Attack arcs use attacker-IP count as intensity, normal arcs use bytes
      const tArc = isAtk ? Math.log10(atkIps + 1) / logMaxAtk : t;
      return {
        startLat: outbound ? HOME.lat : d.lat,
        startLng: outbound ? HOME.lng : d.lng,
        endLat: outbound ? d.lat : HOME.lat,
        endLng: outbound ? d.lng : HOME.lng,
        color: [`rgba(${r},${g},${b},${(.3 + tArc * .5).toFixed(2)})`, `rgba(${r},${g},${b},${(.1 + tArc * .2).toFixed(2)})`],
        stroke: 0.3 + tArc * 1.5,
        label: `${countryName(c.country_code)}: ${formatBytes(c.bytes)}${isAtk ? ` · ${atkIps} attacker IPs` : ''}`,
      };
    }), [countries, logMax, logMaxAtk, direction]);

  async function handleBlock(cc: string) {
    try { await blockCountry(cc, 'both'); queryClient.invalidateQueries({ queryKey: ['geo-block-rules'] }); } catch (e) { console.error(e); }
  }
  async function handleUnblock(cc: string) {
    try { await unblockCountry(cc); queryClient.invalidateQueries({ queryKey: ['geo-block-rules'] }); } catch (e) { console.error(e); }
  }

  const totalCountries = countries.length;
  const totalBytes = countries.reduce((s, c) => s + c.bytes, 0);
  const totalHits = countries.reduce((s, c) => s + c.hits, 0);
  const topCountry = countries[0];
  const dark = typeof document !== 'undefined' && document.documentElement.classList.contains('dark');

  // ── Compact mode: globe + direction toggle (used on Dashboard) ──
  if (compact) {
    return (
      <div ref={rootRef} className="w-full h-full flex flex-col">
        {/* Compact direction toggle */}
        <div className="flex items-center gap-1 p-2">
          <button
            onClick={() => setDirection('inbound')}
            className={`text-[11px] px-2.5 py-1 rounded-md font-medium transition-colors ${
              direction === 'inbound'
                ? 'bg-blue-600 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <i className="ph-duotone ph-arrow-down-left text-xs mr-1" />Inbound
          </button>
          <button
            onClick={() => setDirection('outbound')}
            className={`text-[11px] px-2.5 py-1 rounded-md font-medium transition-colors ${
              direction === 'outbound'
                ? 'bg-blue-600 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <i className="ph-duotone ph-arrow-up-right text-xs mr-1" />Outbound
          </button>
        </div>
        <div ref={globeWrapRef} className="flex-1 flex items-center justify-center" style={{ minHeight: 340 }}>
          {geoJson && globeSize > 0 && (
            <GlobeBoundary globeRef={globeRef}><Globe ref={globeRef}
              width={globeSize} height={globeSize}
              backgroundColor="rgba(0,0,0,0)"
              showAtmosphere={true}
              atmosphereColor={dark ? '#1e3a8a' : '#3b82f6'}
              atmosphereAltitude={0.15}
              polygonsData={geoJson}
              polygonGeoJsonGeometry="geometry"
              polygonCapColor={polygonCapColor}
              polygonSideColor={() => 'rgba(30,58,100,0.15)'}
              polygonStrokeColor={() => 'rgba(100,140,200,0.2)'}
              polygonAltitude={(f: any) => {
                const bytes = bytesByCC[f?.properties?.ISO_A2 || ''] || 0;
                return bytes > 0 ? 0.005 + (Math.log10(bytes + 1) / logMax) * 0.02 : 0.003;
              }}
              polygonLabel={polygonLabel}
              onPolygonClick={handlePolygonClick}
              arcsData={arcsData}
              arcStartLat="startLat" arcStartLng="startLng"
              arcEndLat="endLat" arcEndLng="endLng"
              arcColor="color" arcStroke="stroke"
              arcDashLength={0.5} arcDashGap={0.3} arcDashAnimateTime={2000}
              arcLabel="label" arcsTransitionDuration={500}
              pointsData={[{ lat: HOME.lat, lng: HOME.lng, size: 0.4, color: '#3b82f6' }]}
              pointLat="lat" pointLng="lng" pointColor="color"
              pointAltitude={0.03} pointRadius="size"
            /></GlobeBoundary>
          )}
          {isLoading && (
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="w-5 h-5 border-2 border-slate-600 border-t-indigo-500 rounded-full animate-spin" />
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div ref={rootRef} className="space-y-4">
      {/* Direction tabs */}
      <div className="flex items-center gap-1 bg-slate-100 dark:bg-white/[0.04] rounded-lg p-1 w-fit">
        <TabBtn active={direction === 'outbound'} onClick={() => setDirection('outbound')} icon="ph-duotone ph-arrow-up-right" label="Outbound" />
        <TabBtn active={direction === 'inbound'} onClick={() => setDirection('inbound')} icon="ph-duotone ph-arrow-down-left" label="Inbound" />
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Stat label="Countries" value={totalCountries} />
        <Stat label="Bandwidth" value={formatBytes(totalBytes)} />
        <Stat label="Connections" value={formatNumber(totalHits)} />
        <Stat label="Top Destination" value={topCountry ? countryName(topCountry.country_code) : '—'} sub={topCountry ? formatBytes(topCountry.bytes) : undefined} />
      </div>

      {/* Filters */}
      <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl px-4 py-3 flex flex-wrap items-center gap-3">
        <span className="text-xs text-slate-500 dark:text-slate-400 font-medium">Filters</span>
        <select value={serviceFilter} onChange={e => setServiceFilter(e.target.value)} className="text-xs border border-slate-200 dark:border-white/[0.1] rounded-md px-2 py-1.5 bg-white dark:bg-white/[0.05] text-slate-600 dark:text-slate-300">
          <option value="">All services</option>
          {serviceOptions.map(s => <option key={s} value={s}>{svcDisplayName(s)}</option>)}
        </select>
        <select value={deviceFilter} onChange={e => setDeviceFilter(e.target.value)} className="text-xs border border-slate-200 dark:border-white/[0.1] rounded-md px-2 py-1.5 bg-white dark:bg-white/[0.05] text-slate-600 dark:text-slate-300">
          <option value="">All devices</option>
          {deviceOptions.map(d => <option key={d.mac} value={d.ip}>{d.name}</option>)}
        </select>
        <select value={period} onChange={e => setPeriod(e.target.value)} className="text-xs border border-slate-200 dark:border-white/[0.1] rounded-md px-2 py-1.5 bg-white dark:bg-white/[0.05] text-slate-600 dark:text-slate-300">
          <option value="">All time</option>
          <option value="60">Last hour</option>
          <option value="1440">Last 24h</option>
          <option value="10080">Last 7 days</option>
        </select>
      </div>

      {isLoading && (
        <div className="py-10 text-center text-sm text-slate-400">
          <div className="inline-block w-5 h-5 border-2 border-slate-300 dark:border-slate-600 border-t-indigo-500 rounded-full animate-spin mb-2" />
          <p>Loading geo data...</p>
        </div>
      )}
      {isError && <div className="py-8 text-center text-sm text-red-500">Failed to load geo data</div>}

      {/* ===== Side-by-side: Flat map (left ~2/3) + Globe (right ~1/3 square) ===== */}
      {!isLoading && (
        <div className="flex gap-3" style={{ minHeight: 320 }}>
          {/* Flat map */}
          <div className="flex-[2] min-w-0 bg-white dark:bg-white/[0.02] border border-slate-200 dark:border-white/[0.05] rounded-xl overflow-hidden relative">
            {hoveredCC && tooltip.html && (
              <div className="absolute z-10 px-2.5 py-1.5 rounded-lg bg-slate-800 text-white text-xs shadow-lg pointer-events-none"
                style={{ left: tooltip.x + 10, top: tooltip.y - 10 }}
                dangerouslySetInnerHTML={{ __html: tooltip.html }} />
            )}
            <ComposableMap
              projection="geoNaturalEarth1"
              projectionConfig={{ rotate: [-10, 0, 0], scale: 140 }}
              width={800}
              height={380}
              style={{ width: '100%', height: '100%', display: 'block' }}
            >
              <ZoomableGroup>
                <Geographies geography={TOPO_URL}>
                  {({ geographies }: { geographies: any[] }) =>
                    geographies.map((geo: any) => {
                      const cc = NUM_TO_ALPHA2[geo.id] || '';
                      const bytes = bytesByCC[cc] || 0;
                      const isDark = document.documentElement.classList.contains('dark');
                      const hasAttack = isAttackCountry(cc);
                      return (
                        <Geography key={geo.rsmKey} geography={geo}
                          fill={flatColor(bytes, cc)}
                          stroke={hasAttack ? (isDark ? '#991b1b' : '#fca5a5') : (isDark ? '#334155' : '#cbd5e1')}
                          strokeWidth={hasAttack ? 0.8 : 0.4}
                          style={{
                            default: { outline: 'none' },
                            hover: { outline: 'none', stroke: hasAttack ? '#ef4444' : (isDark ? '#e2e8f0' : '#334155'), strokeWidth: 1.2, cursor: 'pointer' },
                            pressed: { outline: 'none' },
                          }}
                          onMouseEnter={(evt: any) => {
                            setHoveredCC(cc);
                            const c = countries.find(x => x.country_code === cc);
                            const atkHtml = c?.attack_ips ? `<br/><span style="color:#f87171">⚠ ${c.attack_ips} attacker IPs</span>` : '';
                            const html = c
                              ? `<b>${countryName(cc)}</b><br/>${formatBytes(c.bytes)} · ${formatNumber(c.hits)} connections${atkHtml}`
                              : `<b>${geo.properties?.name || cc}</b><br/>No traffic`;
                            const rect = (evt.target as SVGElement).closest('svg')?.getBoundingClientRect();
                            setTooltip({ html, x: rect ? evt.clientX - rect.left : 0, y: rect ? evt.clientY - rect.top : 0 });
                          }}
                          onMouseLeave={() => { setHoveredCC(null); setTooltip({ html: '', x: 0, y: 0 }); }}
                          onClick={() => { if (cc) setDrawerCC(cc); }}
                        />
                      );
                    })
                  }
                </Geographies>
              </ZoomableGroup>
            </ComposableMap>
          </div>

          {/* Globe (square) */}
          <div ref={globeWrapRef}
            className="flex-[1] min-w-0 bg-slate-950 border border-slate-200 dark:border-white/[0.05] rounded-xl overflow-hidden flex items-center justify-center"
            style={{ aspectRatio: '1' }}
          >
            {geoJson && globeSize > 0 && (
              <GlobeBoundary globeRef={globeRef}><Globe ref={globeRef}
                width={globeSize} height={globeSize}
                backgroundColor="rgba(0,0,0,0)"
                showAtmosphere={true}
                atmosphereColor={dark ? '#1e3a8a' : '#3b82f6'}
                atmosphereAltitude={0.15}
                polygonsData={geoJson}
                polygonGeoJsonGeometry="geometry"
                polygonCapColor={polygonCapColor}
                polygonSideColor={() => 'rgba(30,58,100,0.15)'}
                polygonStrokeColor={() => 'rgba(100,140,200,0.2)'}
                polygonAltitude={(f: any) => {
                  const bytes = bytesByCC[f?.properties?.ISO_A2 || ''] || 0;
                  return bytes > 0 ? 0.005 + (Math.log10(bytes + 1) / logMax) * 0.02 : 0.003;
                }}
                polygonLabel={polygonLabel}
                onPolygonClick={handlePolygonClick}
                arcsData={arcsData}
                arcStartLat="startLat" arcStartLng="startLng"
                arcEndLat="endLat" arcEndLng="endLng"
                arcColor="color" arcStroke="stroke"
                arcDashLength={0.5} arcDashGap={0.3} arcDashAnimateTime={2000}
                arcLabel="label" arcsTransitionDuration={500}
                pointsData={[{ lat: HOME.lat, lng: HOME.lng, size: 0.4, color: '#3b82f6' }]}
                pointLat="lat" pointLng="lng" pointColor="color"
                pointAltitude={0.03} pointRadius="size"
              /></GlobeBoundary>
            )}
          </div>
        </div>
      )}

      {!isLoading && !isError && countries.length === 0 && (
        <div className="py-12 text-center text-sm text-slate-400">No geo traffic data for this period.</div>
      )}

      {/* Blocked countries */}
      {blockRules.length > 0 && (
        <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
              <i className="ph-duotone ph-shield-warning text-red-500" /> Blocked Countries
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
        <CountriesTable countries={countries} direction={direction} blockedSet={blockedSet} onBlock={handleBlock} onUnblock={handleUnblock} onCountryClick={setDrawerCC} />
      )}

      <CountryDrawer
        cc={drawerCC}
        direction={direction}
        onClose={() => setDrawerCC(null)}
        onDirectionChange={setDirection}
      />
    </div>
  );
}

// --- Sub-components ---

function TabBtn({ active, onClick, icon, label }: { active: boolean; onClick: () => void; icon: string; label: string }) {
  return (
    <button onClick={onClick} className={`px-4 py-1.5 rounded-md text-xs font-medium transition-colors inline-flex items-center gap-1.5 ${active ? 'bg-blue-700 text-white shadow-sm' : 'text-slate-500 dark:text-slate-400 hover:text-slate-700'}`}>
      <i className={`${icon} text-sm`} /> {label}
    </button>
  );
}

function Stat({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4">
      <p className="text-[11px] text-slate-400 dark:text-slate-500 font-medium">{label}</p>
      <p className="text-xl font-bold mt-1 tabular-nums text-slate-700 dark:text-slate-100">{value}</p>
      {sub && <p className="text-[10px] text-slate-400 mt-0.5">{sub}</p>}
    </div>
  );
}

function CountriesTable({ countries, direction, blockedSet, onBlock, onUnblock, onCountryClick }: {
  countries: GeoCountry[]; direction: Direction; blockedSet: Set<string>;
  onBlock: (cc: string) => void; onUnblock: (cc: string) => void;
  onCountryClick: (cc: string) => void;
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
            const color = c.attack_ips ? '#ef4444' : ratioColor(c.bytes, c.opposite_bytes, direction);
            const isBlocked = blockedSet.has(c.country_code);
            return (
              <tr key={c.country_code} className="border-b border-slate-50 dark:border-white/[0.02] hover:bg-slate-50 dark:hover:bg-white/[0.02] transition-colors">
                <td className="py-2.5 px-4 text-slate-400 tabular-nums text-xs">{i + 1}</td>
                <td className="py-2.5 px-4 cursor-pointer" onClick={() => onCountryClick(c.country_code)}>
                  <span className="inline-flex items-center gap-2">
                    <span className={`${flagClass(c.country_code)} text-base`} />
                    <span className="font-medium text-slate-700 dark:text-slate-200">{countryName(c.country_code)}</span>
                    {isBlocked && <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 font-medium">blocked</span>}
                    {!!c.attack_ips && <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 font-medium" title={`${formatNumber(c.attack_hits || 0)} cumulative hits`}>⚠ {c.attack_ips} attacker IPs</span>}
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
                  <button onClick={e => { e.stopPropagation(); isBlocked ? onUnblock(c.country_code) : onBlock(c.country_code); }}
                    className={`p-1.5 rounded-lg transition-colors ${isBlocked ? 'text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20' : 'text-slate-300 dark:text-slate-600 hover:text-red-500 hover:bg-slate-100 dark:hover:bg-white/[0.05]'}`}
                    title={isBlocked ? `Unblock ${countryName(c.country_code)}` : `Block ${countryName(c.country_code)}`}>
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
