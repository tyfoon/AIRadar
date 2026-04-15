import { useRef, useEffect, useMemo, useState, useCallback } from 'react';
import type { DashEvent } from './types';
import { categoryColor, categoryName, formatBytes } from '../colors';

const CAT_COLORS: Record<string, string> = {
  ai: '#6366f1', cloud: '#3b82f6', streaming: '#e50914', gaming: '#10b981',
  social: '#f59e0b', tracking: '#ef4444', shopping: '#8b5cf6', news: '#06b6d4',
  adult: '#64748b', communication: '#0ea5e9',
};

interface GraphNode {
  id: string;
  name: string;
  type: 'device' | 'category';
  val: number;
  color: string;
}

interface GraphLink {
  source: string;
  target: string;
  value: number;
  color: string;
}

function buildGraphData(events: DashEvent[], isMobile: boolean) {
  if (!events.length) return null;

  const devName = (ip: string) => {
    if (typeof (window as any).deviceName === 'function') return (window as any).deviceName(ip);
    return ip;
  };

  const flowMap: Record<string, number> = {};
  const devTotals: Record<string, number> = {};
  const catTotals: Record<string, number> = {};

  events.forEach(e => {
    const dev = devName(e.source_ip);
    const cat = e.category || 'other';
    const bytes = e.bytes_transferred || 1;
    const key = `${dev}\0${cat}`;
    flowMap[key] = (flowMap[key] || 0) + bytes;
    devTotals[dev] = (devTotals[dev] || 0) + bytes;
    catTotals[cat] = (catTotals[cat] || 0) + bytes;
  });

  const maxDevices = isMobile ? 5 : 8;
  const topDevs = Object.entries(devTotals)
    .sort((a, b) => b[1] - a[1])
    .slice(0, maxDevices)
    .map(([d]) => d);
  const topDevSet = new Set(topDevs);

  const nodes: GraphNode[] = [];
  const nodeIds = new Set<string>();

  // Normalize node sizes to a small range (1–6) so no single node dominates
  const maxDevBytes = Math.max(...topDevs.map(d => devTotals[d] || 1));

  topDevs.forEach(dev => {
    const id = `dev_${dev}`;
    nodeIds.add(id);
    const ratio = (devTotals[dev] || 1) / maxDevBytes; // 0–1
    nodes.push({
      id,
      name: dev,
      type: 'device',
      val: 1 + ratio * 4, // range: 1–5
      color: '#3b82f6',
    });
  });

  const usedCats = new Set<string>();
  Object.keys(flowMap).forEach(key => {
    const [dev, cat] = key.split('\0');
    if (topDevSet.has(dev)) usedCats.add(cat);
  });

  const maxCatBytes = Math.max(...[...usedCats].map(c => catTotals[c] || 1));

  usedCats.forEach(cat => {
    const id = `cat_${cat}`;
    nodeIds.add(id);
    const ratio = (catTotals[cat] || 1) / maxCatBytes; // 0–1
    nodes.push({
      id,
      name: categoryName(cat),
      type: 'category',
      val: 2 + ratio * 4, // range: 2–6 (slightly bigger than devices)
      color: CAT_COLORS[cat] || categoryColor(cat),
    });
  });

  const links: GraphLink[] = [];
  Object.entries(flowMap).forEach(([key, bytes]) => {
    const [dev, cat] = key.split('\0');
    if (!topDevSet.has(dev)) return;
    const srcId = `dev_${dev}`;
    const tgtId = `cat_${cat}`;
    if (!nodeIds.has(srcId) || !nodeIds.has(tgtId)) return;
    links.push({
      source: srcId,
      target: tgtId,
      value: bytes,
      color: CAT_COLORS[cat] || categoryColor(cat),
    });
  });

  if (nodes.length === 0 || links.length === 0) return null;
  return { nodes, links };
}

export default function NetworkGraph3D({ events }: { events: DashEvent[] }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<any>(null);
  const [isMobile, setIsMobile] = useState(() => window.matchMedia('(max-width: 640px)').matches);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const mq = window.matchMedia('(max-width: 640px)');
    const handler = (e: MediaQueryListEvent) => setIsMobile(e.matches);
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, []);

  const graphData = useMemo(() => buildGraphData(events, isMobile), [events, isMobile]);

  const initGraph = useCallback(async () => {
    const container = containerRef.current;
    if (!container || !graphData) return;

    try {
      // Clean up previous instance
      if (graphRef.current) {
        try { graphRef.current._destructor(); } catch {}
        graphRef.current = null;
      }
      container.innerHTML = '';

      const mod = await import('3d-force-graph');
      const ForceGraph3D = mod.default;

      if (!containerRef.current) return; // unmounted during await

      const isDark = document.documentElement.classList.contains('dark');
      const w = container.clientWidth || 600;
      const h = isMobile ? 300 : 400;

      const graph = new ForceGraph3D(container)
        .width(w)
        .height(h)
        .backgroundColor(isDark ? '#0B0C10' : '#f8fafc')
        .showNavInfo(false)
        // Nodes
        .nodeVal((n: any) => n.val)
        .nodeColor((n: any) => n.color)
        .nodeLabel((n: any) => {
          if (n.type === 'category') return `<b style="color:${n.color}">${n.name}</b>`;
          return `<b>${n.name}</b>`;
        })
        .nodeOpacity(0.9)
        // Links — normalize widths to 0.3–3 range
        .linkColor((l: any) => l.color)
        .linkWidth((l: any) => {
          const maxVal = Math.max(...graphData!.links.map((x: any) => x.value));
          return 0.3 + (l.value / maxVal) * 2.7;
        })
        .linkOpacity(0.5)
        // Animated particles — 1–4 particles, speed relative to traffic
        .linkDirectionalParticles((l: any) => {
          const maxVal = Math.max(...graphData!.links.map((x: any) => x.value));
          return 1 + Math.round((l.value / maxVal) * 3);
        })
        .linkDirectionalParticleSpeed(0.005)
        .linkDirectionalParticleWidth(1.5)
        .linkDirectionalParticleColor((l: any) => l.color)
        // Hover
        .onNodeHover((node: any) => {
          if (container) container.style.cursor = node ? 'pointer' : 'default';
        })
        // Force layout tuning — prevent oscillation
        .d3AlphaDecay(0.03)
        .d3VelocityDecay(0.4)
        .warmupTicks(80)
        .cooldownTicks(100)
        // Data
        .graphData({ nodes: [...graphData.nodes], links: [...graphData.links] });

      // Auto-rotate
      try {
        const controls = graph.controls() as any;
        if (controls?.autoRotate !== undefined) {
          controls.autoRotate = true;
          controls.autoRotateSpeed = 0.4;
        }
      } catch {}

      // Zoom to fit after layout settles
      setTimeout(() => {
        try { graph.zoomToFit(800, isMobile ? 100 : 60); } catch {}
      }, 1500);

      graphRef.current = graph;
      setError(null);
    } catch (err: any) {
      console.error('3D Graph init failed:', err);
      setError(err?.message || 'WebGL not available');
    }
  }, [graphData, isMobile]);

  // Init graph when data is ready
  useEffect(() => {
    initGraph();
    return () => {
      if (graphRef.current) {
        try { graphRef.current._destructor(); } catch {}
        graphRef.current = null;
      }
    };
  }, [initGraph]);

  // Resize handler
  useEffect(() => {
    const container = containerRef.current;
    if (!container || !graphRef.current) return;
    const ro = new ResizeObserver(() => {
      if (graphRef.current && container) {
        graphRef.current.width(container.clientWidth);
      }
    });
    ro.observe(container);
    return () => ro.disconnect();
  }, [graphRef.current]);

  if (!graphData) return null;

  const chartH = isMobile ? 300 : 400;

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
          <i className="ph-duotone ph-graph text-indigo-500" /> Network Constellation
        </h3>
        <div className="flex items-center gap-3 text-[10px] text-slate-400">
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-blue-500 inline-block" /> Devices</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-indigo-500 inline-block" /> Categories</span>
        </div>
      </div>
      {error ? (
        <div className="flex items-center justify-center text-xs text-slate-400" style={{ height: chartH }}>
          3D visualization unavailable: {error}
        </div>
      ) : (
        <div
          ref={containerRef}
          style={{ width: '100%', height: chartH, borderRadius: 8, overflow: 'hidden', position: 'relative' }}
        />
      )}
    </div>
  );
}
