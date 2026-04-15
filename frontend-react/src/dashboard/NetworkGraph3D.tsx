import { useRef, useEffect, useMemo, useState } from 'react';
import type { DashEvent } from './types';
import { categoryColor, categoryName, formatBytes } from '../colors';

const DEVICE_TYPE_COLORS: Record<string, string> = {
  computer: '#3b82f6',
  phone: '#f59e0b',
  tablet: '#f59e0b',
  iot: '#10b981',
  tv: '#e50914',
  router: '#6366f1',
  default: '#94a3b8',
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

  // Aggregate flows: device → category
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

  // Top devices
  const maxDevices = isMobile ? 5 : 8;
  const topDevs = Object.entries(devTotals)
    .sort((a, b) => b[1] - a[1])
    .slice(0, maxDevices)
    .map(([d]) => d);
  const topDevSet = new Set(topDevs);

  // Build nodes
  const nodes: GraphNode[] = [];
  const nodeIds = new Set<string>();

  // Device nodes
  topDevs.forEach(dev => {
    const id = `dev_${dev}`;
    nodeIds.add(id);
    nodes.push({
      id,
      name: dev,
      type: 'device',
      val: Math.max(2, Math.sqrt(devTotals[dev] || 1) / 100),
      color: '#3b82f6',
    });
  });

  // Category nodes (only categories that connect to top devices)
  const usedCats = new Set<string>();
  Object.keys(flowMap).forEach(key => {
    const [dev, cat] = key.split('\0');
    if (topDevSet.has(dev)) usedCats.add(cat);
  });

  usedCats.forEach(cat => {
    const id = `cat_${cat}`;
    nodeIds.add(id);
    nodes.push({
      id,
      name: categoryName(cat),
      type: 'category',
      val: Math.max(3, Math.sqrt(catTotals[cat] || 1) / 80),
      color: categoryColor(cat),
    });
  });

  // Build links
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
      color: categoryColor(cat),
    });
  });

  return { nodes, links };
}

export default function NetworkGraph3D({ events }: { events: DashEvent[] }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<any>(null);
  const [isMobile, setIsMobile] = useState(false);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    const mq = window.matchMedia('(max-width: 640px)');
    setIsMobile(mq.matches);
    const handler = (e: MediaQueryListEvent) => setIsMobile(e.matches);
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, []);

  const graphData = useMemo(() => buildGraphData(events, isMobile), [events, isMobile]);

  // Initialize 3D graph
  useEffect(() => {
    if (!containerRef.current || !graphData) return;

    let destroyed = false;

    import('3d-force-graph').then(({ default: ForceGraph3D }) => {
      if (destroyed || !containerRef.current) return;

      const isDark = document.documentElement.classList.contains('dark');
      const container = containerRef.current;
      const w = container.clientWidth;
      const h = isMobile ? 300 : 400;

      // Clean up previous instance
      if (graphRef.current) {
        graphRef.current._destructor();
        graphRef.current = null;
      }
      container.innerHTML = '';

      const graph = ForceGraph3D(container)
        .width(w)
        .height(h)
        .backgroundColor(isDark ? '#0B0C10' : '#f8fafc')
        .showNavInfo(false)

        // Nodes
        .nodeVal((n: any) => n.val)
        .nodeColor((n: any) => n.color)
        .nodeLabel((n: any) => {
          const node = n as GraphNode;
          if (node.type === 'category') return `<b style="color:${node.color}">${node.name}</b>`;
          return `<b>${node.name}</b>`;
        })
        .nodeOpacity(0.9)

        // Links
        .linkColor((l: any) => l.color)
        .linkWidth((l: any) => Math.max(0.3, Math.sqrt(l.value) / 500))
        .linkOpacity(0.4)

        // Animated particles flowing along links
        .linkDirectionalParticles((l: any) => Math.max(1, Math.min(6, Math.sqrt(l.value) / 300)))
        .linkDirectionalParticleSpeed(0.006)
        .linkDirectionalParticleWidth((l: any) => Math.max(0.5, Math.sqrt(l.value) / 600))
        .linkDirectionalParticleColor((l: any) => l.color)

        // Hover effects
        .onNodeHover((node: any) => {
          container.style.cursor = node ? 'pointer' : 'default';
        })

        // Data
        .graphData(graphData);

      // Slow auto-rotation
      const controls = graph.controls() as any;
      if (controls && controls.autoRotate !== undefined) {
        controls.autoRotate = true;
        controls.autoRotateSpeed = 0.5;
      }

      // Zoom to fit after layout settles
      setTimeout(() => {
        if (!destroyed) graph.zoomToFit(1000, isMobile ? 80 : 50);
      }, 2000);

      graphRef.current = graph;
      setLoaded(true);
    });

    return () => {
      destroyed = true;
      if (graphRef.current) {
        graphRef.current._destructor();
        graphRef.current = null;
      }
    };
  }, [graphData, isMobile]);

  // Handle resize
  useEffect(() => {
    if (!containerRef.current || !graphRef.current) return;
    const ro = new ResizeObserver(() => {
      if (containerRef.current && graphRef.current) {
        graphRef.current.width(containerRef.current.clientWidth);
      }
    });
    ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, [loaded]);

  if (!graphData) return null;

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
      <div
        ref={containerRef}
        style={{ width: '100%', height: isMobile ? 300 : 400, borderRadius: 8, overflow: 'hidden' }}
      />
    </div>
  );
}
