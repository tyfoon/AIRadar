import { useMemo, useState, Suspense, lazy } from 'react';
import { Canvas } from '@react-three/fiber';
import { OrbitControls, Text, Box } from '@react-three/drei';
import type { DashEvent } from './types';
import { categoryColor, categoryName, formatBytes } from '../colors';

// ---------------------------------------------------------------------------
// Data processing — build a grid: devices (X) × hours (Z) → bytes + category
// ---------------------------------------------------------------------------
interface Cell {
  device: string;
  hour: number;
  hits: number;
  dominantCategory: string;
}

function buildGrid(events: DashEvent[], isMobile: boolean) {
  if (!events.length) return null;

  const devName = (ip: string) => {
    if (typeof (window as any).deviceName === 'function') return (window as any).deviceName(ip);
    return ip;
  };

  // Aggregate per device — count hits (every event = 1 hit)
  const devTotals: Record<string, number> = {};
  events.forEach(e => {
    const d = devName(e.source_ip);
    devTotals[d] = (devTotals[d] || 0) + 1;
  });

  const maxDevices = isMobile ? 5 : 8;
  const topDevs = Object.entries(devTotals)
    .sort((a, b) => b[1] - a[1])
    .slice(0, maxDevices)
    .map(([d]) => d);
  const topDevSet = new Set(topDevs);

  // Build grid: device×hour → { hits, catHits }
  const grid: Record<string, { hits: number; catHits: Record<string, number> }> = {};

  events.forEach(e => {
    const dev = devName(e.source_ip);
    if (!topDevSet.has(dev)) return;
    const hour = new Date(e.timestamp).getHours();
    const cat = e.category || 'other';
    const key = `${dev}\0${hour}`;
    if (!grid[key]) grid[key] = { hits: 0, catHits: {} };
    grid[key].hits += 1;
    grid[key].catHits[cat] = (grid[key].catHits[cat] || 0) + 1;
  });

  // Find max hits for normalization
  let maxHits = 0;
  Object.values(grid).forEach(v => { if (v.hits > maxHits) maxHits = v.hits; });
  if (maxHits === 0) return null;

  // Build cells
  const cells: Cell[] = [];
  topDevs.forEach(dev => {
    for (let h = 0; h < 24; h++) {
      const key = `${dev}\0${h}`;
      const data = grid[key];
      if (!data || data.hits === 0) {
        cells.push({ device: dev, hour: h, hits: 0, dominantCategory: 'none' });
      } else {
        // Find dominant category by hit count
        let topCat = 'other';
        let topCatHits = 0;
        Object.entries(data.catHits).forEach(([cat, h]) => {
          if (h > topCatHits) { topCat = cat; topCatHits = h; }
        });
        cells.push({ device: dev, hour: h, hits: data.hits, dominantCategory: topCat });
      }
    }
  });

  return { cells, devices: topDevs, maxHits };
}

// ---------------------------------------------------------------------------
// 3D Scene components
// ---------------------------------------------------------------------------
const BAR_SIZE = 0.4;
const GAP = 0.6;

function Bar({ position, height, color, opacity }: {
  position: [number, number, number];
  height: number;
  color: string;
  opacity: number;
}) {
  if (height < 0.02) return null;
  return (
    <Box position={[position[0], height / 2, position[2]]} args={[BAR_SIZE, height, BAR_SIZE]}>
      <meshPhongMaterial color={color} opacity={opacity} transparent={opacity < 1} />
    </Box>
  );
}

function AxisLabels({ devices, isMobile }: { devices: string[]; isMobile: boolean }) {
  const fontSize = isMobile ? 0.2 : 0.25;
  const maxLen = isMobile ? 8 : 14;

  return (
    <>
      {/* Device labels along X axis */}
      {devices.map((dev, i) => {
        const label = dev.length > maxLen ? dev.slice(0, maxLen - 1) + '…' : dev;
        return (
          <Text
            key={`dev-${i}`}
            position={[i * GAP, -0.3, -0.8]}
            fontSize={fontSize}
            color="#94a3b8"
            anchorX="center"
            anchorY="top"
            rotation={[-Math.PI / 4, 0, 0]}
          >
            {label}
          </Text>
        );
      })}

      {/* Hour labels along Z axis — every 3 hours */}
      {[0, 3, 6, 9, 12, 15, 18, 21].map(h => (
        <Text
          key={`hr-${h}`}
          position={[-0.8, -0.3, h * GAP]}
          fontSize={fontSize}
          color="#94a3b8"
          anchorX="right"
          anchorY="top"
        >
          {`${h}:00`}
        </Text>
      ))}
    </>
  );
}

function GridFloor({ deviceCount }: { deviceCount: number }) {
  const width = deviceCount * GAP;
  const depth = 24 * GAP;
  return (
    <mesh rotation={[-Math.PI / 2, 0, 0]} position={[(width - GAP) / 2, -0.01, (depth - GAP) / 2]}>
      <planeGeometry args={[width + 0.5, depth + 0.5]} />
      <meshBasicMaterial color="#1e293b" opacity={0.3} transparent />
    </mesh>
  );
}

function Scene({ cells, devices, maxHits, isMobile }: {
  cells: Cell[];
  devices: string[];
  maxHits: number;
  isMobile: boolean;
}) {
  const maxHeight = isMobile ? 3 : 5;

  return (
    <>
      {/* Lighting */}
      <ambientLight intensity={0.5} />
      <directionalLight position={[10, 15, 10]} intensity={1} />
      <directionalLight position={[-5, 10, -5]} intensity={0.3} />

      {/* Grid floor */}
      <GridFloor deviceCount={devices.length} />

      {/* Bars */}
      {cells.map((cell, i) => {
        const devIdx = devices.indexOf(cell.device);
        if (devIdx === -1) return null;
        const x = devIdx * GAP;
        const z = cell.hour * GAP;
        const normalizedHeight = (cell.hits / maxHits) * maxHeight;
        const color = cell.hits > 0 ? categoryColor(cell.dominantCategory) : '#334155';
        const opacity = cell.hits > 0 ? 0.85 : 0.15;

        return (
          <Bar
            key={i}
            position={[x, 0, z]}
            height={normalizedHeight}
            color={color}
            opacity={opacity}
          />
        );
      })}

      {/* Axis labels */}
      <AxisLabels devices={devices} isMobile={isMobile} />

      {/* Camera controls */}
      <OrbitControls
        autoRotate
        autoRotateSpeed={0.3}
        enableDamping
        dampingFactor={0.1}
        minDistance={3}
        maxDistance={isMobile ? 20 : 30}
        maxPolarAngle={Math.PI / 2.1}
      />
    </>
  );
}

// ---------------------------------------------------------------------------
// Legend
// ---------------------------------------------------------------------------
const LEGEND_CATS = ['ai', 'cloud', 'streaming', 'gaming', 'social', 'tracking'];

function Legend() {
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-slate-400">
      {LEGEND_CATS.map(cat => (
        <span key={cat} className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-sm inline-block" style={{ backgroundColor: categoryColor(cat) }} />
          {categoryName(cat)}
        </span>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------
export default function ActivityLandscape3D({ events }: { events: DashEvent[] }) {
  const [isMobile] = useState(() => window.matchMedia('(max-width: 640px)').matches);

  const gridData = useMemo(() => buildGrid(events, isMobile), [events, isMobile]);

  if (!gridData) return null;

  const isDark = document.documentElement.classList.contains('dark');
  const chartH = isMobile ? 280 : 400;

  // Camera position: looking at the grid from an angle
  const camPos: [number, number, number] = isMobile
    ? [2, 6, 18]
    : [3, 8, 22];

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl p-4">
      <div className="flex items-center justify-between mb-2 flex-wrap gap-2">
        <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
          <i className="ph-duotone ph-chart-bar text-indigo-500" /> Activity Landscape
        </h3>
        <Legend />
      </div>
      <div style={{ height: chartH, borderRadius: 8, overflow: 'hidden' }}>
        <Canvas
          camera={{ position: camPos, fov: 45 }}
          style={{ background: isDark ? '#0B0C10' : '#f8fafc' }}
        >
          <Scene
            cells={gridData.cells}
            devices={gridData.devices}
            maxHits={gridData.maxHits}
            isMobile={isMobile}
          />
        </Canvas>
      </div>
      <p className="text-[10px] text-slate-400 mt-1.5">
        X: devices &middot; Z: hour of day &middot; Height: number of connections &middot; Drag to rotate
      </p>
    </div>
  );
}
