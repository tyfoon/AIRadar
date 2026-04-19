import React, { useRef, useMemo, useState, useEffect, useCallback } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { OrbitControls, Html } from '@react-three/drei'
import * as THREE from 'three'

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const MAX_PACKETS = 1500
const TUBE_LENGTH = 16
const TUBE_RADIUS = 2.0
const HALF_LEN = TUBE_LENGTH / 2
const XRAY_HALF = 5.0
const CABLE_LEN = HALF_LEN - XRAY_HALF

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface FlowDef {
  id: string
  service: string
  device: string
  category: string
  direction: 1 | -1
  bandwidth: number
  lane: { y: number; z: number }
}

interface ApiFlow {
  service: string
  device: string
  category: string
  direction: 'inbound' | 'outbound'
  bandwidth: number
  bytes: number
  hits: number
}

/* ------------------------------------------------------------------ */
/*  Category colors                                                    */
/* ------------------------------------------------------------------ */

const CATEGORY_COLORS: Record<string, { color: THREE.Color; emissive: THREE.Color }> = {
  streaming:  { color: new THREE.Color(0xff3366), emissive: new THREE.Color(0x991133) },
  ai:         { color: new THREE.Color(0xaa44ff), emissive: new THREE.Color(0x6622aa) },
  social:     { color: new THREE.Color(0x22bbff), emissive: new THREE.Color(0x1166aa) },
  gaming:     { color: new THREE.Color(0x44ff66), emissive: new THREE.Color(0x22aa44) },
  cloud:      { color: new THREE.Color(0xffaa22), emissive: new THREE.Color(0xaa7711) },
  tracking:   { color: new THREE.Color(0xff6644), emissive: new THREE.Color(0x993322) },
  background: { color: new THREE.Color(0x334455), emissive: new THREE.Color(0x1a2233) },
}

function catColor(cat: string) {
  return CATEGORY_COLORS[cat] || CATEGORY_COLORS.background
}

/* Speed ranges per category */
const CATEGORY_SPEED: Record<string, [number, number]> = {
  streaming:  [2.0, 3.5],
  ai:         [6, 12],
  social:     [3, 5],
  gaming:     [4, 7],
  cloud:      [2, 4],
  tracking:   [3, 5],
  background: [1.5, 3],
}

function catSpeed(cat: string): [number, number] {
  return CATEGORY_SPEED[cat] || CATEGORY_SPEED.background
}

/** Prettify API service IDs: "anthropic_claude" → "Anthropic Claude" */
function prettyService(s: string): string {
  return s.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

/* ------------------------------------------------------------------ */
/*  Convert API flows to lane-assigned FlowDefs                        */
/* ------------------------------------------------------------------ */

function assignLanes(apiFlows: ApiFlow[]): FlowDef[] {
  // Arrange lanes in a grid pattern within the tube cross-section
  const LANE_POSITIONS: { y: number; z: number }[] = []
  const rows = 5
  const cols = 3
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      LANE_POSITIONS.push({
        y: 1.2 - r * 0.6,
        z: -0.7 + c * 0.7,
      })
    }
  }

  return apiFlows.slice(0, LANE_POSITIONS.length).map((f, i) => ({
    id: `${f.service}-${f.device}-${i}`,
    service: f.service,
    device: f.device,
    category: f.category,
    direction: f.direction === 'outbound' ? 1 : -1,
    bandwidth: f.bandwidth,
    lane: LANE_POSITIONS[i],
  }))
}

/* ------------------------------------------------------------------ */
/*  Mock flows for when API has no data                                 */
/* ------------------------------------------------------------------ */

const MOCK_FLOWS: FlowDef[] = [
  { id: 'yt',     service: 'YouTube',   device: "Robin's Laptop",  category: 'streaming', direction: -1, bandwidth: 8, lane: { y: 1.2, z: 0.0 } },
  { id: 'nf',     service: 'Netflix',   device: 'Smart TV',        category: 'streaming', direction: -1, bandwidth: 9, lane: { y: 0.6, z: 0.5 } },
  { id: 'cl',     service: 'Claude',    device: "Robin's Laptop",  category: 'ai',        direction:  1, bandwidth: 2, lane: { y: 0.0, z: 0.7 } },
  { id: 'cl-r',   service: 'Claude',    device: "Robin's Laptop",  category: 'ai',        direction: -1, bandwidth: 3, lane: { y: 0.0, z: 0.0 } },
  { id: 'ig',     service: 'Instagram', device: "Robin's iPhone",  category: 'social',    direction: -1, bandwidth: 5, lane: { y: -0.6, z: 0.0 } },
  { id: 'dns',    service: 'DNS',       device: 'All devices',     category: 'background', direction: 1, bandwidth: 1, lane: { y: -1.2, z: 0.7 } },
]

/* ------------------------------------------------------------------ */
/*  Packet data                                                        */
/* ------------------------------------------------------------------ */

interface Packet {
  alive: boolean
  flowIdx: number
  x: number
  y: number
  z: number
  speed: number
  scaleX: number
  scaleYZ: number
}

function randRange(a: number, b: number) { return a + Math.random() * (b - a) }

/* ------------------------------------------------------------------ */
/*  Instanced packet system (box geometry)                             */
/* ------------------------------------------------------------------ */

function PacketSystem({ flows }: { flows: FlowDef[] }) {
  const meshRef = useRef<THREE.InstancedMesh>(null!)
  const dummy = useMemo(() => new THREE.Object3D(), [])
  const colorBuf = useRef<Float32Array>(null!)
  const packets = useRef<Packet[]>([])
  const spawnTimers = useRef<number[]>([])

  // Re-init when flows change
  const flowKey = flows.map(f => f.id).join(',')
  useMemo(() => {
    packets.current = Array.from({ length: MAX_PACKETS }, () => ({
      alive: false, flowIdx: 0,
      x: 0, y: 0, z: 0,
      speed: 1, scaleX: 0.2, scaleYZ: 0.08,
    }))
    colorBuf.current = new Float32Array(MAX_PACKETS * 3)
    spawnTimers.current = flows.map(() => Math.random() * 0.3)
  }, [flowKey])

  useFrame((_, delta) => {
    if (!meshRef.current || flows.length === 0) return

    for (let fi = 0; fi < flows.length; fi++) {
      const flow = flows[fi]
      if (fi >= spawnTimers.current.length) continue
      spawnTimers.current[fi] -= delta
      if (spawnTimers.current[fi] <= 0) {
        const interval = randRange(0.08, 0.25) / (flow.bandwidth * 0.5)
        spawnTimers.current[fi] = interval

        const idx = packets.current.findIndex(p => !p.alive)
        if (idx === -1) continue

        const p = packets.current[idx]
        const speeds = catSpeed(flow.category)
        p.alive = true
        p.flowIdx = fi
        p.speed = randRange(speeds[0], speeds[1]) * flow.direction
        p.scaleX = randRange(0.15, 0.35) * (1 + flow.bandwidth * 0.12)
        p.scaleYZ = randRange(0.06, 0.10) * (1 + flow.bandwidth * 0.05)
        p.y = flow.lane.y
        p.z = flow.lane.z
        p.x = flow.direction === 1
          ? -HALF_LEN - Math.random() * 1.5
          :  HALF_LEN + Math.random() * 1.5

        const c = catColor(flow.category).color
        colorBuf.current[idx * 3] = c.r
        colorBuf.current[idx * 3 + 1] = c.g
        colorBuf.current[idx * 3 + 2] = c.b
      }
    }

    for (let i = 0; i < MAX_PACKETS; i++) {
      const p = packets.current[i]
      if (!p.alive) {
        dummy.scale.set(0, 0, 0)
        dummy.position.set(0, 0, 0)
        dummy.updateMatrix()
        meshRef.current.setMatrixAt(i, dummy.matrix)
        continue
      }

      p.x += p.speed * delta

      if (p.x > HALF_LEN + 2 || p.x < -HALF_LEN - 2) {
        p.alive = false
        dummy.scale.set(0, 0, 0)
        dummy.position.set(0, 0, 0)
        dummy.updateMatrix()
        meshRef.current.setMatrixAt(i, dummy.matrix)
        continue
      }

      const dist = Math.abs(p.x)
      const fadeZone = 1.2
      let fade = 1
      if (dist > XRAY_HALF - fadeZone) {
        fade = Math.max(0, 1 - (dist - (XRAY_HALF - fadeZone)) / fadeZone)
      }

      dummy.position.set(p.x, p.y, p.z)
      dummy.scale.set(p.scaleX * fade, p.scaleYZ * fade, p.scaleYZ * fade)
      dummy.updateMatrix()
      meshRef.current.setMatrixAt(i, dummy.matrix)
    }

    meshRef.current.instanceMatrix.needsUpdate = true
    const attr = meshRef.current.geometry.getAttribute('color') as THREE.InstancedBufferAttribute
    if (attr) attr.needsUpdate = true
  })

  return (
    <instancedMesh ref={meshRef} args={[undefined, undefined, MAX_PACKETS]}>
      <boxGeometry args={[1, 1, 1]}>
        <instancedBufferAttribute attach="attributes-color" args={[colorBuf.current, 3]} />
      </boxGeometry>
      <meshStandardMaterial
        vertexColors
        emissive={new THREE.Color(0x111111)}
        emissiveIntensity={0.8}
        roughness={0.2}
        metalness={0.3}
        transparent
        opacity={0.92}
      />
    </instancedMesh>
  )
}

/* ------------------------------------------------------------------ */
/*  Lane labels                                                        */
/* ------------------------------------------------------------------ */

function LaneLabels({ flows }: { flows: FlowDef[] }) {
  const seen = new Set<string>()
  const labels: FlowDef[] = []
  for (const flow of flows) {
    const key = `${flow.service}→${flow.device}`
    if (seen.has(key)) continue
    seen.add(key)
    labels.push(flow)
  }

  return (
    <group>
      {labels.map((flow) => {
        const labelX = flow.direction === 1 ? -XRAY_HALF + 0.3 : XRAY_HALF - 0.3
        const c = catColor(flow.category).color
        return (
          <Html
            key={flow.id}
            position={[labelX, flow.lane.y + 0.18, flow.lane.z]}
            center
            style={{ pointerEvents: 'none', whiteSpace: 'nowrap' }}
          >
            <div style={{
              fontSize: 9,
              fontFamily: "'Inter', monospace",
              color: `rgb(${Math.round(c.r*255)},${Math.round(c.g*255)},${Math.round(c.b*255)})`,
              opacity: 0.85,
              textShadow: `0 0 6px rgba(${Math.round(c.r*255)},${Math.round(c.g*255)},${Math.round(c.b*255)},0.5)`,
              background: 'rgba(0,0,0,0.5)',
              padding: '1px 5px',
              borderRadius: 3,
            }}>
              {flow.direction === 1
                ? `${flow.device} → ${prettyService(flow.service)}`
                : `${prettyService(flow.service)} → ${flow.device}`}
            </div>
          </Html>
        )
      })}
    </group>
  )
}

/* ------------------------------------------------------------------ */
/*  Lane glow trails                                                   */
/* ------------------------------------------------------------------ */

function LaneGlows({ flows }: { flows: FlowDef[] }) {
  const laneMap = new Map<string, { y: number; z: number; bw: number; color: THREE.Color }>()
  for (const flow of flows) {
    const key = `${flow.lane.y},${flow.lane.z}`
    const existing = laneMap.get(key)
    if (existing) {
      existing.bw += flow.bandwidth
    } else {
      laneMap.set(key, { ...flow.lane, bw: flow.bandwidth, color: catColor(flow.category).color })
    }
  }

  const lanes = Array.from(laneMap.values())
  const maxBw = Math.max(...lanes.map(l => l.bw), 1)

  return (
    <group>
      {lanes.map(({ y, z, bw, color }, i) => {
        const t = bw / maxBw
        const glowWidth = 0.03 + t * 0.12
        const glowOpacity = 0.06 + t * 0.18
        return (
          <group key={i}>
            <mesh position={[0, y, z]}>
              <boxGeometry args={[XRAY_HALF * 2, 0.008, 0.008]} />
              <meshBasicMaterial color={color} transparent opacity={glowOpacity + 0.1} />
            </mesh>
            <mesh position={[0, y, z]}>
              <boxGeometry args={[XRAY_HALF * 2, glowWidth, glowWidth]} />
              <meshBasicMaterial color={color} transparent opacity={glowOpacity * 0.6} />
            </mesh>
            <mesh position={[0, y, z]}>
              <boxGeometry args={[XRAY_HALF * 2, glowWidth * 2.5, glowWidth * 2.5]} />
              <meshBasicMaterial color={color} transparent opacity={glowOpacity * 0.2} />
            </mesh>
          </group>
        )
      })}
    </group>
  )
}

/* ------------------------------------------------------------------ */
/*  Glass tube                                                         */
/* ------------------------------------------------------------------ */

function GlassTube() {
  return (
    <mesh rotation={[0, 0, Math.PI / 2]}>
      <cylinderGeometry args={[TUBE_RADIUS, TUBE_RADIUS, XRAY_HALF * 2, 64, 1, true]} />
      <meshPhysicalMaterial
        color={0x1a2a3a}
        transparent opacity={0.06}
        roughness={0.05} metalness={0.1}
        transmission={0.92} thickness={0.5}
        side={THREE.DoubleSide} depthWrite={false}
      />
    </mesh>
  )
}

/* ------------------------------------------------------------------ */
/*  Cable jacket ends — white UTP cable                                */
/* ------------------------------------------------------------------ */

const CABLE_COLOR = 0xd8d8d0
const CABLE_EMISSIVE = 0x333330

function CableJacket({ side }: { side: 'left' | 'right' }) {
  const dir = side === 'left' ? -1 : 1
  const cx = dir * (XRAY_HALF + CABLE_LEN / 2)
  return (
    <group>
      <mesh position={[cx, 0, 0]} rotation={[0, 0, Math.PI / 2]}>
        <cylinderGeometry args={[TUBE_RADIUS, TUBE_RADIUS, CABLE_LEN, 64, 1, false]} />
        <meshStandardMaterial color={CABLE_COLOR} emissive={CABLE_EMISSIVE} roughness={0.6} metalness={0.02} />
      </mesh>
      <mesh position={[dir * HALF_LEN, 0, 0]} rotation={[0, 0, dir * Math.PI / 2]}>
        <sphereGeometry args={[TUBE_RADIUS, 32, 16, 0, Math.PI * 2, 0, Math.PI / 2]} />
        <meshStandardMaterial color={CABLE_COLOR} emissive={CABLE_EMISSIVE} roughness={0.6} metalness={0.02} />
      </mesh>
      <mesh position={[dir * XRAY_HALF, 0, 0]} rotation={[0, Math.PI / 2, 0]}>
        <torusGeometry args={[TUBE_RADIUS, 0.05, 16, 64]} />
        <meshStandardMaterial color={0x44aaff} emissive={0x2266cc} emissiveIntensity={3} transparent opacity={0.8} />
      </mesh>
    </group>
  )
}

/* ------------------------------------------------------------------ */
/*  HTML overlays                                                      */
/* ------------------------------------------------------------------ */

const LEGEND_ITEMS = [
  { label: 'Streaming', color: '#ff3366' },
  { label: 'AI', color: '#aa44ff' },
  { label: 'Social', color: '#22bbff' },
  { label: 'Gaming', color: '#44ff66' },
  { label: 'Cloud', color: '#ffaa22' },
  { label: 'Infra', color: '#334455' },
]

function Legend() {
  return (
    <div style={{
      position: 'absolute', bottom: 24, left: 24,
      display: 'flex', gap: 14, flexWrap: 'wrap',
      fontFamily: "'Inter', monospace", fontSize: 11,
      color: '#aabbcc', pointerEvents: 'none',
    }}>
      {LEGEND_ITEMS.map(({ label, color }) => (
        <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <div style={{
            width: 14, height: 6, borderRadius: 2,
            background: color, boxShadow: `0 0 6px ${color}`,
          }} />
          {label}
        </div>
      ))}
    </div>
  )
}

function CloseButton({ onClose }: { onClose?: () => void }) {
  return (
    <button
      onClick={() => {
        if (onClose) {
          onClose()
        } else {
          const root = document.getElementById('3d-tube-root')
          if (root) root.style.display = 'none'
        }
      }}
      style={{
        position: 'absolute', top: 16, right: 16,
        width: 40, height: 40, borderRadius: '50%',
        background: 'rgba(255,255,255,0.08)',
        border: '1px solid rgba(255,255,255,0.15)',
        color: '#ccc', fontSize: 20, cursor: 'pointer',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        backdropFilter: 'blur(8px)', zIndex: 10,
      }}
      title="Close 3D view"
    >✕</button>
  )
}

/* ------------------------------------------------------------------ */
/*  Data fetching hook                                                 */
/* ------------------------------------------------------------------ */

function useLiveFlows(active: boolean): FlowDef[] {
  const [flows, setFlows] = useState<FlowDef[]>(MOCK_FLOWS)

  useEffect(() => {
    if (!active) return

    let cancelled = false

    async function poll() {
      try {
        const res = await fetch('/api/traffic/live?window=300')
        if (!res.ok) return
        const data = await res.json()
        if (cancelled) return
        const apiFlows: ApiFlow[] = data.flows || []
        if (apiFlows.length > 0) {
          setFlows(assignLanes(apiFlows))
        } else {
          setFlows(MOCK_FLOWS)
        }
      } catch {
        // Silently fall back to mock data
      }
    }

    poll()
    const timer = setInterval(poll, 8000)
    return () => { cancelled = true; clearInterval(timer) }
  }, [active])

  return flows
}

/* ------------------------------------------------------------------ */
/*  3D Scene (reusable — used in both fullscreen overlay & inline)      */
/* ------------------------------------------------------------------ */

function TubeScene({ flows, cameraZ }: { flows: FlowDef[]; cameraZ: number }) {
  return (
    <Canvas
      camera={{ position: [0, 2.5, cameraZ], fov: 50 }}
      gl={{ antialias: true, alpha: false }}
      style={{ background: '#050a12' }}
    >
      <ambientLight intensity={0.15} />
      <pointLight position={[8, 4, 6]} intensity={80} color={0x4488ff} />
      <pointLight position={[-8, -3, 4]} intensity={40} color={0xff4488} />
      <pointLight position={[0, 5, -5]} intensity={30} color={0xaa44ff} />

      <GlassTube />
      <CableJacket side="left" />
      <CableJacket side="right" />
      <LaneGlows flows={flows} />
      <PacketSystem flows={flows} />
      <LaneLabels flows={flows} />

      <OrbitControls
        enablePan={false}
        minDistance={4}
        maxDistance={25}
        autoRotate
        autoRotateSpeed={0.3}
      />
    </Canvas>
  )
}

/* ------------------------------------------------------------------ */
/*  Fullscreen overlay (opened via sidebar button)                     */
/* ------------------------------------------------------------------ */

export function NetworkTube() {
  const flows = useLiveFlows(true)

  return (
    <div style={{ width: '100%', height: '100%', position: 'relative', background: '#050a12' }}>
      <TubeScene flows={flows} cameraZ={14} />
      <div style={{
        position: 'absolute', top: 20, left: 24,
        fontFamily: "'Inter', monospace",
        color: '#88aacc', fontSize: 13, fontWeight: 600,
        letterSpacing: 1, textTransform: 'uppercase',
        pointerEvents: 'none',
        textShadow: '0 0 20px rgba(68, 136, 255, 0.4)',
      }}>
        Network Traffic — X-Ray View
      </div>
      <Legend />
      <CloseButton />
    </div>
  )
}

/* ------------------------------------------------------------------ */
/*  Inline dashboard card (embedded in existing page)                  */
/* ------------------------------------------------------------------ */

export function NetworkTubeCard() {
  const [expanded, setExpanded] = useState(false)
  const flows = useLiveFlows(true)

  if (expanded) {
    return (
      <div style={{
        position: 'fixed', top: 0, left: 0,
        width: '100vw', height: '100vh',
        zIndex: 9999, background: '#050a12',
      }}>
        <TubeScene flows={flows} cameraZ={14} />
        <Legend />
        <CloseButton onClose={() => setExpanded(false)} />
      </div>
    )
  }

  return (
    <div className="rounded-2xl border border-slate-200 dark:border-white/[0.06] bg-white dark:bg-[#0f1117] overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-200 dark:border-white/[0.04]">
        <div className="flex items-center gap-2">
          <i className="ph-duotone ph-cylinder text-base text-slate-400" />
          <h3 className="text-[13px] font-semibold text-slate-700 dark:text-slate-200">Network Cable — X-Ray</h3>
        </div>
        <button
          onClick={() => setExpanded(true)}
          className="text-[11px] text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors flex items-center gap-1"
        >
          <i className="ph-duotone ph-arrows-out text-sm" />
          Fullscreen
        </button>
      </div>
      <div style={{ height: 280, position: 'relative', background: '#050a12' }}>
        <TubeScene flows={flows} cameraZ={16} />
      </div>
    </div>
  )
}
