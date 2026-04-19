import React, { useRef, useMemo } from 'react'
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
/*  Flow definitions — each flow is a "lane" in the cable              */
/* ------------------------------------------------------------------ */

interface FlowDef {
  id: string
  service: string
  device: string
  category: 'streaming' | 'ai' | 'social' | 'gaming' | 'background'
  direction: 1 | -1          // 1 = outbound (L→R), -1 = inbound (R→L)
  bandwidth: number           // 1–10, affects packet size & spawn rate
  lane: { y: number; z: number }  // fixed position in tube cross-section
}

const CATEGORY_COLORS: Record<string, { color: THREE.Color; emissive: THREE.Color }> = {
  streaming: { color: new THREE.Color(0xff3366), emissive: new THREE.Color(0x991133) },
  ai:        { color: new THREE.Color(0xaa44ff), emissive: new THREE.Color(0x6622aa) },
  social:    { color: new THREE.Color(0x22bbff), emissive: new THREE.Color(0x1166aa) },
  gaming:    { color: new THREE.Color(0x44ff66), emissive: new THREE.Color(0x22aa44) },
  background:{ color: new THREE.Color(0x334455), emissive: new THREE.Color(0x1a2233) },
}

// Lane positions arranged like parallel fiber strands in a cable
// Top lanes → bottom lanes, spread across the tube cross-section
const FLOWS: FlowDef[] = [
  // === Big streaming flows (inbound / download) ===
  { id: 'yt',       service: 'YouTube',      device: "Robin's Laptop",    category: 'streaming', direction: -1, bandwidth: 8,  lane: { y:  1.2, z:  0.0 } },
  { id: 'nf',       service: 'Netflix',      device: 'Smart TV',          category: 'streaming', direction: -1, bandwidth: 9,  lane: { y:  0.6, z:  0.5 } },
  { id: 'hbo',      service: 'HBO Max',      device: 'iPad',             category: 'streaming', direction: -1, bandwidth: 7,  lane: { y:  0.6, z: -0.5 } },

  // === AI (small, fast bursts — both directions) ===
  { id: 'claude',   service: 'Claude',       device: "Robin's Laptop",    category: 'ai',        direction:  1, bandwidth: 2,  lane: { y:  0.0, z:  0.8 } },
  { id: 'claude-r', service: 'Claude',       device: "Robin's Laptop",    category: 'ai',        direction: -1, bandwidth: 3,  lane: { y:  0.0, z:  0.6 } },
  { id: 'gemini',   service: 'Gemini',       device: "Robin's iPhone",    category: 'ai',        direction:  1, bandwidth: 1,  lane: { y:  0.0, z: -0.6 } },
  { id: 'gemini-r', service: 'Gemini',       device: "Robin's iPhone",    category: 'ai',        direction: -1, bandwidth: 2,  lane: { y:  0.0, z: -0.8 } },

  // === Social ===
  { id: 'insta',    service: 'Instagram',    device: "Robin's iPhone",    category: 'social',    direction: -1, bandwidth: 5,  lane: { y: -0.5, z:  0.4 } },
  { id: 'tiktok',   service: 'TikTok',       device: "Robin's iPhone",    category: 'social',    direction: -1, bandwidth: 6,  lane: { y: -0.5, z: -0.4 } },

  // === Gaming ===
  { id: 'game',     service: 'Fortnite',     device: 'Gaming PC',         category: 'gaming',    direction: -1, bandwidth: 4,  lane: { y: -1.1, z:  0.0 } },

  // === Background noise ===
  { id: 'dns',      service: 'DNS',          device: 'All devices',       category: 'background', direction:  1, bandwidth: 1,  lane: { y:  1.2, z:  0.8 } },
  { id: 'ntp',      service: 'NTP',          device: 'Router',            category: 'background', direction:  1, bandwidth: 1,  lane: { y:  1.2, z: -0.8 } },
  { id: 'mdns',     service: 'mDNS',         device: 'Local',             category: 'background', direction:  1, bandwidth: 1,  lane: { y: -1.1, z:  0.7 } },
]

/* Speed ranges per category */
const CATEGORY_SPEED: Record<string, [number, number]> = {
  streaming:  [2.0, 3.5],
  ai:         [6, 12],
  social:     [3, 5],
  gaming:     [4, 7],
  background: [1.5, 3],
}

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
  scaleX: number    // length of the block
  scaleYZ: number   // width/height of the block
}

function randRange(a: number, b: number) { return a + Math.random() * (b - a) }

/* ------------------------------------------------------------------ */
/*  Instanced packet system (box geometry)                             */
/* ------------------------------------------------------------------ */

function PacketSystem() {
  const meshRef = useRef<THREE.InstancedMesh>(null!)
  const dummy = useMemo(() => new THREE.Object3D(), [])
  const colorBuf = useRef<Float32Array>(null!)
  const packets = useRef<Packet[]>([])
  const spawnTimers = useRef<number[]>([])

  useMemo(() => {
    packets.current = Array.from({ length: MAX_PACKETS }, () => ({
      alive: false, flowIdx: 0,
      x: 0, y: 0, z: 0,
      speed: 1, scaleX: 0.2, scaleYZ: 0.08,
    }))
    colorBuf.current = new Float32Array(MAX_PACKETS * 3)
    spawnTimers.current = FLOWS.map(() => Math.random() * 0.3)
  }, [])

  useFrame((_, delta) => {
    if (!meshRef.current) return

    // Spawn packets per flow
    for (let fi = 0; fi < FLOWS.length; fi++) {
      const flow = FLOWS[fi]
      spawnTimers.current[fi] -= delta
      if (spawnTimers.current[fi] <= 0) {
        // Spawn interval inversely proportional to bandwidth
        const interval = randRange(0.08, 0.25) / (flow.bandwidth * 0.5)
        spawnTimers.current[fi] = interval

        const idx = packets.current.findIndex(p => !p.alive)
        if (idx === -1) continue

        const p = packets.current[idx]
        const speeds = CATEGORY_SPEED[flow.category]
        p.alive = true
        p.flowIdx = fi
        p.speed = randRange(speeds[0], speeds[1]) * flow.direction
        // Packet length proportional to bandwidth
        p.scaleX = randRange(0.15, 0.35) * (1 + flow.bandwidth * 0.12)
        p.scaleYZ = randRange(0.06, 0.10) * (1 + flow.bandwidth * 0.05)
        p.y = flow.lane.y
        p.z = flow.lane.z
        // Start outside tube
        p.x = flow.direction === 1
          ? -HALF_LEN - Math.random() * 1.5
          :  HALF_LEN + Math.random() * 1.5

        const c = CATEGORY_COLORS[flow.category].color
        colorBuf.current[idx * 3] = c.r
        colorBuf.current[idx * 3 + 1] = c.g
        colorBuf.current[idx * 3 + 2] = c.b
      }
    }

    // Update positions
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

      // Kill when past tube end
      if (p.x > HALF_LEN + 2 || p.x < -HALF_LEN - 2) {
        p.alive = false
        dummy.scale.set(0, 0, 0)
        dummy.position.set(0, 0, 0)
        dummy.updateMatrix()
        meshRef.current.setMatrixAt(i, dummy.matrix)
        continue
      }

      // Fade near x-ray boundary
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
        <instancedBufferAttribute
          attach="attributes-color"
          args={[colorBuf.current, 3]}
        />
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
/*  Lane labels — floating text at the x-ray boundary                  */
/* ------------------------------------------------------------------ */

function LaneLabels() {
  // Deduplicate: only show label once per unique service+device combo
  const seen = new Set<string>()
  const labels: { flow: FlowDef; key: string }[] = []
  for (const flow of FLOWS) {
    const key = `${flow.service}→${flow.device}`
    if (seen.has(key)) continue
    seen.add(key)
    labels.push({ flow, key })
  }

  return (
    <group>
      {labels.map(({ flow, key }) => {
        const labelX = flow.direction === 1
          ? -XRAY_HALF + 0.3
          :  XRAY_HALF - 0.3
        const c = CATEGORY_COLORS[flow.category].color

        return (
          <Html
            key={key}
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
                ? `${flow.device} → ${flow.service}`
                : `${flow.service} → ${flow.device}`}
            </div>
          </Html>
        )
      })}
    </group>
  )
}

/* ------------------------------------------------------------------ */
/*  Glass tube (x-ray transparent middle section)                      */
/* ------------------------------------------------------------------ */

function GlassTube() {
  return (
    <mesh rotation={[0, 0, Math.PI / 2]}>
      <cylinderGeometry args={[TUBE_RADIUS, TUBE_RADIUS, XRAY_HALF * 2, 64, 1, true]} />
      <meshPhysicalMaterial
        color={0x1a2a3a}
        transparent
        opacity={0.06}
        roughness={0.05}
        metalness={0.1}
        transmission={0.92}
        thickness={0.5}
        side={THREE.DoubleSide}
        depthWrite={false}
      />
    </mesh>
  )
}

/* ------------------------------------------------------------------ */
/*  Opaque cable jacket ends                                           */
/* ------------------------------------------------------------------ */

const CABLE_COLOR = 0x2a4060
const CABLE_EMISSIVE = 0x0a1520

function CableJacket({ side }: { side: 'left' | 'right' }) {
  const dir = side === 'left' ? -1 : 1
  const cx = dir * (XRAY_HALF + CABLE_LEN / 2)

  return (
    <group>
      <mesh position={[cx, 0, 0]} rotation={[0, 0, Math.PI / 2]}>
        <cylinderGeometry args={[TUBE_RADIUS, TUBE_RADIUS, CABLE_LEN, 64, 1, false]} />
        <meshStandardMaterial color={CABLE_COLOR} emissive={CABLE_EMISSIVE} roughness={0.7} metalness={0.05} />
      </mesh>
      <mesh position={[dir * HALF_LEN, 0, 0]} rotation={[0, 0, dir * Math.PI / 2]}>
        <sphereGeometry args={[TUBE_RADIUS, 32, 16, 0, Math.PI * 2, 0, Math.PI / 2]} />
        <meshStandardMaterial color={CABLE_COLOR} emissive={CABLE_EMISSIVE} roughness={0.7} metalness={0.05} />
      </mesh>
      <mesh position={[dir * XRAY_HALF, 0, 0]} rotation={[0, Math.PI / 2, 0]}>
        <torusGeometry args={[TUBE_RADIUS, 0.05, 16, 64]} />
        <meshStandardMaterial color={0x44aaff} emissive={0x2266cc} emissiveIntensity={3} transparent opacity={0.8} />
      </mesh>
    </group>
  )
}

/* ------------------------------------------------------------------ */
/*  Thin lane guide lines (like road markings)                         */
/* ------------------------------------------------------------------ */

function LaneGuides() {
  const seen = new Set<string>()
  const guides: { y: number; z: number; color: THREE.Color }[] = []
  for (const flow of FLOWS) {
    const key = `${flow.lane.y},${flow.lane.z}`
    if (seen.has(key)) continue
    seen.add(key)
    guides.push({ ...flow.lane, color: CATEGORY_COLORS[flow.category].color })
  }

  return (
    <group>
      {guides.map(({ y, z, color }, i) => (
        <mesh key={i} position={[0, y, z]}>
          <boxGeometry args={[XRAY_HALF * 2, 0.005, 0.005]} />
          <meshBasicMaterial color={color} transparent opacity={0.12} />
        </mesh>
      ))}
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

function CloseButton() {
  return (
    <button
      onClick={() => {
        const root = document.getElementById('3d-tube-root')
        if (root) root.style.display = 'none'
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

function Title() {
  return (
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
  )
}

/* ------------------------------------------------------------------ */
/*  Main scene                                                         */
/* ------------------------------------------------------------------ */

export function NetworkTube() {
  return (
    <div style={{ width: '100%', height: '100%', position: 'relative', background: '#050a12' }}>
      <Canvas
        camera={{ position: [0, 2.5, 10], fov: 50 }}
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
        <LaneGuides />
        <PacketSystem />
        <LaneLabels />

        <OrbitControls
          enablePan={false}
          minDistance={4}
          maxDistance={20}
          autoRotate
          autoRotateSpeed={0.3}
        />
      </Canvas>

      <Title />
      <Legend />
      <CloseButton />
    </div>
  )
}
