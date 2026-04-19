import React, { useRef, useMemo, useCallback } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { OrbitControls } from '@react-three/drei'
import * as THREE from 'three'

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const MAX_PARTICLES = 2000
const TUBE_LENGTH = 14
const TUBE_RADIUS = 1.8
const HALF_LEN = TUBE_LENGTH / 2

// The transparent "x-ray" section is the middle portion;
// opaque cable jackets cover the ends.
const XRAY_HALF = 4.5            // transparent zone: -4.5 … +4.5
const CABLE_LEN = HALF_LEN - XRAY_HALF  // length of each solid end cap

/* Category visual config */
interface CategoryStyle {
  color: THREE.Color
  emissive: THREE.Color
  speed: [number, number]      // min/max units per second
  size: [number, number]       // min/max scale
  spawnWeight: number          // relative spawn probability
  radius: [number, number]     // min/max distance from tube center
}

const CATEGORIES: Record<string, CategoryStyle> = {
  streaming: {
    color: new THREE.Color(0xff3366),
    emissive: new THREE.Color(0x991133),
    speed: [1.5, 3],
    size: [0.08, 0.18],
    spawnWeight: 4,
    radius: [0, 1.2],
  },
  ai: {
    color: new THREE.Color(0xaa44ff),
    emissive: new THREE.Color(0x6622aa),
    speed: [5, 10],
    size: [0.03, 0.07],
    spawnWeight: 2,
    radius: [0, 1.0],
  },
  social: {
    color: new THREE.Color(0x22bbff),
    emissive: new THREE.Color(0x1166aa),
    speed: [2, 5],
    size: [0.04, 0.10],
    spawnWeight: 2,
    radius: [0, 1.1],
  },
  gaming: {
    color: new THREE.Color(0x44ff66),
    emissive: new THREE.Color(0x22aa44),
    speed: [3, 7],
    size: [0.04, 0.09],
    spawnWeight: 1,
    radius: [0, 0.9],
  },
  background: {
    color: new THREE.Color(0x445566),
    emissive: new THREE.Color(0x223344),
    speed: [0.8, 2],
    size: [0.02, 0.04],
    spawnWeight: 6,
    radius: [0, 1.5],
  },
}

const CAT_KEYS = Object.keys(CATEGORIES)
const TOTAL_WEIGHT = Object.values(CATEGORIES).reduce((s, c) => s + c.spawnWeight, 0)

/* ------------------------------------------------------------------ */
/*  Particle data                                                      */
/* ------------------------------------------------------------------ */

interface Particle {
  alive: boolean
  category: string
  x: number
  y: number
  z: number
  speed: number        // signed: positive = left→right, negative = right→left
  scale: number
  angle: number
  radius: number
}

function randRange(min: number, max: number) {
  return min + Math.random() * (max - min)
}

function pickCategory(): string {
  let r = Math.random() * TOTAL_WEIGHT
  for (const key of CAT_KEYS) {
    r -= CATEGORIES[key].spawnWeight
    if (r <= 0) return key
  }
  return 'background'
}

/* ------------------------------------------------------------------ */
/*  Instanced particle system                                          */
/* ------------------------------------------------------------------ */

function ParticleSystem() {
  const meshRef = useRef<THREE.InstancedMesh>(null!)
  const dummy = useMemo(() => new THREE.Object3D(), [])
  const colorAttr = useRef<Float32Array>(null!)

  const particles = useRef<Particle[]>([])

  useMemo(() => {
    particles.current = Array.from({ length: MAX_PARTICLES }, () => ({
      alive: false,
      category: 'background',
      x: 0, y: 0, z: 0,
      speed: 1,
      scale: 0.03,
      angle: 0,
      radius: 0,
    }))
    colorAttr.current = new Float32Array(MAX_PARTICLES * 3)
  }, [])

  const spawnBurst = useCallback(() => {
    const count = Math.floor(Math.random() * 6) + 2
    for (let i = 0; i < count; i++) {
      const idx = particles.current.findIndex(p => !p.alive)
      if (idx === -1) break

      const cat = pickCategory()
      const style = CATEGORIES[cat]
      const p = particles.current[idx]
      p.alive = true
      p.category = cat

      // ~35% of traffic flows right→left (download-heavy network)
      const goingRight = Math.random() > 0.35
      const rawSpeed = randRange(style.speed[0], style.speed[1])
      p.speed = goingRight ? rawSpeed : -rawSpeed

      p.scale = randRange(style.size[0], style.size[1])
      p.angle = Math.random() * Math.PI * 2
      p.radius = randRange(style.radius[0], style.radius[1])

      // Spawn just outside the tube on the appropriate end
      p.x = goingRight
        ? -HALF_LEN - Math.random() * 2
        :  HALF_LEN + Math.random() * 2
      p.y = Math.cos(p.angle) * p.radius
      p.z = Math.sin(p.angle) * p.radius

      colorAttr.current[idx * 3] = style.color.r
      colorAttr.current[idx * 3 + 1] = style.color.g
      colorAttr.current[idx * 3 + 2] = style.color.b
    }
  }, [])

  const spawnTimer = useRef(0)

  useFrame((_, delta) => {
    if (!meshRef.current) return

    spawnTimer.current += delta
    if (spawnTimer.current > 0.05) {
      spawnBurst()
      spawnTimer.current = 0
    }

    for (let i = 0; i < MAX_PARTICLES; i++) {
      const p = particles.current[i]
      if (!p.alive) {
        dummy.position.set(0, 0, 0)
        dummy.scale.set(0, 0, 0)
        dummy.updateMatrix()
        meshRef.current.setMatrixAt(i, dummy.matrix)
        continue
      }

      p.x += p.speed * delta

      // Slight wobble in cross-section
      p.angle += delta * 0.3
      p.y = Math.cos(p.angle) * p.radius
      p.z = Math.sin(p.angle) * p.radius

      // Kill when past tube end (either direction)
      if (p.x > HALF_LEN + 2 || p.x < -HALF_LEN - 2) {
        p.alive = false
        dummy.scale.set(0, 0, 0)
        dummy.position.set(0, 0, 0)
        dummy.updateMatrix()
        meshRef.current.setMatrixAt(i, dummy.matrix)
        continue
      }

      // Fade particles near x-ray boundary so they emerge/disappear
      // smoothly from the opaque cable jacket
      const distFromCenter = Math.abs(p.x)
      const fadeZone = 1.0
      let fade = 1
      if (distFromCenter > XRAY_HALF - fadeZone) {
        fade = Math.max(0, 1 - (distFromCenter - (XRAY_HALF - fadeZone)) / fadeZone)
      }
      const s = p.scale * fade

      dummy.position.set(p.x, p.y, p.z)
      dummy.scale.set(s, s, s)
      dummy.updateMatrix()
      meshRef.current.setMatrixAt(i, dummy.matrix)
    }

    meshRef.current.instanceMatrix.needsUpdate = true

    const colorAttribute = meshRef.current.geometry.getAttribute('color') as THREE.InstancedBufferAttribute
    if (colorAttribute) {
      colorAttribute.needsUpdate = true
    }
  })

  return (
    <instancedMesh ref={meshRef} args={[undefined, undefined, MAX_PARTICLES]}>
      <sphereGeometry args={[1, 8, 6]}>
        <instancedBufferAttribute
          attach="attributes-color"
          args={[colorAttr.current, 3]}
        />
      </sphereGeometry>
      <meshStandardMaterial
        vertexColors
        emissive={new THREE.Color(0x222222)}
        emissiveIntensity={0.5}
        roughness={0.3}
        metalness={0.1}
        transparent
        opacity={0.9}
      />
    </instancedMesh>
  )
}

/* ------------------------------------------------------------------ */
/*  Glass tube (x-ray transparent middle section)                      */
/* ------------------------------------------------------------------ */

function GlassTube() {
  const xrayLen = XRAY_HALF * 2
  return (
    <mesh rotation={[0, 0, Math.PI / 2]}>
      <cylinderGeometry args={[TUBE_RADIUS, TUBE_RADIUS, xrayLen, 64, 1, true]} />
      <meshPhysicalMaterial
        color={0x1a2a3a}
        transparent
        opacity={0.08}
        roughness={0.05}
        metalness={0.1}
        transmission={0.9}
        thickness={0.5}
        side={THREE.DoubleSide}
        depthWrite={false}
      />
    </mesh>
  )
}

/* ------------------------------------------------------------------ */
/*  Opaque cable jacket ends (look like UTP cable)                     */
/* ------------------------------------------------------------------ */

// UTP cable color: blue-grey jacket
const CABLE_COLOR = 0x2a4060
const CABLE_EMISSIVE = 0x0a1520

function CableJacket({ side }: { side: 'left' | 'right' }) {
  const dir = side === 'left' ? -1 : 1
  // Position: center of the solid section
  const cx = dir * (XRAY_HALF + CABLE_LEN / 2)

  return (
    <group>
      {/* Main opaque cable body */}
      <mesh position={[cx, 0, 0]} rotation={[0, 0, Math.PI / 2]}>
        <cylinderGeometry args={[TUBE_RADIUS, TUBE_RADIUS, CABLE_LEN, 64, 1, false]} />
        <meshStandardMaterial
          color={CABLE_COLOR}
          emissive={CABLE_EMISSIVE}
          roughness={0.7}
          metalness={0.05}
        />
      </mesh>

      {/* Rounded end cap */}
      <mesh position={[dir * HALF_LEN, 0, 0]} rotation={[0, 0, dir * Math.PI / 2]}>
        <sphereGeometry args={[TUBE_RADIUS, 32, 16, 0, Math.PI * 2, 0, Math.PI / 2]} />
        <meshStandardMaterial
          color={CABLE_COLOR}
          emissive={CABLE_EMISSIVE}
          roughness={0.7}
          metalness={0.05}
        />
      </mesh>

      {/* Glowing ring at the x-ray / cable boundary */}
      <mesh position={[dir * XRAY_HALF, 0, 0]} rotation={[0, Math.PI / 2, 0]}>
        <torusGeometry args={[TUBE_RADIUS, 0.05, 16, 64]} />
        <meshStandardMaterial
          color={0x44aaff}
          emissive={0x2266cc}
          emissiveIntensity={3}
          transparent
          opacity={0.8}
        />
      </mesh>
    </group>
  )
}

/* ------------------------------------------------------------------ */
/*  Legend overlay (HTML, not 3D)                                       */
/* ------------------------------------------------------------------ */

const LEGEND_ITEMS = [
  { label: 'Streaming', color: '#ff3366' },
  { label: 'AI', color: '#aa44ff' },
  { label: 'Social', color: '#22bbff' },
  { label: 'Gaming', color: '#44ff66' },
  { label: 'Background', color: '#445566' },
]

function Legend() {
  return (
    <div style={{
      position: 'absolute', bottom: 24, left: 24,
      display: 'flex', gap: 16, flexWrap: 'wrap',
      fontFamily: "'Inter', monospace", fontSize: 11,
      color: '#aabbcc', pointerEvents: 'none',
    }}>
      {LEGEND_ITEMS.map(({ label, color }) => (
        <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{
            width: 10, height: 10, borderRadius: '50%',
            background: color, boxShadow: `0 0 8px ${color}`,
          }} />
          {label}
        </div>
      ))}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginLeft: 12, opacity: 0.6 }}>
        <span>→ outbound</span>
        <span style={{ margin: '0 4px' }}>|</span>
        <span>← inbound</span>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/*  Close button                                                       */
/* ------------------------------------------------------------------ */

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
        backdropFilter: 'blur(8px)',
        zIndex: 10,
      }}
      title="Close 3D view"
    >
      ✕
    </button>
  )
}

/* ------------------------------------------------------------------ */
/*  Title overlay                                                      */
/* ------------------------------------------------------------------ */

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
/*  Main exported component                                            */
/* ------------------------------------------------------------------ */

export function NetworkTube() {
  return (
    <div style={{ width: '100%', height: '100%', position: 'relative', background: '#050a12' }}>
      <Canvas
        camera={{ position: [0, 2, 10], fov: 50 }}
        gl={{ antialias: true, alpha: false }}
        style={{ background: '#050a12' }}
      >
        {/* Lighting */}
        <ambientLight intensity={0.15} />
        <pointLight position={[8, 4, 6]} intensity={80} color={0x4488ff} />
        <pointLight position={[-8, -3, 4]} intensity={40} color={0xff4488} />
        <pointLight position={[0, 5, -5]} intensity={30} color={0xaa44ff} />

        {/* Scene */}
        <GlassTube />
        <CableJacket side="left" />
        <CableJacket side="right" />
        <ParticleSystem />

        {/* Controls */}
        <OrbitControls
          enablePan={false}
          minDistance={4}
          maxDistance={20}
          autoRotate
          autoRotateSpeed={0.3}
        />
      </Canvas>

      {/* HTML overlays */}
      <Title />
      <Legend />
      <CloseButton />
    </div>
  )
}
