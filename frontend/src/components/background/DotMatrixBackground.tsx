import { useRef, useMemo } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import * as THREE from 'three'
import { useTheme } from '../../context/ThemeContext'

function WaveDotGrid({ opacity }: { opacity: number }) {
  const pointsRef = useRef<THREE.Points>(null!)

  const { geometry, origPos, count } = useMemo(() => {
    const COLS = 32
    const ROWS = 20
    const total = COLS * ROWS
    const positions = new Float32Array(total * 3)
    const origPos = new Float32Array(total * 3)

    for (let i = 0; i < COLS; i++) {
      for (let j = 0; j < ROWS; j++) {
        const idx = (i * ROWS + j) * 3
        const x = (i / (COLS - 1) - 0.5) * 22
        const y = (j / (ROWS - 1) - 0.5) * 13
        positions[idx] = origPos[idx] = x
        positions[idx + 1] = origPos[idx + 1] = y
        positions[idx + 2] = origPos[idx + 2] = 0
      }
    }

    const geo = new THREE.BufferGeometry()
    geo.setAttribute('position', new THREE.BufferAttribute(positions, 3))
    return { geometry: geo, origPos, count: total }
  }, [])

  useFrame(({ clock }) => {
    if (!pointsRef.current) return
    const t = clock.getElapsedTime()
    const posAttr = pointsRef.current.geometry.attributes.position
    const arr = posAttr.array as Float32Array

    for (let i = 0; i < count; i++) {
      const ix = i * 3
      const ox = origPos[ix]
      const oy = origPos[ix + 1]
      arr[ix + 2] =
        Math.sin(ox * 0.45 + t * 0.55) * Math.cos(oy * 0.45 + t * 0.38) * 0.65
    }
    posAttr.needsUpdate = true
  })

  return (
    <points ref={pointsRef} geometry={geometry}>
      <pointsMaterial
        size={0.09}
        color="#0d6efd"
        transparent
        opacity={opacity}
        sizeAttenuation
      />
    </points>
  )
}

export default function DotMatrixBackground() {
  const { theme } = useTheme()
  const bgColor = theme === 'dark' ? '#060b18' : '#f5f8ff'
  const dotOpacity = theme === 'dark' ? 0.35 : 0.22

  return (
    <div className="fixed inset-0 z-0 pointer-events-none">
      {/* Canvas renders first (behind vignette) */}
      <Canvas
        camera={{ position: [0, 0, 10], fov: 65 }}
        style={{ position: 'absolute', inset: 0 }}
        dpr={[1, 1.5]}
      >
        {/* Set Three.js scene background to match theme — prevents black canvas */}
        <color attach="background" args={[bgColor]} />
        <WaveDotGrid opacity={dotOpacity} />
      </Canvas>

      {/* Vignette rendered AFTER canvas so it overlays on top */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background: `radial-gradient(ellipse 75% 55% at 50% 45%, transparent 25%, ${bgColor} 100%)`,
        }}
      />
    </div>
  )
}
