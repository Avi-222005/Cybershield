import { useMemo, useState } from 'react'
import {
  Globe,
  Network,
  Radio,
  Server,
  Cpu,
  Lock,
  AlertOctagon,
  ShieldAlert,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Info,
  Filter,
} from 'lucide-react'
import type { AttackGraphNode, AttackGraphEdge, PotentialExposurePath } from '../../../types'

interface AttackGraphViewProps {
  nodes: AttackGraphNode[]
  edges: AttackGraphEdge[]
  paths: PotentialExposurePath[]
}

const TYPE_CONFIG: Record<
  string,
  { label: string; color: string; bg: string; border: string; icon: any }
> = {
  Internet: {
    label: 'Internet',
    color: '#38bdf8',
    bg: 'rgba(56, 189, 248, 0.15)',
    border: '#38bdf8',
    icon: Globe,
  },
  Domain: {
    label: 'Apex Domain',
    color: '#818cf8',
    bg: 'rgba(129, 140, 248, 0.15)',
    border: '#818cf8',
    icon: Network,
  },
  Subdomain: {
    label: 'Subdomain',
    color: '#60a5fa',
    bg: 'rgba(96, 165, 250, 0.15)',
    border: '#60a5fa',
    icon: Radio,
  },
  IP: {
    label: 'IP Address',
    color: '#34d399',
    bg: 'rgba(52, 211, 153, 0.15)',
    border: '#34d399',
    icon: Server,
  },
  Port: {
    label: 'Port / Service',
    color: '#fbbf24',
    bg: 'rgba(251, 191, 36, 0.15)',
    border: '#fbbf24',
    icon: Cpu,
  },
  Technology: {
    label: 'Technology',
    color: '#a78bfa',
    bg: 'rgba(167, 139, 250, 0.15)',
    border: '#a78bfa',
    icon: Cpu,
  },
  Certificate: {
    label: 'TLS Certificate',
    color: '#2dd4bf',
    bg: 'rgba(45, 212, 191, 0.15)',
    border: '#2dd4bf',
    icon: Lock,
  },
  CVE: {
    label: 'Vulnerability (CVE)',
    color: '#f87171',
    bg: 'rgba(248, 113, 113, 0.2)',
    border: '#f87171',
    icon: AlertOctagon,
  },
}

export default function AttackGraphView({ nodes, edges, paths }: AttackGraphViewProps) {
  const [selectedNode, setSelectedNode] = useState<AttackGraphNode | null>(null)
  const [activeFilter, setActiveFilter] = useState<string>('ALL')
  const [zoomLevel, setZoomLevel] = useState<number>(1)
  const [activePathId, setActivePathId] = useState<string | null>(paths[0]?.path_id || null)

  const filteredNodes = useMemo(() => {
    if (activeFilter === 'ALL') return nodes
    return nodes.filter((n) => n.type === activeFilter)
  }, [nodes, activeFilter])

  // Compute a simple dynamic layout positions for SVG visualization
  const layout = useMemo(() => {
    const width = 850
    const height = 480

    // Group nodes by hierarchical tiers
    const tiers: Record<string, AttackGraphNode[]> = {
      tier1: [], // Internet
      tier2: [], // Domain & Subdomains
      tier3: [], // IPs
      tier4: [], // Ports & Services
      tier5: [], // Tech & CVEs
    }

    filteredNodes.forEach((node) => {
      if (node.type === 'Internet') tiers.tier1.push(node)
      else if (node.type === 'Domain' || node.type === 'Subdomain') tiers.tier2.push(node)
      else if (node.type === 'IP') tiers.tier3.push(node)
      else if (node.type === 'Port' || node.type === 'Certificate') tiers.tier4.push(node)
      else tiers.tier5.push(node)
    })

    const positions: Record<string, { x: number; y: number }> = {}

    const placeTier = (nodesInTier: AttackGraphNode[], xCoord: number) => {
      const count = nodesInTier.length
      if (count === 0) return
      const step = height / (count + 1)
      nodesInTier.forEach((n, idx) => {
        positions[n.id] = {
          x: xCoord,
          y: step * (idx + 1),
        }
      })
    }

    placeTier(tiers.tier1, 70)
    placeTier(tiers.tier2, 230)
    placeTier(tiers.tier3, 400)
    placeTier(tiers.tier4, 580)
    placeTier(tiers.tier5, 750)

    return { positions, width, height }
  }, [filteredNodes])

  const visibleEdges = useMemo(() => {
    const visibleIds = new Set(filteredNodes.map((n) => n.id))
    return edges.filter((e) => visibleIds.has(e.source) && visibleIds.has(e.target))
  }, [edges, filteredNodes])

  const selectedPath = useMemo(() => {
    return paths.find((p) => p.path_id === activePathId) || paths[0]
  }, [paths, activePathId])

  return (
    <div className="space-y-6">
      {/* Top Filter and Controls Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-xl bg-white/[0.02] border border-white/10">
        <div className="flex items-center gap-2 text-xs text-gray-400">
          <Filter size={14} className="text-cyan-400" />
          <span>Filter Nodes:</span>
          <div className="flex flex-wrap gap-1">
            {['ALL', 'Domain', 'Subdomain', 'IP', 'Port', 'Technology', 'CVE'].map((typeKey) => (
              <button
                key={typeKey}
                onClick={() => setActiveFilter(typeKey)}
                className={`px-2.5 py-1 rounded text-xs transition-colors ${
                  activeFilter === typeKey
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'bg-white/5 text-gray-400 hover:text-white border border-transparent'
                }`}
              >
                {typeKey}
              </button>
            ))}
          </div>
        </div>

        {/* Zoom Controls */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => setZoomLevel((z) => Math.max(0.7, z - 0.15))}
            className="p-1.5 rounded bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10"
            title="Zoom Out"
          >
            <ZoomOut size={14} />
          </button>
          <span className="text-xs font-mono text-gray-400">{Math.round(zoomLevel * 100)}%</span>
          <button
            onClick={() => setZoomLevel((z) => Math.min(1.6, z + 0.15))}
            className="p-1.5 rounded bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10"
            title="Zoom In"
          >
            <ZoomIn size={14} />
          </button>
          <button
            onClick={() => setZoomLevel(1)}
            className="p-1.5 rounded bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10 ml-1"
            title="Reset Zoom"
          >
            <Maximize2 size={14} />
          </button>
        </div>
      </div>

      {/* Main Canvas + Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* SVG Graph Viewport */}
        <div className="lg:col-span-3 rounded-2xl bg-[#090d16] border border-white/10 p-4 overflow-hidden relative min-h-[460px] flex items-center justify-center">
          <div className="absolute top-3 left-4 text-xs font-mono text-gray-500 flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
            ATTACK SURFACE TOPOLOGY GRAPH ({filteredNodes.length} nodes, {visibleEdges.length} edges)
          </div>

          <div
            className="w-full h-full overflow-auto transition-transform duration-200"
            style={{ transform: `scale(${zoomLevel})`, transformOrigin: 'center center' }}
          >
            <svg
              viewBox={`0 0 ${layout.width} ${layout.height}`}
              className="w-full h-[440px] select-none"
            >
              <defs>
                <linearGradient id="edgeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.4" />
                  <stop offset="100%" stopColor="#818cf8" stopOpacity="0.4" />
                </linearGradient>
                <marker
                  id="arrow"
                  viewBox="0 0 10 10"
                  refX="18"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b" />
                </marker>
              </defs>

              {/* Render Edges */}
              {visibleEdges.map((edge) => {
                const src = layout.positions[edge.source]
                const dst = layout.positions[edge.target]
                if (!src || !dst) return null

                // Curved bezier path
                const midX = (src.x + dst.x) / 2
                const d = `M ${src.x} ${src.y} C ${midX} ${src.y}, ${midX} ${dst.y}, ${dst.x} ${dst.y}`

                return (
                  <g key={edge.id} className="opacity-60 hover:opacity-100 transition-opacity">
                    <path
                      d={d}
                      fill="none"
                      stroke="url(#edgeGrad)"
                      strokeWidth="1.5"
                      strokeDasharray="4 2"
                      markerEnd="url(#arrow)"
                    />
                    <text
                      x={midX}
                      y={(src.y + dst.y) / 2 - 4}
                      fill="#64748b"
                      fontSize="9"
                      textAnchor="middle"
                      className="font-mono select-none"
                    >
                      {edge.label}
                    </text>
                  </g>
                )
              })}

              {/* Render Nodes */}
              {filteredNodes.map((node) => {
                const pos = layout.positions[node.id]
                if (!pos) return null
                const conf = TYPE_CONFIG[node.type] || TYPE_CONFIG.Domain
                const isSelected = selectedNode?.id === node.id

                return (
                  <g
                    key={node.id}
                    transform={`translate(${pos.x}, ${pos.y})`}
                    onClick={() => setSelectedNode(node)}
                    className="cursor-pointer group"
                  >
                    {/* Pulsing ring on selected */}
                    {isSelected && (
                      <circle
                        r="24"
                        fill="none"
                        stroke={conf.color}
                        strokeWidth="2"
                        className="animate-ping opacity-30"
                      />
                    )}

                    {/* Node circle */}
                    <circle
                      r="16"
                      fill={conf.bg}
                      stroke={conf.border}
                      strokeWidth={isSelected ? '2.5' : '1.5'}
                      className="transition-all duration-200 group-hover:scale-110"
                    />

                    {/* Type indicator dot */}
                    <circle r="4" fill={conf.color} />

                    {/* Node text label */}
                    <text
                      y="26"
                      textAnchor="middle"
                      fill="#e2e8f0"
                      fontSize="10"
                      fontWeight={isSelected ? '600' : '400'}
                      className="font-mono select-none drop-shadow"
                    >
                      {node.label.length > 20 ? `${node.label.slice(0, 18)}...` : node.label}
                    </text>
                  </g>
                )
              })}
            </svg>
          </div>
        </div>

        {/* Node Inspector Drawer */}
        <div className="rounded-2xl bg-[#090d16] border border-white/10 p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 mb-4 border-b border-white/10">
              <div className="flex items-center gap-2">
                <Info size={16} className="text-cyan-400" />
                <span className="text-xs font-mono uppercase tracking-wider text-gray-300">
                  Node Inspector
                </span>
              </div>
              {selectedNode && (
                <span
                  className="px-2 py-0.5 rounded text-[10px] font-mono uppercase"
                  style={{
                    color: TYPE_CONFIG[selectedNode.type]?.color || '#38bdf8',
                    background: TYPE_CONFIG[selectedNode.type]?.bg || 'rgba(56, 189, 248, 0.1)',
                  }}
                >
                  {selectedNode.type}
                </span>
              )}
            </div>

            {selectedNode ? (
              <div className="space-y-4">
                <div>
                  <div className="text-xs text-gray-500 font-mono">LABEL</div>
                  <div className="text-sm font-semibold text-white break-all">{selectedNode.label}</div>
                </div>

                <div>
                  <div className="text-xs text-gray-500 font-mono">SEVERITY / STATUS</div>
                  <div className="mt-1">
                    <span
                      className={`inline-block px-2.5 py-0.5 rounded text-xs font-semibold ${
                        selectedNode.severity === 'CRITICAL'
                          ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                          : selectedNode.severity === 'HIGH'
                          ? 'bg-orange-500/20 text-orange-300 border border-orange-500/30'
                          : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                      }`}
                    >
                      {selectedNode.severity}
                    </span>
                  </div>
                </div>

                {/* Additional Node Data */}
                {selectedNode.data && (
                  <div className="space-y-2 pt-2 border-t border-white/5">
                    <div className="text-xs text-gray-500 font-mono">TECHNICAL METADATA</div>
                    <div className="text-xs text-gray-300 space-y-1.5 font-mono bg-white/[0.02] p-2.5 rounded-lg border border-white/5 max-h-48 overflow-y-auto">
                      {Object.entries(selectedNode.data).map(([key, val]) => {
                        if (typeof val === 'object' && val !== null) return null
                        return (
                          <div key={key} className="flex justify-between gap-2">
                            <span className="text-gray-500">{key}:</span>
                            <span className="text-gray-200 truncate">{String(val)}</span>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center py-12 text-gray-500 text-xs">
                <ShieldAlert size={28} className="mx-auto mb-2 opacity-40 text-cyan-400" />
                Click on any node in the graph to inspect its perimeter metadata, associated ports, and vulnerability details.
              </div>
            )}
          </div>

          <div className="mt-6 pt-3 border-t border-white/5 text-[11px] text-gray-500 font-mono text-center">
            CyberShield External Attack Surface Graph v2.0
          </div>
        </div>
      </div>

      {/* Potential Exposure Paths Section (Part 19) */}
      {paths && paths.length > 0 && (
        <div className="rounded-2xl glass-card border border-white/10 p-6 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <AlertOctagon size={18} className="text-red-400" />
                <h3 className="text-base font-bold text-white tracking-wide">
                  Potential Exposure Paths ({paths.length})
                </h3>
              </div>
              <p className="text-xs text-gray-400 mt-1">
                Passive, analytical mapping of internet-facing perimeter hops. (Analytical model only — no offensive requests executed).
              </p>
            </div>

            <div className="flex flex-wrap gap-2">
              {paths.map((p) => (
                <button
                  key={p.path_id}
                  onClick={() => setActivePathId(p.path_id)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
                    activePathId === p.path_id
                      ? 'bg-red-500/20 text-red-300 border border-red-500/40 shadow-[0_0_12px_rgba(239,68,68,0.2)]'
                      : 'bg-white/5 text-gray-400 hover:text-white border border-white/10'
                  }`}
                >
                  {p.path_id}: {p.title.length > 28 ? `${p.title.slice(0, 25)}...` : p.title}
                </button>
              ))}
            </div>
          </div>

          {selectedPath && (
            <div className="p-4 rounded-xl bg-red-950/20 border border-red-500/20 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <span className="text-xs font-mono text-red-400 font-semibold uppercase tracking-wider">
                    {selectedPath.path_id} — {selectedPath.severity} EXPOSURE VECTOR
                  </span>
                  <h4 className="text-sm font-semibold text-white mt-0.5">{selectedPath.title}</h4>
                  <div className="text-xs text-gray-400 mt-1">{selectedPath.risk_summary}</div>
                </div>
                {selectedPath.kev && (
                  <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-red-500/20 text-red-300 border border-red-500/40">
                    CISA KEV Cataloged
                  </span>
                )}
              </div>

              {/* Hop Timeline */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-2 pt-2">
                {selectedPath.steps.map((st, i) => (
                  <div
                    key={st.step}
                    className="p-3 rounded-lg bg-black/40 border border-white/10 relative flex flex-col justify-between"
                  >
                    <div>
                      <div className="text-[10px] font-mono text-cyan-400 font-semibold mb-1">
                        HOP {st.step}
                      </div>
                      <div className="text-xs font-bold text-gray-200">{st.title}</div>
                      <div className="text-[11px] text-gray-400 mt-1 break-words">{st.detail}</div>
                    </div>
                    {i < selectedPath.steps.length - 1 && (
                      <div className="hidden lg:block absolute -right-2 top-1/2 -translate-y-1/2 text-gray-600 text-xs font-bold z-10">
                        &rarr;
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
