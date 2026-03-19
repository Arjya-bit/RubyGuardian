import React, { useRef, useEffect, useState, useMemo, useCallback } from 'react';
import Badge from '../common/Badge';

const MAP_WIDTH = 960;
const MAP_HEIGHT = 500;

// Simplified world regions with approximate SVG path coordinates
const REGIONS = [
  { id: 'na', name: 'North America', cx: 200, cy: 180, r: 60 },
  { id: 'sa', name: 'South America', cx: 280, cy: 350, r: 50 },
  { id: 'eu', name: 'Europe', cx: 500, cy: 150, r: 45 },
  { id: 'af', name: 'Africa', cx: 510, cy: 300, r: 55 },
  { id: 'as', name: 'Asia', cx: 680, cy: 180, r: 70 },
  { id: 'oc', name: 'Oceania', cx: 800, cy: 380, r: 40 },
];

/**
 * ThreatMap - Geographic visualization of threat sources and targets.
 * Renders an SVG-based world map with animated threat indicators.
 *
 * @param {Object} props
 * @param {Array} props.threats - Array of threat objects with geo data
 * @param {Function} [props.onThreatClick] - Callback when a threat marker is clicked
 * @param {boolean} [props.showConnections] - Draw lines between source and target
 */
export default function ThreatMap({ threats = [], onThreatClick, showConnections = true }) {
  const svgRef = useRef(null);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [hoveredRegion, setHoveredRegion] = useState(null);
  const [animationPhase, setAnimationPhase] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setAnimationPhase((p) => (p + 1) % 360);
    }, 50);
    return () => clearInterval(interval);
  }, []);

  const threatsByRegion = useMemo(() => {
    const map = {};
    REGIONS.forEach((r) => { map[r.id] = []; });
    threats.forEach((t) => {
      const regionId = t.source_region || 'na';
      if (map[regionId]) map[regionId].push(t);
    });
    return map;
  }, [threats]);

  const connections = useMemo(() => {
    if (!showConnections) return [];
    return threats
      .filter((t) => t.source_region && t.target_region && t.source_region !== t.target_region)
      .map((t) => {
        const src = REGIONS.find((r) => r.id === t.source_region);
        const tgt = REGIONS.find((r) => r.id === t.target_region);
        if (!src || !tgt) return null;
        return { id: t.id, x1: src.cx, y1: src.cy, x2: tgt.cx, y2: tgt.cy, severity: t.severity };
      })
      .filter(Boolean);
  }, [threats, showConnections]);

  const handleThreatClick = useCallback((threat) => {
    setSelectedThreat(threat);
    onThreatClick?.(threat);
  }, [onThreatClick]);

  const getSeverityColor = (severity) => {
    const colors = { critical: '#ff1744', high: '#ff6d00', medium: '#ffab00', low: '#66bb6a', info: '#42a5f5' };
    return colors[severity] || colors.info;
  };

  const getRegionHeatColor = (count) => {
    if (count === 0) return 'rgba(59, 130, 246, 0.1)';
    if (count <= 3) return 'rgba(251, 191, 36, 0.2)';
    if (count <= 10) return 'rgba(249, 115, 22, 0.3)';
    return 'rgba(239, 68, 68, 0.4)';
  };

  return (
    <div className="bg-dark-800 rounded-lg border border-dark-700 overflow-hidden">
      <div className="p-4 border-b border-dark-700 flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Threat Origin Map</h3>
        <div className="flex items-center gap-4 text-xs text-gray-400">
          {['critical', 'high', 'medium', 'low'].map((sev) => (
            <span key={sev} className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full" style={{ backgroundColor: getSeverityColor(sev) }} />
              {sev}
            </span>
          ))}
        </div>
      </div>

      <div className="relative">
        <svg
          ref={svgRef}
          viewBox={`0 0 ${MAP_WIDTH} ${MAP_HEIGHT}`}
          className="w-full h-auto"
          style={{ background: 'radial-gradient(ellipse at center, #1a1a2e 0%, #0f0f1a 100%)' }}
        >
          {/* Grid lines */}
          {Array.from({ length: 12 }, (_, i) => (
            <line
              key={`vg-${i}`}
              x1={i * (MAP_WIDTH / 12)}
              y1={0}
              x2={i * (MAP_WIDTH / 12)}
              y2={MAP_HEIGHT}
              stroke="rgba(255,255,255,0.03)"
              strokeWidth="1"
            />
          ))}
          {Array.from({ length: 8 }, (_, i) => (
            <line
              key={`hg-${i}`}
              x1={0}
              y1={i * (MAP_HEIGHT / 8)}
              x2={MAP_WIDTH}
              y2={i * (MAP_HEIGHT / 8)}
              stroke="rgba(255,255,255,0.03)"
              strokeWidth="1"
            />
          ))}

          {/* Region heat zones */}
          {REGIONS.map((region) => (
            <g key={region.id}>
              <circle
                cx={region.cx}
                cy={region.cy}
                r={region.r}
                fill={getRegionHeatColor(threatsByRegion[region.id]?.length || 0)}
                stroke="rgba(255,255,255,0.1)"
                strokeWidth="1"
                onMouseEnter={() => setHoveredRegion(region.id)}
                onMouseLeave={() => setHoveredRegion(null)}
                className="cursor-pointer transition-all duration-300"
              />
              <text
                x={region.cx}
                y={region.cy + region.r + 14}
                textAnchor="middle"
                fill="rgba(255,255,255,0.4)"
                fontSize="10"
              >
                {region.name}
              </text>
              {threatsByRegion[region.id]?.length > 0 && (
                <text
                  x={region.cx}
                  y={region.cy + 5}
                  textAnchor="middle"
                  fill="white"
                  fontSize="14"
                  fontWeight="bold"
                >
                  {threatsByRegion[region.id].length}
                </text>
              )}
            </g>
          ))}

          {/* Connection lines */}
          {connections.map((conn) => {
            const midX = (conn.x1 + conn.x2) / 2;
            const midY = Math.min(conn.y1, conn.y2) - 40;
            return (
              <g key={conn.id}>
                <path
                  d={`M ${conn.x1} ${conn.y1} Q ${midX} ${midY} ${conn.x2} ${conn.y2}`}
                  fill="none"
                  stroke={getSeverityColor(conn.severity)}
                  strokeWidth="1.5"
                  strokeDasharray="6,4"
                  opacity="0.6"
                />
                <circle r="3" fill={getSeverityColor(conn.severity)}>
                  <animateMotion
                    dur="3s"
                    repeatCount="indefinite"
                    path={`M ${conn.x1} ${conn.y1} Q ${midX} ${midY} ${conn.x2} ${conn.y2}`}
                  />
                </circle>
              </g>
            );
          })}

          {/* Individual threat markers */}
          {threats.slice(0, 50).map((threat, i) => {
            const region = REGIONS.find((r) => r.id === (threat.source_region || 'na'));
            if (!region) return null;
            const angle = (i / Math.min(threats.length, 50)) * Math.PI * 2;
            const spread = region.r * 0.7;
            const tx = region.cx + Math.cos(angle) * spread * (0.5 + Math.random() * 0.5);
            const ty = region.cy + Math.sin(angle) * spread * (0.5 + Math.random() * 0.5);
            return (
              <circle
                key={threat.id || i}
                cx={tx}
                cy={ty}
                r={threat.severity === 'critical' ? 5 : 3}
                fill={getSeverityColor(threat.severity)}
                opacity={0.8}
                className="cursor-pointer"
                onClick={() => handleThreatClick(threat)}
              >
                {threat.severity === 'critical' && (
                  <animate attributeName="r" values="4;7;4" dur="1.5s" repeatCount="indefinite" />
                )}
              </circle>
            );
          })}
        </svg>

        {/* Hover tooltip */}
        {hoveredRegion && (
          <div className="absolute top-4 right-4 bg-dark-900 border border-dark-600 rounded-lg p-3 text-sm">
            <p className="text-white font-medium">{REGIONS.find((r) => r.id === hoveredRegion)?.name}</p>
            <p className="text-gray-400">{threatsByRegion[hoveredRegion]?.length || 0} active threats</p>
          </div>
        )}
      </div>

      {/* Selected threat detail */}
      {selectedThreat && (
        <div className="p-4 border-t border-dark-700 flex items-center justify-between">
          <div>
            <p className="text-white font-medium">{selectedThreat.rule_name || 'Unknown Threat'}</p>
            <p className="text-sm text-gray-400">
              {selectedThreat.source_ip} &rarr; {selectedThreat.target_ip || 'local'}
            </p>
          </div>
          <Badge variant={selectedThreat.severity}>{selectedThreat.severity}</Badge>
        </div>
      )}
    </div>
  );
}
