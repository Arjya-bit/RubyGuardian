import React, { useState, useEffect } from 'react';

/**
 * HoneypotMap - Displays a geographic visualization of honeypot connection sources.
 * Uses a simplified SVG world map with connection markers.
 */

const SAMPLE_CONNECTIONS = [
  { ip: '203.0.113.42', lat: 39.9, lng: 116.4, country: 'CN', attacks: 15, lastSeen: '2m ago' },
  { ip: '198.51.100.7', lat: 55.7, lng: 37.6, country: 'RU', attacks: 8, lastSeen: '10m ago' },
  { ip: '192.0.2.100', lat: 37.8, lng: -122.4, country: 'US', attacks: 3, lastSeen: '1h ago' },
  { ip: '198.51.100.22', lat: -23.5, lng: -46.6, country: 'BR', attacks: 5, lastSeen: '30m ago' },
  { ip: '203.0.113.88', lat: 35.7, lng: 139.7, country: 'JP', attacks: 2, lastSeen: '2h ago' },
];

function latLngToXY(lat, lng, width = 800, height = 400) {
  const x = ((lng + 180) / 360) * width;
  const y = ((90 - lat) / 180) * height;
  return { x, y };
}

export default function HoneypotMap({ connections = SAMPLE_CONNECTIONS }) {
  const [selected, setSelected] = useState(null);
  const [animate, setAnimate] = useState(true);

  useEffect(() => {
    const timer = setInterval(() => setAnimate(prev => !prev), 2000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="bg-gray-900 rounded-xl p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-white font-semibold">Connection Sources</h3>
        <span className="text-xs text-gray-400">{connections.length} active sources</span>
      </div>

      <svg viewBox="0 0 800 400" className="w-full h-auto bg-gray-800 rounded-lg">
        {/* Grid lines */}
        {[...Array(7)].map((_, i) => (
          <line key={`h${i}`} x1="0" y1={i * 66} x2="800" y2={i * 66} stroke="#374151" strokeWidth="0.5" />
        ))}
        {[...Array(13)].map((_, i) => (
          <line key={`v${i}`} x1={i * 66} y1="0" x2={i * 66} y2="400" stroke="#374151" strokeWidth="0.5" />
        ))}

        {/* Connection markers */}
        {connections.map((conn, i) => {
          const { x, y } = latLngToXY(conn.lat, conn.lng);
          const radius = Math.max(4, Math.min(12, conn.attacks));
          return (
            <g key={i} onClick={() => setSelected(conn)} className="cursor-pointer">
              {animate && (
                <circle cx={x} cy={y} r={radius + 8} fill="rgba(239, 68, 68, 0.2)">
                  <animate attributeName="r" values={`${radius};${radius + 16};${radius}`} dur="2s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.6;0;0.6" dur="2s" repeatCount="indefinite" />
                </circle>
              )}
              <circle cx={x} cy={y} r={radius} fill="#ef4444" opacity="0.8" stroke="#fca5a5" strokeWidth="1" />
              <text x={x} y={y - radius - 4} textAnchor="middle" fill="#9ca3af" fontSize="10">
                {conn.country}
              </text>
            </g>
          );
        })}
      </svg>

      {selected && (
        <div className="mt-4 bg-gray-800 rounded-lg p-3 text-sm">
          <div className="flex justify-between text-gray-300">
            <span>IP: {selected.ip}</span>
            <span>{selected.country}</span>
          </div>
          <div className="flex justify-between text-gray-400 mt-1">
            <span>Attacks: {selected.attacks}</span>
            <span>Last seen: {selected.lastSeen}</span>
          </div>
        </div>
      )}
    </div>
  );
}
