/**
 * ThreatMap — Geographic threat origin visualizer
 *
 * Plots REAL latitude/longitude coordinates (resolved by the backend via
 * ip-api.com) on an equirectangular world projection. A point from Tokyo
 * appears top-right; a point from Brazil appears lower-left. No fake positions.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Globe, RefreshCw } from 'lucide-react';

const API_BASE = (typeof window !== 'undefined' && window.location.protocol === 'file:')
  ? 'http://localhost:3001/api'
  : '/api';

const SEV_COLORS = {
  CRITICAL: { fill: 'rgba(239,68,68,0.95)',  ring: 'rgba(239,68,68,0.35)',  text: 'text-red-400'    },
  HIGH:     { fill: 'rgba(249,115,22,0.85)', ring: 'rgba(249,115,22,0.25)', text: 'text-orange-400' },
  MEDIUM:   { fill: 'rgba(251,191,36,0.8)',  ring: 'rgba(251,191,36,0.25)', text: 'text-yellow-400' },
  LOW:      { fill: 'rgba(52,211,153,0.7)',  ring: 'rgba(52,211,153,0.2)',  text: 'text-emerald-400' },
};

// Equirectangular projection: lon [-180,180] → x [0,100]%, lat [90,-90] → y [0,100]%
function project(lat, lon) {
  const x = ((lon + 180) / 360) * 100;
  const y = ((90 - lat) / 180) * 100;
  return { x, y };
}

// Coarse continent outlines as [lon, lat] vertices. Drawn with the SAME projection
// as the threat dots, so a dot in Tokyo lands on Asia, a dot in Brazil on South
// America, etc. Deliberately low-detail — just enough to read as a world map.
const CONTINENTS = [
  // North America
  [[-168,66],[-150,70],[-125,70],[-95,69],[-81,73],[-60,66],[-56,52],[-66,46],[-80,42],[-75,35],[-81,25],[-97,18],[-110,23],[-117,32],[-124,40],[-130,54],[-150,59],[-168,66]],
  // South America
  [[-81,8],[-70,10],[-60,5],[-50,0],[-44,-3],[-35,-7],[-40,-20],[-48,-25],[-58,-35],[-65,-45],[-72,-52],[-75,-45],[-71,-30],[-70,-18],[-78,-5],[-81,8]],
  // Europe
  [[-10,36],[-9,43],[-2,48],[2,51],[-5,58],[5,62],[12,66],[28,70],[40,66],[40,55],[30,46],[20,42],[10,38],[0,38],[-10,36]],
  // Africa
  [[-17,21],[-16,32],[10,37],[24,33],[35,31],[43,12],[51,12],[40,-5],[40,-18],[32,-28],[20,-35],[18,-30],[12,-16],[8,4],[-8,5],[-17,21]],
  // Asia
  [[28,70],[60,75],[100,78],[140,73],[170,68],[180,65],[160,60],[145,45],[140,35],[122,30],[120,22],[108,12],[95,5],[80,8],[72,20],[60,25],[45,40],[40,48],[40,66],[28,70]],
  // India peninsula
  [[68,24],[80,30],[88,22],[80,8],[74,15],[68,24]],
  // Australia
  [[113,-22],[129,-13],[141,-13],[150,-22],[153,-28],[146,-38],[137,-35],[129,-32],[118,-35],[114,-28],[113,-22]],
];

export default function ThreatMap({ logs }) {
  const [points,  setPoints]  = useState([]);
  const [hovered, setHovered] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchGeo = useCallback(async () => {
    setLoading(true);
    try {
      const res  = await fetch(`${API_BASE}/threats/geo`);
      const data = await res.json();
      setPoints(data.points ?? []);
    } catch {
      setPoints([]);
    } finally {
      setLoading(false);
    }
  }, []);

  // Fetch on mount and whenever the threat log count changes (new IPs to locate)
  useEffect(() => { fetchGeo(); }, [fetchGeo, logs.length]);

  return (
    <motion.div
      key="threat"
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="flex flex-col w-full h-full p-6"
    >
      <div className="flex items-center gap-2 mb-4">
        <Globe className="w-5 h-5 text-cobalt" />
        <h2 className="text-base font-bold text-white">Threat Origin Map</h2>
        <span className="text-[10px] font-mono text-cobalt/60 ml-2">Real coordinates · ip-api.com</span>
        <button
          onClick={fetchGeo}
          className="ml-auto flex items-center gap-1.5 text-[10px] font-mono text-cobalt/60 hover:text-cobalt bg-cobalt/10 border border-cobalt/20 rounded px-2 py-1 transition-colors"
        >
          <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
          {points.length} located
        </button>
      </div>

      {/* World projection */}
      <div className="flex-1 relative bg-black/30 rounded-xl overflow-hidden border border-white/5">
        {/* World map: continents drawn with the same projection as the dots */}
        <svg className="absolute inset-0 w-full h-full" viewBox="0 0 100 100" preserveAspectRatio="none">
          {/* Continent fills */}
          {CONTINENTS.map((poly, i) => {
            const pts = poly.map(([lon, lat]) => {
              const { x, y } = project(lat, lon);
              return `${x},${y}`;
            }).join(' ');
            return (
              <polygon
                key={i}
                points={pts}
                fill="rgba(0,229,255,0.06)"
                stroke="rgba(0,229,255,0.25)"
                strokeWidth={0.15}
              />
            );
          })}
          {/* Faint lat/long grid */}
          {Array.from({ length: 13 }, (_, i) => (
            <line key={`v${i}`} x1={(i / 12) * 100} y1="0" x2={(i / 12) * 100} y2="100" stroke="#00E5FF" strokeWidth={0.08} opacity={0.12} />
          ))}
          {Array.from({ length: 7 }, (_, i) => (
            <line key={`h${i}`} x1="0" y1={(i / 6) * 100} x2="100" y2={(i / 6) * 100} stroke="#00E5FF" strokeWidth={0.08} opacity={0.12} />
          ))}
          {/* Equator + prime meridian */}
          <line x1="0" y1="50" x2="100" y2="50" stroke="#00E5FF" strokeWidth={0.12} opacity={0.2} />
          <line x1="50" y1="0" x2="50" y2="100" stroke="#00E5FF" strokeWidth={0.12} opacity={0.2} />
        </svg>

        {/* Threat points at real geographic positions */}
        {points.map((p, i) => {
          const { x, y } = project(p.lat, p.lon);
          const sev   = SEV_COLORS[p.severity] ?? SEV_COLORS.MEDIUM;
          const isHov = hovered === p.ip;

          return (
            <div key={`${p.ip}-${i}`}
              style={{ position: 'absolute', left: `${x}%`, top: `${y}%`, transform: 'translate(-50%,-50%)' }}
              onMouseEnter={() => setHovered(p.ip)}
              onMouseLeave={() => setHovered(null)}
              className="cursor-pointer z-10"
            >
              <motion.div
                animate={{ scale: isHov ? 1.6 : 1 }}
                className="relative flex items-center justify-center"
              >
                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: sev.fill }} />
                <motion.div
                  animate={{ scale: [1, 2.2, 1], opacity: [0.5, 0, 0.5] }}
                  transition={{ duration: 1.5 + (i % 5) * 0.2, repeat: Infinity }}
                  className="absolute w-3 h-3 rounded-full"
                  style={{ backgroundColor: sev.ring }}
                />
              </motion.div>

              <AnimatePresence>
                {isHov && (
                  <motion.div
                    initial={{ opacity: 0, y: -4 }}
                    animate={{ opacity: 1, y: -8 }}
                    exit={{ opacity: 0 }}
                    className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1 z-50 w-44 glass-panel rounded-lg p-2 border border-white/10 shadow-glow"
                  >
                    <p className="text-white text-[10px] font-mono font-bold">{p.ip}</p>
                    <p className="text-cobalt text-[10px]">{p.city ? `${p.city}, ` : ''}{p.country}</p>
                    <p className={`text-[10px] font-mono ${sev.text}`}>{p.severity} · {p.type}</p>
                    {p.isp && <p className="text-slate/40 text-[9px] truncate mt-0.5">{p.isp}</p>}
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          );
        })}

        {/* Empty state */}
        {points.length === 0 && !loading && (
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="text-center">
              <Globe className="w-10 h-10 text-slate/20 mx-auto mb-2" />
              <p className="text-slate/30 text-xs font-mono">No external threat sources located yet</p>
              <p className="text-slate/20 text-[10px] mt-1">External IPs appear here as they're detected</p>
            </div>
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 mt-4">
        {Object.entries(SEV_COLORS).map(([sev, c]) => (
          <div key={sev} className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full" style={{ backgroundColor: c.fill }} />
            <span className={`text-[10px] font-mono ${c.text}`}>{sev}</span>
          </div>
        ))}
        <span className="text-[9px] font-mono text-slate/30 ml-auto">Equirectangular projection · lat/lon</span>
      </div>
    </motion.div>
  );
}
