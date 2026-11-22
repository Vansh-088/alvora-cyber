/**
 * LiveLogFeed — Real-time threat log with waveform and NVIDIA metadata
 */

import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Activity } from 'lucide-react';
import LogModal from './LogModal.jsx';

const API_BASE = (typeof window !== 'undefined' && window.location.protocol === 'file:')
  ? 'http://localhost:3001/api'
  : '/api';

// ─── Waveform ─────────────────────────────────────────────────────────────────

const SEV_Y = { CRITICAL: 0.15, HIGH: 0.35, MEDIUM: 0.55, LOW: 0.72, INFO: 0.85 };

function buildWaveform(logs, W, H) {
  const pts = logs.slice(-40);
  if (pts.length < 2) return { d: '', last: null };

  const xs = pts.map((_, i) => (i / (pts.length - 1)) * W);
  const ys = pts.map(l => (SEV_Y[l.severity] ?? 0.6) * H);

  let d = `M ${xs[0]},${ys[0]}`;
  for (let i = 1; i < pts.length; i++) {
    const cpx = (xs[i - 1] + xs[i]) / 2;
    d += ` C ${cpx},${ys[i - 1]} ${cpx},${ys[i]} ${xs[i]},${ys[i]}`;
  }
  return { d, last: { x: xs[xs.length - 1], y: ys[ys.length - 1] } };
}

function Waveform({ logs }) {
  const ref    = useRef(null);
  const [dims, setDims] = useState({ W: 300, H: 60 });

  useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(([e]) => {
      setDims({ W: e.contentRect.width, H: e.contentRect.height });
    });
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);

  const { d, last } = buildWaveform(logs, dims.W, dims.H);

  return (
    <div ref={ref} className="w-full h-16 relative">
      <svg className="absolute inset-0 w-full h-full" viewBox={`0 0 ${dims.W} ${dims.H}`} preserveAspectRatio="none">
        {d && (
          <>
            <path d={d} fill="none" stroke="rgba(0,229,255,0.5)" strokeWidth={1.5} />
            <path d={`${d} L ${dims.W},${dims.H} L 0,${dims.H} Z`} fill="rgba(0,229,255,0.04)" />
            {last && (
              <circle cx={last.x} cy={last.y} r={3} fill="#00E5FF" className="animate-pulse" />
            )}
          </>
        )}
      </svg>
    </div>
  );
}

// ─── Severity badge ────────────────────────────────────────────────────────────

function SevBadge({ severity }) {
  const styles = {
    CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/40 glow-pulse',
    HIGH:     'bg-orange-500/20 text-orange-400 border-orange-500/40',
    MEDIUM:   'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
    LOW:      'bg-emerald-500/20 text-emerald-400 border-emerald-500/40',
    INFO:     'bg-cobalt/15 text-cobalt border-cobalt/30',
  };
  const labels = { CRITICAL: 'SERIOUS', HIGH: 'HIGH', MEDIUM: 'MEDIUM', LOW: 'LOW', INFO: 'LIVE' };
  return (
    <span className={`text-[9px] font-bold font-mono border rounded px-1.5 py-0.5 ${styles[severity] ?? styles.LOW}`}>
      {labels[severity] ?? severity}
    </span>
  );
}

// ─── Log row ──────────────────────────────────────────────────────────────────

function LogRow({ log, onClick }) {
  return (
    <motion.div
      initial={{ opacity: 0, x: 16 }}
      animate={{ opacity: 1, x: 0 }}
      onClick={() => onClick(log)}
      className="flex items-start gap-2 px-3 py-2 hover:bg-white/5 rounded-lg cursor-pointer transition-colors group"
    >
      {/* Severity indicator */}
      <div className={`mt-1 flex-shrink-0 w-1.5 h-1.5 rounded-full ${
        log.severity === 'CRITICAL' ? 'bg-red-500 shadow-[0_0_6px_rgba(239,68,68,0.8)]' :
        log.severity === 'HIGH'     ? 'bg-orange-400' :
        log.severity === 'MEDIUM'   ? 'bg-yellow-400' :
        log.severity === 'INFO'     ? 'bg-cobalt' :
        'bg-emerald-400'
      }`} />

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          <SevBadge severity={log.severity} />
          <span className="text-[10px] text-slate/40 font-mono flex-shrink-0">{log.timestamp}</span>
        </div>
        <p className="text-xs text-white/80">{log.type}</p>
        <div className="flex items-center gap-2 mt-0.5">
          {/* Network threats show source:port; monitoring/activity lines show their detail */}
          {log.severity === 'INFO' ? (
            log.detail && <span className="text-[10px] text-slate/40 font-mono truncate">{log.detail}</span>
          ) : (
            <>
              {log.source && (
                <span className="text-[10px] text-slate/50 font-mono">
                  {log.source}{log.port ? `:${log.port}` : ''}
                </span>
              )}
              <span className={`text-[10px] font-mono ${['BLOCKED', 'ALERT'].includes(log.action) ? 'text-red-400' : 'text-yellow-400'}`}>
                {log.action}
              </span>
            </>
          )}
        </div>
        {/* Alvora engine confidence (real threats only) */}
        {log.engine && (
          <div className="flex items-center gap-2 mt-1 text-[9px] font-mono text-slate/30">
            <span className="text-cobalt/50">{log.engine.name ?? 'Alvora Engine'}</span>
            <span>{Math.round((log.engine.confidence ?? 0) * 100)}% confident</span>
          </div>
        )}
      </div>
    </motion.div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function LiveLogFeed({ logs, onDismiss, onTrust }) {
  const [selectedLog, setSelectedLog] = useState(null);
  const [aiEngine,    setAiEngine]    = useState(null);   // { provider, model } of the real-time AI tier

  // Show which AI is triaging threats — only when one is genuinely reachable.
  // Re-checked every 30s: right after start-up the local model can be slow to
  // answer, and a one-off reading would keep showing the fallback provider.
  useEffect(() => {
    const load = () => fetch(`${API_BASE}/integrations/status`)
      .then(r => r.json())
      .then(d => {
        const provider = d?.llm?.active?.fast;
        setAiEngine(provider ? { provider, model: d.llm.providers[provider]?.model } : null);
      })
      .catch(() => {});
    load();
    const t = setInterval(load, 30_000);
    return () => clearInterval(t);
  }, []);

  return (
    <>
      <div className="flex-[2] glass-panel scanlines rounded-xl border border-white/5 flex flex-col overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-white/5 flex-shrink-0">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cobalt" />
            <h3 className="text-xs uppercase text-slate/50 font-mono">Live Security Feed</h3>
          </div>
          <div className="flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-[10px] text-slate/40 font-mono">{logs.length} events</span>
          </div>
        </div>

        {/* Waveform */}
        <div className="px-4 pt-3 pb-1 border-b border-white/5 flex-shrink-0">
          <Waveform logs={logs} />
        </div>

        {/* Log list */}
        <div className="flex-1 overflow-y-auto py-2">
          {logs.length === 0 ? (
            <div className="flex items-center justify-center h-full">
              <p className="text-slate/30 text-xs font-mono">Starting up — first scan in progress…</p>
            </div>
          ) : (
            <AnimatePresence initial={false}>
              {logs.map(log => (
                <LogRow key={log.id} log={log} onClick={setSelectedLog} />
              ))}
            </AnimatePresence>
          )}
        </div>

        {/* Active AI engine — only shown when a provider is actually reachable */}
        {aiEngine && (
          <div className="flex items-center justify-center gap-1.5 px-4 py-2 border-t border-white/5 flex-shrink-0">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" style={{ boxShadow: '0 0 6px #34d399' }} />
            <span className="text-[9px] font-mono tracking-wider text-emerald-400/80 uppercase">
              AI triage: {aiEngine.provider === 'ollama' ? 'local' : aiEngine.provider} · {aiEngine.model}
            </span>
          </div>
        )}
      </div>

      {/* Modal */}
      <AnimatePresence>
        {selectedLog && <LogModal log={selectedLog} onClose={() => setSelectedLog(null)} onDismiss={onDismiss} onTrust={onTrust} />}
      </AnimatePresence>
    </>
  );
}
