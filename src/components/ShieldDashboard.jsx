/**
 * ShieldDashboard — Central security posture visualizer
 */

import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, ShieldOff, ShieldCheck, ShieldAlert, CheckCircle2, Zap, Wrench } from 'lucide-react';

const MATRIX_CHARS = '01アイウエオ∆∇⊗⊕∞≠√πΩ';

function MatrixColumn({ x, speed, delay }) {
  const chars = Array.from({ length: 12 }, () => MATRIX_CHARS[Math.floor(Math.random() * MATRIX_CHARS.length)]);
  return (
    <motion.div
      initial={{ y: -200, opacity: 0 }}
      animate={{ y: 300, opacity: [0, 0.7, 0] }}
      transition={{ duration: speed, delay, repeat: Infinity, ease: 'linear' }}
      className="absolute top-0 font-mono text-[10px] text-emerald-400/60 flex flex-col gap-1 leading-3 select-none pointer-events-none"
      style={{ left: x }}
    >
      {chars.map((c, i) => <span key={i}>{c}</span>)}
    </motion.div>
  );
}

const MATRIX_COLS = Array.from({ length: 14 }, (_, i) => ({
  x: `${i * 7}%`,
  speed: 1.2 + Math.random() * 1.5,
  delay: Math.random() * 2,
}));

const BURST_PARTICLES = Array.from({ length: 16 }, (_, i) => {
  const angle = (i / 16) * Math.PI * 2;
  return { x: Math.cos(angle) * 120, y: Math.sin(angle) * 120, rotate: angle * (180 / Math.PI) };
});

// One line per issue (biggest gain first) + a way into the full guide
function CheckSummary({ audit, onOpenGuide }) {
  const toFix = audit.checks
    .filter(c => c.status === 'fail' || c.status === 'warn')
    .sort((a, b) => b.points - a.points);
  const passed = audit.checks.filter(c => c.status === 'pass').length;

  return (
    <div className="w-full max-w-md mb-6 space-y-2">
      <p className="text-[11px] text-slate/50 text-center">
        {passed} of {audit.checks.length} checks passed
        {toFix.length > 0 && ` · ${toFix.length} to fix`}
      </p>
      {toFix.slice(0, 3).map(c => (
        <button
          key={c.id}
          onClick={onOpenGuide}
          className="w-full flex items-center gap-2 bg-black/20 hover:bg-black/30 rounded-lg px-3 py-2 text-left transition-colors"
        >
          <span className={`w-2 h-2 rounded-full flex-shrink-0 ${c.status === 'fail' ? 'bg-red-400' : 'bg-yellow-400'}`} />
          <span className="text-xs text-white/75 flex-1 truncate">{c.guide.title}</span>
          <span className="text-[10px] font-mono font-bold text-emerald-400 flex-shrink-0">+{c.points}</span>
        </button>
      ))}
      <button
        onClick={onOpenGuide}
        className="w-full flex items-center justify-center gap-1.5 text-xs text-cobalt hover:text-cobalt/80 py-1 transition-colors"
      >
        <Wrench className="w-3.5 h-3.5" />
        {toFix.length ? 'How to fix these' : 'See all checks'}
      </button>
    </div>
  );
}

export default function ShieldDashboard({
  isHardening, hardeningProgress, isSecured, securityScore, isCritical,
  lockdownActive, hardeningMetrics, audit, onHarden, onOpenGuide,
}) {
  const [showBurst, setShowBurst] = useState(false);
  const prevSecured = useRef(false);

  useEffect(() => {
    if (isSecured && !prevSecured.current) {
      setShowBurst(true);
      setTimeout(() => setShowBurst(false), 1200);
    }
    prevSecured.current = isSecured;
  }, [isSecured]);

  const shieldColor = lockdownActive ? '#ef4444' : isCritical ? '#f97316' : isSecured ? '#00E5FF' : '#94a3b8';
  const needsWork   = !isSecured && securityScore != null;
  const statusText  = lockdownActive ? 'LOCKDOWN' : isCritical ? 'THREAT ACTIVE' : isSecured ? 'DEVICE SECURE'
                    : needsWork ? `NEEDS ATTENTION · ${securityScore}/100` : 'READY TO CHECK';
  const statusColor = lockdownActive ? 'text-rose-400' : isCritical ? 'text-orange-400' : isSecured ? 'text-cobalt'
                    : needsWork ? 'text-yellow-400' : 'text-slate/70';
  const ShieldIcon  = lockdownActive ? ShieldOff : isCritical ? ShieldAlert : isSecured ? ShieldCheck : Shield;

  return (
    <motion.div
      key="dashboard"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="flex flex-col items-center justify-center w-full h-full p-8 relative overflow-hidden"
    >
      {/* Matrix data stream (during hardening) */}
      <AnimatePresence>
        {isHardening && (
          <motion.div
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="absolute inset-0 overflow-hidden pointer-events-none"
          >
            {MATRIX_COLS.map((col, i) => <MatrixColumn key={i} {...col} />)}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Conical sweep (hardening) */}
      <AnimatePresence>
        {isHardening && (
          <motion.div
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="absolute inset-0 pointer-events-none"
          >
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
              className="absolute inset-0"
              style={{
                background: 'conic-gradient(from 0deg, transparent 0deg, rgba(0,229,255,0.06) 30deg, transparent 60deg)',
              }}
            />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Concentric rings — static: rotating a uniform circle looks identical
          but kept the compositor busy every frame */}
      {[
        { size: 200, color: 'rgba(0,229,255,0.08)'  },
        { size: 260, color: 'rgba(0,229,255,0.05)'  },
        { size: 320, color: 'rgba(0,229,255,0.03)'  },
      ].map((ring, i) => (
        <div
          key={i}
          className="absolute rounded-full border pointer-events-none"
          style={{
            width:  ring.size,
            height: ring.size,
            borderColor: ring.color,
            top:  '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
          }}
        />
      ))}

      {/* Burst particles */}
      <AnimatePresence>
        {showBurst && BURST_PARTICLES.map((p, i) => (
          <motion.div
            key={i}
            initial={{ x: 0, y: 0, opacity: 1, scale: 1 }}
            animate={{ x: p.x, y: p.y, opacity: 0, scale: 0 }}
            exit={{}}
            transition={{ duration: 1.2, ease: 'easeOut', delay: i * 0.02 }}
            className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-none"
          >
            <div className="w-2 h-2 rounded-full bg-cobalt shadow-[0_0_8px_rgba(0,229,255,0.8)]" />
          </motion.div>
        ))}
      </AnimatePresence>

      {/* Central shield */}
      <motion.div
        animate={{ scale: isHardening ? [1, 1.04, 1] : 1 }}
        transition={isHardening
          ? { duration: 0.6, repeat: Infinity, ease: 'easeInOut' }
          : { duration: 0.4, ease: 'easeOut' }}
        className="relative z-10 mb-8 flex items-center justify-center"
      >
        {/* Steady glow layer — separate element so we never mix keyframe-array
            and string filters on the same node (the old flicker source).
            Color comes from a CSS transition; only opacity pulses, and only
            when critical — a single animatable prop, no type-mixing. */}
        <motion.div
          aria-hidden
          animate={{ opacity: isCritical ? [0.5, 1, 0.5] : 1 }}
          transition={isCritical
            ? { duration: 1.6, repeat: Infinity, ease: 'easeInOut' }
            : { duration: 0.5 }}
          className="absolute rounded-full"
          style={{
            width: 150, height: 150,
            background: `radial-gradient(circle, ${shieldColor}40 0%, transparent 70%)`,
            filter: 'blur(8px)',
            transition: 'background 0.5s ease',
          }}
        />
        <ShieldIcon
          strokeWidth={1}
          style={{ width: 128, height: 128, color: shieldColor, transition: 'color 0.5s ease', position: 'relative' }}
        />
        {isSecured && !isCritical && !lockdownActive && (
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ type: 'spring', stiffness: 400, damping: 25 }}
            className="absolute inset-0 flex items-center justify-center"
          >
            <CheckCircle2 className="w-10 h-10 text-cobalt" />
          </motion.div>
        )}
      </motion.div>

      {/* Status text — no `key` remount; color/text update in place to avoid flicker */}
      <p className={`text-xs font-mono tracking-[0.25em] uppercase mb-3 transition-colors duration-500 ${statusColor}`}>
        {statusText}
      </p>

      {/* Progress bar */}
      <AnimatePresence>
        {isHardening && (
          <motion.div
            initial={{ opacity: 0, width: 0 }}
            animate={{ opacity: 1, width: '100%' }}
            exit={{ opacity: 0 }}
            className="w-64 mb-4"
          >
            <div className="h-1 bg-white/10 rounded-full overflow-hidden">
              <motion.div
                className="h-full bg-cobalt rounded-full"
                style={{ width: `${hardeningProgress}%` }}
                transition={{ duration: 0.15 }}
              />
            </div>
            <p className="text-center text-[10px] text-cobalt/60 font-mono mt-1">{hardeningProgress}%</p>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Real Security Audit Results (post-hardening) */}
      <AnimatePresence>
        {hardeningMetrics && !isHardening && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="w-full max-w-md mb-6 space-y-2"
          >
            {/* Score bar */}
            {hardeningMetrics.securityScore !== undefined && (
              <div className="bg-black/30 rounded-xl p-3 border border-white/5">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] uppercase font-mono text-slate/50">Security Score</span>
                  <span className={`text-sm font-bold font-mono ${
                    hardeningMetrics.securityScore >= 80 ? 'text-emerald-400' :
                    hardeningMetrics.securityScore >= 55 ? 'text-yellow-400' : 'text-red-400'
                  }`}>{hardeningMetrics.securityScore}/100</span>
                </div>
                <div className="h-1.5 bg-white/10 rounded-full overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${hardeningMetrics.securityScore}%` }}
                    transition={{ duration: 0.8, ease: 'easeOut' }}
                    className={`h-full rounded-full ${
                      hardeningMetrics.securityScore >= 80 ? 'bg-emerald-400' :
                      hardeningMetrics.securityScore >= 55 ? 'bg-yellow-400' : 'bg-red-400'
                    }`}
                  />
                </div>
              </div>
            )}

          </motion.div>
        )}
      </AnimatePresence>

      {/* What to fix — opens the plain-language guide */}
      {audit && !isHardening && <CheckSummary audit={audit} onOpenGuide={onOpenGuide} />}

      {/* Harden button */}
      <motion.button
        whileHover={{ scale: isHardening ? 1 : 1.04 }}
        whileTap={{ scale: 0.97 }}
        onClick={onHarden}
        disabled={isHardening || lockdownActive}
        className={`relative flex items-center gap-2 px-8 py-3 rounded-xl font-semibold text-sm transition-all
          ${lockdownActive
            ? 'bg-red-500/20 text-red-400 border border-red-500/30 cursor-not-allowed'
            : isHardening
            ? 'bg-cobalt/20 text-cobalt border border-cobalt/30 cursor-not-allowed'
            : 'bg-cobalt text-obsidian hover:bg-cobalt/90 shadow-glow'}`}
      >
        <Zap className={`w-4 h-4 ${isHardening ? 'animate-pulse' : ''}`} />
        {isHardening ? 'Checking…' : lockdownActive ? 'Lockdown Active' : 'Run Security Check'}
      </motion.button>
    </motion.div>
  );
}
