/**
 * CriticalAlert — Fixed-top critical threat notification banner
 */

import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, X } from 'lucide-react';

export default function CriticalAlert({ threat, onDismiss }) {
  const [progress, setProgress] = useState(100);

  useEffect(() => {
    if (!threat) { setProgress(100); return; }
    setProgress(100);
    const start  = Date.now();
    const dur    = 10_000;
    const timer  = setInterval(() => {
      const elapsed = Date.now() - start;
      const pct     = Math.max(0, 100 - (elapsed / dur) * 100);
      setProgress(pct);
      if (pct <= 0) { clearInterval(timer); onDismiss?.(); }
    }, 50);
    return () => clearInterval(timer);
  }, [threat, onDismiss]);

  return (
    <AnimatePresence>
      {threat && (
        <motion.div
          initial={{ y: -80, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          exit={{ y: -80, opacity: 0 }}
          transition={{ type: 'spring', stiffness: 400, damping: 30 }}
          className="fixed top-4 left-1/2 -translate-x-1/2 z-[100] w-[520px] max-w-[90vw]"
        >
          <div className="relative bg-red-950/90 border border-red-500/60 rounded-xl overflow-hidden shadow-glow-red backdrop-blur-md">
            {/* Content */}
            <div className="flex items-start gap-3 px-4 py-3">
              <div className="flex-shrink-0 mt-0.5">
                <AlertTriangle className="w-5 h-5 text-red-400 animate-pulse" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="text-red-400 font-bold text-xs font-mono uppercase tracking-wide">Critical Threat Detected</span>
                  {threat.engine?.name && (
                    <span className="text-[9px] font-mono text-red-400/50 bg-red-500/10 border border-red-500/20 rounded px-1.5 py-0.5">
                      {threat.engine.model ?? threat.engine.name}
                    </span>
                  )}
                </div>
                <p className="text-white/90 text-sm font-medium truncate">{threat.type}</p>
                <div className="flex items-center gap-3 mt-1 text-[10px] font-mono text-red-400/60">
                  <span>{threat.source}:{threat.port}</span>
                  {threat.engine?.confidence != null && (
                    <span>{Math.round(threat.engine.confidence * 100)}% confident</span>
                  )}
                  <span className="text-red-400 font-bold">{threat.action}</span>
                </div>
              </div>
              <button
                onClick={onDismiss}
                className="flex-shrink-0 p-1 hover:bg-red-500/20 rounded transition-colors"
              >
                <X className="w-4 h-4 text-red-400/60" />
              </button>
            </div>

            {/* Drain bar */}
            <div className="h-0.5 bg-red-900/50 mx-0">
              <motion.div
                className="h-full bg-red-500"
                style={{ width: `${progress}%` }}
                transition={{ duration: 0.05 }}
              />
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
