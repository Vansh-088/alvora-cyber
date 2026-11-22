/**
 * SecurityGuide — plain-language "how to fix it" for the Security Check
 *
 * Shows what to fix first (biggest score gain first), why each item matters,
 * numbered steps, and a shortcut to the right System Settings page. Passing
 * checks are listed underneath so the user can see what's already good.
 */

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  X, ShieldCheck, ChevronDown, CheckCircle2, AlertTriangle, XCircle, HelpCircle,
  ExternalLink, RefreshCw, Loader2,
} from 'lucide-react';

const STATUS = {
  fail:    { Icon: XCircle,       cls: 'text-red-400',     label: 'Fix this' },
  warn:    { Icon: AlertTriangle, cls: 'text-yellow-400',  label: 'Worth improving' },
  pass:    { Icon: CheckCircle2,  cls: 'text-emerald-400', label: 'Good' },
  unknown: { Icon: HelpCircle,    cls: 'text-slate/50',    label: 'Couldn\'t check' },
};

const scoreColor = s => (s >= 80 ? 'text-emerald-400' : s >= 55 ? 'text-yellow-400' : 'text-red-400');

function headline(score, toFix) {
  if (!toFix.length) return { title: 'Your Mac is set up safely', body: 'Every setting Alvora checks is in good shape. Keep automatic updates on and run a check now and then — settings can change after big macOS updates.' };
  const gain = toFix.reduce((s, c) => s + c.points, 0);
  const n = toFix.length;
  return {
    title: n === 1 ? 'One thing to fix' : `${n} things to fix`,
    body: `Start at the top — it makes the biggest difference. Fixing ${n === 1 ? 'it' : 'everything below'} takes your score from ${score} to ${Math.min(100, score + gain)}.`,
  };
}

function FixCard({ check, defaultOpen, onOpenSettings }) {
  const [open, setOpen] = useState(defaultOpen);
  const { Icon, cls, label } = STATUS[check.status] ?? STATUS.unknown;
  return (
    <div className="bg-black/30 rounded-xl border border-white/5 overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        aria-expanded={open}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/5 transition-colors"
      >
        <Icon className={`w-4 h-4 flex-shrink-0 ${cls}`} />
        <div className="flex-1 min-w-0">
          <div className="text-sm text-white/90 font-medium">{check.guide.title}</div>
          <div className={`text-[11px] truncate ${cls}`} title={check.value}>{label} · now: {check.value}</div>
        </div>
        {check.points > 0 && (
          <span className="text-[11px] font-mono font-bold text-emerald-400 bg-emerald-400/10 rounded px-2 py-0.5 flex-shrink-0">
            +{check.points} pts
          </span>
        )}
        <ChevronDown className={`w-4 h-4 text-slate/40 flex-shrink-0 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
          >
            <div className="px-4 pb-4 space-y-3">
              <p className="text-xs text-white/60 leading-relaxed">
                <span className="text-white/80 font-medium">Why it matters: </span>{check.guide.why}
              </p>
              <ol className="space-y-2">
                {check.guide.steps.map((step, i) => (
                  <li key={i} className="flex gap-3 text-xs text-white/75 leading-relaxed">
                    <span className="w-5 h-5 rounded-full bg-cobalt/15 text-cobalt text-[10px] font-bold flex items-center justify-center flex-shrink-0 mt-px">
                      {i + 1}
                    </span>
                    <span>{step}</span>
                  </li>
                ))}
              </ol>
              {check.settings && onOpenSettings && (
                <button
                  onClick={() => onOpenSettings(check.settings)}
                  className="flex items-center gap-1.5 text-xs text-cobalt hover:text-cobalt/80 transition-colors"
                >
                  <ExternalLink className="w-3.5 h-3.5" /> Open this in System Settings
                </button>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default function SecurityGuide({ audit, onClose, onRecheck, rechecking, error, onOpenSettings }) {
  const checks  = audit?.checks ?? [];
  const toFix   = checks.filter(c => c.status === 'fail' || c.status === 'warn').sort((a, b) => b.points - a.points);
  const good    = checks.filter(c => c.status === 'pass');
  const unknown = checks.filter(c => c.status === 'unknown');
  const { title, body } = headline(audit?.score ?? 0, toFix);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-black/60 backdrop-blur-sm"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.95, y: 16 }}
        animate={{ scale: 1, y: 0 }}
        exit={{ scale: 0.95, y: 16 }}
        role="dialog"
        aria-modal="true"
        aria-labelledby="guide-title"
        className="glass-panel rounded-2xl border border-white/10 w-full max-w-xl max-h-[90vh] flex flex-col shadow-glow-strong"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-4 p-5 border-b border-white/5">
          <div className="flex items-start gap-3">
            <ShieldCheck className="w-5 h-5 text-cobalt mt-0.5" />
            <div>
              <h3 id="guide-title" className="text-white font-semibold text-sm">{title}</h3>
              <p className="text-slate/60 text-xs mt-1 leading-relaxed">{body}</p>
            </div>
          </div>
          <div className="flex items-center gap-3 flex-shrink-0">
            <span className={`text-lg font-bold font-mono ${scoreColor(audit?.score ?? 0)}`}>{audit?.score ?? '—'}<span className="text-xs text-slate/40">/100</span></span>
            <button onClick={onClose} aria-label="Close" className="p-1 hover:bg-white/10 rounded-lg transition-colors">
              <X className="w-4 h-4 text-slate/50" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="p-5 space-y-5 overflow-y-auto">
          {toFix.length > 0 && (
            <section className="space-y-2">
              <h4 className="text-[10px] uppercase tracking-wider font-mono text-slate/50">Your next steps</h4>
              {toFix.map((c, i) => (
                <FixCard key={c.id} check={c} defaultOpen={i === 0} onOpenSettings={onOpenSettings} />
              ))}
            </section>
          )}

          {unknown.length > 0 && (
            <section className="space-y-2">
              <h4 className="text-[10px] uppercase tracking-wider font-mono text-slate/50">Couldn't check</h4>
              {unknown.map(c => (
                <div key={c.id} className="flex items-start gap-3 bg-black/20 rounded-lg px-4 py-2.5">
                  <HelpCircle className="w-4 h-4 text-slate/50 mt-0.5 flex-shrink-0" />
                  <div>
                    <div className="text-xs text-white/80">{c.name}</div>
                    <div className="text-[11px] text-slate/50">{c.detail}</div>
                  </div>
                </div>
              ))}
            </section>
          )}

          {good.length > 0 && (
            <section className="space-y-1.5">
              <h4 className="text-[10px] uppercase tracking-wider font-mono text-slate/50">Already good ({good.length})</h4>
              {good.map(c => (
                <div key={c.id} className="flex items-center gap-3 bg-black/20 rounded-lg px-4 py-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="text-xs text-white/80">{c.name}</div>
                    <div className="text-[11px] text-slate/50 truncate">{c.detail}</div>
                  </div>
                  <span className="text-[10px] font-mono text-emerald-400/80 flex-shrink-0">{c.value}</span>
                </div>
              ))}
            </section>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between gap-3 px-5 py-4 border-t border-white/5">
          <p className={`text-[11px] ${error && !rechecking ? 'text-red-400/80' : 'text-slate/40'}`}>
            {error && !rechecking ? error : 'Changed something? Re-check to update your score.'}
          </p>
          <button
            onClick={onRecheck}
            disabled={rechecking}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cobalt text-obsidian text-xs font-semibold hover:bg-cobalt/90 disabled:opacity-60 transition-colors"
          >
            {rechecking ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
            {rechecking ? 'Checking…' : 'Re-check'}
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
}
