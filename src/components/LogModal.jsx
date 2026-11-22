/**
 * LogModal — Detailed threat event inspector with on-demand AI explanation
 */

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { X, Shield, Cpu, Sparkles, Loader2, Trash2, BadgeCheck } from 'lucide-react';

const API_BASE = (typeof window !== 'undefined' && window.location.protocol === 'file:')
  ? 'http://localhost:3001/api'
  : '/api';

const VERDICT_STYLE = {
  likely_safe:      { label: 'Probably fine',     cls: 'text-emerald-400' },
  worth_checking:   { label: 'Worth checking',    cls: 'text-yellow-400'  },
  likely_malicious: { label: 'Likely malicious',  cls: 'text-red-400'     },
};

// Asks the backend's deep AI tier (NVIDIA Nemotron Ultra when configured)
// to explain this event in plain English.
function ExplainPanel({ log }) {
  const [state, setState] = useState({ status: 'idle' });

  async function explain() {
    setState({ status: 'loading' });
    try {
      const res  = await fetch(`${API_BASE}/ai/explain`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ event: log }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Explanation failed');
      setState({ status: 'done', data });
    } catch (e) {
      setState({ status: 'error', error: e.message });
    }
  }

  if (state.status === 'idle' || state.status === 'error') {
    return (
      <div>
        <button
          onClick={explain}
          className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg border border-cobalt/30 text-cobalt text-xs hover:bg-cobalt/10 transition-colors"
        >
          <Sparkles className="w-3.5 h-3.5" /> Explain this with AI
        </button>
        {state.error && <p className="text-[10px] text-red-400/80 mt-1.5">{state.error}</p>}
      </div>
    );
  }

  if (state.status === 'loading') {
    return (
      <div className="flex items-center gap-2 text-xs text-slate/50 bg-black/30 rounded-lg px-4 py-3">
        <Loader2 className="w-3.5 h-3.5 animate-spin" /> Analyzing… large models can take up to a minute.
      </div>
    );
  }

  const { data } = state;
  const verdict = VERDICT_STYLE[data.verdict] ?? VERDICT_STYLE.worth_checking;
  return (
    <div className="bg-black/30 rounded-lg px-4 py-3 space-y-2">
      <div className="flex items-center justify-between">
        <span className={`text-xs font-semibold ${verdict.cls}`}>{verdict.label}</span>
        <span className="text-[9px] text-slate/30 font-mono truncate ml-2">{data.model} · {(data.ms / 1000).toFixed(1)}s</span>
      </div>
      <p className="text-white/80 text-xs">{data.summary}</p>
      {data.likelyCause && <p className="text-white/50 text-xs"><span className="text-slate/40">Likely cause: </span>{data.likelyCause}</p>}
      {data.steps?.length > 0 && (
        <ol className="list-decimal list-inside text-xs text-white/70 space-y-0.5">
          {data.steps.map((s, i) => <li key={i}>{s}</li>)}
        </ol>
      )}
    </div>
  );
}

// "This was fine" controls. Trusting is offered only where Alvora made a
// judgement call (an app's behaviour, or community reputation of an address) —
// never for known-malware threat-intel hits.
function AlertActions({ log, onDismiss, onTrust, onClose }) {
  const [busy, setBusy] = useState(null);
  const [msg,  setMsg]  = useState('');
  const canTrust = !!log.appPath || String(log.id).startsWith('REP-');
  const what     = log.appPath ? (log.app || log.appPath.split('/').pop().replace(/\.app$/, '')) : log.source;

  async function trust() {
    setBusy('trust');
    const res = await onTrust(log);
    setBusy(null);
    if (res?.success) onClose();
    else setMsg(res?.error || 'Couldn\'t save that — try again.');
  }
  async function dismiss() {
    setBusy('dismiss');
    await onDismiss(log.id);
    onClose();
  }

  return (
    <div className="border-t border-white/5 pt-4 space-y-2">
      <p className="text-[11px] text-slate/50">Know what this is and it's fine?</p>
      <div className="flex gap-2">
        {canTrust && (
          <button
            onClick={trust}
            disabled={!!busy}
            className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg border border-emerald-400/30 text-emerald-400 text-xs hover:bg-emerald-400/10 disabled:opacity-50 transition-colors"
          >
            {busy === 'trust' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <BadgeCheck className="w-3.5 h-3.5" />}
            Trust {what ? `"${what}"` : 'this'} — stop alerting
          </button>
        )}
        <button
          onClick={dismiss}
          disabled={!!busy}
          className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg border border-white/10 text-slate/70 text-xs hover:bg-white/5 disabled:opacity-50 transition-colors"
        >
          {busy === 'dismiss' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
          Dismiss this alert
        </button>
      </div>
      {msg && <p className="text-[10px] text-red-400/80">{msg}</p>}
    </div>
  );
}

export default function LogModal({ log, onClose, onDismiss, onTrust }) {
  if (!log) return null;
  const isAlert = !String(log.id).startsWith('ACT-') && onDismiss;

  const sevColor = {
    CRITICAL: 'text-red-400 border-red-500/40 bg-red-500/10',
    HIGH:     'text-orange-400 border-orange-500/40 bg-orange-500/10',
    MEDIUM:   'text-yellow-400 border-yellow-500/40 bg-yellow-500/10',
    LOW:      'text-emerald-400 border-emerald-500/40 bg-emerald-500/10',
  }[log.severity] ?? 'text-slate/60 border-white/10 bg-white/5';

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-black/60 backdrop-blur-sm"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.9, y: 20 }}
        animate={{ scale: 1, y: 0 }}
        exit={{ scale: 0.9, y: 20 }}
        className="glass-panel rounded-2xl border border-white/10 w-full max-w-lg max-h-[90vh] overflow-y-auto shadow-glow-strong"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-white/5">
          <div className="flex items-center gap-3">
            <Shield className="w-5 h-5 text-cobalt" />
            <div>
              <h3 className="text-white font-semibold text-sm">{log.type}</h3>
              <p className="text-slate/40 text-xs font-mono">{log.id}</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className={`text-xs font-bold font-mono border rounded px-2 py-0.5 ${sevColor}`}>{log.severity}</span>
            <button onClick={onClose} className="p-1 hover:bg-white/10 rounded-lg transition-colors">
              <X className="w-4 h-4 text-slate/50" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="p-5 space-y-4">
          {/* Core facts */}
          <div className="grid grid-cols-2 gap-3 text-xs font-mono">
            {[
              ['Source IP',  log.source],
              ['Port',       log.port],
              ['Protocol',   log.details?.protocol],
              ['Action',     log.action],
              ['Timestamp',  log.timestamp],
              ['Payload',    log.details?.payloadSize],
              ['MAC',        log.details?.mac],
              ['Signature',  log.details?.signature],
            ].map(([k, v]) => (
              <div key={k} className="bg-black/30 rounded-lg px-3 py-2">
                <div className="text-slate/40 text-[9px] uppercase">{k}</div>
                <div className="text-white/80 mt-0.5 truncate">{v ?? '—'}</div>
              </div>
            ))}
          </div>

          {/* Engine that made the call (rules or a named AI model) */}
          {log.engine && (
            <div className="bg-cobalt/5 border border-cobalt/20 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-3">
                <Cpu className="w-4 h-4 text-cobalt" />
                <span className="text-cobalt text-xs font-bold font-mono uppercase tracking-wide">{log.engine.name}</span>
              </div>
              <div className="grid grid-cols-2 gap-2 text-xs font-mono mb-3">
                <div>
                  <div className="text-slate/40 text-[9px]">MODEL</div>
                  <div className="text-white/70 truncate">{log.engine.model ?? 'Rule engine'}</div>
                </div>
                <div>
                  <div className="text-slate/40 text-[9px]">CONFIDENCE</div>
                  <div className="text-white/70">{Math.round((log.engine.confidence ?? 0) * 100)}%</div>
                </div>
              </div>
              {log.detail && <p className="text-white/60 text-xs">{log.detail}</p>}
            </div>
          )}

          {/* On-demand deep explanation */}
          {log.severity !== 'INFO' && <ExplainPanel log={log} />}

          {/* Resolution */}
          {log.details?.resolution && (
            <div className="bg-black/30 rounded-lg px-4 py-3">
              <div className="text-slate/40 text-[9px] uppercase font-mono mb-1">Resolution</div>
              <p className="text-white/70 text-xs">{log.details.resolution}</p>
            </div>
          )}

          {isAlert && <AlertActions log={log} onDismiss={onDismiss} onTrust={onTrust} onClose={onClose} />}
        </div>
      </motion.div>
    </motion.div>
  );
}
