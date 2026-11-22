/**
 * KernelMonitor → "System Health" — real device security checks.
 *
 * Replaces the old hardcoded kext list / fake "attack vectors" with the
 * genuine macOS security audit (FileVault, Firewall, Gatekeeper, SIP, etc.)
 * pulled live from /api/security/audit, plus real CPU/memory readings, and
 * every startup item (LaunchAgents/Daemons, cron) with who signed it.
 */

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Cpu, Activity, Lock, AlertTriangle, CheckCircle2, ShieldCheck, ShieldAlert, Power, Download, FolderOpen, Trash2 } from 'lucide-react';
import { useElectron } from '../hooks/useElectron.js';

const API_BASE = (typeof window !== 'undefined' && window.location.protocol === 'file:')
  ? 'http://localhost:3001/api'
  : '/api';

const STATUS_STYLE = {
  pass: { dot: 'bg-emerald-400', text: 'text-emerald-400', Icon: CheckCircle2 },
  warn: { dot: 'bg-yellow-400',  text: 'text-yellow-400',  Icon: AlertTriangle },
  fail: { dot: 'bg-red-400',     text: 'text-red-400',     Icon: ShieldAlert },
  unknown: { dot: 'bg-slate/40', text: 'text-slate/50',    Icon: AlertTriangle },
};

const RISK_STYLE = {
  CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/30',
  HIGH:     'text-orange-400 bg-orange-500/10 border-orange-500/30',
  MEDIUM:   'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
  LOW:      'text-slate/60 bg-white/5 border-white/10',
  OK:       'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
};

const SIGNER_LABEL = {
  'apple':        'Apple',
  'developer-id': 'Verified developer',
  'app-store':    'App Store',
  'adhoc':        'Unsigned (ad-hoc)',
  'unsigned':     'Unsigned',
  'invalid':      'Broken signature',
  'missing':      'Program missing',
  'unreadable':   'Admin-only (not checked)',
};

// Everything set to launch automatically — riskiest first
function StartupItems() {
  const [inv, setInv] = useState(null);

  useEffect(() => {
    fetch(`${API_BASE}/persistence`).then(r => r.json()).then(setInv).catch(() => setInv(null));
  }, []);

  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, OK: 4 };
  const items = [...(inv?.items ?? [])].sort((a, b) => order[a.risk] - order[b.risk]);
  const risky = items.filter(i => order[i.risk] <= order.MEDIUM).length;

  return (
    <div className="bg-black/30 border border-white/5 rounded-xl p-4">
      <div className="flex items-center justify-between mb-1">
        <p className="text-[10px] uppercase text-slate/40 font-mono flex items-center gap-1.5">
          <Power className="w-3 h-3" /> Startup Items
        </p>
        {inv && (
          <span className={`text-[10px] font-mono ${risky ? 'text-orange-400' : 'text-emerald-400'}`}>
            {items.length} items · {risky ? `${risky} need a look` : 'none suspicious'}
          </span>
        )}
      </div>
      <p className="text-[10px] text-slate/40 mb-3">
        Programs set to run automatically. Malware almost always hides here — Alvora alerts you the moment anything new appears.
      </p>
      {!inv ? (
        <p className="text-slate/30 text-xs">Checking startup items…</p>
      ) : items.length === 0 ? (
        <p className="text-slate/30 text-xs">No startup items found.</p>
      ) : (
        <div className="space-y-2">
          {items.map(item => (
            <div key={item.id} className="flex items-start gap-2">
              <span className={`text-[9px] font-mono font-bold border rounded px-1.5 py-0.5 flex-shrink-0 ${RISK_STYLE[item.risk]}`}>
                {item.risk}
              </span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs text-white/80 truncate">{item.label}</span>
                  <span className="text-[10px] text-slate/40 flex-shrink-0">{SIGNER_LABEL[item.signer?.status] ?? '—'}</span>
                </div>
                <p className="text-[10px] text-slate/40 truncate">
                  {item.scope}{item.signer?.name ? ` · ${item.signer.name}` : ''}
                </p>
                {item.reasons?.length > 0 && item.risk !== 'OK' && (
                  <p className="text-[10px] text-slate/50 mt-0.5">{item.reasons.join(' ')}</p>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

const VERDICT_STYLE = {
  dangerous: { label: 'Dangerous', cls: 'text-red-400 bg-red-500/10 border-red-500/30' },
  caution:   { label: 'Caution',   cls: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30' },
  clean:     { label: 'Safe',      cls: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' },
};

function hostOf(u) { try { return new URL(u).hostname; } catch { return null; } }

// Every new download, checked the moment it finishes
function DownloadsPanel() {
  const { isElectron, revealDownload, trashDownload } = useElectron();
  const [state, setState] = useState(null);
  const [msg, setMsg] = useState('');

  const load = () => fetch(`${API_BASE}/downloads`).then(r => r.json()).then(setState).catch(() => setState(null));
  useEffect(() => { load(); const t = setInterval(load, 10_000); return () => clearInterval(t); }, []);

  async function trash(r) {
    if (!window.confirm(`Move "${r.name}" to the Trash?`)) return;
    const res = await trashDownload(r.path);
    setMsg(res?.error ?? `Moved "${r.name}" to the Trash.`);
    load();
  }

  const needsPermission = state?.dirs?.some(d => d.state === 'needs-permission');
  const results = state?.results ?? [];
  const dangerous = results.filter(r => r.verdict === 'dangerous').length;

  return (
    <div className="bg-black/30 border border-white/5 rounded-xl p-4">
      <div className="flex items-center justify-between mb-1">
        <p className="text-[10px] uppercase text-slate/40 font-mono flex items-center gap-1.5">
          <Download className="w-3 h-3" /> Downloads
        </p>
        {state && !needsPermission && (
          <span className={`text-[10px] font-mono ${dangerous ? 'text-red-400' : 'text-emerald-400'}`}>
            {state.scanning ? 'Scanning…' : `${results.length} checked · ${dangerous ? `${dangerous} dangerous` : 'none dangerous'}`}
          </span>
        )}
      </div>
      <p className="text-[10px] text-slate/40 mb-3">
        New files in Downloads are checked on this Mac as soon as they finish: where they came from, what they really are, whether Apple trusts them, and what scripts inside would do.
      </p>

      {needsPermission && (
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3 mb-3">
          <p className="text-xs text-yellow-300 font-semibold mb-1">Alvora needs permission to see your Downloads folder</p>
          <p className="text-[10px] text-slate/50">
            Open System Settings → Privacy &amp; Security → Files and Folders → Alvora Cyber and turn on “Downloads Folder”, then restart Alvora.
          </p>
        </div>
      )}

      {!state ? (
        <p className="text-slate/30 text-xs">Loading…</p>
      ) : results.length === 0 && !needsPermission ? (
        <p className="text-slate/30 text-xs">No recent downloads yet — new ones will appear here automatically.</p>
      ) : (
        <div className="space-y-2.5">
          {results.slice(0, 15).map(r => {
            const v = VERDICT_STYLE[r.verdict] ?? VERDICT_STYLE.caution;
            const issues = r.findings.filter(f => f.severity !== 'OK');
            const from = hostOf(r.origin?.url) ?? hostOf(r.origin?.referrer);
            return (
              <div key={r.path} className="flex items-start gap-2">
                <span className={`text-[9px] font-mono font-bold border rounded px-1.5 py-0.5 flex-shrink-0 ${v.cls}`}>{v.label}</span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs text-white/80 truncate">{r.name}</span>
                    {isElectron && (
                      <span className="flex items-center gap-1 flex-shrink-0">
                        <button title="Show in Finder" onClick={() => revealDownload(r.path)} className="p-1 text-slate/40 hover:text-cobalt">
                          <FolderOpen className="w-3 h-3" />
                        </button>
                        {r.verdict !== 'clean' && (
                          <button title="Move to Trash" onClick={() => trash(r)} className="p-1 text-slate/40 hover:text-red-400">
                            <Trash2 className="w-3 h-3" />
                          </button>
                        )}
                      </span>
                    )}
                  </div>
                  <p className="text-[10px] text-slate/40 truncate">
                    {from ? `From ${from}` : 'Origin not recorded'}{r.findings.find(f => f.severity === 'OK') ? ` · ${r.findings.find(f => f.severity === 'OK').title}` : ''}
                  </p>
                  {issues.slice(0, 2).map((f, i) => (
                    <p key={i} className="text-[10px] text-slate/60 mt-0.5"><span className="text-white/70">{f.title}.</span> {f.detail}</p>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}
      {msg && <p className="text-[10px] text-cobalt/70 mt-2">{msg}</p>}
      {state && !state.abuseChKey && (
        <p className="text-[10px] text-slate/30 mt-3">Tip: add a free abuse.ch key in Settings to also check programs against the MalwareBazaar malware database.</p>
      )}
    </div>
  );
}

export default function KernelMonitor({ systemStats, logs }) {
  const [audit, setAudit] = useState(null);

  useEffect(() => {
    fetch(`${API_BASE}/security/audit`)
      .then(r => r.json())
      .then(setAudit)
      .catch(() => setAudit(null));
  }, []);

  const critCount = logs.filter(l => l.severity === 'CRITICAL').length;
  const highCount = logs.filter(l => l.severity === 'HIGH').length;

  const usePct  = systemStats.memStats?.usePct != null ? Math.round(systemStats.memStats.usePct) : null;
  const cpuLoad = systemStats.cpuLoad?.currentLoad != null ? Math.round(systemStats.cpuLoad.currentLoad) : null;
  const score   = audit?.score ?? null;

  return (
    <motion.div
      key="kernel"
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="flex flex-col w-full h-full p-6 gap-5 overflow-y-auto"
    >
      <div className="flex items-center gap-2">
        <ShieldCheck className="w-5 h-5 text-cobalt" />
        <h2 className="text-base font-bold text-white">System Health</h2>
        <span className="text-[10px] font-mono text-slate/40 ml-2">Live checks on this device</span>
      </div>

      {/* Real metric cards */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'Processor Use', value: cpuLoad != null ? `${cpuLoad}%` : '—',
            color: cpuLoad > 80 ? 'text-red-400' : cpuLoad > 50 ? 'text-yellow-400' : 'text-cobalt', icon: Activity },
          { label: 'Memory Use', value: usePct != null ? `${usePct}%` : '—',
            color: usePct > 85 ? 'text-red-400' : 'text-cobalt', icon: Cpu },
          { label: 'Security Score', value: score != null ? `${score}/100` : '—',
            color: score >= 80 ? 'text-emerald-400' : score >= 55 ? 'text-yellow-400' : 'text-red-400', icon: Lock },
        ].map(({ label, value, color, icon: Icon }) => (
          <div key={label} className="bg-black/30 border border-white/5 rounded-xl p-4">
            <div className="flex items-center gap-1 mb-2">
              <Icon className="w-3.5 h-3.5 text-slate/40" />
              <span className="text-[10px] text-slate/40 uppercase font-mono">{label}</span>
            </div>
            <p className={`text-2xl font-bold ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      {/* Real security checks */}
      <div className="bg-black/30 border border-white/5 rounded-xl p-4">
        <p className="text-[10px] uppercase text-slate/40 font-mono mb-3">Your Device's Security Settings</p>
        {!audit ? (
          <p className="text-slate/30 text-xs">Checking your device…</p>
        ) : (
          <div className="space-y-3">
            {audit.checks.map((c, i) => {
              const st = STATUS_STYLE[c.status] ?? STATUS_STYLE.warn;
              return (
                <motion.div
                  key={c.id}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.04 }}
                  className="flex items-start gap-2"
                >
                  <span className={`mt-1.5 w-2 h-2 rounded-full flex-shrink-0 ${st.dot}`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs text-white/80">{c.name}</span>
                      <span className={`text-[10px] font-mono font-bold flex-shrink-0 ${st.text}`}>{c.value}</span>
                    </div>
                    <p className="text-[10px] text-slate/40 mt-0.5">{c.detail}</p>
                    {c.fix && (
                      <p className="text-[10px] text-cobalt/60 mt-0.5">How to fix: {c.fix}</p>
                    )}
                  </div>
                </motion.div>
              );
            })}
          </div>
        )}
      </div>

      <DownloadsPanel />

      <StartupItems />

      {/* Real threat summary this session */}
      {(critCount > 0 || highCount > 0) && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            <span className="text-xs text-red-400 font-semibold">Threats Caught This Session</span>
          </div>
          <div className="flex gap-4 text-sm font-mono">
            <span className="text-red-400">{critCount} serious</span>
            <span className="text-orange-400">{highCount} high</span>
          </div>
        </div>
      )}
    </motion.div>
  );
}
