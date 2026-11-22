/**
 * FirewallView — AI Lockdown + real network defense status.
 *
 * No hardcoded rule lists. Everything here is real:
 *   • AI Lockdown — when engaged, the backend force-blocks EVERY AI prompt
 *     (verifiable: the AI Monitor and browser extension will block all sends).
 *   • macOS firewall state — reported honestly from the real security audit
 *     (we report the OS firewall; we don't pretend to be it).
 *   • Flagged sources — the real connections the monitor + AbuseIPDB caught
 *     this session.
 *   • Threat intelligence — the live public blocklists every connection is
 *     checked against.
 *   • App connections — which apps use the network and where (per-app baseline).
 */

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Flame, Shield, ShieldOff, CheckCircle2, AlertTriangle, Lock, Database, AppWindow } from 'lucide-react';

const API_BASE = (typeof window !== 'undefined' && window.location.protocol === 'file:')
  ? 'http://localhost:3001/api'
  : '/api';

function timeAgo(ms) {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

// Which apps use the network and where — learned baseline
function AppConnections() {
  const [data, setData] = useState(null);

  useEffect(() => {
    const load = () => fetch(`${API_BASE}/network/apps`).then(r => r.json()).then(setData).catch(() => {});
    load();
    const t = setInterval(load, 30_000);
    return () => clearInterval(t);
  }, []);

  const pct = data ? Math.min(100, Math.round(((Date.now() - data.startedAt) / (data.learningEndsAt - data.startedAt)) * 100)) : 0;

  return (
    <div className="bg-black/30 border border-white/5 rounded-xl p-4">
      <div className="flex items-center justify-between mb-1">
        <p className="text-[10px] uppercase text-slate/40 font-mono flex items-center gap-1.5">
          <AppWindow className="w-3 h-3" /> App Connections
        </p>
        {data && (
          <span className={`text-[10px] font-mono ${data.learning ? 'text-yellow-400/80' : 'text-emerald-400'}`}>
            {data.learning ? `Learning · ${pct}%` : 'Watching for changes'}
          </span>
        )}
      </div>
      <p className="text-[11px] text-slate/40 mb-3">
        {data?.learning
          ? `Alvora is learning where your apps normally connect (done ${new Date(data.learningEndsAt).toLocaleDateString()}). After that it alerts when an app reaches a network it never has. Unsigned programs are flagged right away.`
          : 'Alvora alerts when an app goes online for the first time or reaches a network it has never used.'}
      </p>
      {data?.learning && (
        <div className="h-1 bg-white/10 rounded-full overflow-hidden mb-3">
          <div className="h-full bg-yellow-400/60 rounded-full" style={{ width: `${pct}%` }} />
        </div>
      )}
      {!data ? (
        <p className="text-slate/30 text-xs">Loading…</p>
      ) : data.apps.length === 0 ? (
        <p className="text-slate/30 text-xs">No apps seen on the network yet — first check runs within 30 seconds.</p>
      ) : (
        <div className="space-y-2">
          {data.apps.slice(0, 12).map(a => (
            <div key={a.path} className="flex items-start gap-2">
              <span className={`mt-1.5 w-1.5 h-1.5 rounded-full flex-shrink-0 ${a.signer?.trusted ? 'bg-emerald-400' : a.signer?.status === 'unreadable' ? 'bg-slate/40' : 'bg-orange-400'}`} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs text-white/80 truncate">{a.name}</span>
                  <span className="text-[10px] font-mono text-slate/40 flex-shrink-0">
                    {a.browserLike ? 'many networks' : `${a.networks} network${a.networks === 1 ? '' : 's'}`} · {timeAgo(a.lastSeen)}
                  </span>
                </div>
                <p className="text-[10px] text-slate/40 truncate">
                  {a.signer?.trusted ? (a.signer.name ?? 'Signed') : `Not developer-signed (${a.signer?.status ?? 'unknown'})`}
                  {a.topNetworks?.length ? ` · ${a.topNetworks.slice(0, 3).map(n => n.split(' (')[0]).join(', ')}` : ''}
                </p>
              </div>
            </div>
          ))}
          {data.apps.length > 12 && (
            <p className="text-[10px] text-slate/30">+ {data.apps.length - 12} more apps</p>
          )}
        </div>
      )}
    </div>
  );
}

export default function FirewallView({ lockdownActive, onLockdown, logs }) {
  const [audit, setAudit] = useState(null);
  const [intel, setIntel] = useState(null);
  const [links, setLinks] = useState(null);

  useEffect(() => {
    fetch(`${API_BASE}/security/audit`).then(r => r.json()).then(setAudit).catch(() => {});
    fetch(`${API_BASE}/intel/status`).then(r => r.json()).then(setIntel).catch(() => {});
    fetch(`${API_BASE}/url/status`).then(r => r.json()).then(setLinks).catch(() => {});
  }, []);

  // Real flagged sources from this session's live threat feed
  const flagged = [...new Map(
    logs
      .filter(l => l.severity === 'CRITICAL' || l.severity === 'HIGH')
      .filter(l => l.source && /^\d{1,3}\./.test(l.source))
      .map(l => [l.source, l])
  ).values()].slice(0, 8);

  const osFirewall = audit?.checks?.find(c => c.id === 'firewall');

  return (
    <motion.div
      key="firewall"
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="flex flex-col w-full h-full p-6 gap-5 overflow-y-auto"
    >
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Flame className="w-5 h-5 text-cobalt" />
          <h2 className="text-base font-bold text-white">Network Defense</h2>
        </div>
        <button
          onClick={onLockdown}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl font-semibold text-xs transition-all ${
            lockdownActive
              ? 'bg-red-500/20 text-red-400 border border-red-500/40 hover:bg-red-500/30'
              : 'bg-cobalt/10 text-cobalt border border-cobalt/30 hover:bg-cobalt/20'
          }`}
        >
          {lockdownActive ? <ShieldOff className="w-4 h-4" /> : <Shield className="w-4 h-4" />}
          {lockdownActive ? 'Disengage AI Lockdown' : 'Engage AI Lockdown'}
        </button>
      </div>

      {/* AI Lockdown — the real, central control */}
      <div className={`rounded-xl p-5 border transition-colors ${
        lockdownActive ? 'bg-red-500/10 border-red-500/30' : 'bg-black/30 border-white/5'
      }`}>
        <div className="flex items-center gap-2 mb-2">
          <Lock className={`w-4 h-4 ${lockdownActive ? 'text-red-400' : 'text-cobalt'}`} />
          <h3 className="text-sm font-semibold text-white">AI Lockdown</h3>
          <span className={`ml-auto text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
            lockdownActive ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/15 text-emerald-400'
          }`}>{lockdownActive ? 'ACTIVE' : 'STANDBY'}</span>
        </div>
        <p className="text-xs text-slate/60 leading-relaxed">
          {lockdownActive
            ? 'Every prompt is being blocked before it reaches any AI model — across the AI Monitor and the browser extension. Nothing you or your apps type can leave for an AI until you disengage.'
            : 'When engaged, Alvora blocks every prompt to every AI model — total stop, regardless of content. Use it when you need a guarantee that nothing leaves for an AI.'}
        </p>
      </div>

      {/* Real macOS firewall status (reported, not faked) */}
      <div className="bg-black/30 border border-white/5 rounded-xl p-4">
        <p className="text-[10px] uppercase text-slate/40 font-mono mb-3">Your Mac's Built-in Firewall</p>
        {!osFirewall ? (
          <p className="text-slate/30 text-xs">Checking…</p>
        ) : (
          <div className="flex items-start gap-2">
            {osFirewall.status === 'pass'
              ? <CheckCircle2 className="w-4 h-4 text-emerald-400 mt-0.5 flex-shrink-0" />
              : <AlertTriangle className="w-4 h-4 text-yellow-400 mt-0.5 flex-shrink-0" />}
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm text-white/80">macOS Application Firewall</span>
                <span className={`text-[10px] font-mono font-bold ${osFirewall.status === 'pass' ? 'text-emerald-400' : 'text-yellow-400'}`}>
                  {osFirewall.value}
                </span>
              </div>
              <p className="text-[11px] text-slate/40 mt-0.5">{osFirewall.detail}</p>
              {osFirewall.fix && (
                <p className="text-[11px] text-cobalt/60 mt-1">How to turn it on: {osFirewall.fix}</p>
              )}
            </div>
          </div>
        )}
      </div>

      <AppConnections />

      {/* Live threat-intelligence feeds */}
      <div className="bg-black/30 border border-white/5 rounded-xl p-4">
        <div className="flex items-center justify-between mb-3">
          <p className="text-[10px] uppercase text-slate/40 font-mono flex items-center gap-1.5">
            <Database className="w-3 h-3" /> Threat Intelligence
          </p>
          {intel && (
            <span className="text-[10px] font-mono text-cobalt/70">
              {intel.totalEntries.toLocaleString()} known-bad addresses
            </span>
          )}
        </div>
        <p className="text-[11px] text-slate/40 mb-3">
          Every connection your Mac makes is checked against these public blocklists, refreshed daily.
        </p>
        {!intel ? (
          <p className="text-slate/30 text-xs">Loading feeds…</p>
        ) : (
          <div className="space-y-1.5">
            {intel.feeds.map(f => (
              <div key={f.id} className="flex items-center gap-2 text-[11px]">
                <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${f.entries ? 'bg-emerald-400' : 'bg-red-400'}`} />
                <span className="text-white/70 flex-1">{f.name}</span>
                <span className="font-mono text-slate/40">{f.entries.toLocaleString()}</span>
                <span className="font-mono text-slate/30 w-24 text-right">
                  {f.error && !f.entries ? 'unavailable' : f.updatedAt ? new Date(f.updatedAt).toLocaleDateString() : '—'}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Browser Link Guard feeds (used by the extension) */}
      <div className="bg-black/30 border border-white/5 rounded-xl p-4">
        <div className="flex items-center justify-between mb-3">
          <p className="text-[10px] uppercase text-slate/40 font-mono flex items-center gap-1.5">
            <Shield className="w-3 h-3" /> Browser Link Guard
          </p>
          {links && (
            <span className="text-[10px] font-mono text-cobalt/70">
              {links.feeds.filter(f => f.kind !== 'popular').reduce((n, f) => n + f.entries, 0).toLocaleString()} phishing entries
            </span>
          )}
        </div>
        <p className="text-[11px] text-slate/40 mb-3">
          With the Alvora browser extension, every page you open is checked against these lists on this Mac — the address never leaves it.
          Known phishing sites are replaced by a warning page. Popular sites are never blocked by domain lists alone.
        </p>
        {!links ? (
          <p className="text-slate/30 text-xs">Loading feeds…</p>
        ) : (
          <div className="space-y-1.5">
            {links.feeds.map(f => (
              <div key={f.id} className="flex items-center gap-2 text-[11px]">
                <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${f.entries ? 'bg-emerald-400' : 'bg-red-400'}`} />
                <span className="text-white/70 flex-1">{f.name}</span>
                <span className="font-mono text-slate/40">{f.entries.toLocaleString()}</span>
                <span className="font-mono text-slate/30 w-24 text-right">
                  {f.error && !f.entries ? 'unavailable' : f.updatedAt ? new Date(f.updatedAt).toLocaleDateString() : '—'}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Real flagged sources this session */}
      <div className="bg-black/30 border border-white/5 rounded-xl p-4">
        <p className="text-[10px] uppercase text-slate/40 font-mono mb-3">
          Flagged Connections (this session)
        </p>
        {flagged.length === 0 ? (
          <p className="text-slate/30 text-xs">No high-risk connections caught yet — your traffic looks clean.</p>
        ) : (
          <div className="space-y-2">
            {flagged.map(l => (
              <div key={l.source} className="flex items-center gap-3">
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${l.severity === 'CRITICAL' ? 'bg-red-500' : 'bg-orange-400'}`} />
                <span className="text-xs font-mono text-white/70">{l.source}</span>
                <span className="text-[11px] text-slate/50 flex-1 truncate">{l.type}</span>
                <span className={`text-[10px] font-mono ${['BLOCKED', 'ALERT'].includes(l.action) ? 'text-red-400' : 'text-yellow-400'}`}>{l.action}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </motion.div>
  );
}
