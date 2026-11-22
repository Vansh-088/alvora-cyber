/**
 * Reports — Security session summary and export
 */

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { FileBarChart, Download, Shield, AlertTriangle, CheckCircle2, Activity } from 'lucide-react';
import { useElectron } from '../hooks/useElectron.js';

const API_BASE = (typeof window !== 'undefined' && window.location.protocol === 'file:')
  ? 'http://localhost:3001/api'
  : '/api';

function StatCard({ label, value, color, icon: Icon }) {
  return (
    <div className="bg-black/30 border border-white/5 rounded-xl p-4 flex items-center gap-3">
      <div className={`p-2 rounded-lg ${color.bg}`}>
        <Icon className={`w-5 h-5 ${color.icon}`} />
      </div>
      <div>
        <motion.p
          key={value}
          initial={{ opacity: 0, y: -4 }}
          animate={{ opacity: 1, y: 0 }}
          className={`text-2xl font-bold ${color.text}`}
        >
          {value}
        </motion.p>
        <p className="text-[10px] text-slate/40 uppercase font-mono">{label}</p>
      </div>
    </div>
  );
}

export default function Reports({ logs, scanHistory }) {
  const [exporting, setExporting] = useState(false);
  const [stats,     setStats]     = useState(null);   // persisted DB stats
  const { exportReport } = useElectron();

  // Pull all-time persisted stats from SQLite (survives restarts). Refresh on mount
  // and whenever new events arrive this session.
  useEffect(() => {
    fetch(`${API_BASE}/threats/stats`)
      .then(r => r.json())
      .then(setStats)
      .catch(() => setStats(null));
  }, [logs.length, scanHistory.length]);

  // All-time totals from the database (fall back to 0 while loading)
  const totalThreats = stats?.threats?.total    ?? 0;
  const blocked      = stats?.threats?.blocked  ?? 0;
  const critical     = stats?.threats?.critical ?? 0;
  const aiScans      = stats?.scans?.total      ?? 0;
  const aiBlocked    = stats?.scans?.blocked    ?? 0;
  const piiDetected  = stats?.scans?.piiTotal   ?? 0;
  const injections   = scanHistory.filter(s => s.injection?.threats?.length > 0).length;

  // Top threat types / sources straight from the DB aggregation
  const topThreats = (stats?.topThreatTypes ?? []).map(t => [t.type, t.count]);
  const topIPs     = (stats?.topSources ?? []).map(s => [s.source, s.count]);

  async function handleExport() {
    setExporting(true);
    try {
      const report = {
        generatedAt:   new Date().toISOString(),
        version:       '1.0.0',
        allTimeSummary: { totalThreats, blocked, critical, aiScans, aiBlocked, piiDetected, injections },
        topThreatTypes: topThreats,
        topSources:     topIPs,
        recentThreats:  logs,
        recentScans:    scanHistory,
      };
      await exportReport(report);
    } finally {
      setExporting(false);
    }
  }

  return (
    <motion.div
      key="reports"
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="flex flex-col w-full h-full p-6 gap-5 overflow-y-auto"
    >
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FileBarChart className="w-5 h-5 text-cobalt" />
          <h2 className="text-base font-bold text-white">Security Reports</h2>
        </div>
        <button
          onClick={handleExport}
          disabled={exporting}
          className="flex items-center gap-2 px-4 py-2 bg-cobalt text-obsidian font-semibold text-xs rounded-xl hover:bg-cobalt/90 disabled:opacity-50 transition-all"
        >
          <Download className="w-4 h-4" />
          {exporting ? 'Exporting…' : 'Export Report'}
        </button>
      </div>

      {/* Network stats */}
      <div>
        <p className="text-[10px] uppercase text-slate/40 font-mono mb-3">Network &amp; Device Threats (all time)</p>
        <div className="grid grid-cols-2 gap-3">
          <StatCard label="Total Detected" value={totalThreats} icon={Activity}
            color={{ bg: 'bg-cobalt/10', icon: 'text-cobalt', text: 'text-cobalt' }} />
          <StatCard label="Needed Attention" value={blocked} icon={Shield}
            color={{ bg: 'bg-emerald-500/10', icon: 'text-emerald-400', text: 'text-emerald-400' }} />
          <StatCard label="Serious" value={critical} icon={AlertTriangle}
            color={{ bg: 'bg-red-500/10', icon: 'text-red-400', text: 'text-red-400' }} />
          <StatCard label="Attention Rate" value={totalThreats > 0 ? `${Math.round((blocked / totalThreats) * 100)}%` : '—'} icon={CheckCircle2}
            color={{ bg: 'bg-blue-500/10', icon: 'text-blue-400', text: 'text-blue-400' }} />
        </div>
      </div>

      {/* AI scan stats */}
      <div>
        <p className="text-[10px] uppercase text-slate/40 font-mono mb-3">AI Prompts Checked (all time)</p>
        <div className="grid grid-cols-2 gap-3">
          <StatCard label="Prompts Scanned" value={aiScans} icon={Activity}
            color={{ bg: 'bg-cobalt/10', icon: 'text-cobalt', text: 'text-cobalt' }} />
          <StatCard label="Blocked" value={aiBlocked} icon={Shield}
            color={{ bg: 'bg-red-500/10', icon: 'text-red-400', text: 'text-red-400' }} />
          <StatCard label="Personal Info Caught" value={piiDetected} icon={AlertTriangle}
            color={{ bg: 'bg-orange-500/10', icon: 'text-orange-400', text: 'text-orange-400' }} />
          <StatCard label="Hijack Attempts" value={injections} icon={AlertTriangle}
            color={{ bg: 'bg-yellow-500/10', icon: 'text-yellow-400', text: 'text-yellow-400' }} />
        </div>
      </div>

      {/* Top threats + IPs side by side */}
      <div className="grid grid-cols-2 gap-4">
        {/* Top threat types */}
        <div className="bg-black/30 border border-white/5 rounded-xl p-4">
          <p className="text-[10px] uppercase text-slate/40 font-mono mb-3">Top Threat Types</p>
          <div className="space-y-2">
            {topThreats.length === 0 ? (
              <p className="text-slate/30 text-xs">No data yet</p>
            ) : topThreats.map(([type, count], i) => (
              <div key={type} className="flex items-center gap-2">
                <span className="text-[10px] font-mono text-slate/40 w-4">{i + 1}.</span>
                <div className="flex-1 min-w-0">
                  <div className="flex justify-between text-xs mb-0.5">
                    <span className="text-white/70 truncate">{type}</span>
                    <span className="text-cobalt font-mono ml-2 flex-shrink-0">{count}</span>
                  </div>
                  <div className="h-1 bg-white/10 rounded-full overflow-hidden">
                    <div className="h-full bg-cobalt/50 rounded-full" style={{ width: `${(count / (topThreats[0]?.[1] ?? 1)) * 100}%` }} />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Top source IPs */}
        <div className="bg-black/30 border border-white/5 rounded-xl p-4">
          <p className="text-[10px] uppercase text-slate/40 font-mono mb-3">Where Threats Came From</p>
          <div className="space-y-2">
            {topIPs.length === 0 ? (
              <p className="text-slate/30 text-xs">No data yet</p>
            ) : topIPs.map(([ip, count], i) => (
              <div key={ip} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-slate/40">{i + 1}.</span>
                  <span className="text-xs font-mono text-white/70">{ip}</span>
                </div>
                <span className="text-[10px] font-mono text-red-400">{count}×</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Persistence note */}
      <div className="bg-cobalt/5 border border-cobalt/20 rounded-xl p-4">
        <p className="text-xs text-cobalt/60">
          These numbers are saved permanently on your device and build up over time — they don't reset when you
          close the app. Export as a file anytime to keep a copy or share it.
        </p>
      </div>
    </motion.div>
  );
}
