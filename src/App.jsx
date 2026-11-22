/**
 * Alvora Cyber — Main Application
 *
 * Root router. Handles:
 *   1. License gate (LicenseActivation screen before anything else)
 *   2. Main dashboard with all panels
 *   3. Electron IPC bridge (tray navigation, native notifications)
 *   4. Critical threat alerts + screen flash
 *   5. Hardening state machine
 */

import React, { useState, useEffect, useRef } from 'react';
import { AnimatePresence, motion } from 'framer-motion';

// ── Screens ──────────────────────────────────────────────────────────────────
import AIMonitor         from './screens/AIMonitor.jsx';
import BetaWelcome       from './screens/BetaWelcome.jsx';
import AlvoraAI          from './screens/AlvoraAI.jsx';

// ── Components ───────────────────────────────────────────────────────────────
import Sidebar          from './components/Sidebar.jsx';
import ShieldDashboard  from './components/ShieldDashboard.jsx';
import LiveLogFeed      from './components/LiveLogFeed.jsx';
import VaultView        from './components/VaultView.jsx';
import ThreatMap        from './components/ThreatMap.jsx';
import KernelMonitor    from './components/KernelMonitor.jsx';
import FirewallView     from './components/FirewallView.jsx';
import CriticalAlert    from './components/CriticalAlert.jsx';
import ParticleBackground from './components/ParticleBackground.jsx';
import SettingsPanel    from './components/SettingsPanel.jsx';
import Reports          from './components/Reports.jsx';
import SecurityGuide    from './components/SecurityGuide.jsx';

// ── Hooks ────────────────────────────────────────────────────────────────────
import { useSecurity }  from './hooks/useSecurity.js';
import { useElectron }  from './hooks/useElectron.js';

// ─── Main Dashboard ───────────────────────────────────────────────────────────

function Dashboard({ licenseInfo, onDeactivate }) {
  const [activeTab, setActiveTab] = useState('dashboard');

  const {
    systemStats, logs, scanHistory,
    lockdownActive, backendConnected,
    rescanSystem, toggleLockdown, scanText,
    dismissLog, trustFromLog, clearAlertHistory, clearScanHistory,
  } = useSecurity();

  const {
    sendNotification, onNavigate, isElectron,
    minimizeWindow, maximizeWindow, closeWindow,
    openSystemSettings,
  } = useElectron();

  // Hardening state machine
  const [isHardening,       setIsHardening]       = useState(false);
  const [hardeningProgress, setHardeningProgress] = useState(0);
  const [isSecured,         setIsSecured]         = useState(false);
  const [hardeningMetrics,  setHardeningMetrics]  = useState(null);
  const [securityScore,     setSecurityScore]     = useState(null);
  const [audit,             setAudit]             = useState(null);   // full check results for the fix guide
  const [guideOpen,         setGuideOpen]         = useState(false);
  const [checkError,        setCheckError]        = useState(null);

  // Establish a real, stable posture on mount from the actual security audit
  // (so the dashboard settles to a genuine state instead of looping "ANALYZING").
  useEffect(() => {
    const apiBase = window.location.protocol === 'file:' ? 'http://localhost:3001/api' : '/api';
    fetch(`${apiBase}/security/audit`)
      .then(r => r.json())
      .then(a => {
        if (!Array.isArray(a?.checks)) return;
        setAudit(a);
        setSecurityScore(a.score ?? null);
        if (typeof a.score === 'number') setIsSecured(a.score >= 70);
      })
      .catch(() => {}); // offline: stay "CHECKING…" rather than assume anything
  }, []);

  // Critical alert + screen flash
  const [criticalThreat, setCriticalThreat] = useState(null);
  const [screenFlash,    setScreenFlash]    = useState(false);
  const seenLogIds  = useRef(null);   // ids already on screen — only genuinely new ones alert

  // Real vault file count for telemetry
  const [vaultCount, setVaultCount] = useState(0);
  useEffect(() => {
    const apiBase = window.location.protocol === 'file:' ? 'http://localhost:3001/api' : '/api';
    const poll = () => fetch(`${apiBase}/vault/status`)
      .then(r => r.json())
      .then(s => setVaultCount(s.fileCount ?? 0))
      .catch(() => {});
    poll();
    const t = setInterval(poll, 10_000);
    return () => clearInterval(t);
  }, [activeTab]);

  const isCritical = systemStats.threatLevel === 'Critical';

  // Watch for new CRITICAL logs. Tracked by id, not list length: the feed is
  // capped (so its length stops growing) and history reloads on start-up
  // (which must not re-alert on yesterday's threats).
  useEffect(() => {
    seenLogIds.current ??= new Set();
    const fresh = logs.filter(l => !seenLogIds.current.has(l.id));
    for (const l of fresh) seenLogIds.current.add(l.id);
    const crit = fresh.find(l => l.severity === 'CRITICAL' && !l.fromHistory);
    if (crit) {
      setCriticalThreat(crit);
      setScreenFlash(true);
      setTimeout(() => setScreenFlash(false), 700);
      sendNotification(
        'Critical Threat Detected',
        crit.source ? `${crit.type} — ${crit.source}` : crit.type,
        'critical'
      );
    }
  }, [logs, sendNotification]);

  // Handle tray menu navigation
  useEffect(() => {
    const cleanup = onNavigate((tab) => setActiveTab(tab));
    return cleanup;
  }, [onNavigate]);

  // Hardening sequence
  async function handleHardening() {
    if (isHardening) return;
    setIsHardening(true);
    setIsSecured(false);
    setHardeningProgress(0);

    const tick = setInterval(() => {
      setHardeningProgress(prev => Math.min(prev + Math.floor(Math.random() * 8) + 2, 99));
    }, 150);

    const result = await rescanSystem();
    clearInterval(tick);
    setHardeningProgress(100);
    setCheckError(result?.audit ? null : 'The check couldn\'t run — Alvora\'s security engine isn\'t responding. Your last result is shown.');
    // The check only reads settings — "secure" follows the real score, not the click
    const score = result?.securityScore ?? null;
    if (score !== null) setSecurityScore(score);
    if (result?.audit) setAudit(result.audit);
    setHardeningMetrics(result?.metrics ? { ...result.metrics, securityScore: score ?? undefined } : null);
    setTimeout(() => { setIsHardening(false); setIsSecured(score !== null && score >= 70); }, 300);
  }

  const threatColor =
    systemStats.threatLevel === 'Critical' ? 'text-rose-500' :
    systemStats.threatLevel === 'Elevated' ? 'text-yellow-400' :
    systemStats.threatLevel === 'Unknown'  ? 'text-slate/50' :
    'text-emerald-400';

  return (
    <div className="flex h-screen w-full bg-obsidian text-slate font-sans overflow-hidden">

      {/* Neural particle field */}
      <ParticleBackground isCritical={isCritical} lockdownActive={lockdownActive} />

      {/* Screen flash on CRITICAL */}
      <AnimatePresence>
        {screenFlash && (
          <motion.div
            className="fixed inset-0 z-[90] pointer-events-none"
            initial={{ opacity: 0.35 }}
            animate={{ opacity: 0 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.7, ease: 'easeOut' }}
            style={{ backgroundColor: '#ef4444' }}
          />
        )}
      </AnimatePresence>

      {/* Critical threat banner */}
      <CriticalAlert threat={criticalThreat} onDismiss={() => setCriticalThreat(null)} />

      {/* Security Check: how to fix each issue */}
      <AnimatePresence>
        {guideOpen && audit && (
          <SecurityGuide
            audit={audit}
            onClose={() => setGuideOpen(false)}
            onRecheck={handleHardening}
            rechecking={isHardening}
            error={checkError}
            onOpenSettings={openSystemSettings}
          />
        )}
      </AnimatePresence>

      {/* Sidebar */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        lockdownActive={lockdownActive}
        onLockdown={toggleLockdown}
        backendConnected={backendConnected}
        licenseInfo={licenseInfo}
      />

      {/* Main content */}
      <main className="flex-1 flex flex-col relative overflow-hidden">

        {/* Electron drag bar — native macOS traffic lights render top-left via
            titleBarStyle:'hiddenInset'. We only provide a draggable region here;
            no custom window buttons (avoids a duplicate set on the right). */}
        {isElectron && (
          <div className="h-8 flex items-center px-20 drag-region flex-shrink-0 border-b border-white/5">
            <span className="text-[10px] font-mono text-slate/30 no-drag">Alvora Cyber</span>
          </div>
        )}

        <div className="flex-1 flex flex-col px-8 py-6 max-w-7xl mx-auto w-full overflow-hidden">

          {/* Header */}
          <header className="w-full flex justify-between items-center mb-6 h-12 flex-shrink-0">
            <div>
              <h1 className="text-xl font-bold text-white tracking-wide uppercase">Alvora Cyber</h1>
              <p className="text-xs text-slate/50 font-mono tracking-wider">
                Device Posture:{' '}
                <span className={`transition-colors duration-500 ${
                  lockdownActive ? 'text-rose-400 animate-pulse'
                  : isCritical   ? 'text-orange-400'
                  : isSecured    ? 'text-emerald-400'
                  : securityScore !== null ? 'text-yellow-400'
                  : 'text-slate/50'
                }`}>
                  {lockdownActive ? 'LOCKDOWN'
                   : isCritical   ? 'THREAT DETECTED'
                   : isSecured    ? 'SECURE'
                   : securityScore !== null ? 'NEEDS ATTENTION'
                   : 'CHECKING…'}
                </span>
                {securityScore !== null && !lockdownActive && (
                  <span className="text-slate/30 ml-2">· Security Score {securityScore}/100</span>
                )}
              </p>
            </div>

            <div className="flex space-x-6 text-sm font-mono text-slate/80">
              {systemStats && (
                <>
                  <div className="flex flex-col items-end">
                    <span className="text-slate/40 text-[10px] uppercase">CPU Temp</span>
                    <motion.span
                      key={systemStats.cpuTemp}
                      initial={{ opacity: 0, y: -4 }}
                      animate={{ opacity: 1, y: 0 }}
                      className={`font-semibold ${systemStats.cpuTemp > 60 ? 'text-rose-400' : 'text-cobalt'}`}
                    >
                      {systemStats.cpuTemp != null ? `${systemStats.cpuTemp}°C` : '—'}
                    </motion.span>
                  </div>

                  <div className="flex flex-col items-end">
                    <span className="text-slate/40 text-[10px] uppercase">Memory</span>
                    <span className="text-white">{systemStats.memStats
                      ? `${systemStats.memStats.usePct ?? '—'}%`
                      : systemStats.memoryEncryption
                    }</span>
                  </div>

                  <div className="flex flex-col items-end">
                    <span className="text-slate/40 text-[10px] uppercase">Threat Level</span>
                    <motion.span
                      key={systemStats.threatLevel}
                      initial={{ scale: 0.8 }}
                      animate={{ scale: 1 }}
                      className={`font-semibold ${threatColor} ${isCritical ? 'glow-pulse' : ''}`}
                    >
                      {systemStats.threatLevel}
                    </motion.span>
                  </div>
                </>
              )}
            </div>
          </header>

          {/* Main layout */}
          <div className="flex-1 flex gap-6 overflow-hidden">

            {/* Central panel */}
            <section className="flex-[2] relative glass-panel scanlines rounded-2xl flex flex-col overflow-hidden border border-white/5">
              <AnimatePresence mode="wait">
                {activeTab === 'dashboard' && (
                  <ShieldDashboard
                    key="dashboard"
                    isHardening={isHardening}
                    hardeningProgress={hardeningProgress}
                    isSecured={isSecured}
                    securityScore={securityScore}
                    isCritical={isCritical}
                    lockdownActive={lockdownActive}
                    hardeningMetrics={hardeningMetrics}
                    audit={audit}
                    onHarden={handleHardening}
                    onOpenGuide={() => setGuideOpen(true)}
                  />
                )}
                {activeTab === 'assistant' && (
                  <AlvoraAI key="assistant" />
                )}
                {activeTab === 'ai-monitor' && (
                  <AIMonitor key="ai-monitor" scanText={scanText} scanHistory={scanHistory} logs={logs} />
                )}
                {activeTab === 'vault' && (
                  <VaultView key="vault" />
                )}
                {activeTab === 'threat' && (
                  <ThreatMap key="threat" logs={logs} systemStats={systemStats} />
                )}
                {activeTab === 'kernel' && (
                  <KernelMonitor key="kernel" systemStats={systemStats} logs={logs} isSecured={isSecured} />
                )}
                {activeTab === 'firewall' && (
                  <FirewallView key="firewall" lockdownActive={lockdownActive} onLockdown={toggleLockdown} logs={logs} />
                )}
                {activeTab === 'reports' && (
                  <Reports key="reports" logs={logs} scanHistory={scanHistory} />
                )}
                {activeTab === 'settings' && (
                  <SettingsPanel key="settings" licenseInfo={licenseInfo} onDeactivate={onDeactivate} onClearAlerts={clearAlertHistory} onClearScans={clearScanHistory} />
                )}
              </AnimatePresence>
            </section>

            {/* Right sidebar */}
            <aside className="flex-[1] flex flex-col gap-4 h-full min-w-[280px] max-w-[320px] overflow-hidden">
              <LiveLogFeed logs={logs} onDismiss={dismissLog} onTrust={trustFromLog} />

              {/* Node telemetry widget */}
              <div className="h-[180px] glass-panel scanlines rounded-xl p-4 border border-white/5 flex-shrink-0">
                <h3 className="text-[10px] uppercase text-slate/50 font-mono mb-3">Node Telemetry</h3>
                <div className="space-y-3 font-mono text-sm">
                  <div className="flex justify-between items-center">
                    <span className="text-slate/40 text-xs">Vault Files</span>
                    <motion.span
                      key={vaultCount}
                      initial={{ color: '#ffffff', y: -2 }}
                      animate={{ color: '#00E5FF', y: 0 }}
                      transition={{ duration: 0.5 }}
                      className="text-cobalt font-bold text-xs"
                    >
                      {vaultCount}
                    </motion.span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-slate/40 text-xs">Threats Logged</span>
                    {/* Real alerts only — "all clear" heartbeats in the feed aren't threats */}
                    <span className="text-white text-xs">{logs.filter(l => !String(l.id).startsWith('ACT-')).length}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-slate/40 text-xs">AI Scans</span>
                    <span className="text-cobalt text-xs">{scanHistory.length}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-slate/40 text-xs">Backend</span>
                    <span className={`text-xs ${backendConnected ? 'text-emerald-400' : 'text-yellow-400'}`}>
                      {backendConnected ? 'Live ●' : 'Connecting ◌'}
                    </span>
                  </div>
                </div>
              </div>
            </aside>
          </div>
        </div>
      </main>
    </div>
  );
}

// ─── Root App ─────────────────────────────────────────────────────────────────

// Free public beta: all features unlocked. First run captures name + email so we
// know who's using it; after that it goes straight to the dashboard.
const BETA_LICENSE = { tier: 'Beta', valid: true, key: null, unlimited: true };

export default function App() {
  const [ready,      setReady]      = useState(false);
  const [registered, setRegistered] = useState(false);
  const { readSettings } = useElectron();

  useEffect(() => {
    readSettings()
      .then(s => { setRegistered(!!s?.registered); setReady(true); })
      .catch(() => setReady(true));
  }, [readSettings]);

  if (!ready) {
    return (
      <div className="flex h-screen w-full items-center justify-center bg-obsidian">
        <div className="w-8 h-8 border-2 border-cobalt border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!registered) {
    return <BetaWelcome onComplete={() => setRegistered(true)} />;
  }

  return <Dashboard licenseInfo={BETA_LICENSE} onDeactivate={() => {}} />;
}
