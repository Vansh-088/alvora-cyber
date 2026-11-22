/**
 * useSecurity — Primary data layer for Alvora Cyber
 *
 * Connects to the backend SSE stream + REST endpoints.
 * When the backend is offline, values show as unknown. Nothing is simulated.
 * Now includes scan history and AI monitor integration.
 */

import { useState, useEffect, useCallback, useRef } from 'react';

// In Electron (file:// protocol) relative URLs don't resolve — use absolute.
// In dev (Vite) relative /api is proxied → localhost:3001.
const _isFile  = typeof window !== 'undefined' && window.location.protocol === 'file:';
const API_BASE = _isFile ? 'http://localhost:3001/api' : '/api';
const SSE_BASE = 'http://localhost:3001/api'; // Always direct — Vite proxy buffers SSE

// No local simulation. Every event in this hook comes from the real backend
// (real network scans, real PII/injection detections, real monitoring activity).
// If the backend is unreachable the feed shows "Reconnecting…" — never fake data.

// ─── Hook ─────────────────────────────────────────────────────────────────────

export function useSecurity() {
  const [systemStats, setSystemStats] = useState({
    cpuTemp: null,
    threatLevel: 'Unknown',
    memoryEncryption: 'Unknown',
    cpuLoad: null,
    memStats: null,
    network: [],
    processes: [],
  });
  const [logs,             setLogs]             = useState([]);
  const [scanHistory,      setScanHistory]      = useState([]);
  const [lockdownActive,   setLockdownActive]   = useState(false);
  const [backendConnected, setBackendConnected] = useState(false);

  // ── Log push (deduplicated, capped at 60) ─────────────────────────────────
  const pushLog = useCallback((log) => {
    setLogs(prev => {
      if (prev.some(l => l.id === log.id)) return prev;
      const updated = [log, ...prev];
      return updated.length > 60 ? updated.slice(0, 60) : updated;
    });
  }, []);

  // ── Backend SSE ───────────────────────────────────────────────────────────
  useEffect(() => {
    // Fetch initial status
    fetch(`${API_BASE}/status`)
      .then(r => r.json())
      .then(data => setSystemStats(prev => ({
        ...prev,
        cpuTemp:          data.cpuTemp  ?? prev.cpuTemp,
        threatLevel:      data.threatLevel ?? prev.threatLevel,
        memoryEncryption: data.memoryEncryption ?? prev.memoryEncryption,
        cpuLoad:          data.cpuLoad ?? null,
        memStats:         data.memStats ?? null,
        network:          data.network ?? [],
        processes:        data.processes ?? [],
      })))
      .catch(() => {});

    // Fetch scan history
    fetch(`${API_BASE}/scan/history`)
      .then(r => r.json())
      .then(data => setScanHistory(data.scans ?? []))
      .catch(() => {});

    // Fetch persisted threat logs (survives restarts via SQLite)
    fetch(`${API_BASE}/threats/history`)
      .then(r => r.json())
      .then(data => {
        if (Array.isArray(data.threats) && data.threats.length) {
          setLogs(data.threats.map(t => ({
            id:        t.id,
            timestamp: t.timestamp?.slice(11, 19) ?? new Date().toLocaleTimeString('en-US', { hour12: false }),
            type:      t.type,
            source:    t.source,
            port:      t.port,
            action:    t.action,
            severity:  t.severity,
            detail:    t.detail ?? '',
            appPath:   t.app_path ?? null,
            fromHistory: true,   // saved earlier — shown, but never re-alerted
            details:   { resolution: t.detail ?? '' },
          })));
        }
      })
      .catch(() => {});

    // SSE can't set headers, so the token rides as a query param
    const _tok = typeof window !== 'undefined' ? window.__ALVORA_TOKEN__ : null;
    const es = new EventSource(`${SSE_BASE}/threats/stream${_tok ? `?token=${_tok}` : ''}`);

    es.onopen = () => {
      setBackendConnected(true);
    };

    es.onmessage = (event) => {
      let data;
      try { data = JSON.parse(event.data); } catch { return; }

      switch (data.msgType) {
        case 'CONNECTED':
          break;

        case 'THREAT': {
          const { msgType: _m, ...threat } = data;
          pushLog(threat);
          if (threat.severity === 'CRITICAL') {
            setSystemStats(prev => ({ ...prev, threatLevel: 'Critical' }));
          } else if (threat.severity === 'HIGH') {
            setSystemStats(prev => ({
              ...prev,
              threatLevel: prev.threatLevel === 'Critical' ? 'Critical' : 'Elevated',
            }));
          }
          break;
        }

        case 'ACTIVITY': {
          // Real monitoring heartbeat — keeps the feed alive with genuine status.
          const { msgType: _ma, ...act } = data;
          pushLog(act);
          break;
        }

        case 'AI_THREAT': {
          const { msgType: _m2, ...aiThreat } = data;
          // Convert AI threat to a log entry
          pushLog({
            id:        `AI-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`,
            timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }),
            ...aiThreat,
            details: {
              protocol:   'HTTPS/AI',
              signature:  aiThreat.scanId,
              resolution: {
                BLOCKED: 'Prompt blocked before reaching the AI.',
                HELD:    'Prompt held so you could review it before sending.',
                FLAGGED: 'Prompt flagged — it was allowed through.',
              }[aiThreat.action] ?? 'Logged for review — the prompt was not stopped.',
            },
          });
          // Fetch updated scan history
          fetch(`${API_BASE}/scan/history`)
            .then(r => r.json())
            .then(d => setScanHistory(d.scans ?? []))
            .catch(() => {});
          break;
        }

        case 'LOCKDOWN_STATE':
          setLockdownActive(data.active);
          break;

        case 'SYSTEM_UPDATE':
          setSystemStats(prev => ({
            ...prev,
            threatLevel: data.threatLevel ?? prev.threatLevel,
            cpuTemp:     data.cpuTemp     ?? prev.cpuTemp,
          }));
          break;

        default:
          break;
      }
    };

    es.onerror = () => {
      setBackendConnected(false);
      // No fake fallback data — the feed simply shows "Reconnecting…" until the
      // real backend is reachable again. EventSource auto-reconnects.
    };

    return () => {
      es.close();
    };
  }, [pushLog]);

  // ── rescanSystem ──────────────────────────────────────────────────────────
  const rescanSystem = useCallback(async () => {
    try {
      const res  = await fetch(`${API_BASE}/harden`, { method: 'POST' });
      const data = await res.json();
      setSystemStats(prev => ({
        ...prev,
        cpuTemp:          data.cpuTemp ?? prev.cpuTemp,
        threatLevel:      data.threatLevel ?? prev.threatLevel,
        memoryEncryption: data.memoryEncryption ?? prev.memoryEncryption,
      }));
      return data;
    } catch {
      // Backend unreachable — report it honestly instead of inventing a result
      setSystemStats(prev => ({ ...prev, threatLevel: 'Unknown' }));
      return { success: false, error: 'Security engine offline' };
    }
  }, []);

  // ── toggleLockdown ────────────────────────────────────────────────────────
  const toggleLockdown = useCallback(async () => {
    const next = !lockdownActive;
    try {
      const res  = await fetch(`${API_BASE}/lockdown`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ active: next }),
      });
      const data = await res.json();
      setLockdownActive(data.lockdown);
    } catch {
      setLockdownActive(next);
    }
  }, [lockdownActive]);

  // ── scanText (AI Monitor) ─────────────────────────────────────────────────
  const scanText = useCallback(async (text, context = 'user_input') => {
    try {
      const res  = await fetch(`${API_BASE}/scan`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ text, context }),
      });
      const data = await res.json();
      if (context !== 'sample') setScanHistory(prev => [data, ...prev].slice(0, 50));
      return data;
    } catch (err) {
      console.error('[scanText]', err);
      return null;
    }
  }, []);

  // ── History controls (user-driven; the backend backs up before clearing) ──
  const dismissLog = useCallback(async (id) => {
    await fetch(`${API_BASE}/threats/${encodeURIComponent(id)}`, { method: 'DELETE' }).catch(() => {});
    setLogs(prev => prev.filter(l => l.id !== id));
  }, []);

  /** "This is fine": trust the app (or address) behind an alert, and drop its alerts. */
  const trustFromLog = useCallback(async (log) => {
    const body = log.appPath ? { appPath: log.appPath, name: log.app } : { ip: log.source };
    const res  = await fetch(`${API_BASE}/trust`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    }).then(r => r.json()).catch(() => ({ error: 'Alvora\'s engine isn\'t responding' }));
    if (res.success) {
      await fetch(`${API_BASE}/threats/${encodeURIComponent(log.id)}`, { method: 'DELETE' }).catch(() => {});
      setLogs(prev => prev.filter(l =>
        l.id !== log.id &&
        !(body.appPath && l.appPath === body.appPath) &&
        !(body.ip && l.source === body.ip)));
    }
    return res;
  }, []);

  const clearAlertHistory = useCallback(async () => {
    const res = await fetch(`${API_BASE}/threats/history`, { method: 'DELETE' }).then(r => r.json()).catch(() => ({}));
    if (res.success) setLogs([]);
    return res;
  }, []);

  const clearScanHistory = useCallback(async () => {
    const res = await fetch(`${API_BASE}/scan/history`, { method: 'DELETE' }).then(r => r.json()).catch(() => ({}));
    if (res.success) setScanHistory([]);
    return res;
  }, []);

  return {
    systemStats,
    logs,
    scanHistory,
    dismissLog,
    trustFromLog,
    clearAlertHistory,
    clearScanHistory,
    lockdownActive,
    backendConnected,
    rescanSystem,
    toggleLockdown,
    scanText,
  };
}
