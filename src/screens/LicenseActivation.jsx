/**
 * LicenseActivation — First-run gate screen
 *
 * Shown when no valid license is found.
 * Supports license key activation and 30-day trial start.
 */

import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Key, ArrowRight, Clock, CheckCircle2, XCircle, Loader2, ExternalLink } from 'lucide-react';
import { useElectron } from '../hooks/useElectron.js';

const API_BASE = (typeof window !== 'undefined' && window.location.protocol === 'file:')
  ? 'http://localhost:3001/api'
  : '/api';

// ─── Particle Background (minimal, license screen) ────────────────────────────

function LicenseParticles() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx  = canvas.getContext('2d');
    let animId;
    let nodes  = [];

    function resize() {
      canvas.width  = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
      nodes = Array.from({ length: 35 }, () => ({
        x:  Math.random() * canvas.width,
        y:  Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.3,
        vy: (Math.random() - 0.5) * 0.3,
        r:  Math.random() * 1.5 + 0.5,
      }));
    }

    function draw() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      for (const n of nodes) {
        n.x += n.vx; n.y += n.vy;
        if (n.x < 0 || n.x > canvas.width)  n.vx *= -1;
        if (n.y < 0 || n.y > canvas.height) n.vy *= -1;
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(0,229,255,0.4)';
        ctx.fill();
      }
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x;
          const dy = nodes[i].y - nodes[j].y;
          const d  = Math.sqrt(dx * dx + dy * dy);
          if (d < 100) {
            ctx.beginPath();
            ctx.moveTo(nodes[i].x, nodes[i].y);
            ctx.lineTo(nodes[j].x, nodes[j].y);
            ctx.strokeStyle = `rgba(0,229,255,${0.08 * (1 - d / 100)})`;
            ctx.stroke();
          }
        }
      }
      animId = requestAnimationFrame(draw);
    }

    resize();
    draw();
    window.addEventListener('resize', resize);
    return () => { cancelAnimationFrame(animId); window.removeEventListener('resize', resize); };
  }, []);

  return <canvas ref={canvasRef} className="absolute inset-0 w-full h-full" />;
}

// ─── Key formatter ────────────────────────────────────────────────────────────

function formatKey(raw) {
  const cleaned = raw.replace(/[^A-Z0-9]/gi, '').toUpperCase().slice(0, 15);
  const parts   = [];
  if (cleaned.length > 0)  parts.push(cleaned.slice(0, 4));
  if (cleaned.length > 4)  parts.push(cleaned.slice(4, 8));
  if (cleaned.length > 8)  parts.push(cleaned.slice(8, 12));
  if (cleaned.length > 12) parts.push(cleaned.slice(12, 16));
  return 'ALVY-' + parts.join('-');
}

// ─── Main Screen ──────────────────────────────────────────────────────────────

export default function LicenseActivation({ onActivated }) {
  const [mode,       setMode]       = useState('home'); // 'home' | 'key' | 'trial' | 'success'
  const [keyInput,   setKeyInput]   = useState('');
  const [status,     setStatus]     = useState(null);  // null | 'loading' | 'success' | 'error'
  const [errorMsg,   setErrorMsg]   = useState('');
  const [successData, setSuccessData] = useState(null);
  const { writeLicense, openExternal } = useElectron();

  function handleKeyChange(e) {
    const raw = e.target.value.replace(/^ALVY-/i, '').replace(/[^A-Z0-9]/gi, '').toUpperCase();
    setKeyInput(raw);
    setStatus(null);
    setErrorMsg('');
  }

  function displayKey() {
    if (!keyInput) return 'ALVY-';
    const parts = [];
    if (keyInput.length > 0)  parts.push(keyInput.slice(0, 4));
    if (keyInput.length > 4)  parts.push(keyInput.slice(4, 8));
    if (keyInput.length > 8)  parts.push(keyInput.slice(8, 12));
    return 'ALVY-' + parts.join('-');
  }

  async function activateKey() {
    if (keyInput.length < 12) {
      setErrorMsg('Key must be 12 characters (format: ALVY-XXXX-XXXX-XXXX)');
      setStatus('error');
      return;
    }
    setStatus('loading');
    setErrorMsg('');

    try {
      const key = `ALVY-${keyInput.slice(0, 4)}-${keyInput.slice(4, 8)}-${keyInput.slice(8, 12)}`;
      const res = await fetch(`${API_BASE}/license/validate`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ key }),
      });
      const data = await res.json();

      if (data.valid) {
        await writeLicense(data);
        setSuccessData(data);
        setStatus('success');
        setTimeout(() => {
          setMode('success');
          setTimeout(() => onActivated(data), 1800);
        }, 600);
      } else {
        setStatus('error');
        setErrorMsg(data.error ?? 'Invalid license key.');
      }
    } catch {
      setStatus('error');
      setErrorMsg('Could not reach the license server. Check your connection.');
    }
  }

  async function startTrial() {
    setStatus('loading');
    try {
      const res  = await fetch(`${API_BASE}/license/trial`, { method: 'POST' });
      const data = await res.json();
      await writeLicense(data);
      setSuccessData(data);
      setStatus('success');
      setTimeout(() => { setMode('success'); setTimeout(() => onActivated(data), 1800); }, 600);
    } catch {
      // Offline fallback: create trial locally
      const now     = new Date();
      const expires = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
      const data    = { valid: true, key: null, tier: 'TRIAL', activatedAt: now.toISOString(), expiresAt: expires.toISOString(), daysLeft: 30 };
      await writeLicense(data);
      setSuccessData(data);
      setStatus('success');
      setTimeout(() => { setMode('success'); setTimeout(() => onActivated(data), 1800); }, 600);
    }
  }

  return (
    <div className="relative flex h-screen w-full items-center justify-center overflow-hidden bg-obsidian">
      <LicenseParticles />

      {/* Background glow */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(0,229,255,0.05)_0%,transparent_70%)]" />

      {/* Panel */}
      <AnimatePresence mode="wait">
        {mode === 'success' ? (
          <motion.div
            key="success"
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="relative z-10 text-center"
          >
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ type: 'spring', stiffness: 300, damping: 20 }}
              className="flex justify-center mb-6"
            >
              <CheckCircle2 className="w-20 h-20 text-emerald-400" strokeWidth={1.5} />
            </motion.div>
            <h2 className="text-2xl font-bold text-white mb-2">
              {successData?.tier === 'TRIAL' ? '30-Day Trial Started' : 'License Activated'}
            </h2>
            <p className="text-slate/60 text-sm">Launching Alvora Cyber…</p>
          </motion.div>
        ) : (
          <motion.div
            key="main"
            initial={{ y: 20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ duration: 0.5 }}
            className="relative z-10 w-full max-w-md mx-4"
          >
            {/* Logo */}
            <div className="text-center mb-10">
              <motion.div
                animate={{ rotate: [0, 5, -5, 0] }}
                transition={{ duration: 4, repeat: Infinity, ease: 'easeInOut' }}
                className="flex justify-center mb-4"
              >
                <div className="relative">
                  <Shield className="w-16 h-16 text-cobalt" strokeWidth={1.5} />
                  <div className="absolute inset-0 flex items-center justify-center">
                    <div className="w-2 h-2 rounded-full bg-cobalt shadow-[0_0_12px_rgba(0,229,255,0.8)]" />
                  </div>
                </div>
              </motion.div>
              <h1 className="text-3xl font-bold text-white tracking-wide">ALVORA CYBER</h1>
              <p className="text-cobalt/70 text-sm font-mono tracking-widest uppercase mt-1">AI Security Layer</p>
            </div>

            {/* Card */}
            <div className="glass-panel rounded-2xl p-8 border border-white/10">
              <AnimatePresence mode="wait">

                {/* Home: choose activation path */}
                {mode === 'home' && (
                  <motion.div key="home" initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 20 }}>
                    <h2 className="text-lg font-semibold text-white mb-2">Activate Alvora Cyber</h2>
                    <p className="text-slate/60 text-sm mb-8">
                      Protect your AI interactions with real-time PII detection, prompt injection blocking, and device hardening.
                    </p>

                    <div className="space-y-3">
                      <button
                        onClick={() => setMode('key')}
                        className="w-full flex items-center justify-between p-4 bg-cobalt/10 hover:bg-cobalt/20 border border-cobalt/30 rounded-xl transition-all group"
                      >
                        <div className="flex items-center gap-3">
                          <Key className="w-5 h-5 text-cobalt" />
                          <div className="text-left">
                            <div className="text-white font-medium text-sm">Enter License Key</div>
                            <div className="text-slate/50 text-xs">Full access, no expiry</div>
                          </div>
                        </div>
                        <ArrowRight className="w-4 h-4 text-cobalt group-hover:translate-x-1 transition-transform" />
                      </button>

                      <button
                        onClick={startTrial}
                        disabled={status === 'loading'}
                        className="w-full flex items-center justify-between p-4 bg-white/5 hover:bg-white/10 border border-white/10 rounded-xl transition-all group"
                      >
                        <div className="flex items-center gap-3">
                          {status === 'loading' ? (
                            <Loader2 className="w-5 h-5 text-slate/60 animate-spin" />
                          ) : (
                            <Clock className="w-5 h-5 text-slate/60" />
                          )}
                          <div className="text-left">
                            <div className="text-white font-medium text-sm">Start 30-Day Free Trial</div>
                            <div className="text-slate/50 text-xs">All features, no credit card</div>
                          </div>
                        </div>
                        <ArrowRight className="w-4 h-4 text-slate/40 group-hover:translate-x-1 transition-transform" />
                      </button>
                    </div>

                    <div className="mt-6 text-center">
                      <button
                        onClick={() => openExternal('https://alvoracyber.com')}
                        className="text-xs text-slate/40 hover:text-cobalt transition-colors flex items-center gap-1 mx-auto"
                      >
                        Get a license at alvoracyber.com <ExternalLink className="w-3 h-3" />
                      </button>
                    </div>
                  </motion.div>
                )}

                {/* Key entry */}
                {mode === 'key' && (
                  <motion.div key="key" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }}>
                    <button onClick={() => { setMode('home'); setStatus(null); setKeyInput(''); }} className="text-slate/40 hover:text-white text-xs mb-6 flex items-center gap-1 transition-colors">
                      ← Back
                    </button>
                    <h2 className="text-lg font-semibold text-white mb-2">Enter Your License Key</h2>
                    <p className="text-slate/60 text-xs mb-6 font-mono">Format: ALVY-XXXX-XXXX-XXXX</p>

                    <div className="relative mb-4">
                      <input
                        type="text"
                        value={displayKey()}
                        onChange={handleKeyChange}
                        placeholder="ALVY-XXXX-XXXX-XXXX"
                        maxLength={19}
                        className={`license-input w-full bg-black/40 border rounded-lg px-4 py-3 text-white text-sm text-center focus:outline-none focus:ring-2 transition-all ${
                          status === 'error'   ? 'border-red-500/50 focus:ring-red-500/30' :
                          status === 'success' ? 'border-emerald-500/50 focus:ring-emerald-500/30' :
                          'border-white/10 focus:ring-cobalt/30 focus:border-cobalt/40'
                        }`}
                        onKeyDown={e => e.key === 'Enter' && activateKey()}
                        autoFocus
                      />
                      {status === 'success' && <CheckCircle2 className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-emerald-400" />}
                      {status === 'error'   && <XCircle className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-red-400" />}
                    </div>

                    {errorMsg && (
                      <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-red-400 text-xs mb-4 text-center">
                        {errorMsg}
                      </motion.p>
                    )}

                    <button
                      onClick={activateKey}
                      disabled={status === 'loading' || keyInput.length < 12}
                      className="w-full py-3 bg-cobalt text-obsidian font-semibold rounded-lg flex items-center justify-center gap-2 hover:bg-cobalt/90 disabled:opacity-40 disabled:cursor-not-allowed transition-all text-sm"
                    >
                      {status === 'loading' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Key className="w-4 h-4" />}
                      {status === 'loading' ? 'Activating…' : 'Activate License'}
                    </button>

                    <p className="text-center text-xs text-slate/40 mt-4">
                      No key?{' '}
                      <button onClick={() => { setMode('home'); setKeyInput(''); setStatus(null); }} className="text-cobalt hover:underline">
                        Start a free trial
                      </button>
                    </p>
                  </motion.div>
                )}

              </AnimatePresence>
            </div>

            {/* Footer */}
            <p className="text-center text-[10px] text-slate/30 font-mono mt-6">
              Alvora Cyber v1.0.0 · © 2025 Vansh Dudhagra
            </p>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
