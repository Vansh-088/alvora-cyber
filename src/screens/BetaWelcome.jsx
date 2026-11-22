/**
 * BetaWelcome — first-run screen for the free public beta.
 *
 * Captures name + email so you know who's using Alvora, posts the signup to your
 * waitlist endpoint (Formspree), stores registration locally, then unlocks the
 * full app. No payment, no license keys — every feature is available.
 *
 * To collect signups centrally, set BETA_SIGNUP_ENDPOINT to your Formspree form
 * URL (https://formspree.io/f/XXXXXXXX). If left blank, registration is stored
 * locally only and the app still works.
 */

import React, { useState, useRef, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, ArrowRight, CheckCircle2, Loader2 } from 'lucide-react';
import { useElectron } from '../hooks/useElectron.js';

const BETA_SIGNUP_ENDPOINT = ''; // ← put your Formspree form URL here to collect signups

function ParticleField() {
  const ref = useRef(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let raf, nodes = [];
    const resize = () => {
      canvas.width = canvas.offsetWidth; canvas.height = canvas.offsetHeight;
      nodes = Array.from({ length: 40 }, () => ({
        x: Math.random() * canvas.width, y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.3, vy: (Math.random() - 0.5) * 0.3, r: Math.random() * 1.5 + 0.5,
      }));
    };
    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      for (const n of nodes) {
        n.x += n.vx; n.y += n.vy;
        if (n.x < 0 || n.x > canvas.width) n.vx *= -1;
        if (n.y < 0 || n.y > canvas.height) n.vy *= -1;
        ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(0,229,255,0.4)'; ctx.fill();
      }
      for (let i = 0; i < nodes.length; i++)
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x, dy = nodes[i].y - nodes[j].y, d = Math.hypot(dx, dy);
          if (d < 110) {
            ctx.beginPath(); ctx.moveTo(nodes[i].x, nodes[i].y); ctx.lineTo(nodes[j].x, nodes[j].y);
            ctx.strokeStyle = `rgba(0,229,255,${0.07 * (1 - d / 110)})`; ctx.stroke();
          }
        }
      raf = requestAnimationFrame(draw);
    };
    resize(); draw();
    window.addEventListener('resize', resize);
    return () => { cancelAnimationFrame(raf); window.removeEventListener('resize', resize); };
  }, []);
  return <canvas ref={ref} className="absolute inset-0 w-full h-full" />;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export default function BetaWelcome({ onComplete }) {
  const [name,  setName]  = useState('');
  const [email, setEmail] = useState('');
  const [busy,  setBusy]  = useState(false);
  const [error, setError] = useState('');
  const { readSettings, writeSettings } = useElectron();

  async function activate() {
    setError('');
    if (!name.trim())          return setError('Please enter your name');
    if (!EMAIL_RE.test(email)) return setError('Please enter a valid email');
    setBusy(true);

    const registration = {
      registered:   true,
      name:         name.trim(),
      email:        email.trim(),
      registeredAt: new Date().toISOString(),
      version:      '1.0.0-beta',
    };

    // Send the signup to your waitlist (best-effort — never blocks the user)
    if (BETA_SIGNUP_ENDPOINT) {
      try {
        await fetch(BETA_SIGNUP_ENDPOINT, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
          body: JSON.stringify({ name: registration.name, email: registration.email, source: 'Alvora Beta App' }),
        });
      } catch { /* offline — registration still proceeds locally */ }
    }

    // Merge into existing settings so behavior prefs (tray, notifications…) survive
    try {
      const existing = (await readSettings()) || {};
      await writeSettings({ ...existing, ...registration });
    } catch { /* localStorage fallback handled in hook */ }
    setBusy(false);
    onComplete(registration);
  }

  return (
    <div className="relative flex h-screen w-full items-center justify-center bg-obsidian overflow-hidden">
      <ParticleField />
      <motion.div
        initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
        className="relative z-10 w-full max-w-md px-8"
      >
        <div className="flex flex-col items-center mb-8">
          <motion.div
            animate={{ filter: ['drop-shadow(0 0 16px rgba(0,229,255,0.4))', 'drop-shadow(0 0 28px rgba(0,229,255,0.6))', 'drop-shadow(0 0 16px rgba(0,229,255,0.4))'] }}
            transition={{ duration: 2.5, repeat: Infinity }}
          >
            <Shield className="w-14 h-14 text-cobalt" strokeWidth={1.4} />
          </motion.div>
          <h1 className="text-2xl font-bold text-white mt-4 tracking-wide">ALVORA CYBER</h1>
          <p className="text-sm text-cobalt/70 mt-1">The security layer between you and AI</p>
          <span className="mt-3 text-[10px] font-mono tracking-widest uppercase text-cobalt bg-cobalt/10 border border-cobalt/30 rounded-full px-3 py-1">
            Free Beta
          </span>
        </div>

        <p className="text-xs text-slate/50 text-center mb-6 leading-relaxed">
          Welcome. Tell us who you are so we can keep you posted on the beta — then you're in.
          Every feature is unlocked, free.
        </p>

        <input
          type="text" value={name} onChange={e => setName(e.target.value)}
          placeholder="Your name" autoFocus
          className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white text-sm focus:outline-none focus:border-cobalt/40 mb-3"
        />
        <input
          type="email" value={email} onChange={e => setEmail(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && activate()}
          placeholder="you@email.com"
          className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white text-sm focus:outline-none focus:border-cobalt/40 mb-3"
        />

        {error && (
          <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-red-400 text-xs mb-3 text-center">
            {error}
          </motion.p>
        )}

        <button
          onClick={activate} disabled={busy}
          className="w-full flex items-center justify-center gap-2 py-3 bg-cobalt text-obsidian font-semibold rounded-xl hover:bg-cobalt/90 disabled:opacity-50 transition-all text-sm"
        >
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <><ArrowRight className="w-4 h-4" /> Start Protecting</>}
        </button>

        <div className="flex items-center justify-center gap-1.5 mt-5 text-[10px] text-slate/30">
          <CheckCircle2 className="w-3 h-3 text-emerald-400/60" />
          Your email stays private — used only to reach you about the beta.
        </div>
      </motion.div>
    </div>
  );
}
