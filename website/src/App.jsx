/**
 * ALVORA CYBER — App.jsx
 * ─────────────────────────────────────────────────────────────────────────────
 * Hosted on Cloudflare (see wrangler.jsonc).
 *   npm run dev      # local dev server on :5180
 *   npm run deploy   # build + publish to alvoracyber.com
 *
 * All styles are inline or injected via a <style> tag — zero Tailwind needed.
 * ─────────────────────────────────────────────────────────────────────────────
 */

import { useState, useEffect, useRef, useCallback } from "react";
import { motion, AnimatePresence, useInView } from "framer-motion";

/* ═══════════════════════════════════════════════════════════════════════════════
   1. DESIGN TOKENS & GLOBAL STYLES
   ─────────────────────────────────────────────────────────────────────────────
   All colours, typography, and base resets live here as injected CSS.
   This keeps the component fully self-contained for Replit.
══════════════════════════════════════════════════════════════════════════════ */
const GLOBAL_CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Cormorant+Garamond:ital,wght@0,300;0,400;0,600;1,300;1,400&family=Outfit:wght@300;400;500;600;700&family=DM+Mono:ital,wght@0,300;0,400;1,300&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg:        #07070f;
    --surface:   rgba(13,11,28,0.90);
    --surface2:  rgba(18,15,38,0.70);
    --lav:       #a78bfa;
    --lav-lt:    #c4b5fd;
    --lav-dk:    #7c3aed;
    --lav-xdk:   #4c1d95;
    --border:    rgba(167,139,250,0.20);
    --border-sm: rgba(167,139,250,0.09);
    --text:      #ede9fb;
    --sub:       #8b879e;
    --dim:       #3f3c52;
    --green:     #34d399;
    --amber:     #fbbf24;
    --red:       #f87171;
  }

  html { scroll-behavior: smooth; overflow-x: clip; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Outfit', sans-serif;
    overflow-x: hidden;
  }

  button, select, a { cursor: pointer; }
  :focus-visible { outline: 2px solid var(--lav-lt); outline-offset: 3px; }

  /* ── Scrollbar ── */
  ::-webkit-scrollbar { width: 3px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--lav-dk); border-radius: 2px; }

  /* ── Cursor halo (decorative; the real pointer stays visible) ── */
  .c-ring {
    position: fixed; top: 0; left: 0; z-index: 9998; pointer-events: none;
    width: 36px; height: 36px; margin: -18px 0 0 -18px; border-radius: 50%;
    border: 1px solid rgba(167,139,250,0.35);
    transition: transform .12s ease-out;
    will-change: transform;
  }
  @media (hover: none) { .c-ring { display: none; } }

  /* ── Glass card ── */
  .glass {
    background: var(--surface);
    backdrop-filter: blur(28px);
    -webkit-backdrop-filter: blur(28px);
    border: 1px solid var(--border);
    border-radius: 18px;
  }
  .glass-sm {
    background: var(--surface2);
    backdrop-filter: blur(16px);
    border: 1px solid var(--border-sm);
    border-radius: 10px;
  }

  /* ── Typography helpers ── */
  .serif { font-family: 'Cormorant Garamond', serif; }
  .mono  { font-family: 'DM Mono', monospace; }

  /* ── Divider ── */
  .hr-v { width: 1px; background: linear-gradient(to bottom, transparent, rgba(167,139,250,0.2), transparent); }
  .hr-h { height: 1px; background: linear-gradient(to right, transparent, rgba(167,139,250,0.2), transparent); }

  /* ── Buttons ── */
  .btn {
    display: inline-flex; align-items: center; justify-content: center; gap: 10px;
    padding: 14px 36px; border-radius: 9px; border: none; cursor: pointer;
    font-family: 'Outfit', sans-serif; font-weight: 500;
    font-size: 12px; letter-spacing: 2px; text-transform: uppercase;
    transition: all .35s ease; position: relative; overflow: hidden;
  }
  .btn-solid {
    background: linear-gradient(135deg, var(--lav-dk), var(--lav));
    color: #fff;
    box-shadow: 0 0 36px rgba(124,58,237,.38);
  }
  .btn-solid:hover { box-shadow: 0 0 64px rgba(124,58,237,.6); transform: translateY(-2px); }
  .btn-solid:disabled { opacity: .5; transform: none; box-shadow: none; cursor: not-allowed; }
  .btn-outline {
    background: transparent; color: var(--lav-lt);
    border: 1px solid rgba(167,139,250,.32);
  }
  .btn-outline:hover { background: rgba(167,139,250,.08); border-color: var(--lav); }

  /* ── Inputs & selects ── */
  .field {
    width: 100%;
    background: rgba(10,8,24,.65);
    border: 1px solid var(--border-sm);
    border-radius: 9px;
    color: var(--text);
    font-family: 'Outfit', sans-serif;
    font-size: 14px; padding: 13px 16px;
    outline: none; transition: border-color .25s, box-shadow .25s;
    appearance: none; -webkit-appearance: none;
  }
  .field:focus { border-color: var(--lav); box-shadow: 0 0 18px rgba(167,139,250,.14); }
  .field::placeholder { color: var(--dim); }
  .field:disabled { opacity: .5; }
  select.field option { background: #100e20; }
  .field-err { border-color: rgba(248,113,113,.55) !important; box-shadow: 0 0 16px rgba(248,113,113,.1) !important; }

  /* ── Nav ── */
  .nav-btn {
    background: none; border: none; cursor: pointer;
    font-family: 'Outfit', sans-serif; font-size: 11px;
    letter-spacing: 2.5px; text-transform: uppercase;
    color: var(--sub); transition: color .25s;
  }
  .nav-btn:hover { color: var(--lav-lt); }

  /* ── Keyframes ── */
  @keyframes rotCW  { to { transform: rotate(360deg);  } }
  @keyframes rotCCW { to { transform: rotate(-360deg); } }
  @keyframes blobPulse { 0%,100% { opacity: .45; } 50% { opacity: .9; } }
  @keyframes liveDot  { 0%,100% { opacity: .55; transform: scale(1); }   50% { opacity: 1; transform: scale(1.5); } }
  @keyframes scanLine { 0% { top: 0%; opacity: 1; } 90% { opacity: .6; } 100% { top: 100%; opacity: 0; } }
  @keyframes shimmerBar {
    0%   { background-position: -800px 0; }
    100% { background-position:  800px 0; }
  }
  @keyframes scrollBob { 0%,100% { transform: translateX(-50%) translateY(0); } 50% { transform: translateX(-50%) translateY(7px); } }
  @keyframes floatCard { 0%,100% { transform: translateY(0px); } 50% { transform: translateY(-7px); } }
  @keyframes glowPulse {
    0%,100% { box-shadow: 0 0 28px rgba(124,58,237,.18); }
    50%      { box-shadow: 0 0 56px rgba(167,139,250,.38); }
  }

  .shimmer-sweep {
    background: linear-gradient(90deg, rgba(167,139,250,0) 0%, rgba(167,139,250,.28) 50%, rgba(167,139,250,0) 100%);
    background-size: 800px 100%;
    animation: shimmerBar 1.5s ease-in-out infinite;
  }

  /* ── Responsive ── */
  @media (max-width: 860px) {
    .two-col   { grid-template-columns: 1fr !important; }
    .three-col { grid-template-columns: 1fr !important; }
    .nav-links { display: none !important; }
    .nav-bar   { padding: 0 16px !important; }
    .nav-tag   { display: none !important; }
    .hero-pad  { padding: 100px 24px 60px !important; }
    .sec-pad   { padding: 80px 24px !important; }
    .card-pad  { padding: 28px 20px !important; }
    .foot      { padding: 36px 24px !important; flex-direction: column; text-align: center; }
    .foot-meta { text-align: center !important; }
  }

  /* ── Respect "reduce motion" ── */
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { animation-duration: .001ms !important; animation-iteration-count: 1 !important; transition-duration: .001ms !important; }
    html { scroll-behavior: auto; }
  }
`;

/* ═══════════════════════════════════════════════════════════════════════════════
   2. NEURAL NETWORK CANVAS BACKGROUND
   ─────────────────────────────────────────────────────────────────────────────
   60 nodes that drift and connect. Mouse proximity pulls them + draws extra
   bright edges — symbolising the Alvora Shield's active perimeter monitoring.
══════════════════════════════════════════════════════════════════════════════ */
function NeuralBg() {
  const ref = useRef(null);
  const mouse = useRef({ x: -999, y: -999 });
  const nodes = useRef([]);
  const raf   = useRef(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    const resize = () => {
      canvas.width  = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener("resize", resize);

    nodes.current = Array.from({ length: 65 }, () => ({
      x:  Math.random() * window.innerWidth,
      y:  Math.random() * window.innerHeight,
      vx: (Math.random() - .5) * .28,
      vy: (Math.random() - .5) * .28,
      r:  Math.random() * 1.4 + .5,
    }));

    const handleMove = e => { mouse.current = { x: e.clientX, y: e.clientY }; };
    window.addEventListener("mousemove", handleMove);

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const ns = nodes.current;
      const { x: mx, y: my } = mouse.current;

      // Move nodes
      ns.forEach(n => {
        n.x += n.vx; n.y += n.vy;
        if (n.x < 0 || n.x > canvas.width)  n.vx *= -1;
        if (n.y < 0 || n.y > canvas.height) n.vy *= -1;
        // Mouse attraction
        const dx = mx - n.x, dy = my - n.y, d = Math.hypot(dx, dy);
        if (d < 180) {
          n.vx += (dx / d) * .015;
          n.vy += (dy / d) * .015;
          const sp = Math.hypot(n.vx, n.vy);
          if (sp > 1.7) { n.vx *= 1.7 / sp; n.vy *= 1.7 / sp; }
        }
      });

      // Node–node edges
      for (let i = 0; i < ns.length; i++) {
        for (let j = i + 1; j < ns.length; j++) {
          const d = Math.hypot(ns[i].x - ns[j].x, ns[i].y - ns[j].y);
          if (d < 130) {
            ctx.beginPath();
            ctx.moveTo(ns[i].x, ns[i].y);
            ctx.lineTo(ns[j].x, ns[j].y);
            ctx.strokeStyle = `rgba(167,139,250,${(1 - d / 130) * .19})`;
            ctx.lineWidth = .5;
            ctx.stroke();
          }
        }
      }

      // Mouse edges (brighter)
      ns.forEach(n => {
        const d = Math.hypot(mx - n.x, my - n.y);
        if (d < 190) {
          ctx.beginPath();
          ctx.moveTo(n.x, n.y); ctx.lineTo(mx, my);
          ctx.strokeStyle = `rgba(196,181,253,${(1 - d / 190) * .42})`;
          ctx.lineWidth = .75; ctx.stroke();
        }
      });

      // Dots
      ns.forEach(n => {
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(167,139,250,.52)";
        ctx.fill();
      });

      if (!still) raf.current = requestAnimationFrame(draw);
    };
    // Reduced-motion visitors get a single static frame
    const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    draw();

    return () => {
      cancelAnimationFrame(raf.current);
      window.removeEventListener("resize", resize);
      window.removeEventListener("mousemove", handleMove);
    };
  }, []);

  return (
    <canvas
      ref={ref}
      style={{ position: "fixed", inset: 0, zIndex: 0, pointerEvents: "none", opacity: .6 }}
    />
  );
}

/* ═══════════════════════════════════════════════════════════════════════════════
   3. 4-TRIANGLE PYRAMID LOGO
   ─────────────────────────────────────────────────────────────────────────────
   Matches the screenshot exactly: top triangle brightest, two base triangles,
   inverted centre triangle for depth. Lavender → deep violet gradient.
══════════════════════════════════════════════════════════════════════════════ */
function PyramidLogo({ size = 40, glow = false }) {
  const id = useRef(`lg-${Math.random().toString(36).slice(2)}`).current;
  return (
    <svg
      width={size}
      height={size * 0.92}
      viewBox="0 0 52 48"
      fill="none"
      style={glow ? { filter: "drop-shadow(0 0 12px rgba(167,139,250,.55))" } : {}}
    >
      <defs>
        <linearGradient id={`${id}a`} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#ddd6fe" />
          <stop offset="100%" stopColor="#7c3aed" />
        </linearGradient>
        <linearGradient id={`${id}b`} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#a78bfa" />
          <stop offset="100%" stopColor="#6d28d9" />
        </linearGradient>
        <linearGradient id={`${id}c`} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#c4b5fd" />
          <stop offset="100%" stopColor="#8b5cf6" />
        </linearGradient>
        <linearGradient id={`${id}d`} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#7c3aed" />
          <stop offset="100%" stopColor="#3b0764" />
        </linearGradient>
      </defs>
      {/* Top */}
      <polygon points="26,2 39,22 13,22"  fill={`url(#${id}a)`} opacity=".96" />
      {/* Bottom-left */}
      <polygon points="13,25 26,45 1,45"  fill={`url(#${id}b)`} opacity=".88" />
      {/* Bottom-right */}
      <polygon points="39,25 51,45 27,45" fill={`url(#${id}c)`} opacity=".82" />
      {/* Centre depth */}
      <polygon points="13,22 39,22 26,45" fill={`url(#${id}d)`} opacity=".38" />
    </svg>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════════
   4. BRAND HEADER (logo + wordmark)
══════════════════════════════════════════════════════════════════════════════ */
function Brand({ size = 40 }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
      <PyramidLogo size={size} />
      <div>
        <div style={{
          fontFamily: "'Outfit', sans-serif", fontWeight: 600,
          fontSize: size > 30 ? 16 : 13, letterSpacing: ".14em", color: "#ede9fb", lineHeight: 1.1,
        }}>
          ALVORA CYBER
        </div>
        {size > 28 && (
          <div className="nav-tag" style={{
            fontFamily: "'DM Mono', monospace", fontSize: 8,
            letterSpacing: ".24em", color: "var(--sub)", marginTop: 3,
          }}>
            ELEVATING TRUST · SECURING TOMORROW
          </div>
        )}
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════════
   5. SCROLL-TRIGGERED REVEAL
══════════════════════════════════════════════════════════════════════════════ */
function Reveal({ children, delay = 0, y = 32, blur = true, style = {} }) {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-60px" });
  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, y, filter: blur ? "blur(10px)" : "none" }}
      animate={inView ? { opacity: 1, y: 0, filter: "blur(0px)" } : {}}
      transition={{ duration: .85, delay, ease: [.16, 1, .3, 1] }}
      style={style}
    >
      {children}
    </motion.div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════════
   6. SECTION LABEL
══════════════════════════════════════════════════════════════════════════════ */
function SectionLabel({ n, text }) {
  return (
    <Reveal>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 28 }}>
        <span className="mono" style={{ fontSize: 10, color: "var(--lav)", letterSpacing: 3, opacity: .65 }}>
          {String(n).padStart(2, "0")} ·
        </span>
        <span className="mono" style={{ fontSize: 10, color: "var(--sub)", letterSpacing: ".28em", textTransform: "uppercase" }}>
          {text}
        </span>
        <div className="hr-h" style={{ flex: 1 }} />
      </div>
    </Reveal>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════════
   7. AI RISK GAUGE
   ─────────────────────────────────────────────────────────────────────────────
   Two modes:
   • "about"  — auto-runs once on scroll-in (used in About section)
   • "quote"  — externally controlled; caller passes finalScore + onDone
══════════════════════════════════════════════════════════════════════════════ */
function RiskGauge({ mode = "about", finalScore = 82, onDone }) {
  const [phase, setPhase]   = useState(mode === "about" ? "idle" : "idle");
  const [display, setDisplay] = useState(0);
  const timer = useRef(null);
  const containerRef = useRef(null);
  const inView = useInView(containerRef, { once: true });

  // About mode: auto-start on scroll
  useEffect(() => {
    if (mode !== "about" || !inView || phase !== "idle") return;
    startCount(finalScore);
  }, [inView, mode]);

  // Quote mode: start when finalScore changes (not 0)
  useEffect(() => {
    if (mode !== "quote" || finalScore === 0) return;
    setPhase("spin");
    setDisplay(0);
    const spinTimer = setTimeout(() => {
      setPhase("count");
      startCount(finalScore);
    }, 2500);
    return () => clearTimeout(spinTimer);
  }, [finalScore, mode]);

  const startCount = (target) => {
    setPhase("count");
    let v = 0;
    clearInterval(timer.current);
    timer.current = setInterval(() => {
      v += 1;
      setDisplay(v);
      if (v >= target) {
        clearInterval(timer.current);
        setPhase("done");
        onDone && onDone();
      }
    }, 20);
  };

  useEffect(() => () => clearInterval(timer.current), []);

  const R = 86, circ = 2 * Math.PI * R;
  const filled = circ * (display / 100);
  const col = display >= 72 ? "#a78bfa" : display >= 48 ? "#fbbf24" : "#f87171";
  const label = display >= 72 ? "LOW RISK" : display >= 48 ? "MODERATE" : "ELEVATED RISK";

  return (
    <div ref={containerRef} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 20 }}>
      <div style={{ position: "relative", width: 240, height: 240 }}>
        {/* Orbit rings */}
        <svg
          viewBox="0 0 240 240"
          style={{ position: "absolute", inset: 0, width: "100%", height: "100%",
            animation: "rotCW 32s linear infinite" }}
        >
          <circle cx="120" cy="120" r="112" fill="none"
            stroke="rgba(167,139,250,.06)" strokeWidth="1" strokeDasharray="6 16" />
        </svg>
        <svg
          viewBox="0 0 240 240"
          style={{ position: "absolute", inset: 0, width: "100%", height: "100%",
            animation: "rotCCW 22s linear infinite" }}
        >
          <circle cx="120" cy="120" r="98" fill="none"
            stroke="rgba(196,181,253,.05)" strokeWidth="1" strokeDasharray="3 10" />
        </svg>

        {/* Shimmer ring during spin */}
        {phase === "spin" && (
          <div style={{
            position: "absolute", inset: 0, borderRadius: "50%",
            border: "2px solid transparent",
            background: "linear-gradient(135deg,rgba(167,139,250,.4),transparent) border-box",
          }} className="shimmer-sweep" />
        )}

        {/* Main SVG */}
        <svg viewBox="0 0 240 240" style={{
          width: "100%", height: "100%",
          filter: phase === "done" ? `drop-shadow(0 0 14px ${col}60)` : "none",
          transition: "filter .6s",
        }}>
          <defs>
            <radialGradient id="gaugeBg" cx="50%" cy="38%" r="62%">
              <stop offset="0%" stopColor="#1c1040" />
              <stop offset="100%" stopColor="#080612" />
            </radialGradient>
            <linearGradient id="gaugeArc" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#c4b5fd" />
              <stop offset="100%" stopColor="#7c3aed" />
            </linearGradient>
          </defs>

          {/* Background */}
          <circle cx="120" cy="120" r="115" fill="url(#gaugeBg)"
            stroke="rgba(167,139,250,.1)" strokeWidth="1" />

          {/* Track */}
          <circle cx="120" cy="120" r={R} fill="none"
            stroke="rgba(167,139,250,.07)" strokeWidth="9" />

          {/* Progress arc */}
          <circle cx="120" cy="120" r={R} fill="none"
            stroke="url(#gaugeArc)" strokeWidth="9" strokeLinecap="round"
            strokeDasharray={`${filled} ${circ}`}
            transform="rotate(-90 120 120)"
            style={{
              transition: phase === "count" ? "stroke-dasharray .035s linear" : "none",
              filter: `drop-shadow(0 0 7px ${col}88)`,
            }}
          />

          {/* Scan sweep during spin */}
          {phase === "spin" && (
            <circle cx="120" cy="120" r={R} fill="none"
              stroke="rgba(196,181,253,.4)" strokeWidth="9" strokeDasharray="48 999"
              transform="rotate(-90 120 120)">
              <animateTransform attributeName="transform" type="rotate"
                from="-90 120 120" to="270 120 120" dur="1s" repeatCount="indefinite" />
            </circle>
          )}

          {/* Mini pyramid inside */}
          <polygon points="120,55 136,80 104,80" fill="none"
            stroke="rgba(196,181,253,.28)" strokeWidth="1.2" />
          <polygon points="104,83 120,108 88,108" fill="rgba(124,58,237,.1)"
            stroke="rgba(167,139,250,.18)" strokeWidth="1" />
          <polygon points="136,83 152,108 120,108" fill="rgba(196,181,253,.07)"
            stroke="rgba(196,181,253,.16)" strokeWidth="1" />
          <polygon points="104,80 136,80 120,108" fill="rgba(76,29,149,.22)" />

          {/* Score text */}
          {phase !== "idle" && phase !== "spin" && (
            <>
              <text x="120" y="152" textAnchor="middle"
                fontFamily="'Cormorant Garamond',serif" fontSize="48" fontWeight="300"
                fill={col} style={{ transition: "fill .4s" }}>
                {display}
              </text>
              <text x="120" y="170" textAnchor="middle"
                fontFamily="'DM Mono',monospace" fontSize="8.5" fill="var(--sub)" letterSpacing="3">
                / 100
              </text>
            </>
          )}
          {(phase === "idle" || phase === "spin") && (
            <text x="120" y="155" textAnchor="middle"
              fontFamily="'Cormorant Garamond',serif" fontSize="14" fontWeight="300"
              fill="var(--dim)" letterSpacing="2">
              {phase === "spin" ? "SCANNING…" : "AWAITING SCAN"}
            </text>
          )}
        </svg>
      </div>

      {/* Label */}
      <AnimatePresence>
        {phase === "done" && (
          <motion.div key="lbl"
            initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: .5 }}
            style={{ textAlign: "center" }}>
            <div className="mono" style={{ fontSize: 11, letterSpacing: ".2em", color: col, fontWeight: 600 }}>
              {label}
            </div>
            <div className="mono" style={{ fontSize: 9, color: "var(--sub)", marginTop: 4 }}>
              {mode === "about" ? "Sample score" : "Benchmark estimate complete"}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════════
   8. QUOTE ENGINE
   ─────────────────────────────────────────────────────────────────────────────
   Step 1 → form inputs
   Step 2 → animated gauge (2.5 s spin + count-up)
   Step 3 → three plan cards with computed premiums
   Logic: base premium × industry multiplier × size multiplier × risk discount
══════════════════════════════════════════════════════════════════════════════ */

const INDUSTRIES = [
  { label: "Technology / SaaS",      risk: 0.78, mult: 1.00 },
  { label: "Healthcare / MedTech",   risk: 0.58, mult: 1.38 },
  { label: "Finance / FinTech",      risk: 0.54, mult: 1.46 },
  { label: "Legal & Professional",   risk: 0.62, mult: 1.28 },
  { label: "Retail / eCommerce",     risk: 0.74, mult: 0.96 },
  { label: "Manufacturing",          risk: 0.68, mult: 1.10 },
  { label: "Gov / Public Sector",    risk: 0.55, mult: 1.24 },
  { label: "Education",              risk: 0.72, mult: 1.04 },
  { label: "Other",                  risk: 0.66, mult: 1.05 },
];

// adj: larger organisations present a larger attack surface
const EMP_BANDS = [
  { label: "1 – 50 employees",    mult: 0.68, adj:  3 },
  { label: "51 – 200 employees",  mult: 1.00, adj:  0 },
  { label: "201 – 500 employees", mult: 1.42, adj: -4 },
  { label: "500+ employees",      mult: 1.92, adj: -8 },
];

const BASE = { std: 4400, pro: 8200, elite: 15800 };

// Deterministic benchmark: the same answers always give the same score
function computeScore(industryRisk, sizeAdj) {
  return Math.max(22, Math.min(97, Math.round(industryRisk * 100 + sizeAdj)));
}

function computePlans(score, iMult, eMult) {
  const riskMult = score >= 72 ? 0.82 : score >= 48 ? 1.0 : 1.38;
  const fmt = v => "$" + (Math.round((v * iMult * eMult * riskMult) / 50) * 50).toLocaleString();
  const shielded = score < 72;
  return {
    shielded,
    riskLabel: score >= 72 ? "LOW RISK" : score >= 48 ? "MODERATE RISK" : "ELEVATED RISK",
    plans: [
      {
        tier: "Standard", accent: "#a78bfa", popular: false,
        annual: fmt(BASE.std), coverage: "$1M",
        features: [
          "AI Cyber Risk Score (live)",
          "Dark Web Monitoring — 24/7",
          "Basic Incident Response",
          "Alvora Shield — AI Firewall",
          "Email Support",
        ],
      },
      {
        tier: "Pro", accent: "#c4b5fd", popular: true,
        annual: fmt(BASE.pro), coverage: "$5M",
        features: [
          "Everything in Standard",
          "Ethical Hacker Response Team",
          "Real-Time Telemetry Feed",
          "Business Interruption Cover",
          "Quarterly Red Team Assessment",
          "Priority 24/7 Support",
        ],
      },
      {
        tier: "Elite", accent: "#e9d5ff", popular: false,
        annual: fmt(BASE.elite), coverage: "$25M",
        features: [
          "Everything in Pro",
          "Dedicated Security Advisor",
          "Supply-Chain Risk Coverage",
          "Regulatory Breach Support",
          "Custom Underwriting Terms",
          "Board-Level Risk Reporting",
          "White-Glove Onboarding",
        ],
      },
    ],
  };
}

function QuoteEngine({ onSelectPlan }) {
  const [step, setStep] = useState(1);
  const [industry, setIndustry] = useState("");
  const [empBand, setEmpBand]   = useState("");
  const [err, setErr]           = useState("");
  const [score, setScore]       = useState(0);
  const [quoteData, setQuoteData] = useState(null);
  const [gaugeReady, setGaugeReady] = useState(false);

  const handleGenerate = () => {
    if (!industry || !empBand) { setErr("Please select both fields to continue."); return; }
    setErr("");
    const ind = INDUSTRIES.find(i => i.label === industry);
    const emp = EMP_BANDS.find(e => e.label === empBand);
    const computed = computeScore(ind.risk, emp.adj);
    setScore(computed);
    setStep(2);
    setGaugeReady(false);
  };

  const handleGaugeDone = () => {
    setGaugeReady(true);
    const ind = INDUSTRIES.find(i => i.label === industry);
    const emp = EMP_BANDS.find(e => e.label === empBand);
    setQuoteData(computePlans(score, ind.mult, emp.mult));
    // Small delay for elegance
    setTimeout(() => setStep(3), 700);
  };

  const reset = () => { setStep(1); setIndustry(""); setEmpBand(""); setScore(0); setQuoteData(null); setErr(""); };

  // Step dots
  const StepDot = ({ n }) => (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
      <div style={{
        width: 30, height: 30, borderRadius: "50%",
        display: "flex", alignItems: "center", justifyContent: "center",
        background: step > n ? "linear-gradient(135deg,#7c3aed,#a78bfa)"
          : step === n ? "rgba(124,58,237,.22)" : "rgba(167,139,250,.06)",
        border: step >= n ? "1px solid rgba(167,139,250,.45)" : "1px solid rgba(167,139,250,.12)",
        transition: "all .4s",
        boxShadow: step === n ? "0 0 14px rgba(124,58,237,.4)" : "none",
      }}>
        {step > n
          ? <span style={{ fontSize: 13, color: "#fff" }}>✓</span>
          : <span className="mono" style={{ fontSize: 11, color: step === n ? "#c4b5fd" : "var(--dim)" }}>{n}</span>}
      </div>
      <span className="mono" style={{
        fontSize: 8, letterSpacing: ".18em", whiteSpace: "nowrap",
        color: step >= n ? "var(--lav)" : "var(--dim)",
      }}>
        {n === 1 ? "PROFILE" : n === 2 ? "AI SCAN" : "QUOTES"}
      </span>
    </div>
  );

  return (
    <div>
      {/* Step indicator */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 0, marginBottom: 44 }}>
        {[1, 2, 3].map((n, i) => (
          <div key={n} style={{ display: "flex", alignItems: "center" }}>
            <StepDot n={n} />
            {i < 2 && (
              <div style={{
                width: 56, height: 1, margin: "0 8px", marginBottom: 22,
                background: `linear-gradient(90deg, ${step > n ? "rgba(167,139,250,.4)" : "rgba(167,139,250,.1)"}, ${step > n + 1 ? "rgba(167,139,250,.4)" : "rgba(167,139,250,.08)"})`,
                transition: "background .4s",
              }} />
            )}
          </div>
        ))}
      </div>

      <AnimatePresence mode="wait">

        {/* ── STEP 1: INPUTS ─────────────────────────────────────── */}
        {step === 1 && (
          <motion.div key="s1"
            initial={{ opacity: 0, y: 22 }} animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -16 }} transition={{ duration: .5, ease: [.16, 1, .3, 1] }}>
            <div className="glass card-pad" style={{ padding: "40px 44px" }}>
              <div className="mono" style={{ fontSize: 9, color: "var(--lav)", letterSpacing: ".3em", marginBottom: 6, opacity: .8 }}>
                STEP 01 · COMPANY PROFILE
              </div>
              <h3 className="serif" style={{ fontSize: 28, fontWeight: 400, color: "var(--text)", marginBottom: 10, lineHeight: 1.1 }}>
                Tell Us About Your Business
              </h3>
              <p style={{ fontSize: 13, color: "var(--sub)", lineHeight: 1.78, marginBottom: 32 }}>
                Two questions, no paperwork. Get an indicative risk score and premium range
                for businesses like yours in seconds. Your final quote is priced on your own
                live security posture once the Alvora Shield is connected.
              </p>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 20 }} className="two-col">
                {/* Industry */}
                <div>
                  <label htmlFor="q-industry" className="mono" style={{ fontSize: 9, color: "var(--sub)", letterSpacing: ".22em", display: "block", marginBottom: 9 }}>
                    INDUSTRY TYPE
                  </label>
                  <div style={{ position: "relative" }}>
                    <select
                      id="q-industry"
                      className="field"
                      value={industry}
                      onChange={e => { setIndustry(e.target.value); setErr(""); }}
                      style={{ paddingRight: 38 }}
                    >
                      <option value="" disabled>Select industry…</option>
                      {INDUSTRIES.map(i => <option key={i.label} value={i.label}>{i.label}</option>)}
                    </select>
                    <span style={{ position: "absolute", right: 14, top: "50%", transform: "translateY(-50%)", color: "var(--sub)", pointerEvents: "none", fontSize: 11 }}>▾</span>
                  </div>
                </div>

                {/* Employee count */}
                <div>
                  <label htmlFor="q-size" className="mono" style={{ fontSize: 9, color: "var(--sub)", letterSpacing: ".22em", display: "block", marginBottom: 9 }}>
                    EMPLOYEE COUNT
                  </label>
                  <div style={{ position: "relative" }}>
                    <select
                      id="q-size"
                      className="field"
                      value={empBand}
                      onChange={e => { setEmpBand(e.target.value); setErr(""); }}
                      style={{ paddingRight: 38 }}
                    >
                      <option value="" disabled>Select headcount…</option>
                      {EMP_BANDS.map(b => <option key={b.label} value={b.label}>{b.label}</option>)}
                    </select>
                    <span style={{ position: "absolute", right: 14, top: "50%", transform: "translateY(-50%)", color: "var(--sub)", pointerEvents: "none", fontSize: 11 }}>▾</span>
                  </div>
                </div>
              </div>

              {/* Error */}
              <AnimatePresence>
                {err && (
                  <motion.div key="err"
                    initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                    style={{
                      fontSize: 12, color: "#fca5a5", marginBottom: 20,
                      padding: "11px 16px", borderRadius: 8,
                      background: "rgba(248,113,113,.07)", border: "1px solid rgba(248,113,113,.22)",
                      display: "flex", alignItems: "center", gap: 8,
                    }}>
                    <span style={{ fontSize: 14 }}>⚠</span> {err}
                  </motion.div>
                )}
              </AnimatePresence>

              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 16 }}>
                <button className="btn btn-solid" onClick={handleGenerate} style={{ padding: "14px 38px" }}>
                  ⚡ Generate AI Quote
                </button>
                <div className="mono" style={{ fontSize: 9, color: "var(--dim)", letterSpacing: ".18em", lineHeight: 1.7 }}>
                  INDICATIVE ESTIMATE<br />NO PERSONAL DATA NEEDED
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {/* ── STEP 2: AI SCAN ────────────────────────────────────── */}
        {step === 2 && (
          <motion.div key="s2"
            initial={{ opacity: 0, scale: .97 }} animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: .97 }} transition={{ duration: .5 }}>
            <div className="glass card-pad" style={{ padding: "52px 44px", textAlign: "center" }}>
              <div className="mono" style={{ fontSize: 9, color: "var(--lav)", letterSpacing: ".3em", marginBottom: 8, opacity: .8 }}>
                STEP 02 · AI RISK ANALYSIS
              </div>
              <h3 className="serif" style={{ fontSize: 28, fontWeight: 400, color: "var(--text)", marginBottom: 16 }}>
                Scoring Your Profile
              </h3>
              <p style={{ fontSize: 13, color: "var(--sub)", maxWidth: 440, margin: "0 auto 36px", lineHeight: 1.8 }}>
                Alvora's risk model is weighing your sector's threat exposure and your
                organisation's size to estimate where you sit against comparable businesses.
              </p>

              <div style={{ display: "flex", justifyContent: "center", marginBottom: 36 }}>
                <RiskGauge mode="quote" finalScore={score} onDone={handleGaugeDone} />
              </div>

              {/* Activity log */}
              <div style={{ maxWidth: 400, margin: "0 auto", textAlign: "left" }}>
                {[
                  "Weighing sector threat exposure…",
                  "Adjusting for organisation size…",
                  "Computing benchmark risk score…",
                ].map((line, i) => (
                  <motion.div key={line}
                    initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: .5 + i * .7, duration: .4 }}
                    style={{
                      display: "flex", alignItems: "center", gap: 12,
                      padding: "9px 0", borderBottom: "1px solid rgba(167,139,250,.06)",
                    }}>
                    <motion.div
                      initial={{ scale: 0 }} animate={{ scale: 1 }}
                      transition={{ delay: .7 + i * .7, type: "spring", stiffness: 200 }}
                      style={{ width: 6, height: 6, borderRadius: "50%", background: "#a78bfa",
                        boxShadow: "0 0 6px #a78bfa", flexShrink: 0 }}
                    />
                    <span className="mono" style={{ fontSize: 11, color: "var(--sub)" }}>{line}</span>
                  </motion.div>
                ))}
              </div>
            </div>
          </motion.div>
        )}

        {/* ── STEP 3: QUOTE RESULTS ──────────────────────────────── */}
        {step === 3 && quoteData && (
          <motion.div key="s3"
            initial={{ opacity: 0, y: 28 }} animate={{ opacity: 1, y: 0 }}
            transition={{ duration: .7, ease: [.16, 1, .3, 1] }}>

            {/* Score banner */}
            <motion.div initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: .1 }}
              className="glass-sm"
              style={{ padding: "20px 28px", marginBottom: 22, display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 14 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
                <div style={{ textAlign: "center" }}>
                  <div className="serif" style={{
                    fontSize: 44, fontWeight: 300, lineHeight: 1,
                    color: score >= 72 ? "#a78bfa" : score >= 48 ? "#fbbf24" : "#f87171",
                  }}>{score}</div>
                  <div className="mono" style={{ fontSize: 8, color: "var(--sub)", letterSpacing: 2 }}>/ 100</div>
                </div>
                <div style={{ borderLeft: "1px solid rgba(167,139,250,.12)", paddingLeft: 18 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text)", marginBottom: 4 }}>
                    {quoteData.riskLabel} · {industry.split("/")[0].trim()} · {empBand.split(" ")[0]}–{empBand.split("–")[1]?.split(" ")[0] || "+"} employees
                  </div>
                  <div style={{ fontSize: 12, color: "var(--sub)", lineHeight: 1.6 }}>
                    Indicative estimate from{" "}
                    <span style={{ color: "#c4b5fd" }}>industry &amp; size benchmarks</span>
                    {" "}— final pricing uses your live security posture.
                    {quoteData.shielded && (
                      <span style={{ color: "#a78bfa" }}> Alvora Shield rate discount applied.</span>
                    )}
                  </div>
                </div>
              </div>
              <button className="btn btn-outline" onClick={reset} style={{ padding: "9px 20px", fontSize: 11 }}>
                ↺ New Quote
              </button>
            </motion.div>

            {/* Plan cards */}
            <div className="three-col" style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 16, marginBottom: 22 }}>
              {quoteData.plans.map((plan, i) => (
                <motion.div key={plan.tier}
                  initial={{ opacity: 0, y: 32 }} animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: .16 + i * .1, duration: .65, ease: [.16, 1, .3, 1] }}
                  style={{
                    position: "relative", borderRadius: 18, padding: "30px 26px",
                    background: plan.popular
                      ? "linear-gradient(160deg, rgba(22,16,52,.96) 0%, rgba(13,10,30,.92) 100%)"
                      : "rgba(13,11,28,.88)",
                    backdropFilter: "blur(24px)",
                    border: `1px solid ${plan.popular ? "rgba(167,139,250,.42)" : "rgba(167,139,250,.13)"}`,
                    animation: plan.popular ? "glowPulse 3s ease-in-out infinite, floatCard 4.5s ease-in-out infinite" : "none",
                  }}>

                  {/* Top accent line on popular */}
                  {plan.popular && (
                    <div style={{
                      position: "absolute", top: 0, left: 0, right: 0, height: 2, borderRadius: "18px 18px 0 0",
                      background: "linear-gradient(90deg, transparent, #a78bfa, #c4b5fd, #a78bfa, transparent)",
                    }} />
                  )}

                  {plan.popular && (
                    <div style={{
                      position: "absolute", top: 14, right: 14,
                      background: "linear-gradient(135deg,#7c3aed,#a78bfa)",
                      padding: "3px 10px", borderRadius: 20,
                    }}>
                      <span className="mono" style={{ fontSize: 8, color: "#fff", letterSpacing: ".18em" }}>MOST POPULAR</span>
                    </div>
                  )}

                  {/* Pyramid mini-icon */}
                  <div style={{ marginBottom: 18 }}>
                    <PyramidLogo size={22} />
                  </div>

                  <div className="mono" style={{ fontSize: 9, color: plan.accent, letterSpacing: ".2em", marginBottom: 10, opacity: .85 }}>
                    {plan.tier.toUpperCase()} PLAN
                  </div>

                  <div style={{ marginBottom: 6 }}>
                    <span className="serif" style={{ fontSize: 36, fontWeight: 300, color: "var(--text)", lineHeight: 1 }}>
                      {plan.annual}
                    </span>
                    <span className="mono" style={{ fontSize: 10, color: "var(--sub)", marginLeft: 6 }}>/yr</span>
                  </div>
                  <div style={{ fontSize: 12, color: plan.accent, fontWeight: 500, marginBottom: 6 }}>
                    Up to {plan.coverage} coverage
                  </div>

                  {/* Shield rate discount badge */}
                  {quoteData.shielded && (
                    <div style={{
                      fontSize: 11, color: "#34d399", marginBottom: 14,
                      padding: "5px 10px", borderRadius: 6,
                      background: "rgba(52,211,153,.07)", border: "1px solid rgba(52,211,153,.18)",
                    }}>
                      ✦ Rate reduced by Alvora Shield
                    </div>
                  )}

                  <div className="hr-h" style={{ margin: "16px 0" }} />

                  {/* Features */}
                  <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 24 }}>
                    {plan.features.map(f => (
                      <div key={f} style={{ display: "flex", alignItems: "flex-start", gap: 9 }}>
                        <span style={{ color: plan.accent, fontSize: 11, marginTop: 1, flexShrink: 0 }}>◎</span>
                        <span style={{ fontSize: 12, color: "#9d9ab8", lineHeight: 1.5 }}>{f}</span>
                      </div>
                    ))}
                  </div>

                  <button
                    className={`btn ${plan.popular ? "btn-solid" : "btn-outline"}`}
                    style={{ width: "100%", padding: "12px 20px" }}
                    onClick={() => onSelectPlan && onSelectPlan(`${plan.tier} (${plan.annual}/yr est., ${industry}, ${empBand})`)}
                  >
                    Request {plan.tier}
                  </button>
                </motion.div>
              ))}
            </div>

            {/* Footer note */}
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: .65 }}
              className="glass-sm" style={{ padding: "18px 26px", textAlign: "center" }}>
              <p style={{ fontSize: 12, color: "var(--sub)", lineHeight: 1.8 }}>
                <span style={{ color: "#c4b5fd" }}>The Alvora Shield</span> — AI Firewall and Ethical Hacker Response Team —
                is included across <span style={{ color: "#c4b5fd" }}>all plans</span> to actively
                maintain your risk posture and preserve your quoted rate. All operations are strictly
                defensive and fully authorised.
              </p>
              <p className="mono" style={{ fontSize: 9, color: "var(--sub)", letterSpacing: ".12em", lineHeight: 1.8, marginTop: 10 }}>
                FIGURES ARE INDICATIVE ESTIMATES FOR ILLUSTRATION ONLY AND ARE NOT AN OFFER OF INSURANCE.
                COVERAGE IS SUBJECT TO UNDERWRITING AND POLICY TERMS.
              </p>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════════
   9. DARK WEB ALERT FEED
══════════════════════════════════════════════════════════════════════════════ */
const FEED = [
  { sev: "CRITICAL", col: "#f87171", msg: "3 corporate emails indexed in BreachForums data dump" },
  { sev: "HIGH",     col: "#fb923c", msg: "Domain lookalike alv0racyber[.]io registered 4 h ago" },
  { sev: "HIGH",     col: "#fb923c", msg: "C2 beacon signature matching SILKTHREAD APT detected" },
  { sev: "MEDIUM",   col: "#fbbf24", msg: "API token fragment exposed in public GitHub repository" },
  { sev: "LOW",      col: "#a78bfa", msg: "SSL cert on api.domain.com expires in 11 days" },
  { sev: "INFO",     col: "#6b7280", msg: "Threat actor forum targeting SMEs in FinTech vertical" },
];

function DarkWebFeed() {
  const [start, setStart] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setStart(p => (p + 1) % FEED.length), 3200);
    return () => clearInterval(t);
  }, []);
  const items = Array.from({ length: 4 }, (_, i) => FEED[(start + i) % FEED.length]);

  return (
    <div>
      {items.map((a, i) => (
        <motion.div key={`${a.msg}-${i}`}
          initial={{ opacity: 0, x: -12 }} animate={{ opacity: 1, x: 0 }}
          transition={{ duration: .38, delay: i * .05 }}
          style={{
            display: "flex", alignItems: "center", gap: 13,
            padding: "13px 0", borderBottom: "1px solid rgba(167,139,250,.06)",
          }}>
          <div style={{
            padding: "2px 8px", borderRadius: 4, flexShrink: 0,
            background: `${a.col}14`, border: `1px solid ${a.col}30`,
            fontFamily: "'DM Mono',monospace", fontSize: 9, color: a.col, letterSpacing: 1,
          }}>
            {a.sev}
          </div>
          <span style={{ fontSize: 12, color: "#9d9ab8", flex: 1, lineHeight: 1.5 }}>{a.msg}</span>
        </motion.div>
      ))}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════════
   10. WAITLIST FORM — Formspree POST
   ─────────────────────────────────────────────────────────────────────────────
   Endpoint: https://formspree.io/f/mgolnpzw
   Fields sent: name, company, email (name="email" so Formspree identifies it)
   Validation: non-empty + regex before any network call
   States: idle → submitting → success | error
══════════════════════════════════════════════════════════════════════════════ */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const FORMSPREE  = "https://formspree.io/f/mgolnpzw";

function WaitlistForm({ plan = "", onClearPlan }) {
  const [name,    setName]    = useState("");
  const [company, setCompany] = useState("");
  const [email,   setEmail]   = useState("");
  const [emailErr, setEmailErr] = useState("");
  const [status,  setStatus]  = useState("idle"); // idle | submitting | success | error

  const handleSubmit = async () => {
    // Validate
    if (!email.trim()) { setEmailErr("Please enter your work email address."); return; }
    if (!EMAIL_RE.test(email.trim())) { setEmailErr("Please enter a valid email address."); return; }
    setEmailErr("");
    setStatus("submitting");

    try {
      const res = await fetch(FORMSPREE, {
        method:  "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body:    JSON.stringify({ name, company, email: email.trim(), ...(plan && { plan }) }),
      });
      setStatus(res.ok ? "success" : "error");
    } catch {
      setStatus("error");
    }
  };

  return (
    <AnimatePresence mode="wait">

      {/* ── SUCCESS ── */}
      {status === "success" && (
        <motion.div key="ok"
          initial={{ opacity: 0, scale: .93, y: 16 }} animate={{ opacity: 1, scale: 1, y: 0 }}
          transition={{ duration: .7, ease: [.16, 1, .3, 1] }}
          className="glass" style={{ padding: "68px 52px", position: "relative", overflow: "hidden", textAlign: "center" }}>
          {/* Top shimmer */}
          <div style={{
            position: "absolute", top: 0, left: 0, right: 0, height: 2,
            background: "linear-gradient(90deg, transparent, #a78bfa, #c4b5fd, #a78bfa, transparent)",
          }} />
          {/* Radial bloom */}
          <div style={{
            position: "absolute", top: "50%", left: "50%", transform: "translate(-50%,-50%)",
            width: 320, height: 320, borderRadius: "50%", pointerEvents: "none",
            background: "radial-gradient(circle, rgba(124,58,237,.07) 0%, transparent 70%)",
          }} />

          <motion.div
            initial={{ scale: .4, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
            transition={{ delay: .2, type: "spring", stiffness: 160, damping: 12 }}
            style={{ display: "flex", justifyContent: "center", marginBottom: 28 }}>
            <PyramidLogo size={52} glow />
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: .38 }}>
            <div className="mono" style={{ fontSize: 10, color: "var(--lav)", letterSpacing: ".35em", marginBottom: 16, opacity: .8 }}>
              ACCESS GRANTED
            </div>
            <h3 className="serif" style={{ fontSize: "clamp(26px,4vw,40px)", fontWeight: 300, color: "var(--text)", lineHeight: 1.1, marginBottom: 18 }}>
              Welcome to the Future<br />
              <em style={{ color: "var(--lav-lt)", fontStyle: "italic" }}>of Alvora.</em>
            </h3>
          </motion.div>

          <motion.p initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: .52 }}
            style={{ fontSize: 14, color: "var(--sub)", lineHeight: 1.85, maxWidth: 400, margin: "0 auto 32px" }}>
            You're on the list. We'll reach out at the email you provided to arrange your
            complimentary AI risk assessment as early access opens.
          </motion.p>

          <motion.div initial={{ scaleX: 0 }} animate={{ scaleX: 1 }} transition={{ delay: .66, duration: .8 }}
            className="hr-h" style={{ maxWidth: 220, margin: "0 auto 26px" }} />

          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: .82 }}
            style={{ display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap" }}>
            {["Priority Access", "Complimentary Assessment", "Early Onboarding"].map(t => (
              <span key={t} style={{
                fontFamily: "'DM Mono',monospace", fontSize: 9, letterSpacing: ".18em",
                color: "var(--lav)", border: "1px solid rgba(167,139,250,.22)",
                padding: "5px 14px", borderRadius: 20, background: "rgba(167,139,250,.05)",
              }}>
                ✦ {t}
              </span>
            ))}
          </motion.div>
        </motion.div>
      )}

      {/* ── FORM ── */}
      {status !== "success" && (
        <motion.div key="form" exit={{ opacity: 0, y: -10 }} transition={{ duration: .3 }}>
          <div className="glass card-pad" style={{ padding: "42px 46px", textAlign: "left" }}>

            {/* Network error banner */}
            <AnimatePresence>
              {status === "error" && (
                <motion.div key="neterr"
                  initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                  style={{
                    padding: "12px 18px", marginBottom: 22, borderRadius: 8,
                    background: "rgba(248,113,113,.07)", border: "1px solid rgba(248,113,113,.24)",
                    fontSize: 12, color: "#fca5a5", lineHeight: 1.6,
                    display: "flex", alignItems: "center", gap: 8,
                  }}>
                  <span style={{ fontSize: 14 }}>⚠</span>
                  Something went wrong. Please try again in a moment.
                </motion.div>
              )}
            </AnimatePresence>

            {/* Plan carried over from the quote engine */}
            {plan && (
              <div className="glass-sm" style={{ padding: "11px 16px", marginBottom: 20, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
                <span style={{ fontSize: 12, color: "var(--lav-lt)" }}>Interested in: {plan}</span>
                <button type="button" className="nav-btn" onClick={onClearPlan} aria-label="Remove selected plan" style={{ fontSize: 14, letterSpacing: 0 }}>✕</button>
              </div>
            )}

            {/* Name + Company */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }} className="two-col">
              <div>
                <label htmlFor="w-name" className="mono" style={{ fontSize: 9, color: "var(--sub)", letterSpacing: ".22em", display: "block", marginBottom: 9 }}>
                  FULL NAME
                </label>
                <input
                  id="w-name"
                  autoComplete="name"
                  className="field"
                  name="name"
                  placeholder="Jane Smith"
                  value={name}
                  onChange={e => setName(e.target.value)}
                  disabled={status === "submitting"}
                />
              </div>
              <div>
                <label htmlFor="w-company" className="mono" style={{ fontSize: 9, color: "var(--sub)", letterSpacing: ".22em", display: "block", marginBottom: 9 }}>
                  COMPANY
                </label>
                <input
                  id="w-company"
                  autoComplete="organization"
                  className="field"
                  name="company"
                  placeholder="Acme Corp"
                  value={company}
                  onChange={e => setCompany(e.target.value)}
                  disabled={status === "submitting"}
                />
              </div>
            </div>

            {/* Email */}
            <div style={{ marginBottom: 8 }}>
              <label htmlFor="w-email" className="mono" style={{ fontSize: 9, color: "var(--sub)", letterSpacing: ".22em", display: "block", marginBottom: 9 }}>
                WORK EMAIL <span style={{ color: "var(--red)" }}>*</span>
              </label>
              <input
                id="w-email"
                autoComplete="email"
                aria-invalid={!!emailErr}
                className={`field${emailErr ? " field-err" : ""}`}
                type="email"
                name="email"
                placeholder="jane@company.com"
                value={email}
                onChange={e => { setEmail(e.target.value); if (emailErr) setEmailErr(""); if (status === "error") setStatus("idle"); }}
                disabled={status === "submitting"}
              />
            </div>

            {/* Inline email error */}
            <AnimatePresence>
              {emailErr && (
                <motion.div key="emaerr"
                  initial={{ opacity: 0, y: -5 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                  style={{ fontSize: 11, color: "#fca5a5", marginBottom: 18, display: "flex", alignItems: "center", gap: 6 }}>
                  <span>⚠</span> {emailErr}
                </motion.div>
              )}
            </AnimatePresence>

            {!emailErr && <div style={{ marginBottom: 30 }} />}

            {/* Submit */}
            <div style={{ textAlign: "center" }}>
              <button
                className="btn btn-solid"
                style={{ padding: "15px 56px", opacity: status === "submitting" ? .7 : 1 }}
                disabled={status === "submitting"}
                onClick={handleSubmit}
              >
                {status === "submitting"
                  ? <><span style={{
                      display: "inline-block", width: 12, height: 12, borderRadius: "50%",
                      border: "2px solid rgba(255,255,255,.35)", borderTopColor: "#fff",
                      animation: "rotCW .75s linear infinite",
                    }} /> Submitting…</>
                  : "Request Early Access →"}
              </button>
            </div>

            <div style={{ textAlign: "center", marginTop: 18 }}>
              <span className="mono" style={{ fontSize: 9, color: "var(--dim)", letterSpacing: ".2em" }}>
                NO COMMITMENT · STRICTLY CONFIDENTIAL · COMPLIMENTARY ASSESSMENT
              </span>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════════
   11. SERVICE CARD
══════════════════════════════════════════════════════════════════════════════ */
function ServiceCard({ n, icon, title, sub, body, tags, accent = "#a78bfa", delay = 0 }) {
  const [hov, setHov] = useState(false);
  return (
    <Reveal delay={delay}>
      <div
        className="glass"
        onMouseEnter={() => setHov(true)}
        onMouseLeave={() => setHov(false)}
        style={{
          padding: 30, height: "100%", transition: "all .35s ease",
          borderColor: hov ? "rgba(167,139,250,.42)" : "rgba(167,139,250,.14)",
          boxShadow: hov ? "0 0 44px rgba(124,58,237,.14)" : "none",
          position: "relative", overflow: "hidden",
        }}
      >
        <div style={{
          position: "absolute", top: 16, right: 20,
          fontFamily: "'Cormorant Garamond',serif", fontSize: 60, fontWeight: 300,
          color: accent, opacity: .06, lineHeight: 1, userSelect: "none",
        }}>
          {n}
        </div>
        <div style={{ fontSize: 26, marginBottom: 18 }}>{icon}</div>
        <div className="mono" style={{ fontSize: 9, color: accent, letterSpacing: ".22em", marginBottom: 10, opacity: .82 }}>{sub}</div>
        <h3 className="serif" style={{ fontSize: 22, fontWeight: 400, color: "var(--text)", lineHeight: 1.2, marginBottom: 14 }}>{title}</h3>
        <p style={{ fontSize: 13, color: "var(--sub)", lineHeight: 1.85, marginBottom: 22 }}>{body}</p>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 7 }}>
          {tags.map(t => (
            <span key={t} className="mono" style={{
              fontSize: 9, padding: "4px 10px", borderRadius: 4, letterSpacing: ".14em",
              color: accent, border: `1px solid ${accent}22`, background: `${accent}09`,
            }}>{t}</span>
          ))}
        </div>
      </div>
    </Reveal>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════════
   12. ROOT APP
══════════════════════════════════════════════════════════════════════════════ */
// Moves via a ref so pointer movement never re-renders the page
function CursorHalo() {
  const ref = useRef(null);
  useEffect(() => {
    const move = e => {
      if (ref.current) ref.current.style.transform = `translate(${e.clientX}px, ${e.clientY}px)`;
    };
    window.addEventListener("mousemove", move);
    return () => window.removeEventListener("mousemove", move);
  }, []);
  return <div ref={ref} className="c-ring" style={{ transform: "translate(-200px,-200px)" }} aria-hidden="true" />;
}

export default function App() {
  const [plan, setPlan] = useState("");

  const goto = id => document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
  const selectPlan = p => { setPlan(p); goto("waitlist"); };

  return (
    <>
      <style dangerouslySetInnerHTML={{ __html: GLOBAL_CSS }} />

      <CursorHalo />

      {/* Neural network BG */}
      <NeuralBg />

      <div style={{ position: "relative", zIndex: 1 }}>

        {/* ═══ NAV ═══════════════════════════════════════════════════════════ */}
        <nav className="nav-bar" style={{
          position: "fixed", top: 0, left: 0, right: 0, zIndex: 200,
          height: 66, padding: "0 48px",
          display: "flex", alignItems: "center", justifyContent: "space-between",
          background: "rgba(7,7,15,.88)", backdropFilter: "blur(26px)",
          borderBottom: "1px solid rgba(167,139,250,.08)",
        }}>
          <Brand size={36} />
          <div className="nav-links" style={{ display: "flex", gap: 34 }}>
            {[["ABOUT","about"],["SHIELD","shield"],["SERVICES","services"],["QUOTE","quote"],["WAITLIST","waitlist"]].map(([l, id]) => (
              <button key={id} className="nav-btn" onClick={() => goto(id)}>{l}</button>
            ))}
          </div>
          <button className="btn btn-solid" style={{ padding: "10px 22px", fontSize: 11 }} onClick={() => goto("quote")}>
            Get a Quote
          </button>
        </nav>

        {/* ═══ HERO ══════════════════════════════════════════════════════════ */}
        <section style={{
          minHeight: "100vh", display: "flex", flexDirection: "column",
          justifyContent: "center", alignItems: "center", textAlign: "center",
          padding: "120px 40px 80px", position: "relative", overflow: "hidden",
        }} className="hero-pad">
          {/* Radial bloom */}
          <div style={{
            position: "absolute", top: "50%", left: "50%",
            transform: "translate(-50%,-50%)", width: 820, height: 820,
            borderRadius: "50%", pointerEvents: "none",
            background: "radial-gradient(circle, rgba(124,58,237,.055) 0%, transparent 68%)",
          }} />

          {/* Brand lockup */}
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: .7 }}
            style={{ marginBottom: 28 }}>
            <div style={{ display: "flex", justifyContent: "center", marginBottom: 12 }}>
              <Brand size={48} />
            </div>
            <div className="mono" style={{ fontSize: 10, color: "var(--dim)", letterSpacing: ".36em" }}>
              EST. 2025 · AI-DRIVEN CYBER INSURANCE
            </div>
          </motion.div>

          {/* Headline */}
          <motion.h1
            className="serif"
            initial={{ opacity: 0, y: 52, filter: "blur(18px)" }}
            animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
            transition={{ duration: 1.05, delay: .18, ease: [.16, 1, .3, 1] }}
            style={{
              fontSize: "clamp(44px, 8vw, 112px)", fontWeight: 300, lineHeight: .93,
              letterSpacing: "-.02em", marginBottom: 28, color: "var(--text)",
            }}
          >
            Precision Intelligence.<br />
            <em style={{ color: "var(--lav-lt)", fontStyle: "italic" }}>Absolute Defense.</em>
          </motion.h1>

          {/* Tagline */}
          <motion.p
            initial={{ opacity: 0, y: 26, filter: "blur(10px)" }}
            animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
            transition={{ duration: .95, delay: .38, ease: [.16, 1, .3, 1] }}
            style={{
              fontSize: "clamp(14px,1.6vw,18px)", color: "var(--sub)",
              lineHeight: 1.82, maxWidth: 540, marginBottom: 50, letterSpacing: ".03em",
            }}
          >
            Alvora Cyber reimagines cyber insurance for SMEs and individuals — replacing
            outdated guesswork with real-time AI intelligence and wrapping every client in
            a living Shield that never sleeps.
          </motion.p>

          {/* CTAs */}
          <motion.div
            initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }}
            transition={{ duration: .75, delay: .58 }}
            style={{ display: "flex", gap: 16, justifyContent: "center", flexWrap: "wrap" }}
          >
            <button className="btn btn-solid" onClick={() => goto("quote")}>⚡ Get Instant Quote</button>
            <button className="btn btn-outline" onClick={() => goto("about")}>Discover Alvora</button>
          </motion.div>

          {/* Scroll cue */}
          <div style={{
            position: "absolute", bottom: 38, left: "50%",
            display: "flex", flexDirection: "column", alignItems: "center", gap: 9,
            animation: "scrollBob 2.4s ease-in-out infinite",
          }}>
            <span className="mono" style={{ fontSize: 9, color: "var(--dim)", letterSpacing: ".3em" }}>SCROLL TO READ</span>
            <svg width="15" height="25" viewBox="0 0 15 25">
              <rect x=".5" y=".5" width="14" height="24" rx="7" stroke="rgba(167,139,250,.22)" fill="none" />
              <rect x="6.5" y="4" width="2" height="7" rx="1" fill="rgba(167,139,250,.42)" />
            </svg>
          </div>
        </section>

        {/* ═══ STATS BAR ═════════════════════════════════════════════════════ */}
        <div style={{ padding: "0 48px" }}>
          <div className="hr-h" />
          <div style={{ display: "flex", justifyContent: "space-around", padding: "42px 0", flexWrap: "wrap", gap: 24 }}>
            {[["< 3 min", "AI Risk Assessment"], ["0 – 100", "Live Risk Score"], ["24 / 7", "Threat Monitoring"], ["Est. 2025", "Founded"]].map(([v, l]) => (
              <div key={l} style={{ textAlign: "center" }}>
                <div className="serif" style={{ fontSize: 36, fontWeight: 300, color: "var(--lav-lt)", lineHeight: 1 }}>{v}</div>
                <div className="mono" style={{ fontSize: 10, color: "var(--sub)", marginTop: 6, letterSpacing: ".2em" }}>{l}</div>
              </div>
            ))}
          </div>
          <div className="hr-h" />
        </div>

        {/* ═══ ABOUT ═════════════════════════════════════════════════════════ */}
        <section id="about" style={{ padding: "110px 64px", maxWidth: 1240, margin: "0 auto" }} className="sec-pad">
          <SectionLabel n={1} text="About Alvora" />
          <div className="two-col" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 80, alignItems: "center" }}>
            <div>
              <Reveal>
                <h2 className="serif" style={{ fontSize: "clamp(32px,4vw,56px)", fontWeight: 300, lineHeight: 1.08, marginBottom: 26, color: "var(--text)" }}>
                  The Market Was Built<br />
                  <em style={{ color: "var(--lav)", fontStyle: "italic" }}>on Broken Assumptions.</em>
                </h2>
              </Reveal>
              <Reveal delay={.1}>
                <p style={{ fontSize: 14, color: "var(--sub)", lineHeight: 1.95, marginBottom: 20 }}>
                  Traditional cyber underwriting asks businesses to self-assess their own risk once a year
                  on a paper form. In a threat landscape that evolves by the hour, this approach is not
                  just outdated — it is a liability for everyone involved.
                </p>
              </Reveal>
              <Reveal delay={.18}>
                <p style={{ fontSize: 14, color: "var(--sub)", lineHeight: 1.95, marginBottom: 34 }}>
                  Alvora Cyber was founded in 2025 to disrupt this paradigm. We replace manual
                  questionnaires with a{" "}
                  <span style={{ color: "var(--lav-lt)" }}>living, AI-Driven Underwriting Ecosystem</span>{" "}
                  — one that reads your real-time security posture and prices your policy to reflect
                  actual risk, not a yearly estimate.
                </p>
              </Reveal>
              <Reveal delay={.26}>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 14 }}>
                  {[["Real-Time", "AI telemetry, not static forms"], ["Fair Pricing", "Priced to actual posture"], ["Always On", "Continuous recalibration"]].map(([t, d]) => (
                    <div key={t} className="glass-sm" style={{ padding: "16px 14px" }}>
                      <div style={{ fontSize: 12, color: "var(--lav)", letterSpacing: ".12em", marginBottom: 5, fontWeight: 500 }}>{t}</div>
                      <div style={{ fontSize: 11, color: "var(--sub)", lineHeight: 1.55 }}>{d}</div>
                    </div>
                  ))}
                </div>
              </Reveal>
            </div>

            {/* About gauge auto-runs on scroll */}
            <Reveal delay={.14} blur={false}>
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 16 }}>
                <RiskGauge mode="about" finalScore={84} />
                <div className="mono" style={{ fontSize: 9, color: "var(--sub)", letterSpacing: ".25em" }}>
                  ILLUSTRATIVE ALVORA RISK SCORE
                </div>
              </div>
            </Reveal>
          </div>
        </section>

        {/* ═══ ALVORA SHIELD ═════════════════════════════════════════════════ */}
        <section id="shield" style={{
          padding: "110px 64px",
          background: "linear-gradient(to bottom, transparent, rgba(124,58,237,.025), transparent)",
        }} className="sec-pad">
          <div style={{ maxWidth: 1240, margin: "0 auto" }}>
            <SectionLabel n={2} text="The Alvora Shield" />
            <div style={{ textAlign: "center", marginBottom: 68 }}>
              <Reveal>
                <h2 className="serif" style={{ fontSize: "clamp(32px,4vw,56px)", fontWeight: 300, lineHeight: 1.08, color: "var(--text)", marginBottom: 18 }}>
                  The Proactive Defense Moat
                </h2>
              </Reveal>
              <Reveal delay={.1}>
                <p style={{ fontSize: 15, color: "var(--sub)", maxWidth: 560, margin: "0 auto", lineHeight: 1.88 }}>
                  The Alvora Shield is not a passive policy. It is a multi-layered, continuously active
                  defense ecosystem that prevents breaches before they become insurance claims.
                </p>
              </Reveal>
            </div>

            <div className="two-col" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 3 }}>
              {[
                {
                  n: "I", accent: "#a78bfa",
                  title: "Real-Time AI Firewall Intelligence",
                  body: "Our firewall layer goes beyond static rules. Alvora's AI continuously ingests global threat intelligence, applies behavioural traffic analysis, and pushes adaptive rule updates to your perimeter in real time — turning a passive boundary into a self-learning, dynamic shield.",
                  tags: ["Adaptive Rule Engine", "Behavioural Analysis", "Global Threat Feeds", "Zero-Day Pattern Matching"],
                },
                {
                  n: "II", accent: "#c4b5fd",
                  title: "Ethical Hacker Response Team",
                  body: "A standing cohort of certified security professionals conducts continuous, authorised vulnerability discovery, red team exercises, and penetration testing across your entire digital footprint. Every engagement is strictly defensive and fully consensual — closing gaps before adversaries can reach them.",
                  tags: ["Authorised Pen Testing", "Red Team Assessments", "Vulnerability Discovery", "Remediation Guidance"],
                },
              ].map((p, i) => (
                <Reveal key={p.n} delay={i * .12}>
                  <div style={{
                    padding: "50px 44px", border: "1px solid rgba(167,139,250,.09)",
                    borderRadius: 3, height: "100%", position: "relative",
                    background: "linear-gradient(140deg, rgba(14,12,30,.72) 0%, rgba(7,7,15,.55) 100%)",
                  }}>
                    <div className="serif" style={{
                      position: "absolute", top: 24, right: 32,
                      fontSize: 80, color: p.accent, opacity: .07, fontWeight: 300, lineHeight: 1,
                    }}>{p.n}</div>
                    <div className="mono" style={{ fontSize: 9, color: p.accent, letterSpacing: ".3em", marginBottom: 18, opacity: .75 }}>LAYER {p.n}</div>
                    <h3 className="serif" style={{ fontSize: 26, fontWeight: 400, color: "var(--text)", lineHeight: 1.2, marginBottom: 20 }}>{p.title}</h3>
                    <p style={{ fontSize: 13, color: "var(--sub)", lineHeight: 1.92, marginBottom: 28 }}>{p.body}</p>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 7 }}>
                      {p.tags.map(t => (
                        <span key={t} className="mono" style={{
                          fontSize: 9, letterSpacing: ".16em", color: p.accent,
                          border: `1px solid ${p.accent}22`, padding: "5px 11px",
                          opacity: .78, borderRadius: 4,
                        }}>{t}</span>
                      ))}
                    </div>
                  </div>
                </Reveal>
              ))}
            </div>
          </div>
        </section>

        {/* ═══ SERVICES ══════════════════════════════════════════════════════ */}
        <section id="services" style={{ padding: "110px 64px", maxWidth: 1240, margin: "0 auto" }} className="sec-pad">
          <SectionLabel n={3} text="Services" />
          <Reveal>
            <h2 className="serif" style={{ fontSize: "clamp(32px,4vw,54px)", fontWeight: 300, lineHeight: 1.08, color: "var(--text)", marginBottom: 56 }}>
              Four Pillars of<br />
              <em style={{ color: "var(--lav)", fontStyle: "italic" }}>Total Resilience.</em>
            </h2>
          </Reveal>
          <div className="two-col" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 18 }}>
            <ServiceCard n="01" icon="◎" accent="#a78bfa" delay={0}
              title="AI Cyber Risk Score" sub="Real-time 0–100 risk metric"
              body="Our AI engine ingests continuous security telemetry — endpoint signals, network behaviour, patch compliance, access patterns — and translates it into a single, legible 0–100 score that updates in real time. Your risk is a living measurement, not a yearly snapshot."
              tags={["Live Telemetry", "Continuous Updates", "Posture Benchmarking", "Board Reporting"]} />
            <ServiceCard n="02" icon="◈" accent="#c4b5fd" delay={.08}
              title="AI-Driven Underwriting" sub="Disrupting the insurance market"
              body="We replace outdated annual questionnaires with a real-time telemetry pipeline. Insurance partners receive continuously refreshed risk profiles — enabling fair, dynamic underwriting based on actual behaviour, not self-reported estimates completed once a year."
              tags={["API Integration", "Dynamic Pricing", "Partner Network", "Regulatory Compliant"]} />
            <ServiceCard n="03" icon="◇" accent="#a78bfa" delay={.16}
              title="Dark Web Monitoring" sub="24/7 surveillance & recovery guidance"
              body="Alvora monitors thousands of dark web forums, breach databases, paste sites, and threat actor channels around the clock. When your credentials surface, you receive immediate severity-graded alerts and guided remediation steps before exposure becomes exploitation."
              tags={["24/7 Surveillance", "Credential Alerts", "Recovery Guidance", "Sector Intelligence"]} />
            <ServiceCard n="04" icon="△" accent="#c4b5fd" delay={.24}
              title="Proactive Defense" sub="The Alvora Shield's multi-layered moat"
              body="The Alvora Shield combines adaptive AI firewall intelligence with our Ethical Hacker Response Team to form a continuously active defense moat. We identify vulnerabilities, close attack surfaces, and harden your environment — proactively, not reactively."
              tags={["Always-On Protection", "Incident Response", "Remediation Support", "Coverage Alignment"]} />
          </div>
        </section>

        {/* ═══ QUOTE ENGINE ══════════════════════════════════════════════════ */}
        <section id="quote" style={{
          padding: "110px 64px",
          background: "linear-gradient(to bottom, transparent, rgba(124,58,237,.028), transparent)",
        }} className="sec-pad">
          <div style={{ maxWidth: 1060, margin: "0 auto" }}>
            <SectionLabel n={4} text="AI Risk & Insurance Quote" />
            <div style={{ textAlign: "center", marginBottom: 52 }}>
              <Reveal>
                <h2 className="serif" style={{ fontSize: "clamp(32px,4vw,58px)", fontWeight: 300, lineHeight: 1.06, color: "var(--text)", marginBottom: 16 }}>
                  Your Quote,<br />
                  <em style={{ color: "var(--lav)", fontStyle: "italic" }}>Powered by AI.</em>
                </h2>
              </Reveal>
              <Reveal delay={.1}>
                <p style={{ fontSize: 14, color: "var(--sub)", maxWidth: 520, margin: "0 auto", lineHeight: 1.88 }}>
                  No paperwork. Alvora generates your personalised cyber insurance quote in real time
                  using live security telemetry — a first for the industry.
                </p>
              </Reveal>
            </div>
            <Reveal delay={.14}>
              <QuoteEngine onSelectPlan={selectPlan} />
            </Reveal>
          </div>
        </section>

        {/* ═══ LIVE INTELLIGENCE ═════════════════════════════════════════════ */}
        <section id="dashboard" style={{ padding: "110px 64px" }} className="sec-pad">
          <div style={{ maxWidth: 1240, margin: "0 auto" }}>
            <SectionLabel n={5} text="Inside the Client Dashboard" />
            <Reveal>
              <p style={{ fontSize: 14, color: "var(--sub)", maxWidth: 620, lineHeight: 1.88, marginBottom: 40 }}>
                A preview of what Alvora clients see: severity-graded alerts and the posture
                metrics that drive their risk score. Example data shown.
              </p>
            </Reveal>
            <div className="two-col" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 22, alignItems: "start" }}>
              {/* Feed */}
              <Reveal>
                <div className="glass" style={{ padding: 34 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 26 }}>
                    <div>
                      <div className="mono" style={{ fontSize: 9, color: "var(--sub)", letterSpacing: ".3em", marginBottom: 5 }}>DARK WEB ALERT FEED</div>
                      <h3 className="serif" style={{ fontSize: 21, fontWeight: 400, color: "var(--text)" }}>Threat Intelligence Stream</h3>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                      <div style={{ width: 7, height: 7, borderRadius: "50%", background: "#a78bfa", boxShadow: "0 0 8px #a78bfa", animation: "liveDot 1.5s infinite" }} />
                      <span className="mono" style={{ fontSize: 9, color: "#a78bfa", letterSpacing: ".2em" }}>SAMPLE</span>
                    </div>
                  </div>
                  <DarkWebFeed />
                </div>
              </Reveal>

              {/* Metrics */}
              <Reveal delay={.12}>
                <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                  {[
                    { label: "Attack Surface Score",  val: "62 / 100", trend: "↓ 4pts", good: true  },
                    { label: "Patch Compliance",       val: "91%",      trend: "↑ 2%",   good: true  },
                    { label: "Phishing Resistance",    val: "78%",      trend: "↓ 1%",   good: false },
                    { label: "Dark Web Exposure",      val: "3 hits",   trend: "↑ 1",    good: false },
                    { label: "MFA Adoption",           val: "84%",      trend: "↑ 5%",   good: true  },
                    { label: "Endpoint Protection",    val: "97%",      trend: "Stable",  good: true  },
                  ].map((m, i) => (
                    <motion.div key={m.label}
                      initial={{ opacity: 0, x: 18 }} whileInView={{ opacity: 1, x: 0 }}
                      viewport={{ once: true }} transition={{ duration: .5, delay: i * .06 }}
                      className="glass-sm"
                      style={{ padding: "14px 20px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <div>
                        <div className="mono" style={{ fontSize: 9, color: "var(--dim)", letterSpacing: 1, marginBottom: 3 }}>{m.label}</div>
                        <div className="serif" style={{ fontSize: 21, fontWeight: 400, color: "var(--text)" }}>{m.val}</div>
                      </div>
                      <span style={{ fontSize: 13, fontWeight: 500, color: m.good ? "#34d399" : "#f87171" }}>{m.trend}</span>
                    </motion.div>
                  ))}
                </div>
              </Reveal>
            </div>
          </div>
        </section>

        {/* ═══ WAITLIST ══════════════════════════════════════════════════════ */}
        <section id="waitlist" style={{ padding: "130px 64px", position: "relative", overflow: "hidden" }} className="sec-pad">
          {/* Decorative verticals */}
          {[64, "calc(100% - 64px)"].map((x, i) => (
            <div key={i} style={{
              position: "absolute", left: x, top: "8%", bottom: "8%",
              width: 1, background: "linear-gradient(to bottom, transparent, rgba(167,139,250,.07), transparent)",
            }} />
          ))}
          <div style={{ position: "absolute", top: "50%", left: "50%", transform: "translate(-50%,-50%)", width: 580, height: 580, borderRadius: "50%", pointerEvents: "none", background: "radial-gradient(circle, rgba(124,58,237,.05) 0%, transparent 70%)" }} />

          <div style={{ maxWidth: 660, margin: "0 auto", textAlign: "center", position: "relative" }}>
            <SectionLabel n={6} text="Request Access" />
            <Reveal>
              <h2 className="serif" style={{ fontSize: "clamp(36px,5vw,70px)", fontWeight: 300, lineHeight: 1.04, color: "var(--text)", marginBottom: 18 }}>
                An Invitation to<br />
                <em style={{ color: "var(--lav)", fontStyle: "italic" }}>a Safer Tomorrow.</em>
              </h2>
            </Reveal>
            <Reveal delay={.1}>
              <p style={{ fontSize: 14, color: "var(--sub)", lineHeight: 1.88, marginBottom: 56 }}>
                Alvora Cyber is in private early access. We are selectively onboarding forward-thinking
                SMEs who believe cyber resilience should be intelligent, proactive, and fair. Join the
                list — your first AI risk assessment is complimentary.
              </p>
            </Reveal>
            <Reveal delay={.18}>
              <WaitlistForm plan={plan} onClearPlan={() => setPlan("")} />
            </Reveal>
          </div>
        </section>

        {/* ═══ FOOTER ════════════════════════════════════════════════════════ */}
        <footer className="foot" style={{
          borderTop: "1px solid rgba(167,139,250,.07)",
          padding: "44px 64px",
          display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 20,
        }}>
          <Brand size={26} />
          <div style={{ display: "flex", gap: 28, flexWrap: "wrap" }}>
            {[["ABOUT","about"],["SHIELD","shield"],["SERVICES","services"],["QUOTE","quote"],["WAITLIST","waitlist"]].map(([l, id]) => (
              <button key={id} className="nav-btn" onClick={() => goto(id)}>{l}</button>
            ))}
          </div>
          <div className="foot-meta" style={{ textAlign: "right" }}>
            <div className="mono" style={{ fontSize: 9, color: "var(--dim)", letterSpacing: ".22em", marginBottom: 3 }}>© {new Date().getFullYear()} ALVORA CYBER</div>
            <div className="mono" style={{ fontSize: 9, color: "var(--dim)", letterSpacing: ".15em" }}>ALL RIGHTS RESERVED · EST. 2025</div>
          </div>
        </footer>

      </div>
    </>
  );
}
