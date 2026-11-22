import { useEffect, useRef } from 'react';

// ─── Constants ────────────────────────────────────────────────────────────

const NODE_COUNT = 55;
const MAX_DIST   = 130;
const SPEED      = 0.6;    // px per frame at TARGET_FPS (≈ the old 0.25 at 60fps)
const TARGET_FPS = 24;     // decorative — no need to track a 120Hz display
const ALPHA_BUCKETS = 4;   // edges are stroked in a few batched paths, not one-by-one

// ─── Helpers ──────────────────────────────────────────────────────────────

function randomBetween(min, max) {
  return min + Math.random() * (max - min);
}

function buildNodes(width, height) {
  return Array.from({ length: NODE_COUNT }, () => ({
    x:  randomBetween(0, width),
    y:  randomBetween(0, height),
    vx: randomBetween(-SPEED, SPEED) || SPEED,
    vy: randomBetween(-SPEED, SPEED) || SPEED,
    r:  randomBetween(1.5, 3),
  }));
}

// ─── Component ───────────────────────────────────────────────────────────

export default function ParticleBackground({ isCritical, lockdownActive }) {
  const canvasRef = useRef(null);

  // stateRef holds mutable runtime state so the RAF loop never stale-closes
  // over props — we just read stateRef.current.color each frame.
  const stateRef = useRef({
    nodes:         [],
    color:         '0,229,255',
    rafId:         null,
    running:       false,
  });

  // ── Sync color from props without restarting the loop ──────────────────
  useEffect(() => {
    if (lockdownActive) {
      stateRef.current.color = '239,68,68';
    } else if (isCritical) {
      stateRef.current.color = '249,115,22';
    } else {
      stateRef.current.color = '0,229,255';
    }
  }, [isCritical, lockdownActive]);

  // ── Start RAF loop once on mount, clean up on unmount ──────────────────
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx    = canvas.getContext('2d');
    const state  = stateRef.current;

    // Resize + rebuild nodes
    function handleResize() {
      canvas.width  = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
      state.nodes   = buildNodes(canvas.width, canvas.height);
      render();   // resizing clears the canvas — repaint even while paused
    }

    handleResize();

    const ro = new ResizeObserver(handleResize);
    ro.observe(canvas);

    // ── Draw loop ─────────────────────────────────────────────────────────
    // Throttled to TARGET_FPS, batched strokes, no shadowBlur, and paused while
    // the window is hidden or unfocused — this full-window canvas was the app's
    // single biggest CPU/GPU cost.
    const frameMs        = 1000 / TARGET_FPS;
    const reducedMotion  = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    let lastFrame        = 0;

    function step() {
      const { width, height } = canvas;
      for (const n of state.nodes) {
        n.x += n.vx;
        n.y += n.vy;
        if (n.x < 0)      { n.x = 0;      n.vx = Math.abs(n.vx); }
        if (n.x > width)  { n.x = width;  n.vx = -Math.abs(n.vx); }
        if (n.y < 0)      { n.y = 0;      n.vy = Math.abs(n.vy); }
        if (n.y > height) { n.y = height; n.vy = -Math.abs(n.vy); }
      }
    }

    function render() {
      const { width, height } = canvas;
      const color = state.color;
      const nodes = state.nodes;
      ctx.clearRect(0, 0, width, height);

      // Edges — one path per alpha bucket instead of one stroke per edge
      const buckets = Array.from({ length: ALPHA_BUCKETS }, () => new Path2D());
      const maxSq   = MAX_DIST * MAX_DIST;
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x;
          const dy = nodes[i].y - nodes[j].y;
          const sq = dx * dx + dy * dy;
          if (sq >= maxSq) continue;
          const closeness = 1 - Math.sqrt(sq) / MAX_DIST;
          const b = Math.min(ALPHA_BUCKETS - 1, Math.floor(closeness * ALPHA_BUCKETS));
          buckets[b].moveTo(nodes[i].x, nodes[i].y);
          buckets[b].lineTo(nodes[j].x, nodes[j].y);
        }
      }
      ctx.lineWidth = 0.7;
      buckets.forEach((path, b) => {
        ctx.strokeStyle = `rgba(${color},${(((b + 0.5) / ALPHA_BUCKETS) * 0.45).toFixed(3)})`;
        ctx.stroke(path);
      });

      // Nodes — a soft halo + core instead of per-node shadowBlur
      const halo = new Path2D();
      const core = new Path2D();
      for (const n of nodes) {
        halo.moveTo(n.x + n.r * 2, n.y);
        halo.arc(n.x, n.y, n.r * 2, 0, Math.PI * 2);
        core.moveTo(n.x + n.r, n.y);
        core.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      }
      ctx.fillStyle = `rgba(${color},0.12)`;
      ctx.fill(halo);
      ctx.fillStyle = `rgba(${color},0.75)`;
      ctx.fill(core);
    }

    function draw(now) {
      state.rafId = requestAnimationFrame(draw);
      if (now - lastFrame < frameMs) return;
      lastFrame = now;
      step();
      render();
    }

    function start() {
      if (state.running || reducedMotion) return;
      state.running = true;
      state.rafId   = requestAnimationFrame(draw);
    }

    function stop() {
      if (state.rafId) cancelAnimationFrame(state.rafId);
      state.rafId   = null;
      state.running = false;
    }

    // Only animate while the user is actually looking at the app
    const syncActivity = () => (document.hidden || !document.hasFocus() ? stop() : start());
    document.addEventListener('visibilitychange', syncActivity);
    window.addEventListener('focus', syncActivity);
    window.addEventListener('blur', syncActivity);

    render();        // always show a frame (static when reduced motion / unfocused)
    syncActivity();

    return () => {
      stop();
      ro.disconnect();
      document.removeEventListener('visibilitychange', syncActivity);
      window.removeEventListener('focus', syncActivity);
      window.removeEventListener('blur', syncActivity);
    };
  }, []); // intentionally empty — loop runs once, reads from stateRef

  return (
    <canvas
      ref={canvasRef}
      style={{
        position:      'absolute',
        inset:         0,
        width:         '100%',
        height:        '100%',
        zIndex:        0,
        pointerEvents: 'none',
        display:       'block',
      }}
    />
  );
}
