/**
 * rateLimiter.js — Outbound API call governor
 *
 * Protects paid/limited third-party APIs from overuse (cost + ban protection).
 * Persists counters to disk so limits survive app restarts within their window.
 *
 * Limiters defined:
 *   • abuseipdb  — 50 calls / hour   (AbuseIPDB free tier safety margin)
 *   • anthropic  — 100 calls / day   (hard cutoff + alert at 80%)
 *   • ipapi      — 40 calls / minute (ip-api.com free tier is 45/min)
 *
 * Each limiter is a fixed-window counter. When a window expires the count resets.
 * A limiter refuses calls past its cap and reports when 80% is reached.
 */

import fs   from 'fs';
import path from 'path';
import os   from 'os';

const DATA_DIR    = process.env.ALVORA_DATA_DIR || path.join(os.homedir(), '.alvora-cyber');
const STATE_FILE  = path.join(DATA_DIR, 'rate-limits.json');

const LIMITS = {
  abuseipdb: { max: 50,  windowMs: 60 * 60 * 1000 },        // 50 / hour
  anthropic: { max: 100, windowMs: 24 * 60 * 60 * 1000 },   // 100 / day
  ipapi:     { max: 40,  windowMs: 60 * 1000 },             // 40 / minute
  nvidia:    { max: 60,  windowMs: 60 * 1000 },             // 60 / minute (NIM classification)
  openrouter: { max: 15, windowMs: 60 * 1000 },             // free-model endpoints allow ~20 / minute
};

let state = {};

function load() {
  try { state = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); }
  catch { state = {}; }
}
function save() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(STATE_FILE, JSON.stringify(state), 'utf8');
  } catch { /* non-fatal */ }
}
load();

function windowFor(name) {
  const cfg = LIMITS[name];
  if (!cfg) throw new Error(`Unknown rate limiter: ${name}`);
  const now = Date.now();
  let entry = state[name];
  // Reset the window if it has elapsed
  if (!entry || now - entry.windowStart >= cfg.windowMs) {
    entry = { windowStart: now, count: 0, alerted80: false };
    state[name] = entry;
  }
  return { cfg, entry, now };
}

/**
 * Check whether a call is allowed WITHOUT consuming quota.
 * @returns {{ allowed, remaining, used, max, resetMs }}
 */
export function check(name) {
  const { cfg, entry, now } = windowFor(name);
  const remaining = Math.max(0, cfg.max - entry.count);
  return {
    allowed:   entry.count < cfg.max,
    remaining,
    used:      entry.count,
    max:       cfg.max,
    resetMs:   cfg.windowMs - (now - entry.windowStart),
  };
}

/**
 * Consume one unit of quota. Returns a result describing the outcome.
 * If over the cap, allowed=false and the caller MUST NOT make the API call.
 * Emits an 80%-reached warning (once per window) via the onAlert callback.
 *
 * @param {string} name
 * @param {(info:{name,used,max,pct}) => void} [onAlert]
 * @returns {{ allowed, remaining, used, max, resetMs, alert? }}
 */
export function consume(name, onAlert) {
  const { cfg, entry } = windowFor(name);

  if (entry.count >= cfg.max) {
    save();
    return { allowed: false, remaining: 0, used: entry.count, max: cfg.max, reason: 'limit_reached' };
  }

  entry.count += 1;
  const pct = entry.count / cfg.max;

  let alert = null;
  if (pct >= 0.8 && !entry.alerted80) {
    entry.alerted80 = true;
    alert = { name, used: entry.count, max: cfg.max, pct: Math.round(pct * 100) };
    if (typeof onAlert === 'function') onAlert(alert);
    console.warn(`[RateLimit] ${name} at ${alert.pct}% of ${cfg.max} (${entry.count} used) — approaching limit`);
  }

  save();
  return { allowed: true, remaining: cfg.max - entry.count, used: entry.count, max: cfg.max, alert };
}

/** Snapshot of all limiters for display/telemetry. */
export function status() {
  const out = {};
  for (const name of Object.keys(LIMITS)) {
    const { cfg, entry, now } = windowFor(name);
    out[name] = {
      used:      entry.count,
      max:       cfg.max,
      remaining: Math.max(0, cfg.max - entry.count),
      resetInMs: cfg.windowMs - (now - entry.windowStart),
      pct:       Math.round((entry.count / cfg.max) * 100),
    };
  }
  return out;
}

export { LIMITS };
