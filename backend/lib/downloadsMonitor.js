/**
 * downloadsMonitor.js — Scan every new download the moment it finishes.
 *
 * Watches ~/Downloads (override: ALVORA_DOWNLOADS_DIRS="dir1:dir2"), waits
 * until a file has stopped growing and the browser has dropped its partial
 * extension (.crdownload / .download / .part …), then runs fileAnalyzer on it.
 * Results are remembered (keyed by path + size + mtime) so nothing is
 * scanned twice, and survive restarts.
 *
 * On start it also checks files added in the last 3 days, so the dashboard
 * isn't empty after an update or reboot.
 *
 * macOS privacy (TCC) protects ~/Downloads. Until the user allows Alvora to
 * access it, reads fail with EPERM — reported as status 'needs-permission'.
 */

import fs   from 'fs';
import os   from 'os';
import path from 'path';
import { analyzeFile } from './fileAnalyzer.js';

const DATA_DIR     = process.env.ALVORA_DATA_DIR || path.join(os.homedir(), '.alvora-cyber');
const HISTORY_FILE = path.join(DATA_DIR, 'downloads-scans.json');
const DIRS = process.env.ALVORA_DOWNLOADS_DIRS
  ? process.env.ALVORA_DOWNLOADS_DIRS.split(':').filter(Boolean)
  : [path.join(os.homedir(), 'Downloads')];

const PARTIAL      = /\.(?:crdownload|download|part|partial|tmp|opdownload|filepart)$/i;
const SETTLE_MS    = 2000;          // file must be unchanged this long before scanning
const BACKFILL_MS  = 3 * 86400_000;
const MAX_HISTORY  = 300;

let history = [];                    // newest first
let status  = { dirs: DIRS.map(d => ({ dir: d, state: 'starting', error: null })) };
let onResult = () => {};

function load() {
  try { history = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8')); } catch { history = []; }
}
function save() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(HISTORY_FILE, JSON.stringify(history.slice(0, MAX_HISTORY)));
  } catch (e) { console.error('[Downloads] save failed:', e.message); }
}

const keyOf = (p, st) => `${p}|${st.size}|${Math.round(st.mtimeMs)}`;
const known = new Set();

// ── Scan queue (one file at a time — disk images get mounted) ─────────────────

const queue = [];
let busy = false;

async function pump() {
  if (busy) return;
  busy = true;
  while (queue.length) {
    const file = queue.shift();
    try {
      const st = fs.statSync(file);
      const key = keyOf(file, st);
      if (known.has(key)) continue;
      known.add(key);
      const result = { ...(await analyzeFile(file)), key };
      history = [result, ...history.filter(h => h.path !== file)].slice(0, MAX_HISTORY);
      save();
      onResult(result);
      console.log(`[Downloads] ${result.verdict.padEnd(9)} ${result.name}${result.findings[0] && result.verdict !== 'clean' ? ` — ${result.findings[0].title}` : ''}`);
    } catch (e) {
      if (e.code !== 'ENOENT') console.error(`[Downloads] scan failed for ${path.basename(file)}:`, e.message);
    }
  }
  busy = false;
}

// ── Settling: wait for the browser to finish writing ──────────────────────────

const pending = new Map();   // path → timer

function consider(file) {
  const name = path.basename(file);
  if (name.startsWith('.') || PARTIAL.test(name)) return;
  clearTimeout(pending.get(file));
  pending.set(file, setTimeout(async () => {
    pending.delete(file);
    let a, b;
    try { a = fs.statSync(file); } catch { return; }           // gone (renamed/removed)
    if (a.isDirectory() && !name.endsWith('.app')) return;
    await new Promise(r => setTimeout(r, 500));
    try { b = fs.statSync(file); } catch { return; }
    if (a.size !== b.size || a.mtimeMs !== b.mtimeMs) return consider(file);   // still growing
    if (fs.existsSync(`${file}.crdownload`) || fs.existsSync(`${file}.download`)) return consider(file);
    if (!known.has(keyOf(file, b))) { queue.push(file); pump(); }
  }, SETTLE_MS));
}

// ── Public API ────────────────────────────────────────────────────────────────

export function start({ onResult: cb } = {}) {
  if (cb) onResult = cb;
  load();
  for (const h of history) if (h.key) known.add(h.key);

  status.dirs = DIRS.map(dir => {
    try {
      const names = fs.readdirSync(dir);   // throws EPERM without the macOS permission
      fs.watch(dir, { persistent: false }, (_ev, fname) => fname && consider(path.join(dir, fname.toString())));
      // Backfill: recent files not yet scanned
      const cutoff = Date.now() - BACKFILL_MS;
      for (const n of names) {
        const p = path.join(dir, n);
        try { if (fs.statSync(p).mtimeMs >= cutoff) consider(p); } catch { /* vanished */ }
      }
      return { dir, state: 'watching', error: null };
    } catch (e) {
      const needsPermission = e.code === 'EPERM' || e.code === 'EACCES';
      console.warn(`[Downloads] cannot watch ${dir}: ${e.code}${needsPermission ? ' (macOS needs permission to access this folder)' : ''}`);
      return { dir, state: needsPermission ? 'needs-permission' : 'unavailable', error: e.code };
    }
  });
  return status;
}

export function getState() {
  return {
    dirs: status.dirs,
    scanning: busy || queue.length > 0 || pending.size > 0,
    abuseChKey: !!process.env.ABUSECH_KEY,
    results: history.slice(0, 50).map(({ key, ...r }) => r),
  };
}

/** Re-scan one file the monitor already knows about (e.g. after a feed update). */
export async function rescan(file) {
  if (!history.some(h => h.path === file)) throw new Error('unknown file');
  for (const k of [...known]) if (k.startsWith(`${file}|`)) known.delete(k);
  queue.push(file);
  await pump();
  return history.find(h => h.path === file) ?? null;
}

/** Whether a path is one of ours to act on (reveal / move to Trash). */
export function isMonitoredFile(file) {
  const resolved = path.resolve(file);
  return DIRS.some(d => resolved.startsWith(path.resolve(d) + path.sep)) && history.some(h => h.path === resolved);
}
