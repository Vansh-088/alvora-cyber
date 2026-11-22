/**
 * threatIntel.js — Live IP threat-intelligence feeds (free, no API keys)
 *
 * Replaces the old hand-written CIDR list. Downloads public blocklists once a
 * day, caches them on disk (so lookups keep working offline), and answers
 * "is this IP known-bad?" with a binary search over merged IPv4 ranges.
 *
 * Feeds (highest severity wins when an IP is on several):
 *   • Feodo Tracker (abuse.ch)       — botnet command-and-control servers   CRITICAL
 *   • Spamhaus DROP                  — hijacked / criminal-run networks     HIGH
 *   • Emerging Threats compromised   — hosts known to be compromised        HIGH
 *   • IPsum level 3                  — IPs on 3+ independent blocklists     MEDIUM
 *   • Tor exit nodes (torproject)    — anonymizing relays                   LOW
 */

import fs   from 'fs';
import path from 'path';
import os   from 'os';

const DATA_DIR  = process.env.ALVORA_DATA_DIR || path.join(os.homedir(), '.alvora-cyber');
const CACHE_DIR = path.join(DATA_DIR, 'intel');
const MAX_AGE_MS = 24 * 60 * 60 * 1000;

const FEEDS = [
  {
    id: 'feodo', name: 'Feodo Tracker', severity: 'CRITICAL',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    label: 'Connection to a known botnet control server',
    detail: 'This address is listed by abuse.ch Feodo Tracker as an active botnet command-and-control server. Malware uses these to receive orders and send stolen data.',
  },
  {
    id: 'spamhaus-drop', name: 'Spamhaus DROP', severity: 'HIGH',
    url: 'https://www.spamhaus.org/drop/drop.txt',
    label: 'Connection to a network run by criminals',
    detail: 'This address is in a network Spamhaus lists as hijacked or operated by cybercriminals. Legitimate services do not live there.',
  },
  {
    id: 'et-compromised', name: 'Emerging Threats', severity: 'HIGH',
    url: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
    label: 'Connection to a known compromised computer',
    detail: 'Emerging Threats lists this address as a compromised host that is actively attacking others.',
  },
  {
    id: 'ipsum', name: 'IPsum (3+ blocklists)', severity: 'MEDIUM',
    url: 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt',
    label: 'Connection to an address on several blocklists',
    detail: 'At least three independent security blocklists have flagged this address for malicious activity.',
  },
  {
    id: 'tor-exit', name: 'Tor exit nodes', severity: 'LOW',
    url: 'https://check.torproject.org/torbulkexitlist',
    label: 'Connection to an anonymous (Tor) network relay',
    detail: 'This is a Tor exit relay. Fine if you use Tor on purpose; otherwise something may be hiding where its traffic goes.',
  },
];

const SEV_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

// ── IPv4 helpers ──────────────────────────────────────────────────────────────

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function ipToInt(ip) {
  const m = IPV4.exec(ip);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  if (o.some(x => x > 255)) return null;
  return ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3];
}

/** "1.2.3.4" or "1.2.3.0/24" → [start, end] */
function toRange(token) {
  const [ip, bitsRaw] = token.split('/');
  const base = ipToInt(ip);
  if (base == null) return null;
  const bits = bitsRaw == null ? 32 : parseInt(bitsRaw, 10);
  if (!(bits >= 8 && bits <= 32)) return null;   // refuse absurdly wide entries
  const size  = 2 ** (32 - bits);
  const start = Math.floor(base / size) * size;
  return [start, start + size - 1];
}

/** Pull IPs / CIDRs out of any of the feed formats (plain list, "cidr ; comment", ipsum "ip<TAB>count"). */
function parseFeed(text) {
  const ranges = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    const token = line.split(/[\s;]+/)[0];
    const r = toRange(token);
    if (r) ranges.push(r);
  }
  return ranges;
}

// ── Index ─────────────────────────────────────────────────────────────────────

// Per feed: sorted, merged [start, end] arrays → binary search
const index = new Map();       // feedId → { starts: Uint32Array, ends: Uint32Array }
const meta  = new Map();       // feedId → { entries, updatedAt, source: 'network'|'cache', error? }

function buildIndex(ranges) {
  ranges.sort((a, b) => a[0] - b[0]);
  const merged = [];
  for (const r of ranges) {
    const last = merged[merged.length - 1];
    if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]);
    else merged.push([r[0], r[1]]);
  }
  return {
    starts: Uint32Array.from(merged, r => r[0]),
    ends:   Uint32Array.from(merged, r => r[1]),
  };
}

function inIndex({ starts, ends }, n) {
  let lo = 0, hi = starts.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (n < starts[mid]) hi = mid - 1;
    else if (n > ends[mid]) lo = mid + 1;
    else return true;
  }
  return false;
}

// ── Loading / refreshing ──────────────────────────────────────────────────────

function cachePath(feed) { return path.join(CACHE_DIR, `${feed.id}.txt`); }

function loadFromText(feed, text, updatedAt, source) {
  const ranges = parseFeed(text);
  index.set(feed.id, buildIndex(ranges));
  meta.set(feed.id, { entries: ranges.length, updatedAt, source });
}

async function refreshFeed(feed, { force = false } = {}) {
  const file = cachePath(feed);
  let cachedAt = 0;
  try { cachedAt = fs.statSync(file).mtimeMs; } catch { /* no cache yet */ }

  const fresh = cachedAt && Date.now() - cachedAt < MAX_AGE_MS;
  if (fresh && !force) {
    if (!index.has(feed.id)) loadFromText(feed, fs.readFileSync(file, 'utf8'), cachedAt, 'cache');
    return;
  }

  try {
    const res = await fetch(feed.url, { signal: AbortSignal.timeout(20_000), headers: { 'User-Agent': 'AlvoraCyber/1.0' } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    if (parseFeed(text).length === 0) throw new Error('feed was empty or unparseable');
    fs.mkdirSync(CACHE_DIR, { recursive: true });
    fs.writeFileSync(file, text, 'utf8');
    loadFromText(feed, text, Date.now(), 'network');
  } catch (err) {
    // Keep serving the stale cache rather than dropping protection
    if (cachedAt) {
      if (!index.has(feed.id)) loadFromText(feed, fs.readFileSync(file, 'utf8'), cachedAt, 'cache');
      meta.set(feed.id, { ...meta.get(feed.id), error: err.message });
    } else {
      meta.set(feed.id, { entries: 0, updatedAt: null, source: null, error: err.message });
    }
    console.warn(`[Intel] ${feed.name}: ${err.message}${cachedAt ? ' — using cached copy' : ''}`);
  }
}

let refreshing = null;

/** Load cached feeds and download any older than 24h. Safe to call often. */
export function refreshAll(opts) {
  if (!refreshing) {
    refreshing = Promise.all(FEEDS.map(f => refreshFeed(f, opts))).finally(() => { refreshing = null; });
  }
  return refreshing;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * @returns {{ severity, label, detail, feeds: string[] } | null}
 */
export function lookup(ip) {
  const n = ipToInt(ip);
  if (n == null) return null;
  let best = null;
  const hits = [];
  for (const feed of FEEDS) {
    const idx = index.get(feed.id);
    if (!idx || !inIndex(idx, n)) continue;
    hits.push(feed.name);
    if (!best || SEV_RANK[feed.severity] > SEV_RANK[best.severity]) best = feed;
  }
  if (!best) return null;
  return {
    severity: best.severity,
    label:    best.label,
    detail:   hits.length > 1 ? `${best.detail} Also listed by: ${hits.filter(h => h !== best.name).join(', ')}.` : best.detail,
    feeds:    hits,
  };
}

export function status() {
  const feeds = FEEDS.map(f => ({
    id: f.id, name: f.name, severity: f.severity,
    entries:   meta.get(f.id)?.entries ?? 0,
    updatedAt: meta.get(f.id)?.updatedAt ?? null,
    source:    meta.get(f.id)?.source ?? null,
    error:     meta.get(f.id)?.error ?? null,
  }));
  return { feeds, totalEntries: feeds.reduce((s, f) => s + f.entries, 0) };
}
