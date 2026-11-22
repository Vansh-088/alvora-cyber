/**
 * asnDb.js — Offline "which network owns this IP?" (iptoasn.com, free)
 *
 * Maps an IPv4 address to its Autonomous System (e.g. AS15169 GOOGLE, US)
 * entirely on-device — no IPs are sent to a lookup service. The ~7 MB
 * database is downloaded at most weekly and cached. ASNs are stable where IPs
 * aren't (CDNs rotate addresses constantly), which makes them the right unit
 * for "has this app talked to this network before?".
 */

import fs   from 'fs';
import path from 'path';
import os   from 'os';
import zlib from 'zlib';
import { ipToInt } from './threatIntel.js';

const DATA_DIR   = process.env.ALVORA_DATA_DIR || path.join(os.homedir(), '.alvora-cyber');
const CACHE_FILE = path.join(DATA_DIR, 'intel', 'ip2asn-v4.tsv.gz');
const URL        = 'https://iptoasn.com/data/ip2asn-v4.tsv.gz';
const MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

let db = null;   // { starts, ends, asns: Uint32Array, info: Map<asn, {country, name}>, n }
let meta = { entries: 0, updatedAt: null, error: null };

// Kept compact: ~460k ranges in typed arrays, with country + name stored once
// per ASN (not per range) — ~10 MB resident instead of hundreds.
function parse(gz) {
  const text   = zlib.gunzipSync(gz).toString('latin1');
  const cap    = 600_000;
  const starts = new Uint32Array(cap);
  const ends   = new Uint32Array(cap);
  const asns   = new Uint32Array(cap);
  const info   = new Map();   // asn → { country, name }
  let n = 0, pos = 0;
  while (pos < text.length && n < cap) {
    let eol = text.indexOf('\n', pos);
    if (eol === -1) eol = text.length;
    const t1 = text.indexOf('\t', pos);
    const t2 = text.indexOf('\t', t1 + 1);
    const t3 = text.indexOf('\t', t2 + 1);
    const t4 = text.indexOf('\t', t3 + 1);
    if (t4 !== -1 && t4 < eol) {
      const num = parseInt(text.slice(t2 + 1, t3), 10);
      const s = ipToInt(text.slice(pos, t1));
      const e = ipToInt(text.slice(t1 + 1, t2));
      if (num && s != null && e != null) {          // AS0 = "Not routed"
        starts[n] = s; ends[n] = e; asns[n] = num; n++;
        if (!info.has(num)) info.set(num, { country: text.slice(t3 + 1, t4), name: text.slice(t4 + 1, eol).trim() });
      }
    }
    pos = eol + 1;
  }
  // Source file is sorted by range start already
  return { starts: starts.slice(0, n), ends: ends.slice(0, n), asns: asns.slice(0, n), info, n };
}

let loading = null;

/** Load the cached DB and re-download if older than a week. Safe to call often. */
export function refresh({ force = false } = {}) {
  if (loading) return loading;
  loading = (async () => {
    let cachedAt = 0;
    try { cachedAt = fs.statSync(CACHE_FILE).mtimeMs; } catch { /* none yet */ }

    if (!db && cachedAt) {
      try { db = parse(fs.readFileSync(CACHE_FILE)); meta = { entries: db.n, updatedAt: cachedAt, error: null }; }
      catch (e) { meta.error = `cache unreadable: ${e.message}`; }
    }
    if (cachedAt && Date.now() - cachedAt < MAX_AGE_MS && !force) return;

    try {
      const res = await fetch(URL, { signal: AbortSignal.timeout(60_000), headers: { 'User-Agent': 'AlvoraCyber/1.0' } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const gz = Buffer.from(await res.arrayBuffer());
      const parsed = parse(gz);
      if (parsed.n < 100_000) throw new Error('download looked truncated');
      fs.mkdirSync(path.dirname(CACHE_FILE), { recursive: true });
      fs.writeFileSync(CACHE_FILE, gz);
      db = parsed;
      meta = { entries: parsed.n, updatedAt: Date.now(), error: null };
    } catch (err) {
      meta.error = err.message;
      console.warn(`[ASN] update failed: ${err.message}${db ? ' — using cached copy' : ''}`);
    }
  })().finally(() => { loading = null; });
  return loading;
}

/** @returns {{ asn: number, country: string, name: string } | null} */
export function lookup(ip) {
  if (!db) return null;
  const x = ipToInt(ip);
  if (x == null) return null;
  let lo = 0, hi = db.n - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (x < db.starts[mid]) hi = mid - 1;
    else if (x > db.ends[mid]) lo = mid + 1;
    else return { asn: db.asns[mid], ...db.info.get(db.asns[mid]) };
  }
  return null;
}

export function status() { return { ...meta }; }
