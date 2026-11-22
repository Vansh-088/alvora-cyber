/**
 * geoLocator.js — Real IP Geolocation via ip-api.com
 *
 * Resolves external IP addresses to real lat/long coordinates so the Threat Map
 * plots genuine locations instead of random pins.
 *
 * ip-api.com free tier:
 *   • No API key required
 *   • 45 requests / minute (HTTP)
 *   • Batch endpoint: up to 100 IPs per request → we use this to stay way under the limit
 *
 * Strategy:
 *   • In-memory cache (IP → location) so each IP is resolved at most once per session
 *   • On-disk cache so locations persist across restarts (cuts API calls to near zero)
 *   • Batch queue: collect IPs, flush in groups of 100
 *   • Private/reserved IPs are skipped (they have no public geolocation)
 *   • Graceful degradation: if the API is unreachable, returns null (map just won't pin it)
 */

import fs   from 'fs';
import path from 'path';
import os   from 'os';
import { consume as rateConsume } from './rateLimiter.js';

const DATA_DIR   = process.env.ALVORA_DATA_DIR || path.join(os.homedir(), '.alvora-cyber');
const CACHE_FILE = path.join(DATA_DIR, 'geo-cache.json');

const API_BATCH_URL = 'http://ip-api.com/batch';
const FIELDS        = 'status,message,query,country,countryCode,region,city,lat,lon,isp,org,as';
const MAX_BATCH     = 100;
const CACHE_TTL_MS  = 1000 * 60 * 60 * 24; // 24 hours — same IP never looked up twice within a day

// ── Cache ─────────────────────────────────────────────────────────────────────

let cache = {};

function loadCache() {
  try {
    cache = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
  } catch {
    cache = {};
  }
}

function saveCache() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(CACHE_FILE, JSON.stringify(cache), 'utf8');
  } catch { /* non-fatal */ }
}

loadCache();

function getCached(ip) {
  const entry = cache[ip];
  if (!entry) return undefined;
  if (Date.now() - entry.cachedAt > CACHE_TTL_MS) {
    delete cache[ip];
    return undefined;
  }
  return entry.location;
}

// ── IP classification ──────────────────────────────────────────────────────────

function ipToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  return parts.reduce((acc, oct) => (acc << 8) + (parseInt(oct, 10) & 255), 0) >>> 0;
}

/**
 * Skip IPs that have no meaningful public geolocation.
 */
function isPrivateOrReserved(ip) {
  if (!ip || ip.includes(':')) return true; // skip IPv6 / malformed for now
  const n = ipToInt(ip);
  if (n === null) return true;
  return (
    (n >= ipToInt('10.0.0.0')      && n <= ipToInt('10.255.255.255'))   ||
    (n >= ipToInt('172.16.0.0')    && n <= ipToInt('172.31.255.255'))   ||
    (n >= ipToInt('192.168.0.0')   && n <= ipToInt('192.168.255.255'))  ||
    (n >= ipToInt('127.0.0.0')     && n <= ipToInt('127.255.255.255'))  ||
    (n >= ipToInt('169.254.0.0')   && n <= ipToInt('169.254.255.255'))  || // link-local
    (n >= ipToInt('100.64.0.0')    && n <= ipToInt('100.127.255.255'))  || // CGNAT
    (n >= ipToInt('224.0.0.0')     && n <= ipToInt('239.255.255.255'))  || // multicast
    ip === '0.0.0.0'
  );
}

// ── API call ────────────────────────────────────────────────────────────────

/**
 * Resolve a batch of IPs (≤100) via ip-api.com batch endpoint.
 * Returns a Map<ip, location|null>.
 */
async function fetchBatch(ips) {
  const results = new Map();
  if (ips.length === 0) return results;

  // Respect the ip-api free-tier rate limit (40/min). If we're over budget,
  // skip the call (cached entries still serve) rather than risk a ban.
  const gate = rateConsume('ipapi');
  if (!gate.allowed) {
    console.warn('[GeoLocator] ip-api rate budget exhausted this minute — skipping lookup');
    for (const ip of ips) results.set(ip, null);
    return results;
  }

  try {
    const body = ips.map(ip => ({ query: ip, fields: FIELDS }));
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 6000);

    const res = await fetch(API_BATCH_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
      signal:  ctrl.signal,
    });
    clearTimeout(timer);

    if (!res.ok) throw new Error(`ip-api responded ${res.status}`);

    const data = await res.json();
    for (const entry of data) {
      if (entry.status === 'success') {
        const location = {
          ip:          entry.query,
          lat:         entry.lat,
          lon:         entry.lon,
          city:        entry.city,
          region:      entry.region,
          country:     entry.country,
          countryCode: entry.countryCode,
          isp:         entry.isp,
          org:         entry.org,
          as:          entry.as,
        };
        results.set(entry.query, location);
        cache[entry.query] = { location, cachedAt: Date.now() };
      } else {
        results.set(entry.query, null);
      }
    }
    saveCache();
  } catch (err) {
    console.error('[GeoLocator] Batch lookup failed:', err.message);
    for (const ip of ips) results.set(ip, null);
  }

  return results;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Locate a single IP. Returns a location object or null.
 * Uses cache first; only calls the API on a miss.
 */
export async function locateIP(ip) {
  if (isPrivateOrReserved(ip)) return null;

  const cached = getCached(ip);
  if (cached !== undefined) return cached;

  const results = await fetchBatch([ip]);
  return results.get(ip) ?? null;
}

/**
 * Locate many IPs efficiently. Resolves from cache where possible,
 * batches the rest into groups of 100. Returns an array of location objects
 * (nulls and private IPs filtered out).
 */
export async function locateMany(ips) {
  const unique  = [...new Set(ips)].filter(ip => !isPrivateOrReserved(ip));
  const located = [];
  const toFetch = [];

  for (const ip of unique) {
    const cached = getCached(ip);
    if (cached) located.push(cached);
    else if (cached === undefined) toFetch.push(ip);
    // cached === null means "API said no location" — skip silently
  }

  // Batch the misses
  for (let i = 0; i < toFetch.length; i += MAX_BATCH) {
    const batch   = toFetch.slice(i, i + MAX_BATCH);
    const results = await fetchBatch(batch);
    for (const loc of results.values()) {
      if (loc) located.push(loc);
    }
  }

  return located;
}

export function getCacheSize() {
  return Object.keys(cache).length;
}
