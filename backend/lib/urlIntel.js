/**
 * urlIntel.js — Is this link a known phishing / malware site? (local, private)
 *
 * The browser extension asks the local backend about each page you open; the
 * URL never leaves this machine. Lookups run against free public feeds that
 * are downloaded and cached here:
 *
 *   • OpenPhish community feed     — live phishing URLs (exact URL match)      refreshed 6h
 *   • Phishing.Database (ACTIVE)   — ~390k phishing domains                    refreshed 24h
 *   • Phishing Army                — ~155k phishing domains                    refreshed 24h
 *   • Alvora threat-intel IP feeds — for links that point at a raw IP address
 *
 * Domain lists are stored as 64-bit hashes in a sorted array (~4 MB instead of
 * ~30 MB of strings). Community domain lists contain mistakes (amazon.ie,
 * gravatar.com, mercadolibre…), so three guards keep them from blocking real sites:
 *   • Shared hosting platforms (github.io, vercel.app, sites.google.com…): a
 *     listed *platform* is ignored — only a specific site on it can match.
 *   • Major first-party domains (google.com, microsoft.com, apple.com…) and the
 *     Tranco top-100k most popular sites (refreshed weekly) are never blocked by
 *     a domain list — only by an exact phishing-URL match.
 *   • International (IDN) domains are only "suspicious" when they mix Latin with
 *     look-alike Cyrillic/Greek letters — not merely for being non-Latin.
 */

import fs     from 'fs';
import os     from 'os';
import path   from 'path';
import crypto from 'crypto';
import zlib   from 'zlib';
import { domainToUnicode } from 'url';
import * as ipIntel from './threatIntel.js';

const DATA_DIR  = process.env.ALVORA_DATA_DIR || path.join(os.homedir(), '.alvora-cyber');
const CACHE_DIR = path.join(DATA_DIR, 'intel');

const FEEDS = [
  { id: 'openphish',    kind: 'url',    name: 'OpenPhish',         maxAgeMs: 6 * 3600_000,  url: 'https://openphish.com/feed.txt' },
  { id: 'phishing-db',  kind: 'domain', name: 'Phishing.Database', maxAgeMs: 24 * 3600_000, url: 'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt' },
  { id: 'phishing-army', kind: 'domain', name: 'Phishing Army',    maxAgeMs: 24 * 3600_000, url: 'https://phishing.army/download/phishing_army_blocklist.txt' },
  { id: 'tranco-top',   kind: 'popular', name: 'Tranco top sites (allow-guard)', maxAgeMs: 7 * 24 * 3600_000, url: 'https://tranco-list.eu/top-1m.csv.zip', zip: true },
];
const POPULAR_TOP_N = 100_000;

// Platforms where anyone can publish a subdomain/path: the platform itself is never "bad"
const SHARED_PLATFORMS = new Set([
  'github.io', 'gitlab.io', 'vercel.app', 'netlify.app', 'pages.dev', 'workers.dev', 'r2.dev', 'web.app',
  'firebaseapp.com', '000webhostapp.com', 'herokuapp.com', 'onrender.com', 'glitch.me', 'repl.co', 'replit.app',
  'blogspot.com', 'wordpress.com', 'wixsite.com', 'weebly.com', 'godaddysites.com', 'webflow.io', 'framer.app',
  'carrd.co', 'square.site', 'ipfs.io', 'dweb.link', 'azurewebsites.net', 'cloudfront.net', 'amazonaws.com',
  'appspot.com', 'sites.google.com', 'translate.goog', 'notion.site', 'surge.sh', 'fly.dev', 'trycloudflare.com',
  'ngrok.io', 'ngrok-free.app', 'duckdns.org', 'my.canva.site', 'canva.site', 'typedream.app', 'mystrikingly.com',
  'cloudflare-ipfs.com', 'paste.ee', 'pastebin.com', 'telegra.ph', 'linktr.ee', 'bit.ly', 'tinyurl.com', 'is.gd',
]);

// First-party domains of major services — domain feeds never block these
const FIRST_PARTY = new Set([
  'google.com', 'youtube.com', 'gmail.com', 'googleusercontent.com', 'microsoft.com', 'live.com', 'office.com',
  'outlook.com', 'microsoftonline.com', 'apple.com', 'icloud.com', 'amazon.com', 'github.com', 'facebook.com',
  'instagram.com', 'whatsapp.com', 'linkedin.com', 'x.com', 'twitter.com', 'paypal.com', 'openai.com',
  'chatgpt.com', 'claude.ai', 'anthropic.com', 'cloudflare.com', 'dropbox.com', 'zoom.us', 'slack.com',
  'wikipedia.org', 'reddit.com', 'netflix.com', 'stripe.com', 'shopify.com', 'adobe.com', 'yahoo.com',
]);

// ── Hash set (sorted BigUint64Array, binary search) ───────────────────────────

const h64 = s => crypto.createHash('sha1').update(s).digest().readBigUInt64BE(0);

function buildHashSet(items) {
  const arr = new BigUint64Array(items.length);
  let n = 0;
  for (const it of items) arr[n++] = h64(it);
  arr.sort();
  return arr;
}

function hasHash(arr, s) {
  const x = h64(s);
  let lo = 0, hi = arr.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (arr[mid] < x) lo = mid + 1; else if (arr[mid] > x) hi = mid - 1; else return true;
  }
  return false;
}

// ── URL helpers ───────────────────────────────────────────────────────────────

/** "https://WWW.Example.com:443/a/b?x#y" → "example.com/a/b?x" (scheme, www, port, fragment, trailing slash dropped) */
function normUrl(u) {
  try {
    const p = new URL(u);
    const host = p.hostname.toLowerCase().replace(/^www\./, '');
    return `${host}${p.pathname.replace(/\/+$/, '')}${p.search}`.toLowerCase();
  } catch { return null; }
}

function cleanDomain(line) {
  const d = line.trim().toLowerCase().replace(/^(?:0\.0\.0\.0|127\.0\.0\.1)\s+/, '').replace(/^\*\./, '').replace(/^www\./, '');
  return /^[a-z0-9_.-]+\.[a-z0-9-]{2,}$/.test(d) ? d : null;   // underscores occur in real phishing hosts
}

/** example: "a.b.evil.com" → ["a.b.evil.com", "b.evil.com", "evil.com"] */
function hostCandidates(host) {
  const labels = host.split('.');
  const out = [];
  for (let i = 0; i < labels.length - 1; i++) out.push(labels.slice(i).join('.'));
  return out;
}

const underFirstParty = host => hostCandidates(host).some(c => FIRST_PARTY.has(c));

/** Is this exact domain in the Tranco top-N? (Not its parents — a phishing
 *  subdomain on a popular host like x.000webhostapp.com must still match.) */
function isPopular(domain) {
  const set = state.get('tranco-top')?.set;
  return !!set && hasHash(set, domain);
}

// Cyrillic/Greek letters that render like Latin ones
const CONFUSABLE = new Set([...'аеорсухіјѕԁԛԝɡһіӏոօрզսᴠᴡхуᴢαβεικνορτυχ']);
const LATIN = /[a-z]/, CYR_GREEK = /[\u0370-\u03ff\u0400-\u04ff\u0500-\u052f]/;

/** "аpple" (Cyrillic а + Latin pple) → true; "ไทย" (Thai) → false */
function isLookalike(asciiHost) {
  return asciiHost.split('.').filter(l => l.startsWith('xn--')).some(label => {
    const u = domainToUnicode(label).toLowerCase();
    if (!u || u === label) return false;
    const letters = [...u].filter(ch => /\p{L}/u.test(ch));
    const mixed   = letters.some(ch => LATIN.test(ch)) && letters.some(ch => CYR_GREEK.test(ch));
    const allConfusable = letters.length > 0 && letters.every(ch => CONFUSABLE.has(ch) || LATIN.test(ch)) && letters.some(ch => CONFUSABLE.has(ch));
    return mixed || allConfusable;
  });
}

// ── Loading ───────────────────────────────────────────────────────────────────

const state = new Map();   // feedId → { set?: BigUint64Array, urls?: string[], entries, updatedAt, error }

/** Extract the single file from a (non-streamed) .zip using built-in zlib. */
function unzipSingle(buf) {
  if (buf.readUInt32LE(0) !== 0x04034b50) throw new Error('not a zip file');
  const method = buf.readUInt16LE(8), size = buf.readUInt32LE(18);
  const start  = 30 + buf.readUInt16LE(26) + buf.readUInt16LE(28);
  const data   = buf.subarray(start, start + size);
  if (method === 0) return data.toString('utf8');
  if (method === 8) return zlib.inflateRawSync(data).toString('utf8');
  throw new Error(`unsupported zip method ${method}`);
}

function parseFeed(feed, text) {
  if (feed.kind === 'popular') {
    // "rank,domain" — keep the top N
    const domains = [];
    for (const line of text.split('\n')) {
      const d = line.slice(line.indexOf(',') + 1).trim().toLowerCase();
      if (d) domains.push(d);
      if (domains.length >= POPULAR_TOP_N) break;
    }
    return { set: buildHashSet(domains), entries: domains.length };
  }
  if (feed.kind === 'url') {
    const urls = [...new Set(text.split('\n').map(l => normUrl(l.trim())).filter(Boolean))];
    return { urls, entries: urls.length };
  }
  const domains = [];
  for (const line of text.split('\n')) {
    if (!line || line[0] === '#') continue;
    const d = cleanDomain(line);
    if (d && !SHARED_PLATFORMS.has(d)) domains.push(d);
  }
  return { set: buildHashSet(domains), entries: domains.length };
}

async function refreshFeed(feed, force) {
  const file = path.join(CACHE_DIR, `${feed.id}.txt`);   // zipped feeds are cached unzipped
  let cachedAt = 0;
  try { cachedAt = fs.statSync(file).mtimeMs; } catch { /* none */ }

  if (!state.has(feed.id) && cachedAt) {
    try { state.set(feed.id, { ...parseFeed(feed, fs.readFileSync(file, 'utf8')), updatedAt: cachedAt, error: null }); } catch { /* corrupt cache */ }
  }
  if (cachedAt && Date.now() - cachedAt < feed.maxAgeMs && !force) return;

  try {
    const res = await fetch(feed.url, { signal: AbortSignal.timeout(120_000), headers: { 'User-Agent': 'AlvoraCyber/1.0' } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    let text = feed.zip ? unzipSingle(Buffer.from(await res.arrayBuffer())) : await res.text();
    if (feed.kind === 'popular') text = text.split('\n').slice(0, POPULAR_TOP_N).join('\n');   // cache only what we use
    const parsed = parseFeed(feed, text);
    if (parsed.entries < 10) throw new Error('feed looked empty');
    fs.mkdirSync(CACHE_DIR, { recursive: true });
    fs.writeFileSync(file, text, 'utf8');
    state.set(feed.id, { ...parsed, updatedAt: Date.now(), error: null });
  } catch (err) {
    const prev = state.get(feed.id);
    state.set(feed.id, { ...(prev ?? { entries: 0, updatedAt: null }), error: err.message });
    console.warn(`[URLIntel] ${feed.name}: ${err.message}${prev ? ' — using cached copy' : ''}`);
  }
}

let refreshing = null;
export function refreshAll({ force = false } = {}) {
  if (!refreshing) refreshing = Promise.all(FEEDS.map(f => refreshFeed(f, force))).finally(() => { refreshing = null; });
  return refreshing;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * @returns {{ verdict: 'malicious'|'suspicious'|'clean'|'unknown', host: string|null,
 *             reason?: string, sources?: string[] }}
 */
export function check(rawUrl) {
  let u;
  try { u = new URL(rawUrl); } catch { return { verdict: 'unknown', host: null }; }
  if (!/^https?:$/.test(u.protocol)) return { verdict: 'clean', host: u.hostname || null };
  const host = u.hostname.toLowerCase().replace(/^www\./, '').replace(/\.$/, '');

  // Raw-IP links → reuse the network threat-intel feeds
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    const hit = ipIntel.lookup(host);
    if (hit && ['CRITICAL', 'HIGH'].includes(hit.severity)) {
      return { verdict: 'malicious', host, reason: hit.label, sources: hit.feeds };
    }
  }

  const sources = [];
  // Exact phishing URLs (path-prefix match, so /login?x=1 matches /login)
  const n = normUrl(rawUrl);
  for (const feed of FEEDS.filter(f => f.kind === 'url')) {
    const urls = state.get(feed.id)?.urls ?? [];
    if (n && urls.some(p => n === p || n.startsWith(p.endsWith('/') ? p : `${p}/`) || n.startsWith(`${p}?`))) sources.push(feed.name);
  }
  // Phishing domains (host or any parent). A listed entry is ignored when the
  // entry itself is a shared platform or a popular site (list mistakes).
  if (!underFirstParty(host)) {
    const cands = hostCandidates(host).filter(c => !SHARED_PLATFORMS.has(c) && !isPopular(c));
    for (const feed of FEEDS.filter(f => f.kind === 'domain')) {
      const set = state.get(feed.id)?.set;
      if (set && cands.some(c => hasHash(set, c))) sources.push(feed.name);
    }
  }
  if (sources.length) {
    return { verdict: 'malicious', host, reason: 'This site is on public phishing blocklists — it may try to steal passwords or payment details.', sources };
  }

  // Lookalike characters (IDN homographs like "аpple.com" with a Cyrillic а)
  if (isLookalike(host) && !isPopular(host)) {
    const shown = domainToUnicode(host) || host;
    return { verdict: 'suspicious', host, reason: `This address uses look-alike international characters (${shown}) — a trick to imitate real sites.` };
  }

  const loaded = FEEDS.some(f => f.kind !== 'popular' && state.get(f.id)?.entries);
  return { verdict: loaded ? 'clean' : 'unknown', host };
}

export function status() {
  const feeds = FEEDS.map(f => ({
    id: f.id, name: f.name, kind: f.kind,
    entries: state.get(f.id)?.entries ?? 0,
    updatedAt: state.get(f.id)?.updatedAt ?? null,
    error: state.get(f.id)?.error ?? null,
  }));
  return { feeds, totalEntries: feeds.reduce((s, f) => s + f.entries, 0) };
}
