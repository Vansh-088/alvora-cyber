/**
 * abuseIpdb.js — Real IP reputation via AbuseIPDB
 *
 * Looks up an external IP's abuse confidence score (0–100) and report count.
 * Guards every call with the rate limiter (50/hour) and a 24-hour disk cache so
 * the same IP is never checked twice in a day — staying far under the free
 * tier's 1,000 checks/day.
 *
 * No API key configured → every function returns null (feature dormant, no error).
 * The key is injected by the Electron main process from the encrypted Keychain
 * store as process.env.ABUSEIPDB_KEY.
 */

import fs   from 'fs';
import path from 'path';
import os   from 'os';
import { consume as rateConsume, check as rateCheck } from './rateLimiter.js';

const DATA_DIR   = process.env.ALVORA_DATA_DIR || path.join(os.homedir(), '.alvora-cyber');
const CACHE_FILE = path.join(DATA_DIR, 'abuseipdb-cache.json');
const API_URL    = 'https://api.abuseipdb.com/api/v2/check';
const CACHE_TTL  = 1000 * 60 * 60 * 24; // 24 hours

let cache = {};
try { cache = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8')); } catch { cache = {}; }

function saveCache() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(CACHE_FILE, JSON.stringify(cache), 'utf8');
  } catch { /* non-fatal */ }
}

function getCached(ip) {
  const e = cache[ip];
  if (!e) return undefined;
  if (Date.now() - e.cachedAt > CACHE_TTL) { delete cache[ip]; return undefined; }
  return e.data;
}

export function isConfigured() {
  return !!process.env.ABUSEIPDB_KEY;
}

/**
 * Check one IP. Returns:
 *   { ip, abuseScore, totalReports, countryCode, isp, domain, lastReportedAt }
 * or null if no key / rate-limited / error.
 */
export async function checkIP(ip) {
  const key = process.env.ABUSEIPDB_KEY;
  if (!key) return null;

  const cached = getCached(ip);
  if (cached !== undefined) return cached;

  // Respect the 50/hour budget — if exhausted, skip (cache still serves)
  const gate = rateConsume('abuseipdb', (a) =>
    console.warn(`[AbuseIPDB] ${a.pct}% of daily budget used (${a.used}/${a.max})`));
  if (!gate.allowed) {
    console.warn('[AbuseIPDB] hourly budget exhausted — skipping live check');
    return null;
  }

  try {
    const ctrl  = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5000);
    const res = await fetch(`${API_URL}?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
      method:  'GET',
      headers: { 'Key': key, 'Accept': 'application/json' },
      signal:  ctrl.signal,
    });
    clearTimeout(timer);

    if (!res.ok) {
      console.error('[AbuseIPDB] HTTP', res.status);
      return null;
    }

    const json = await res.json();
    const d    = json.data ?? {};
    const data = {
      ip,
      abuseScore:     d.abuseConfidenceScore ?? 0,   // 0–100
      totalReports:   d.totalReports ?? 0,
      countryCode:    d.countryCode ?? null,
      isp:            d.isp ?? null,
      domain:         d.domain ?? null,
      lastReportedAt: d.lastReportedAt ?? null,
    };

    cache[ip] = { data, cachedAt: Date.now() };
    saveCache();
    return data;
  } catch (err) {
    console.error('[AbuseIPDB] lookup failed:', err.message);
    return null;
  }
}

/**
 * Turn an abuse score into a plain-English severity + label, or null if clean/unknown.
 */
// Networks of major platforms (GitHub, Google, Cloudflare, Microsoft, Amazon,
// Apple, Akamai, Fastly, Meta, Anthropic, OpenAI). Their shared IPs collect
// community reports from abuse by *their customers*; a middling score there
// is noise, not evidence. Only a near-certain score alerts.
// Big shared platforms and CDNs: one address serves thousands of unrelated
// sites, so community reports there are usually about a neighbour, not the
// site you're using. Only a near-certain score (≥90) alerts on these networks.
const MAJOR_PLATFORM_ASNS = new Set([
  36459,                                                    // GitHub
  15169, 396982, 19527, 139070,                             // Google / Google Cloud
  13335, 209242,                                            // Cloudflare
  8075, 8068,                                               // Microsoft
  16509, 14618, 8987,                                       // Amazon / AWS / CloudFront
  714, 6185,                                                // Apple
  20940, 16625, 21342, 21399, 33905, 34164, 35994, 12222,   // Akamai
  54113,                                                    // Fastly
  15133,                                                    // Edgecast / Edgio
  32934,                                                    // Meta
  399358, 211458,
]);

export function scoreToThreat(result, { asn } = {}) {
  if (!result || result.abuseScore < 25) return null;
  if (asn && MAJOR_PLATFORM_ASNS.has(asn) && result.abuseScore < 90) return null;
  const { abuseScore, totalReports } = result;
  const severity = abuseScore >= 75 ? 'CRITICAL' : abuseScore >= 50 ? 'HIGH' : 'MEDIUM';
  return {
    severity,
    type:   'Connection to an address other people have reported as malicious',
    detail: `This address has an abuse score of ${abuseScore}/100 and has been reported ${totalReports} time${totalReports !== 1 ? 's' : ''} by the security community.`,
  };
}

export function budgetStatus() {
  return rateCheck('abuseipdb');
}
