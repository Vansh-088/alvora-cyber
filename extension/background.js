/**
 * Alvora Cyber — Background Service Worker
 *
 * Handles:
 *  - Communication with the Alvora backend (localhost:3001)
 *  - Extension badge updates (green/yellow/red)
 *  - Native notifications for blocked prompts
 *  - Session stats tracking
 *  - Link Guard: every page you open is checked against the backend's local
 *    phishing/malware feeds; known-bad sites are replaced by a warning page.
 *    URLs only ever go to localhost — never to a third party.
 */

const BACKEND = 'http://localhost:3001';
const BACKEND_TIMEOUT_MS = 6000;   // backend's AI layer may take up to ALVORA_AI_SCAN_BUDGET_MS (3.5s)

// ── Session Stats ─────────────────────────────────────────────────────────────

let stats = {
  scanned:      0,
  blocked:      0,
  pii:          0,
  injections:   0,
  redacted:     0,   // prompts sent with personal info replaced by placeholders
  linksBlocked: 0,   // phishing / malware pages stopped by Link Guard
  backendOk:    false,
};

// Persist stats across popup opens
async function loadStats() {
  const saved = await chrome.storage.session.get('alvoraStats');
  if (saved.alvoraStats) stats = { ...stats, ...saved.alvoraStats };
}

async function saveStats() {
  await chrome.storage.session.set({ alvoraStats: stats });
}

// ── Badge helpers ─────────────────────────────────────────────────────────────

function setBadge(text, color) {
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
}

function updateBadge() {
  if (!stats.backendOk) {
    setBadge('OFF', '#6b7280');
    return;
  }
  if (stats.blocked > 0) {
    setBadge(String(stats.blocked), '#ef4444');
  } else {
    setBadge('ON', '#10b981');
  }
}

// ── Backend health check ──────────────────────────────────────────────────────

async function checkBackend() {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 2000);
    // /api/health is the token-free liveness probe (/api/status needs the app token)
    const res = await fetch(`${BACKEND}/api/health`, { signal: ctrl.signal });
    clearTimeout(timer);
    stats.backendOk = res.ok;
  } catch {
    stats.backendOk = false;
  }
  updateBadge();
  await saveStats();
}

// Check backend on startup and every 30 seconds
checkBackend();
setInterval(checkBackend, 30_000);

// ── Scan endpoint ─────────────────────────────────────────────────────────────

async function scanPrompt(text, context = 'browser_extension') {
  const ctrl  = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), BACKEND_TIMEOUT_MS);

  try {
    const res = await fetch(`${BACKEND}/api/scan`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ text, context }),
      signal:  ctrl.signal,
    });
    clearTimeout(timer);

    if (!res.ok) throw new Error(`Backend ${res.status}`);
    stats.backendOk = true;

    const data = await res.json();

    // Update session stats
    stats.scanned++;
    if (data.finalAction === 'BLOCK')         stats.blocked++;
    if (data.pii?.totalFindings > 0)          stats.pii++;
    if (data.injection?.threats?.length > 0)  stats.injections++;

    updateBadge();
    await saveStats();

    return { ok: true, data };
  } catch (err) {
    clearTimeout(timer);

    // Backend offline — fail open (don't block user)
    if (err.name === 'AbortError' || err.message.includes('fetch')) {
      stats.backendOk = false;
      updateBadge();
    }

    return { ok: false, data: null, error: err.message };
  }
}

// ── Native notification ───────────────────────────────────────────────────────

function notifyBlocked(site, piiCount, injectionCount) {
  chrome.notifications.create({
    type:     'basic',
    iconUrl:  'icons/icon128.png',
    title:    'Alvora Cyber — Prompt Blocked',
    message:  `${site}: Found ${piiCount} PII issue${piiCount !== 1 ? 's' : ''} and ${injectionCount} injection threat${injectionCount !== 1 ? 's' : ''}. Prompt was NOT sent.`,
    priority: 2,
  });
}

// ── Message handler (from content scripts / popup) ────────────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'SCAN_PROMPT') {
    scanPrompt(msg.text, msg.context || 'browser_extension').then(result => {
      // Trigger notification if blocked
      if (result.ok && result.data?.finalAction === 'BLOCK') {
        notifyBlocked(
          msg.site || 'AI Platform',
          result.data.pii?.totalFindings ?? 0,
          result.data.injection?.threats?.length ?? 0,
        );
      }
      sendResponse(result);
    });
    return true; // Keep channel open for async response
  }

  if (msg.type === 'REDACTED_SEND') {
    stats.redacted++;
    saveStats();
    sendResponse({ ok: true });
    return true;
  }

  // From the Link Guard warning page
  if (msg.type === 'LINK_PROCEED' && sender.tab) {
    allowHostForSession(msg.url).then(() => chrome.tabs.update(sender.tab.id, { url: msg.url }));
    sendResponse({ ok: true });
    return true;
  }
  if (msg.type === 'LINK_BACK' && sender.tab) {
    chrome.tabs.goBack(sender.tab.id).catch(() => chrome.tabs.update(sender.tab.id, { url: 'chrome://newtab' }));
    sendResponse({ ok: true });
    return true;
  }

  if (msg.type === 'GET_STATS') {
    sendResponse({ stats });
    return true;
  }

  if (msg.type === 'RESET_STATS') {
    stats = { scanned: 0, blocked: 0, pii: 0, injections: 0, redacted: 0, linksBlocked: 0, backendOk: stats.backendOk };
    saveStats();
    updateBadge();
    sendResponse({ ok: true });
    return true;
  }
});

// ── Link Guard ────────────────────────────────────────────────────────────────

const LINK_TIMEOUT_MS = 1500;          // never hold up browsing for long; fail open
const linkCache = new Map();           // url → { result, at }
const LINK_CACHE_MS = 10 * 60_000;

async function checkUrl(url) {
  const hit = linkCache.get(url);
  if (hit && Date.now() - hit.at < LINK_CACHE_MS) return hit.result;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), LINK_TIMEOUT_MS);
  try {
    const res = await fetch(`${BACKEND}/api/url/check`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url }),
      signal:  ctrl.signal,
    });
    if (!res.ok) return null;
    const result = await res.json();
    if (linkCache.size > 500) linkCache.delete(linkCache.keys().next().value);
    linkCache.set(url, { result, at: Date.now() });
    return result;
  } catch {
    return null;   // backend offline / slow → don't block browsing
  } finally {
    clearTimeout(timer);
  }
}

async function allowHostForSession(url) {
  try {
    const host = new URL(url).hostname;
    const { linkAllow = [] } = await chrome.storage.session.get('linkAllow');
    if (!linkAllow.includes(host)) await chrome.storage.session.set({ linkAllow: [...linkAllow, host] });
  } catch { /* bad URL */ }
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0 || !/^https?:/i.test(details.url)) return;
  let host;
  try { host = new URL(details.url).hostname; } catch { return; }
  if (host === 'localhost' || host === '127.0.0.1') return;

  const { linkAllow = [] } = await chrome.storage.session.get('linkAllow');
  if (linkAllow.includes(host)) return;   // user chose "continue anyway" this session

  const result = await checkUrl(details.url);
  if (!result || !['malicious', 'suspicious'].includes(result.verdict)) return;

  stats.linksBlocked++;
  saveStats();
  const warning = chrome.runtime.getURL('blocked.html') + '?' + new URLSearchParams({
    u: details.url,
    v: result.verdict,
    r: result.reason ?? '',
    s: (result.sources ?? []).join(', '),
  });
  chrome.tabs.update(details.tabId, { url: warning });
});

// ── Init ──────────────────────────────────────────────────────────────────────

loadStats().then(updateBadge);
