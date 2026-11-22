/**
 * Alvora Cyber — Backend Orchestrator v2
 *
 * Express server with:
 *  • Helmet security headers + strict CORS
 *  • SSE threat stream fed by the real network monitor
 *  • Provider-agnostic AI layer (local Ollama → NVIDIA NIM → Claude)
 *  • Real PII scanning and prompt injection detection
 *  • Real system stats via systeminformation
 *  • License validation endpoint
 *  • Hardening scan + Lockdown mode
 *
 * In production Electron mode, this server also serves the built React app
 * so Electron can load everything from a single HTTP origin.
 */

import express  from 'express';
import helmet   from 'helmet';
import cors     from 'cors';
import path     from 'path';
import { fileURLToPath } from 'url';

import { scanForPII, redactPII, redactForSend } from './lib/piiDetector.js';
import { analyzeForInjection }                 from './lib/promptInjectionGuard.js';
import { validateKey, createTrial, checkLicenseState } from './lib/licenseManager.js';
import { getFullSnapshot }                     from './lib/realSystemStats.js';
import { scanForThreats, getNetworkSummary }   from './lib/realNetworkMonitor.js';
import { runSecurityAudit }                    from './lib/realHardener.js';
import * as db                                 from './lib/db.js';
import * as vault                              from './lib/vault.js';
import { locateMany }                          from './lib/geoLocator.js';
import { checkIP, scoreToThreat, isConfigured as abuseConfigured } from './lib/abuseIpdb.js';
import { analyzeText, classifyConnection, explainThreat, isAvailable as aiAvailable } from './lib/aiAnalyzer.js';
import { status as llmStatus, chat as llmChat } from './lib/llm.js';
import * as assistant                          from './lib/assistant.js';
import { notesFor as playbookNotes }          from './lib/securityPlaybook.js';
import * as intel                              from './lib/threatIntel.js';
import * as persistence                        from './lib/persistenceMonitor.js';
import * as netBaseline                        from './lib/netBaseline.js';
import * as trust                              from './lib/trustList.js';
import * as prefs                              from './lib/prefs.js';
import * as injectionML                        from './lib/injectionClassifier.js';
import * as urlIntel                           from './lib/urlIntel.js';
import * as downloads                          from './lib/downloadsMonitor.js';
import * as asnDb                              from './lib/asnDb.js';
import { status as rateLimitStatus }           from './lib/rateLimiter.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app       = express();
const PORT      = parseInt(process.env.PORT || '3001', 10);
const isProd    = process.env.NODE_ENV === 'production';

// How long a prompt scan waits on the AI layer before answering with the rule
// engines' verdict alone. The browser extension holds the user's send until
// /api/scan responds, so this is the latency budget the AI adds to every send.
const AI_SCAN_BUDGET_MS = parseInt(process.env.ALVORA_AI_SCAN_BUDGET_MS || '3500', 10);

// ─── Security Middleware ──────────────────────────────────────────────────────

app.use(helmet({ contentSecurityPolicy: false }));

// Endpoints the browser extension calls (verdict-only, token-exempt — see below)
const EXTENSION_ENDPOINTS = new Set(['/api/health', '/api/scan', '/api/url/check']);

app.use(cors((req, cb) => {
  const origin = req.header('Origin');
  const allowed =
    !origin ||                                                  // curl / Electron main
    /^http:\/\/localhost(:\d+)?$/.test(origin) ||             // web dev
    // The extension's service worker sends Origin: chrome-extension://<id>. Only
    // its two verdict endpoints accept that; everything else stays localhost-only.
    (/^chrome-extension:\/\/[a-p]{32}$/.test(origin) && EXTENSION_ENDPOINTS.has(req.path));
  if (!allowed) return cb(new Error('Not allowed by CORS'));
  cb(null, {
    origin:         true,
    methods:        ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Alvora-Token'],
    credentials:    false,
  });
}));

// 25 MB limit accommodates base64-encoded vault file uploads.
// (Scan/license payloads are tiny; this only matters for /api/vault/add.)
app.use(express.json({ limit: '25mb' }));

// ─── API access token gate ────────────────────────────────────────────────────
// When ALVORA_API_TOKEN is set (i.e. running inside the desktop app), sensitive
// /api routes require the matching X-Alvora-Token header. This stops other local
// processes or curl from driving the security backend or reading stored data.
//
// Exemptions (by design):
//   • non-/api paths       → the bundled web UI (static files)
//   • GET /api/threats/stream → SSE can't set headers; accepts ?token= instead
//   • POST /api/scan        → used by the browser extension (analyses supplied
//                             text only; never exposes stored user data)
//   • POST /api/url/check   → extension's phishing guard (returns a verdict for
//                             the supplied URL only)
//   • GET  /api/health      → extension's liveness probe (returns { ok: true })
const API_TOKEN = process.env.ALVORA_API_TOKEN || '';
const TOKEN_EXEMPT = EXTENSION_ENDPOINTS;

if (API_TOKEN) {
  app.use((req, res, next) => {
    if (!req.path.startsWith('/api')) return next();           // static UI
    if (TOKEN_EXEMPT.has(req.path)) return next();             // extension endpoint
    if (req.path === '/api/threats/stream') {                  // SSE via query param
      if (req.query.token === API_TOKEN) return next();
      return res.status(401).json({ error: 'Unauthorized' });
    }
    const provided = req.get('X-Alvora-Token');
    if (provided && provided === API_TOKEN) return next();
    return res.status(401).json({ error: 'Unauthorized — invalid or missing API token' });
  });
}

// ─── Application State ────────────────────────────────────────────────────────

let lockdownActive = false;

// Latest real threat level from the network monitor / security audit.
// null until the first scan finishes — the UI shows "Unknown", never a guess.
let lastThreatLevel = null;

// Security audit is a handful of shell calls — cache it for /api/status.
let auditCache = null;   // { at, audit }
async function getAuditCached(maxAgeMs = 10 * 60_000) {
  if (!auditCache || Date.now() - auditCache.at > maxAgeMs) {
    auditCache = { at: Date.now(), audit: await runSecurityAudit() };
  }
  return auditCache.audit;
}

/** @type {Map<string, import('express').Response>} */
const sseClients = new Map();

// Scan history (in-memory, capped at 100)
const scanHistory = [];
function pushScan(record) {
  scanHistory.unshift(record);
  if (scanHistory.length > 100) scanHistory.length = 100;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function broadcast(data) {
  const payload = `data: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients.values()) {
    try { res.write(payload); } catch { /* disconnected */ }
  }
}

// ─── Routes: System Status ────────────────────────────────────────────────────

// Liveness only — no data. The browser extension polls this (token-exempt).
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// Every value here is measured; anything we can't read is null / 'Unknown'.
app.get('/api/status', async (_req, res) => {
  try {
    const [snap, audit] = await Promise.all([
      getFullSnapshot(),
      getAuditCached().catch(() => null),
    ]);
    res.json({
      cpuTemp:          snap.cpuTemp,
      threatLevel:      lastThreatLevel ?? audit?.threatLevel ?? 'Unknown',
      memoryEncryption: audit?.checks.find(c => c.id === 'filevault')?.value ?? 'Unknown',
      securityScore:    audit?.score ?? null,
      memStats:         snap.memStats,
      cpuLoad:          snap.cpuLoad,
      network:          snap.network,
      processes:        snap.processes,
      uptimeSeconds:    process.uptime(),
      timestamp:        snap.timestamp,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/system/snapshot', async (_req, res) => {
  try {
    const snap = await getFullSnapshot();
    res.json(snap);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Routes: Hardening ────────────────────────────────────────────────────────

app.post('/api/harden', async (_req, res) => {
  try {
    // Run real security audit in parallel with system snapshot
    const [audit, snap] = await Promise.all([
      runSecurityAudit(),
      getFullSnapshot(),
    ]);

    const cpuTemp     = snap.cpuTemp;
    const threatLevel = audit.threatLevel;
    auditCache      = { at: Date.now(), audit };
    lastThreatLevel = threatLevel;

    broadcast({ msgType: 'SYSTEM_UPDATE', threatLevel, cpuTemp });

    res.json({
      success:          true,
      cpuTemp,
      threatLevel,
      memoryEncryption: audit.checks.find(c => c.id === 'filevault')?.value ?? 'Unknown',
      securityScore:    audit.score,
      audit,
      metrics: {
        checksRun:       audit.summary.total,
        checksPassed:    audit.summary.pass,
        checksFailed:    audit.summary.fail,
        checksWarned:    audit.summary.warn,
        criticalIssues:  audit.criticalIssues,
        fixes:           audit.fixes,
      },
    });
  } catch (err) {
    console.error('[/api/harden]', err);
    res.status(500).json({ error: 'Hardening sequence failed' });
  }
});

// ─── Routes: Security Audit ───────────────────────────────────────────────────

app.get('/api/security/audit', async (_req, res) => {
  try {
    const audit = await runSecurityAudit();
    res.json(audit);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/network/summary', async (_req, res) => {
  try {
    const summary = await getNetworkSummary();
    res.json(summary);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Routes: SSE Threat Stream ────────────────────────────────────────────────

app.get('/api/threats/stream', (req, res) => {
  res.setHeader('Content-Type',      'text/event-stream');
  res.setHeader('Cache-Control',     'no-cache');
  res.setHeader('Connection',        'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const clientId = `sse-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  sseClients.set(clientId, res);

  const heartbeat = setInterval(() => {
    try { res.write(': heartbeat\n\n'); } catch { clearInterval(heartbeat); }
  }, 25_000);

  res.write(`data: ${JSON.stringify({ msgType: 'CONNECTED', clientId })}\n\n`);

  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(clientId);
  });
});

// ─── Routes: Lockdown ─────────────────────────────────────────────────────────

app.post('/api/lockdown', (req, res) => {
  const { active } = req.body;
  if (typeof active !== 'boolean') {
    return res.status(400).json({ error: '"active" must be a boolean' });
  }
  lockdownActive = active;
  broadcast({ msgType: 'LOCKDOWN_STATE', active: lockdownActive });
  console.log(`[Alvora] Lockdown: ${lockdownActive ? 'ENGAGED' : 'DISENGAGED'}`);
  res.json({ success: true, lockdown: lockdownActive });
});

app.get('/api/lockdown/status', (_req, res) => {
  res.json({ lockdown: lockdownActive });
});

// ─── Routes: AI Security Scanning ─────────────────────────────────────────────

/**
 * POST /api/scan
 * Runs both PII detection and prompt injection analysis on the provided text.
 * This is the core feature of Alvora's AI security layer.
 *
 * Body: { text: string, context?: string }
 * Returns: combined analysis with risk score and recommended action
 */
app.post('/api/scan', async (req, res) => {
  try {
    const { text, context = 'user_input' } = req.body;

    if (!text || typeof text !== 'string') {
      return res.status(400).json({ error: 'text field is required' });
    }

    if (text.length > 20_000) {
      return res.status(400).json({ error: 'Text too long (max 20,000 characters)' });
    }

    // On-device ML injection classifier — started first so it runs while the
    // rules and the LLM layer do their work (it's native, off the JS thread).
    const mlPromise = injectionML.classify(text).catch(() => null);

    // Run both scans in parallel
    const [piiResult, injectionResult] = await Promise.all([
      Promise.resolve(scanForPII(text)),
      Promise.resolve(analyzeForInjection(text)),
    ]);

    // Combined risk score (weighted average of the two regex layers)
    let combinedRisk = parseFloat(
      Math.min(1.0, piiResult.riskScore * 0.4 + injectionResult.injectionScore * 0.6).toFixed(3)
    );

    // ── AI semantic layer (catches what regex misses) ──────────────────────────
    // Skipped when the rules already found a critical leak or high risk — the AI
    // is there to catch *misses*. Local Ollama answers first (free, private).
    // If it can't answer within AI_SCAN_BUDGET_MS we respond with the rule
    // verdict now and raise a follow-up alert if the AI later flags the prompt.
    let aiAnalysis = null;
    let aiPromise  = null;
    if (!piiResult.hasCritical && combinedRisk < 0.8 && await aiAvailable('fast')) {
      aiPromise = analyzeText(text);
      let budgetTimer;
      const TIMED_OUT = Symbol('timeout');
      const first = await Promise.race([
        aiPromise,
        new Promise(r => { budgetTimer = setTimeout(() => r(TIMED_OUT), AI_SCAN_BUDGET_MS); }),
      ]);
      clearTimeout(budgetTimer);
      if (first !== TIMED_OUT) {
        aiAnalysis = first;
        aiPromise  = null;
        if (aiAnalysis?.sensitive) {
          // Fold the AI's judgment into the combined risk (take the stronger signal)
          combinedRisk = parseFloat(Math.max(combinedRisk, aiAnalysis.risk ?? 0).toFixed(3));
        }
      }
    }

    // Rules + classifier → injection verdict (a confident model hit holds the
    // prompt for review; rules and model agreeing blocks it)
    const ml = await mlPromise;
    const fused = injectionML.fuse(injectionResult, ml);
    if (ml?.attack) combinedRisk = parseFloat(Math.max(combinedRisk, ml.score).toFixed(3));

    // Final recommendation
    let action = fused.action;
    if (piiResult.hasCritical && action === 'ALLOW') action = 'FLAG';
    if (piiResult.hasCritical && action === 'FLAG')  action = 'REVIEW';
    // AI escalation: a confident AI "sensitive" verdict raises the action floor
    if (aiAnalysis?.sensitive && (aiAnalysis.risk ?? 0) >= 0.8 && action === 'ALLOW') action = 'REVIEW';
    else if (aiAnalysis?.sensitive && (aiAnalysis.risk ?? 0) >= 0.5 && action === 'ALLOW') action = 'FLAG';

    // AI Lockdown: when engaged, EVERY prompt is blocked before it reaches the AI,
    // regardless of content. This makes the Lockdown control genuinely enforce —
    // the browser extension and AI Monitor will block all sends.
    let lockedDown = false;
    if (lockdownActive) { action = 'BLOCK'; lockedDown = true; }

    const record = {
      id:        `SCAN-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`,
      timestamp: new Date().toISOString(),
      context,
      textLength:     text.length,
      pii:            piiResult,
      injection:      injectionResult,
      classifier:     ml ? { score: +ml.score.toFixed(4), attack: ml.attack, threshold: injectionML.THRESHOLD, ms: Math.round(ml.ms) } : null,
      verdictSource:  fused.source,
      ai:             aiAnalysis,
      aiPending:      !!aiPromise,
      combinedRisk,
      finalAction:    action,
      lockedDown,
      redactedSample: redactPII(text.slice(0, 200)),
    };

    // "Try a sample" scans show their result but aren't real activity — don't keep them
    if (context !== 'sample') {
      pushScan(record);
      // Persist to SQLite (survives restarts)
      try { db.insertScanResult(record); } catch (e) { console.error('[DB] scan insert:', e.message); }
    }

    // Broadcast to SSE clients if high risk
    if (combinedRisk > 0.5) {
      broadcast({
        msgType:   'AI_THREAT',
        severity:  combinedRisk > 0.8 ? 'CRITICAL' : 'HIGH',
        type:      injectionResult.threats[0]?.name
                   ?? (fused.source === 'classifier' ? 'Hidden instructions detected in an AI prompt'
                   : piiResult.hasCritical ? 'Your personal info was found in an AI prompt'
                   : 'Something suspicious in an AI prompt'),
        source:    'AI Traffic Monitor',
        port:      443,
        // Prompt verdicts: BLOCK really stops the send; REVIEW holds it for the user
        action:    { BLOCK: 'BLOCKED', REVIEW: 'HELD', FLAG: 'FLAGGED' }[action] ?? 'MONITORING',
        riskScore: combinedRisk,
        scanId:    record.id,
        detail:    fused.source === 'classifier'
          ? 'The on-device injection classifier found text trying to give the AI new instructions — a common way to hijack it or leak data.'
          : aiAnalysis?.reason || injectionResult.threats[0]?.description,
        engine:    fused.source === 'classifier'
          ? { name: 'Injection classifier', model: 'deberta-v3 (on-device)', confidence: ml.score }
          : aiAnalysis?.sensitive
            ? { name: `AI · ${aiAnalysis.provider}`, model: aiAnalysis.model, confidence: aiAnalysis.risk }
            : { name: 'Alvora Rules', confidence: combinedRisk },
      });
    }

    // Late AI verdict — the prompt already went out, so tell the user after the fact.
    if (aiPromise) {
      aiPromise.then(ai => {
        if (!ai?.sensitive || (ai.risk ?? 0) < 0.5) return;
        broadcast({
          msgType:   'AI_THREAT',
          severity:  ai.risk >= 0.8 ? 'HIGH' : 'MEDIUM',
          type:      'AI review: a prompt you sent may have contained sensitive info',
          source:    'AI Traffic Monitor',
          port:      443,
          action:    'MONITORING',
          riskScore: ai.risk,
          scanId:    record.id,
          detail:    ai.reason,
          engine:    { name: `AI · ${ai.provider}`, model: ai.model, confidence: ai.risk },
        });
      }).catch(() => {});
    }

    // Placeholder-redacted copy for the extension's "Redact & Send". Response
    // only — deliberately NOT part of the stored record.
    const redaction = piiResult.totalFindings > 0 ? redactForSend(text, piiResult.findings) : null;

    res.json({ ...record, redaction });
  } catch (err) {
    console.error('[/api/scan]', err);
    res.status(500).json({ error: 'Scan failed' });
  }
});

/**
 * GET /api/scan/history
 * Returns recent scan history.
 */
app.get('/api/scan/history', (_req, res) => {
  // Read from SQLite so history survives restarts; fall back to in-memory.
  try {
    const scans = db.getScanResults(50);
    res.json({ scans, total: scans.length });
  } catch {
    res.json({ scans: scanHistory.slice(0, 50), total: scanHistory.length });
  }
});

/**
 * DELETE /api/scan/history
 * Clears scan history (memory + DB).
 */
app.delete('/api/scan/history', async (_req, res) => {
  try {
    const backup = await db.backup('before-clearing-scans');
    db.clearScanResults();   // AI scans only — alerts are kept
    scanHistory.length = 0;
    res.json({ success: true, backup: path.basename(backup) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: Threat Log History (persisted) ──────────────────────────────────

app.get('/api/threats/history', (_req, res) => {
  try {
    res.json({ threats: db.getThreatLogs(100) });
  } catch (e) {
    res.json({ threats: [] });
  }
});

// Clear every alert (a backup is taken first)
app.delete('/api/threats/history', async (_req, res) => {
  try {
    const backup = await db.backup('before-clearing-alerts');
    db.clearThreatLogs();
    res.json({ success: true, backup: path.basename(backup) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Dismiss one alert
app.delete('/api/threats/:id', (req, res) => {
  const removed = db.deleteThreatLog(String(req.params.id));
  res.json({ success: removed > 0 });
});

// ─── Routes: Trusted apps / addresses ("this is fine, stop alerting") ─────────

app.get('/api/trust', (_req, res) => res.json(trust.list()));

app.post('/api/trust', (req, res) => {
  const { appPath, name, ip } = req.body ?? {};
  if (appPath) {
    if (!trust.trustApp(appPath, name)) return res.status(400).json({ error: 'Not a valid app path' });
    const removed = db.deleteThreatLogsForApp(appPath);   // its past alerts were the same false alarm
    return res.json({ success: true, removedAlerts: removed });
  }
  if (ip) {
    if (!trust.trustIp(ip)) return res.status(400).json({ error: 'Not a valid address' });
    return res.json({ success: true });
  }
  res.status(400).json({ error: 'Nothing to trust' });
});

app.delete('/api/trust', (req, res) => {
  trust.untrust({ app: req.body?.appPath, ip: req.body?.ip });
  res.json({ success: true });
});

// ─── Routes: Your data (history size, auto-cleanup) ──────────────────────────

app.get('/api/data/summary', (_req, res) => {
  res.json({ ...db.counts(), retentionDays: prefs.get().retentionDays, choices: prefs.RETENTION_CHOICES, trusted: trust.list() });
});

app.put('/api/data/retention', (req, res) => {
  const days = Number(req.body?.days);
  if (!prefs.RETENTION_CHOICES.includes(days)) return res.status(400).json({ error: 'Unsupported retention' });
  prefs.set({ retentionDays: days });
  const pruned = days ? db.pruneOlderThan(days) : { threats: 0, scans: 0 };
  res.json({ success: true, retentionDays: days, pruned });
});

app.get('/api/threats/stats', (_req, res) => {
  try {
    res.json(db.getStats());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Routes: Real Geolocation ─────────────────────────────────────────────────

/**
 * GET /api/threats/geo
 * Resolves all external threat-source IPs to real lat/long coordinates
 * via ip-api.com (cached). Returns points for the Threat Map.
 */
const IPV4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

app.get('/api/threats/geo', async (_req, res) => {
  try {
    // 1. Threat-source IPs (from logged threats)
    const threats   = db.getThreatLogs(100);
    const threatIps = threats.map(t => t.source).filter(s => s && IPV4_RE.test(s));
    const byIp      = {};
    for (const t of threats) if (IPV4_RE.test(t.source)) byIp[t.source] = t;

    // 2. Real active external connections (where your traffic actually goes)
    const summary    = await getNetworkSummary();
    const connIps    = (summary.topExternalIPs ?? []).filter(s => IPV4_RE.test(s));

    // Resolve all unique IPs in one cached batch
    const allIps     = [...new Set([...threatIps, ...connIps])];
    const locations  = await locateMany(allIps);

    const points = locations.map(loc => {
      const threat = byIp[loc.ip];
      return {
        ...loc,
        severity: threat?.severity ?? 'LOW',          // LOW = benign connection
        type:     threat?.type ?? 'Active Connection',
        isThreat: !!threat,
      };
    });

    res.json({ points });
  } catch (e) {
    console.error('[/api/threats/geo]', e.message);
    res.json({ points: [] });
  }
});

// ─── Routes: Encrypted Vault ──────────────────────────────────────────────────

app.get('/api/vault/status', (_req, res) => {
  try {
    res.json(vault.getStats());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/vault/init', (req, res) => {
  try {
    const { password } = req.body;
    res.json(vault.initializeVault(password));
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/api/vault/unlock', (req, res) => {
  const { password } = req.body;
  const ok = vault.verifyPassword(password);
  res.json({ success: ok });
});

app.get('/api/vault/list', (_req, res) => {
  try {
    res.json({ files: vault.listFiles() });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/**
 * POST /api/vault/add
 * Body: { password, fileName, contentBase64 }
 * Encrypts and stores a file.
 */
app.post('/api/vault/add', (req, res) => {
  try {
    const { password, fileName, contentBase64 } = req.body;
    if (!fileName || !contentBase64) {
      return res.status(400).json({ error: 'fileName and contentBase64 required' });
    }
    const content = Buffer.from(contentBase64, 'base64');
    const record  = vault.addFile(fileName, content, password);
    res.json({ success: true, record });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

/**
 * POST /api/vault/get
 * Body: { password, id }
 * Decrypts and returns file content as base64.
 */
app.post('/api/vault/get', (req, res) => {
  try {
    const { password, id } = req.body;
    const { name, content } = vault.getFile(id, password);
    res.json({ success: true, name, contentBase64: content.toString('base64') });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/api/vault/delete', (req, res) => {
  try {
    const { password, id } = req.body;
    res.json(vault.deleteFile(id, password));
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/api/vault/reset', (_req, res) => {
  try {
    res.json(vault.resetVault());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/vault/change-password', (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    res.json(vault.changePassword(currentPassword, newPassword));
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ─── Routes: Integrations status ──────────────────────────────────────────────

app.get('/api/integrations/status', async (_req, res) => {
  const llm = await llmStatus();
  const p   = llm.providers;
  res.json({
    abuseipdb: { configured: abuseConfigured() },
    ollama:    { configured: p.ollama.available, model: p.ollama.model, host: p.ollama.host, installed: p.ollama.installed },
    nvidia:    { configured: p.nvidia.available, model: p.nvidia.model, deepModel: p.nvidia.deepModel },
    openrouter: { configured: p.openrouter.available, model: p.openrouter.model },
    anthropic: { configured: p.anthropic.available, model: p.anthropic.model },
    intel:     { totalEntries: intel.status().totalEntries },
    classifier: injectionML.info(),
    linkGuard:  { totalEntries: urlIntel.status().totalEntries },
    llm,
    rateLimits: rateLimitStatus(),
  });
});

// Live test of an AI tier with a deliberately sketchy sample connection.
//   ?tier=fast → real-time triage (local first)   ?tier=deep → explanation (Nemotron Ultra first)
app.get('/api/integrations/ai/test', async (req, res) => {
  const sample = {
    ip: '45.95.147.10', port: 4444, type: 'Possible hacker backdoor', severity: 'CRITICAL',
    detail: 'Connection on a port commonly used by remote-access malware',
  };
  const started = Date.now();
  const result  = req.query.tier === 'deep'
    ? await explainThreat({ ...sample, source: sample.ip })
    : await classifyConnection(sample);
  res.status(result ? 200 : 503).json({ ok: !!result, ms: Date.now() - started, result });
});

// ─── Routes: Phishing / malware link guard (browser extension) ────────────────
// The URL is checked against locally cached feeds and never stored or logged;
// only the hostname of a blocked site is recorded, once per 10 minutes.

const recentlyReported = new Map();   // host → timestamp

app.post('/api/url/check', (req, res) => {
  const url = req.body?.url;
  if (typeof url !== 'string' || url.length > 4096) return res.status(400).json({ error: '"url" (string) is required' });
  const result = urlIntel.check(url);

  if (['malicious', 'suspicious'].includes(result.verdict) && result.host) {
    const last = recentlyReported.get(result.host) ?? 0;
    if (Date.now() - last > 10 * 60_000) {
      recentlyReported.set(result.host, Date.now());
      const malicious = result.verdict === 'malicious';
      const event = {
        msgType:   'THREAT',
        id:        `WEB-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`,
        timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }),
        type:      malicious ? `Stopped you from opening a phishing site: ${result.host}` : `Warned you about a look-alike site: ${result.host}`,
        severity:  malicious ? 'HIGH' : 'MEDIUM',
        action:    'BLOCKED',   // the extension shows its warning page instead of the site
        source:    result.host,
        port:      443,
        origin:    'real',
        detail:    `${result.reason}${result.sources?.length ? ` Listed by: ${result.sources.join(', ')}.` : ''}`,
        engine:    { name: 'Link Guard', confidence: malicious ? 0.95 : 0.6 },
        details:   { protocol: 'Web', resolution: 'The browser extension showed a warning page instead of loading the site.' },
      };
      broadcast(event);
      try { db.insertThreatLog(event); } catch (err) { console.error('[DB] link guard insert:', err.message); }
    }
  }
  res.json(result);
});

app.get('/api/url/status', (_req, res) => {
  res.json(urlIntel.status());
});

// ─── Routes: Downloads scanner ────────────────────────────────────────────────

app.get('/api/downloads', (_req, res) => {
  res.json(downloads.getState());
});

app.post('/api/downloads/rescan', async (req, res) => {
  try { res.json(await downloads.rescan(String(req.body?.path ?? ''))); }
  catch (err) { res.status(400).json({ error: err.message }); }
});

function onDownloadScanned(r) {
  const timestamp = new Date().toLocaleTimeString('en-US', { hour12: false });
  if (r.verdict === 'clean') {
    broadcast({ msgType: 'ACTIVITY', id: `DLC-${Date.now()}`, timestamp, type: `Checked new download: ${r.name} — looks safe`, severity: 'INFO', action: 'OK', detail: r.findings[0]?.detail ?? `${r.kind} file` });
    return;
  }
  const top = r.findings[0];
  const event = {
    msgType:  'THREAT',
    id:       `DL-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`,
    timestamp,
    type:     r.verdict === 'dangerous' ? `Dangerous download: ${r.name} — ${top.title}` : `Download needs caution: ${r.name} — ${top.title}`,
    severity: r.severity === 'CRITICAL' ? 'CRITICAL' : r.severity === 'HIGH' ? 'HIGH' : r.severity === 'MEDIUM' ? 'MEDIUM' : 'LOW',
    action:   r.verdict === 'dangerous' ? 'ALERT' : 'MONITORING',
    source:   r.name,
    port:     0,
    origin:   'real',
    detail:   r.findings.filter(f => f.severity !== 'OK').slice(0, 3).map(f => `${f.title}: ${f.detail}`).join(' '),
    engine:   { name: 'Downloads Scanner', confidence: r.severity === 'CRITICAL' ? 0.95 : r.severity === 'HIGH' ? 0.85 : 0.6 },
    details:  { protocol: 'File', resolution: r.verdict === 'dangerous' ? "Don't open it. Move it to the Trash from System Health → Downloads." : 'Only open it if you trust where it came from.' },
  };
  broadcast(event);
  try { db.insertThreatLog(event); } catch (err) { console.error('[DB] download insert:', err.message); }
}

// ─── Routes: Threat intelligence + startup items ──────────────────────────────

app.get('/api/intel/status', (_req, res) => {
  res.json(intel.status());
});

app.post('/api/intel/refresh', async (_req, res) => {
  await intel.refreshAll({ force: true });
  res.json(intel.status());
});

// Which apps use the network, where they connect, and learning progress
app.get('/api/network/apps', (_req, res) => {
  res.json(netBaseline.summary());
});

// Everything set to launch automatically, with signer + risk for each item
app.get('/api/persistence', async (_req, res) => {
  try {
    if (!persistence.getInventory().scannedAt) await runPersistenceScan();
    res.json(persistence.getInventory());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Routes: AI explanation ───────────────────────────────────────────────────

// Plain-English investigation of one feed event. Uses the deep tier
// (NVIDIA Nemotron Ultra when a NIM key is set, else Claude, else local).
// ─── Routes: Alvora AI (chat) ─────────────────────────────────────────────────

app.get('/api/assistant/status', async (_req, res) => {
  const st = await llmStatus();
  const cloud = ['openrouter', 'nvidia', 'anthropic'].find(n => st.providers[n]?.available) ?? null;
  res.json({
    private: { available: st.providers.ollama.available, model: st.providers.ollama.model },
    cloud:   { available: !!cloud, provider: cloud, model: cloud ? (st.providers[cloud].deepModel ?? st.providers[cloud].model) : null },
  });
});

/**
 * POST /api/assistant/chat  { messages: [{role, content}], mode: 'private'|'cloud' }
 * Streams newline-delimited JSON: {"delta":"…"} … then {"done":true,provider,model} or {"error":"…"}.
 */
app.post('/api/assistant/chat', async (req, res) => {
  const mode = req.body?.mode === 'cloud' ? 'cloud' : 'private';
  let messages = assistant.sanitizeMessages(req.body?.messages);
  if (!messages) return res.status(400).json({ error: 'Send at least one message.' });

  // Personal data never leaves the Mac in cloud mode
  let redacted = 0;
  if (mode === 'cloud') {
    messages = messages.map(m => {
      if (m.role !== 'user') return m;
      const r = redactForSend(m.content);
      redacted += r.items.length;
      return { ...m, content: r.text };
    });
  }

  // Fresh facts about this Mac for every question
  const [audit] = await Promise.all([getAuditCached(5 * 60_000).catch(() => null)]);
  const safe = fn => { try { return fn(); } catch { return null; } };
  const facts = assistant.buildFacts({
    audit,
    alerts:      safe(() => db.getThreatLogs(50)) ?? [],
    trusted:     safe(() => trust.list()),
    downloads:   safe(() => downloads.getState()),
    persistence: safe(() => persistence.getInventory()),
    network:     safe(() => netBaseline.summary()),
    intel:       safe(() => intel.status()),
    links:       safe(() => urlIntel.status()),
    classifier:  safe(() => injectionML.info()),
    version:     process.env.ALVORA_VERSION,
  });

  res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache');
  const send = obj => res.write(JSON.stringify(obj) + '\n');
  if (redacted) send({ notice: `${redacted} piece${redacted === 1 ? '' : 's'} of personal info were hidden before sending to the cloud model.` });

  const abort = new AbortController();
  res.on('close', () => abort.abort());   // user pressed Stop or left the screen

  try {
    const result = await llmChat({
      mode, messages: assistant.withReminder(messages), signal: abort.signal,
      system:  assistant.systemPrompt(facts, playbookNotes(messages)),
      onDelta: (text, opts) => send(opts?.reset ? { reset: true } : opts?.thinking ? { thinking: true } : { delta: text }),
    });
    if (result.error) {
      send({ error: {
        local_unavailable: 'The private AI on this Mac isn\'t running. Open the Ollama app, or switch to Cloud mode.',
        cloud_unavailable: 'No cloud AI is set up or reachable. Add an OpenRouter or NVIDIA key in Settings, or use Private mode.',
      }[result.error] ?? 'The AI couldn\'t answer just now — please try again.' });
    } else {
      send({ done: true, provider: result.provider, model: result.model });
    }
  } catch (err) {
    if (err.name !== 'AbortError') {
      console.error('[Assistant]', err.message);
      send({ error: 'The AI stopped unexpectedly — please try again.' });
    }
  }
  res.end();
});

app.post('/api/ai/explain', async (req, res) => {
  const event = req.body?.event;
  if (!event || typeof event !== 'object' || typeof event.type !== 'string') {
    return res.status(400).json({ error: '"event" with a "type" is required' });
  }
  const explanation = await explainThreat(event);
  if (!explanation) return res.status(503).json({ error: 'No AI provider available. Start Ollama or add an NVIDIA / Anthropic key.' });
  res.json(explanation);
});

// ─── Routes: License ──────────────────────────────────────────────────────────

app.post('/api/license/validate', async (req, res) => {
  try {
    const { key } = req.body;
    const result  = await validateKey(key);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/license/trial', (_req, res) => {
  res.json(createTrial());
});

// ─── Errors ───────────────────────────────────────────────────────────────────
// Refused cross-origin requests → 403; never leak stack traces to callers.
app.use((err, _req, res, next) => {
  if (res.headersSent) return next(err);
  if (err?.message === 'Not allowed by CORS') return res.status(403).json({ error: 'Origin not allowed' });
  if (err?.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON' });
  console.error('[Server]', err);
  res.status(500).json({ error: 'Internal error' });
});

// ─── Routes: Fallback (prod SPA) ──────────────────────────────────────────────

if (isProd || process.env.ELECTRON_APP === '1') {
  app.get('*', (_req, res) => {
    res.sendFile(path.join(__dirname, '../dist/index.html'));
  });
}

// ─── Real Network Monitor ─────────────────────────────────────────────────────
// Every cycle this:
//   1. Scans real connections + processes for genuine threats (emits THREAT)
//   2. ALWAYS emits a real ACTIVITY event with live counts so the feed is never
//      empty — these are real status lines ("Checked N active connections"),
//      not fabricated threats.

let scanCount = 0;
let scanRunning = false;   // AI triage can be slow — never overlap cycles
const alertedAbuseIps = new Set();   // IPs already flagged by AbuseIPDB this session
const SEV_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

async function runRealScan() {
  // Keep monitoring during lockdown — lockdown blocks AI prompts but we still
  // watch the network. Only pause when no UI is connected.
  if (sseClients.size === 0 || scanRunning) return;

  scanRunning = true;
  scanCount++;
  try {
    // Real connection/process counts for the activity line
    const summary = await getNetworkSummary().catch(() => ({}));
    const threats = await scanForThreats();

    // Emit real threats first
    for (const t of threats) {
      const id        = `NET-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
      const timestamp = new Date().toLocaleTimeString('en-US', { hour12: false });

      // AI triage of the suspicious connection (local model first).
      // Only runs on already-flagged threats — rare — so it stays cheap.
      let aiResult = null;
      if (t.source && /^\d{1,3}\./.test(t.source) && await aiAvailable('fast')) {
        aiResult = await classifyConnection({
          ip: t.source, port: t.port, type: t.type, detail: t.detail,
        });
      }

      const event = {
        msgType:   'THREAT',
        id,
        timestamp,
        type:      t.type,
        source:    t.source,
        port:      t.port,
        action:    t.action,
        appPath:   t.appPath,
        // If the AI classified it more severe, take the higher signal
        severity:  aiResult?.severity && SEV_RANK[aiResult.severity] > SEV_RANK[t.severity] ? aiResult.severity : t.severity,
        origin:    'real',
        detail:    aiResult?.reason || t.detail,
        engine: aiResult
          ? { name: `AI · ${aiResult.provider}`, model: aiResult.model, confidence: (aiResult.score ?? 50) / 100 }
          : { name: 'Alvora Threat Engine', confidence: t.severity === 'CRITICAL' ? 0.97 : t.severity === 'HIGH' ? 0.83 : 0.61 },
        ai: aiResult ? { score: aiResult.score, label: aiResult.label, reason: aiResult.reason, provider: aiResult.provider, model: aiResult.model } : null,
        details: {
          protocol:    t.port === 443 ? 'Secure web (HTTPS)' : t.port === 22 ? 'Remote login (SSH)' : 'Network',
          resolution:  t.action === 'ALERT'
            ? 'Alvora can\'t cut this connection on its own — review it as soon as you can.'
            : 'We\'re keeping an eye on this.',
        },
      };

      broadcast(event);
      try { db.insertThreatLog(event); } catch (e) { console.error('[DB] threat insert:', e.message); }
      console.log(`[Monitor] ${t.severity.padEnd(8)} | ${t.type} | ${t.source}:${t.port}`);
    }

    // ── AbuseIPDB reputation check on real external connections ────────────────
    // Only if a key is configured. Cached 24h + rate-limited, so this is cheap.
    // Alert once per IP per session to avoid repeating the same finding.
    if (abuseConfigured()) {
      // The network-owner lookup decides whether an address is a shared CDN —
      // wait for it, or the first scans after start-up would skip that guard
      await asnDb.refresh().catch(() => {});
      for (const ip of (summary.topExternalIPs ?? [])) {
        if (alertedAbuseIps.has(ip) || trust.isTrustedIp(ip)) continue;
        const rep = await checkIP(ip);
        const threat = scoreToThreat(rep, { asn: asnDb.lookup(ip)?.asn });
        if (threat) {
          alertedAbuseIps.add(ip);
          const id = `REP-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
          const event = {
            msgType:  'THREAT',
            id,
            timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }),
            type:      threat.type,
            source:    ip,
            port:      0,
            action:    threat.severity === 'CRITICAL' ? 'ALERT' : 'MONITORING',
            severity:  threat.severity,
            origin:    'real',
            detail:    threat.detail,
            engine:    { name: 'AbuseIPDB', confidence: (rep.abuseScore ?? 0) / 100 },
            details:   { protocol: 'Network', resolution: 'Reported by the security community.' },
          };
          broadcast(event);
          try { db.insertThreatLog(event); } catch {}
          console.log(`[AbuseIPDB] ${threat.severity} | ${ip} score=${rep.abuseScore}`);
        }
      }
    }

    // ALWAYS emit a real monitoring-activity line (keeps the feed alive, honest)
    const checked = summary.externalConnections ?? 0;
    const msg = threats.length > 0
      ? `Scan complete — caught ${threats.length} issue${threats.length !== 1 ? 's' : ''}`
      : `Monitoring network — ${checked} active connection${checked !== 1 ? 's' : ''} checked, all clear`;

    broadcast({
      msgType:   'ACTIVITY',
      id:        `ACT-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }),
      type:      msg,
      severity:  'INFO',
      action:    'OK',
      detail:    `${summary.totalConnections ?? 0} total connections · ${summary.suspiciousProcesses ?? 0} suspicious programs`,
    });

    // Periodic posture update
    if (scanCount % 4 === 0) {
      const snap = await getFullSnapshot().catch(() => ({}));
      lastThreatLevel = threats.some(t => t.severity === 'CRITICAL') ? 'Critical'
                      : threats.some(t => t.severity === 'HIGH') ? 'Elevated' : 'Low';
      broadcast({
        msgType:     'SYSTEM_UPDATE',
        threatLevel: lastThreatLevel,
        cpuTemp:     snap.cpuTemp ?? null,
      });
    }
  } catch (err) {
    console.error('[Monitor] Error:', err.message);
  } finally {
    scanRunning = false;
  }
}

// ─── Startup-item (persistence) monitor ──────────────────────────────────────
// Runs whether or not a UI is connected — installs happen when you're not
// looking. Alerts on new/changed items vs. the saved baseline.

let persistenceRunning = false;

async function runPersistenceScan() {
  if (persistenceRunning) return;
  persistenceRunning = true;
  try {
    const { events } = await persistence.scanPersistence();
    for (const e of events) {
      const t = persistence.toThreatEvent(e);
      const event = {
        msgType:   'THREAT',
        id:        `PER-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`,
        timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }),
        ...t,
        origin:    'real',
        engine:    { name: 'Startup Item Monitor', confidence: t.severity === 'CRITICAL' ? 0.95 : t.severity === 'HIGH' ? 0.8 : 0.5 },
        details:   { protocol: 'Startup item', resolution: t.detail },
      };
      broadcast(event);
      try { db.insertThreatLog(event); } catch (err) { console.error('[DB] persistence insert:', err.message); }
      console.log(`[Persistence] ${t.severity.padEnd(8)} | ${e.change} | ${e.item.label}`);
    }
  } catch (err) {
    console.error('[Persistence] scan failed:', err.message);
  } finally {
    persistenceRunning = false;
  }
}

// ─── Per-app network baseline ────────────────────────────────────────────────
// Learns which networks each app talks to; alerts on first-time internet use
// and new destinations (after a learning period), and on unsigned programs
// going online (immediately). Runs with or without a UI connected.

let netBaselineRunning = false;

async function runNetBaseline() {
  if (netBaselineRunning) return;
  netBaselineRunning = true;
  try {
    for (const t of await netBaseline.observe()) {
      const event = {
        msgType:   'THREAT',
        id:        `APP-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`,
        timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }),
        ...t,
        origin:    'real',
        engine:    { name: 'App Network Baseline', confidence: t.severity === 'HIGH' ? 0.8 : t.severity === 'MEDIUM' ? 0.6 : 0.4 },
        details:   { protocol: `TCP ${t.port}`, resolution: t.detail },
      };
      broadcast(event);
      try { db.insertThreatLog(event); } catch (err) { console.error('[DB] netbaseline insert:', err.message); }
      console.log(`[NetBaseline] ${t.severity.padEnd(8)} | ${t.type}`);
    }
  } catch (err) {
    console.error('[NetBaseline] scan failed:', err.message);
  } finally {
    netBaselineRunning = false;
  }
}

// ─── Start ────────────────────────────────────────────────────────────────────

// Bind to loopback only — the security backend must never be reachable from the
// LAN/internet, only from this machine (the Electron UI + local browser extension).
app.listen(PORT, '127.0.0.1', () => {
  console.log(`\n  Alvora Cyber Backend  ·  127.0.0.1:${PORT}`);
  console.log(`  Network monitor, security audit, PII scanner, AI guard — all active\n`);

  // Load the injection classifier now so the first scan doesn't pay for it
  injectionML.ready().then(ok => ok && console.log(`  Injection classifier: ${injectionML.info().model} loaded`));
  for (const sig of ['SIGINT', 'SIGTERM']) {
    process.once(sig, async () => { await injectionML.release(); process.exit(0); });
  }

  // Threat feeds first (cached copies load instantly; stale ones re-download)
  intel.refreshAll().then(() => {
    const s = intel.status();
    console.log(`  Threat intel: ${s.totalEntries.toLocaleString()} entries from ${s.feeds.filter(f => f.entries).length}/${s.feeds.length} feeds`);
  });
  setInterval(() => intel.refreshAll(), 6 * 60 * 60_000);   // re-checks age; downloads at most daily

  // Phishing / malware link feeds for the browser extension's Link Guard
  urlIntel.refreshAll().then(() => {
    const s = urlIntel.status();
    const phishing = s.feeds.filter(f => f.kind !== 'popular');
    console.log(`  Link Guard: ${phishing.reduce((n, f) => n + f.entries, 0).toLocaleString()} phishing entries from ${phishing.filter(f => f.entries).length}/${phishing.length} feeds`);
  });
  setInterval(() => urlIntel.refreshAll(), 60 * 60_000);    // each feed re-downloads only when stale

  // Downloads scanner — after the Link Guard feeds load, so download origins can be checked
  urlIntel.refreshAll().finally(() => {
    const st = downloads.start({ onResult: onDownloadScanned });
    for (const d of st.dirs) console.log(`  Downloads scanner: ${d.dir} — ${d.state}`);
  });

  // First pass quickly, then every 15s for a live feel
  setTimeout(runRealScan, 2_500);
  setInterval(runRealScan, 15_000);

  setTimeout(runPersistenceScan, 5_000);
  setInterval(runPersistenceScan, 60_000);

  setTimeout(runNetBaseline, 8_000);
  setInterval(runNetBaseline, 30_000);

  // History cleans itself up: drop anything older than the chosen retention
  const pruneHistory = () => {
    const days = prefs.get().retentionDays;
    if (!days) return;
    try {
      const { threats, scans } = db.pruneOlderThan(days);
      if (threats || scans) console.log(`[Data] removed ${threats} alerts and ${scans} scans older than ${days} days`);
    } catch (e) { console.error('[Data] prune failed:', e.message); }
  };
  setTimeout(pruneHistory, 60_000);
  setInterval(pruneHistory, 24 * 60 * 60_000);
});
