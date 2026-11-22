/**
 * db.js — SQLite Persistence Layer (better-sqlite3)
 *
 * Persists everything that previously lived only in memory:
 *   • threat_logs     — network / process threats detected by realNetworkMonitor
 *   • scan_results    — AI prompt scans (PII + injection summary)
 *   • pii_detections  — individual PII findings, one row each, linked to a scan
 *
 * Uses WAL journaling for fast concurrent reads while writing.
 * The DB file lives in ALVORA_DATA_DIR (Electron userData) so it survives
 * app restarts and reinstalls of the app bundle.
 *
 * better-sqlite3 is synchronous by design — that's correct here. SQLite writes
 * are sub-millisecond and we never block on network I/O inside a transaction.
 */

import Database from 'better-sqlite3';
import fs        from 'fs';
import path      from 'path';
import os        from 'os';

const DATA_DIR = process.env.ALVORA_DATA_DIR || path.join(os.homedir(), '.alvora-cyber');
const DB_PATH  = path.join(DATA_DIR, 'alvora.db');

fs.mkdirSync(DATA_DIR, { recursive: true });

// ── Connection ────────────────────────────────────────────────────────────────

let db;
try {
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');   // concurrent reads during writes
  db.pragma('synchronous = NORMAL'); // safe with WAL, much faster than FULL
  db.pragma('foreign_keys = ON');
} catch (err) {
  // If the native binding fails to load (ABI mismatch in a misbuilt package),
  // surface a clear message rather than a cryptic crash.
  console.error('[DB] Failed to open SQLite database:', err.message);
  throw err;
}

// ── Schema ────────────────────────────────────────────────────────────────────

db.exec(`
  CREATE TABLE IF NOT EXISTS threat_logs (
    id            TEXT PRIMARY KEY,
    timestamp     TEXT NOT NULL,
    type          TEXT NOT NULL,
    source        TEXT,
    port          INTEGER DEFAULT 0,
    action        TEXT,
    severity      TEXT,
    origin        TEXT DEFAULT 'real',
    detail        TEXT,
    anomaly_score REAL DEFAULT 0,
    created_at    INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_threat_created  ON threat_logs(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_threat_severity ON threat_logs(severity);
  CREATE INDEX IF NOT EXISTS idx_threat_source   ON threat_logs(source);

  CREATE TABLE IF NOT EXISTS scan_results (
    id              TEXT PRIMARY KEY,
    timestamp       TEXT NOT NULL,
    context         TEXT,
    text_length     INTEGER DEFAULT 0,
    combined_risk   REAL DEFAULT 0,
    final_action    TEXT,
    pii_total       INTEGER DEFAULT 0,
    injection_total INTEGER DEFAULT 0,
    redacted_sample TEXT,
    raw_json        TEXT,
    created_at      INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_scan_created ON scan_results(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_scan_action  ON scan_results(final_action);

  CREATE TABLE IF NOT EXISTS pii_detections (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    TEXT NOT NULL,
    type       TEXT,
    label      TEXT,
    severity   TEXT,
    category   TEXT,
    redacted   TEXT,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_pii_scan     ON pii_detections(scan_id);
  CREATE INDEX IF NOT EXISTS idx_pii_category ON pii_detections(category);
`);

// Columns added after the first release — older databases get them on open
const hasColumn = (table, col) => db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === col);
if (!hasColumn('threat_logs', 'app_path')) db.exec('ALTER TABLE threat_logs ADD COLUMN app_path TEXT');

// ── Prepared statements (compiled once, reused — fast) ─────────────────────────

const stmts = {
  insertThreat: db.prepare(`
    INSERT OR REPLACE INTO threat_logs
      (id, timestamp, type, source, port, action, severity, origin, detail, anomaly_score, app_path, created_at)
    VALUES
      (@id, @timestamp, @type, @source, @port, @action, @severity, @origin, @detail, @anomaly_score, @app_path, @created_at)
  `),

  getThreats: db.prepare(`
    SELECT * FROM threat_logs ORDER BY created_at DESC LIMIT ?
  `),

  insertScan: db.prepare(`
    INSERT OR REPLACE INTO scan_results
      (id, timestamp, context, text_length, combined_risk, final_action, pii_total, injection_total, redacted_sample, raw_json, created_at)
    VALUES
      (@id, @timestamp, @context, @text_length, @combined_risk, @final_action, @pii_total, @injection_total, @redacted_sample, @raw_json, @created_at)
  `),

  insertPii: db.prepare(`
    INSERT INTO pii_detections
      (scan_id, type, label, severity, category, redacted, created_at)
    VALUES
      (@scan_id, @type, @label, @severity, @category, @redacted, @created_at)
  `),

  getScans: db.prepare(`
    SELECT * FROM scan_results ORDER BY created_at DESC LIMIT ?
  `),

  getPiiForScan: db.prepare(`
    SELECT * FROM pii_detections WHERE scan_id = ? ORDER BY id ASC
  `),

  countThreats:   db.prepare(`SELECT COUNT(*) AS n FROM threat_logs`),
  countBlocked:   db.prepare(`SELECT COUNT(*) AS n FROM threat_logs WHERE action IN ('BLOCKED', 'ALERT')`),
  countCritical:  db.prepare(`SELECT COUNT(*) AS n FROM threat_logs WHERE severity = 'CRITICAL'`),
  countScans:     db.prepare(`SELECT COUNT(*) AS n FROM scan_results`),
  countScanBlock: db.prepare(`SELECT COUNT(*) AS n FROM scan_results WHERE final_action = 'BLOCK'`),
  countPii:       db.prepare(`SELECT COUNT(*) AS n FROM pii_detections`),

  topThreatTypes: db.prepare(`
    SELECT type, COUNT(*) AS count FROM threat_logs
    GROUP BY type ORDER BY count DESC LIMIT 5
  `),
  topSources: db.prepare(`
    SELECT source, COUNT(*) AS count FROM threat_logs
    WHERE source IS NOT NULL GROUP BY source ORDER BY count DESC LIMIT 5
  `),

  clearThreats: db.prepare(`DELETE FROM threat_logs`),
  clearScans:   db.prepare(`DELETE FROM scan_results`),
  clearPii:     db.prepare(`DELETE FROM pii_detections`),
  deleteThreat: db.prepare(`DELETE FROM threat_logs WHERE id = ?`),
  deleteThreatsForApp: db.prepare(`DELETE FROM threat_logs WHERE app_path = ?`),
  pruneThreats: db.prepare(`DELETE FROM threat_logs WHERE created_at < ?`),
  pruneScans:   db.prepare(`DELETE FROM scan_results WHERE created_at < ?`),
};

// ── Threat logs ─────────────────────────────────────────────────────────────

export function insertThreatLog(threat) {
  stmts.insertThreat.run({
    id:            threat.id,
    timestamp:     threat.timestamp ?? new Date().toISOString(),
    type:          threat.type ?? 'Unknown',
    source:        threat.source ?? null,
    port:          threat.port ?? 0,
    action:        threat.action ?? 'MONITORING',
    severity:      threat.severity ?? 'LOW',
    origin:        threat.origin ?? 'real',
    detail:        threat.detail ?? null,
    anomaly_score: threat.nvidia?.anomalyScore ?? threat.anomalyScore ?? 0,
    app_path:      threat.appPath ?? null,
    created_at:    Date.now(),
  });
}

export function getThreatLogs(limit = 100) {
  return stmts.getThreats.all(limit);
}

// ── Scan results (+ PII detections in one transaction) ─────────────────────────

/**
 * Insert a scan result. If the scan has PII findings, insert each as a row
 * in pii_detections — all inside a single transaction for consistency.
 */
export const insertScanResult = db.transaction((scan) => {
  stmts.insertScan.run({
    id:              scan.id,
    timestamp:       scan.timestamp ?? new Date().toISOString(),
    context:         scan.context ?? 'user_input',
    text_length:     scan.textLength ?? 0,
    combined_risk:   scan.combinedRisk ?? 0,
    final_action:    scan.finalAction ?? 'ALLOW',
    pii_total:       scan.pii?.totalFindings ?? 0,
    injection_total: scan.injection?.threats?.length ?? 0,
    redacted_sample: scan.redactedSample ?? null,
    raw_json:        JSON.stringify(scan),
    created_at:      Date.now(),
  });

  const findings = scan.pii?.findings ?? [];
  for (const f of findings) {
    stmts.insertPii.run({
      scan_id:    scan.id,
      type:       f.type ?? null,
      label:      f.label ?? null,
      severity:   f.severity ?? null,
      category:   f.category ?? null,
      redacted:   f.redacted ?? null,
      created_at: Date.now(),
    });
  }
});

export function getScanResults(limit = 50) {
  const rows = stmts.getScans.all(limit);
  // Re-hydrate the full record from raw_json so the frontend gets the same shape
  return rows.map(r => {
    try {
      return JSON.parse(r.raw_json);
    } catch {
      return r;
    }
  });
}

export function getPiiDetections(scanId) {
  return stmts.getPiiForScan.all(scanId);
}

// ── Aggregate stats (for Reports) ──────────────────────────────────────────────

export function getStats() {
  return {
    threats: {
      total:    stmts.countThreats.get().n,
      blocked:  stmts.countBlocked.get().n,
      critical: stmts.countCritical.get().n,
    },
    scans: {
      total:      stmts.countScans.get().n,
      blocked:    stmts.countScanBlock.get().n,
      piiTotal:   stmts.countPii.get().n,
    },
    topThreatTypes: stmts.topThreatTypes.all(),
    topSources:     stmts.topSources.all(),
  };
}

// ── Maintenance ─────────────────────────────────────────────────────────────

export const clearAll = db.transaction(() => {
  stmts.clearPii.run();
  stmts.clearScans.run();
  stmts.clearThreats.run();
});

export function clearThreatLogs() { stmts.clearThreats.run(); }

/** Scan history only (PII rows follow via ON DELETE CASCADE). Alerts are untouched. */
export function clearScanResults() { stmts.clearScans.run(); }

export function deleteThreatLog(id) { return stmts.deleteThreat.run(id).changes; }

export function deleteThreatLogsForApp(appPath) { return stmts.deleteThreatsForApp.run(appPath).changes; }

/** Drop alerts and scans older than `days`. Returns how many rows went. */
export const pruneOlderThan = db.transaction((days) => {
  const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
  return { threats: stmts.pruneThreats.run(cutoff).changes, scans: stmts.pruneScans.run(cutoff).changes };
});

export function counts() {
  return { threats: stmts.countThreats.get().n, scans: stmts.countScans.get().n };
}

// ── Backups (taken automatically before anything is cleared) ──────────────────

const BACKUP_DIR  = path.join(DATA_DIR, 'backups');
const KEEP_BACKUPS = 5;

/** Consistent online copy of the whole database; keeps the newest few. */
export async function backup(reason = 'manual') {
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const file  = path.join(BACKUP_DIR, `alvora-${stamp}-${reason}.db`);
  await db.backup(file);
  const old = fs.readdirSync(BACKUP_DIR).filter(f => f.endsWith('.db')).sort().reverse().slice(KEEP_BACKUPS);
  for (const f of old) fs.rmSync(path.join(BACKUP_DIR, f), { force: true });
  return file;
}

export { DB_PATH };
export default db;
