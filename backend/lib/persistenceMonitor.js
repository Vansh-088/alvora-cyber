/**
 * persistenceMonitor.js — What is set to run automatically on this Mac?
 *
 * Nearly all macOS malware survives reboots the same way: a launchd plist in a
 * LaunchAgents/LaunchDaemons folder (or, rarely, a cron job). This module:
 *
 *   1. Inventories every startup item and who signed the program it launches.
 *   2. Rates each one (unsigned code, inline shell scripts, programs hiding in
 *      temp/hidden folders, fake "com.apple" labels → risky).
 *   3. Remembers a baseline and reports anything NEW or CHANGED since — the
 *      moment something installs itself is the moment you want to know.
 *
 * Read-only: nothing here modifies, unloads or deletes startup items.
 */

import fs     from 'fs';
import os     from 'os';
import path   from 'path';
import crypto from 'crypto';
import { exec }      from 'child_process';
import { promisify } from 'util';
import * as codeSign from './codeSign.js';

const execAsync = promisify(exec);

const DATA_DIR      = process.env.ALVORA_DATA_DIR || path.join(os.homedir(), '.alvora-cyber');
const BASELINE_FILE = path.join(DATA_DIR, 'persistence-baseline.json');

// Overridable for tests: ALVORA_PERSISTENCE_DIRS="scope=/dir:scope=/dir"
const LOCATIONS = process.env.ALVORA_PERSISTENCE_DIRS
  ? process.env.ALVORA_PERSISTENCE_DIRS.split(':').map(s => { const [scope, dir] = s.split('='); return { scope, dir }; })
  : [
      { scope: 'Your account (LaunchAgents)',   dir: path.join(os.homedir(), 'Library/LaunchAgents') },
      { scope: 'All users (LaunchAgents)',      dir: '/Library/LaunchAgents' },
      { scope: 'System-wide (LaunchDaemons)',   dir: '/Library/LaunchDaemons' },
    ];

const INTERPRETERS = /\/(?:ba|z|k|c|tc|da)?sh$|\/(?:python[\d.]*|perl|ruby|osascript|node|php|env)$/;
const SCRIPT_RED_FLAGS = /\bcurl\b|\bwget\b|base64|\beval\b|\/dev\/tcp|\bnc\b|\bdd\b|chmod \+x|xattr -[cd]/i;
const SUSPICIOUS_DIRS = [/^\/(?:private\/)?tmp\//, /^\/var\/tmp\//, /^\/Users\/Shared\//, /\/Downloads\//, /\/\.[^/]+\//];

const SEV_RANK = { OK: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const raise = (cur, next) => (SEV_RANK[next] > SEV_RANK[cur] ? next : cur);

// ── Reading items ─────────────────────────────────────────────────────────────

async function readPlist(file) {
  try {
    const { stdout } = await execAsync(`plutil -convert json -o - ${JSON.stringify(file)}`, { timeout: 5000 });
    return JSON.parse(stdout);
  } catch {
    return null;   // unreadable (permissions) or not a valid plist
  }
}

function sha256(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }

async function rateItem(item) {
  const reasons = [];
  let risk = 'OK';

  if (!item.program) {
    return { ...item, risk: 'OK', reasons: ['Empty or inactive — it does not launch anything.'], signer: null };
  }

  const scripted = INTERPRETERS.test(item.program);
  const cmdline  = [item.program, ...item.args].join(' ');
  // For "sh -c …" / "python script.py" the real payload is the script; judge it too
  const payload  = scripted ? item.args.find(a => a.startsWith('/') && !a.startsWith('-')) : null;
  const target   = payload ?? item.program;
  const signer   = await codeSign.inspect(target);

  if (signer.status === 'missing') {
    risk = raise(risk, 'LOW');
    reasons.push('The program it points to no longer exists (often leftover from an uninstalled app).');
  } else if (signer.status === 'unreadable') {
    reasons.push('Its program is readable only by the administrator, so its signature could not be checked.');
  } else if (signer.status === 'unknown') {
    reasons.push('Its signature couldn\'t be checked just now — it will be re-checked on the next scan.');
  } else if (!signer.trusted && !(scripted && !payload)) {
    risk = raise(risk, 'HIGH');
    reasons.push(signer.status === 'invalid'
      ? 'Its program has a broken or tampered code signature.'
      : 'Its program is not signed by Apple or an identified developer.');
  }

  if (scripted) {
    const inline = item.args.includes('-c') || item.args.includes('-e');
    if (inline && SCRIPT_RED_FLAGS.test(cmdline)) {
      risk = raise(risk, 'CRITICAL');
      reasons.push('It runs an inline script that downloads, decodes or opens network connections — a classic malware pattern.');
    } else if (inline) {
      risk = raise(risk, 'MEDIUM');
      reasons.push('It runs an inline shell/script command at startup instead of a normal app.');
    }
  }

  if (SUSPICIOUS_DIRS.some(rx => rx.test(target))) {
    risk = raise(risk, 'HIGH');
    reasons.push('Its program lives in a temporary, shared, Downloads or hidden folder — legitimate apps install elsewhere.');
  }

  // Real Apple items aren't unsigned and don't run inline shell scripts
  const inlineScript = scripted && (item.args.includes('-c') || item.args.includes('-e'));
  if (/^com\.apple\./i.test(item.label ?? '') && (signer.status !== 'apple' || inlineScript)) {
    risk = raise(risk, 'CRITICAL');
    reasons.push(inlineScript
      ? 'It is named like an Apple system item, but real Apple items never run inline scripts — a disguise malware uses.'
      : 'It is named like an Apple system item but is not signed by Apple — a disguise malware uses.');
  }

  return { ...item, risk, reasons, signer: { status: signer.status, name: signer.signer, team: signer.team } };
}

async function collectLaunchItems() {
  const items = [];
  for (const { scope, dir } of LOCATIONS) {
    let files = [];
    try { files = fs.readdirSync(dir).filter(f => f.endsWith('.plist')); } catch { continue; }
    for (const f of files) {
      const file = path.join(dir, f);
      let raw;
      try { raw = fs.readFileSync(file); } catch { continue; }
      const plist = await readPlist(file);
      const argv  = Array.isArray(plist?.ProgramArguments) ? plist.ProgramArguments.map(String) : [];
      const program = typeof plist?.Program === 'string' ? plist.Program : argv[0] ?? null;
      items.push({
        id:        file,
        kind:      'launchd',
        scope,
        path:      file,
        label:     typeof plist?.Label === 'string' ? plist.Label : f.replace(/\.plist$/, ''),
        program,
        args:      plist?.Program ? argv : argv.slice(1),
        runAtLoad: !!plist?.RunAtLoad,
        keepAlive: !!plist?.KeepAlive,
        disabled:  !!plist?.Disabled,
        hash:      sha256(raw),
      });
    }
  }
  return items;
}

async function collectCron() {
  try {
    const { stdout } = await execAsync('crontab -l 2>/dev/null', { timeout: 3000 });
    return stdout.split('\n')
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('#') && !/^[A-Z_]+=/.test(l))
      .map((line, i) => {
        const cmd = line.split(/\s+/).slice(line.startsWith('@') ? 1 : 5).join(' ');
        const [program, ...args] = cmd.split(/\s+/);
        return {
          id: `crontab:${i}:${sha256(line).slice(0, 12)}`, kind: 'cron', scope: 'Your account (cron)',
          path: 'crontab', label: line, program, args, runAtLoad: false, keepAlive: false, disabled: false,
          hash: sha256(line),
        };
      });
  } catch {
    return [];   // no crontab
  }
}

// ── Baseline ──────────────────────────────────────────────────────────────────

function loadBaseline() {
  try { return JSON.parse(fs.readFileSync(BASELINE_FILE, 'utf8')); }
  catch { return null; }
}

function saveBaseline(items) {
  const data = { savedAt: new Date().toISOString(), items: Object.fromEntries(items.map(i => [i.id, i.hash])) };
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(BASELINE_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch (e) {
    console.error('[Persistence] could not save baseline:', e.message);
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

let lastInventory = { items: [], scannedAt: null, baselineSavedAt: null };

/**
 * Inventory startup items and diff against the baseline.
 * @returns {{ items, events }} events: [{ change:'new'|'changed'|'existing-risk', item }]
 */
export async function scanPersistence() {
  const rawItems = [...await collectLaunchItems(), ...await collectCron()];
  const items    = [];
  for (const it of rawItems) items.push(await rateItem(it));

  const baseline = loadBaseline();
  const events   = [];

  if (!baseline) {
    // First run: everything present becomes the baseline. Only surface the
    // ones that already look dangerous — not every Zoom/Google updater.
    for (const item of items) {
      if (SEV_RANK[item.risk] >= SEV_RANK.HIGH) events.push({ change: 'existing-risk', item });
    }
  } else {
    for (const item of items) {
      const known = baseline.items[item.id];
      if (known === undefined) events.push({ change: 'new', item });
      else if (known !== item.hash) events.push({ change: 'changed', item });
    }
  }

  saveBaseline(items);
  lastInventory = { items, scannedAt: new Date().toISOString(), baselineSavedAt: baseline?.savedAt ?? new Date().toISOString() };
  return { items, events };
}

export function getInventory() {
  return lastInventory;
}

/** Turn a change event into a feed/threat event in Alvora's usual shape. */
export function toThreatEvent({ change, item }) {
  const who = item.signer?.name ? `signed by ${item.signer.name}` : `signature: ${item.signer?.status ?? 'unknown'}`;
  const severity = item.risk === 'OK' ? 'LOW' : item.risk;
  const verb = change === 'new' ? 'New startup item added'
             : change === 'changed' ? 'A startup item was modified'
             : 'Risky startup item found';
  const type = SEV_RANK[severity] >= SEV_RANK.HIGH
    ? `${verb} — looks suspicious: ${item.label}`
    : `${verb}: ${item.label}`;
  const detail = [
    `${item.scope}: ${item.path === 'crontab' ? 'cron job' : item.path}.`,
    item.program ? `Runs ${item.program} (${who}).` : null,
    ...item.reasons,
    SEV_RANK[severity] >= SEV_RANK.HIGH
      ? 'If you did not just install something, check it before your next restart.'
      : 'Normal when you install or update an app.',
  ].filter(Boolean).join(' ');
  return {
    type,
    severity,
    // Read-only monitor: it never blocks, so never claim it did
    action: SEV_RANK[severity] >= SEV_RANK.HIGH ? 'ALERT' : 'MONITORING',
    source: item.label,
    port:   0,
    detail,
  };
}
