/**
 * netBaseline.js — Learn where each app normally connects; flag what's new.
 *
 * Spyware and data theft show up as an app talking somewhere it never has (or
 * a program that never used the network suddenly phoning home). This module:
 *
 *   1. Attributes every established TCP connection to its app (lsof + ps).
 *   2. Identifies the destination by network owner (ASN, via the offline
 *      asnDb) — stable where CDN IP addresses are not.
 *   3. Learns silently for a few days, then alerts on:
 *        • an app using the internet for the first time
 *        • a known app reaching a network it has never used
 *      Unsigned apps are treated more strictly at every step, including
 *      during the learning period.
 *
 * Browser-like apps (many destinations) stop generating "new network" alerts
 * once they have shown they talk to everyone — threat-intel hits still apply.
 * State lives in a small JSON file; nothing leaves the machine.
 */

import fs   from 'fs';
import os   from 'os';
import path from 'path';
import { exec }      from 'child_process';
import { promisify } from 'util';
import * as asnDb    from './asnDb.js';
import * as codeSign from './codeSign.js';
import { executablePaths } from './processPaths.js';
import { isTrustedApp } from './trustList.js';

const execAsync = promisify(exec);

const DATA_DIR      = process.env.ALVORA_DATA_DIR || path.join(os.homedir(), '.alvora-cyber');
const BASELINE_FILE = path.join(DATA_DIR, 'net-baseline.json');
const LEARNING_MS   = (parseFloat(process.env.ALVORA_NET_LEARNING_HOURS) || 72) * 60 * 60 * 1000;
const BROWSER_LIKE  = 25;   // distinct networks after which per-network alerts stop for an app
const MAX_ALERTS_PER_SCAN = 5;

// Package managers install ad-hoc-signed builds; still worth knowing, less alarming
const PACKAGE_MANAGER_DIRS = /^\/opt\/homebrew\/|^\/usr\/local\/(Cellar|opt|bin)\/|\/\.(nvm|pyenv|cargo|rustup|volta|bun|deno|asdf|local\/share\/mise)\/|\/node_modules\//;

// ── State ─────────────────────────────────────────────────────────────────────

let state = null;   // { startedAt, apps: { [key]: { name, path, signer, firstSeen, lastSeen, unsignedAlerted, dests: { [destKey]: {...} } } } }
let dirty = false;

function load() {
  if (state) return state;
  try { state = JSON.parse(fs.readFileSync(BASELINE_FILE, 'utf8')); }
  catch { state = { startedAt: Date.now(), apps: {} }; dirty = true; }
  // Older versions keyed apps by process title ("npm exec …"), not a file path — drop those
  for (const key of Object.keys(state.apps)) {
    if (!key.startsWith('/')) { delete state.apps[key]; dirty = true; }
  }
  return state;
}

function save() {
  if (!dirty) return;
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(BASELINE_FILE, JSON.stringify(state), 'utf8');
    dirty = false;
  } catch (e) { console.error('[NetBaseline] save failed:', e.message); }
}

// ── Collection ────────────────────────────────────────────────────────────────

function isPrivate(ip) {
  return /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/.test(ip);
}

/** App identity: the outermost .app bundle (so Chrome's helpers count as Chrome), else the binary. */
function appKeyFor(exePath) {
  const bundle = exePath.match(/^(.*?\.app)(?:\/|$)/)?.[1];
  const key  = bundle ?? exePath;
  const name = path.basename(key).replace(/\.app$/, '');
  return { key, name };
}

async function collect() {
  const lsofOut = await execAsync('lsof -nP -iTCP -sTCP:ESTABLISHED -F pn 2>/dev/null', { timeout: 8000, maxBuffer: 8 * 1024 * 1024 })
    .then(r => r.stdout).catch(() => '');

  const raw = [];
  let pid = null;
  for (const line of lsofOut.split('\n')) {
    if (line[0] === 'p') pid = parseInt(line.slice(1), 10);
    else if (line[0] === 'n' && pid != null) {
      const m = line.match(/->\[?([\d.]+)\]?:(\d+)$/);
      if (!m || isPrivate(m[1])) continue;
      raw.push({ pid, ip: m[1], port: parseInt(m[2], 10) });
    }
  }

  // Real executable files — not self-chosen process titles
  const exe = await executablePaths(raw.map(c => c.pid));
  return raw
    .filter(c => exe.has(c.pid))   // unresolved (exited / not ours to read) → skip, never guess
    .map(c => ({ ...c, exePath: exe.get(c.pid) }));
}

function isSelf(c) {
  if (c.pid === process.pid || c.pid === process.ppid) return true;
  return c.exePath.includes('/Alvora Cyber.app/');
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Observe current connections, update the baseline, and return alert events.
 * @returns {Promise<Array<{type, severity, action, source, port, detail, app}>>}
 */
export async function observe() {
  load();
  await asnDb.refresh().catch(() => {});
  const now      = Date.now();
  const learning = now - state.startedAt < LEARNING_MS;
  const conns    = (await collect()).filter(c => !isSelf(c));
  const events   = [];
  const pending  = new Map();   // appKey → grouped new-network findings this scan

  for (const c of conns) {
    const { key, name } = appKeyFor(c.exePath);
    const net     = asnDb.lookup(c.ip);
    const destKey = net ? `AS${net.asn}` : c.ip.split('.').slice(0, 2).join('.') + '.0.0/16';
    const destName = net ? `${net.name} (AS${net.asn}, ${net.country})` : `${destKey} (network unknown)`;

    let app = state.apps[key];
    const isNewApp = !app;
    if (!app) {
      const sig = await codeSign.inspect(c.exePath);
      app = state.apps[key] = {
        name, path: key, signer: { status: sig.status, name: sig.signer, trusted: sig.trusted },
        firstSeen: now, lastSeen: now, unsignedAlerted: false, dests: {},
      };
      dirty = true;
    }
    app.lastSeen = now;

    const isNewDest = !app.dests[destKey];
    if (isNewDest) {
      app.dests[destKey] = { name: destName, country: net?.country ?? null, firstSeen: now, lastSeen: now, sampleIp: c.ip, port: c.port };
      dirty = true;
    } else {
      app.dests[destKey].lastSeen = now;
    }

    const trusted   = app.signer?.trusted;
    const base = { source: c.ip, port: c.port, app: name, appPath: key };

    // The user marked this app as fine — keep learning, never alert
    if (isTrustedApp(key)) continue;

    // Signature couldn't be read earlier (e.g. busy start-up) → try again now
    if (app.signer?.status === 'unknown') {
      const sig = await codeSign.inspect(c.exePath);
      app.signer = { status: sig.status, name: sig.signer, trusted: sig.trusted };
      dirty = true;
    }

    // A running program whose file has been deleted is a classic way to hide — always worth a look
    if (app.signer?.status === 'missing' && !app.unsignedAlerted) {
      app.unsignedAlerted = true;
      dirty = true;
      events.push({
        ...base,
        type:     `A program whose file was deleted is using the internet: ${name}`,
        severity: 'HIGH',
        action:   'ALERT',
        detail:   `${name} is still running and just connected to ${destName} on port ${c.port}, but its file (${c.exePath}) no longer exists. Updaters sometimes do this briefly; malware does it to hide. If it keeps happening, check what it is.`,
      });
      continue;
    }

    // Unsigned code on the internet is worth a look even while learning — once per app
    if (!app.signer?.trusted && !app.unsignedAlerted && !['unreadable', 'unknown', 'missing'].includes(app.signer?.status)) {
      app.unsignedAlerted = true;
      dirty = true;
      const managed = PACKAGE_MANAGER_DIRS.test(c.exePath);
      events.push({
        ...base,
        type:     `Unsigned program is using the internet: ${name}`,
        severity: managed ? 'LOW' : 'HIGH',
        action:   'ALERT',
        detail:   managed
          ? `${name} (${c.exePath}) connected to ${destName} on port ${c.port}. It isn't developer-signed, but it lives in a package-manager folder (Homebrew, nvm, etc.), where that's normal.`
          : `${name} (${c.exePath}) isn't signed by Apple or an identified developer, and it just connected to ${destName} on port ${c.port}. Most legitimate Mac software is signed; check you know what this is.`,
      });
      continue;
    }

    if (learning) continue;

    // Group per app: one alert per app per scan, however many connections it opened
    const g = pending.get(key) ?? { app, name, isNewApp, trusted, dests: [], sample: base };
    if (isNewApp || isNewDest) g.dests.push(`${destName} on port ${c.port}`);
    pending.set(key, g);
  }

  for (const g of pending.values()) {
    if (!g.dests.length) continue;
    const list = g.dests.slice(0, 3).join('; ') + (g.dests.length > 3 ? `; and ${g.dests.length - 3} more` : '');
    if (g.isNewApp) {
      events.push({
        ...g.sample,
        type:     `${g.name} used the internet for the first time`,
        severity: g.trusted ? 'LOW' : 'MEDIUM',
        action:   'ALERT',
        detail:   `${g.name} had never made a connection since Alvora started learning. It just reached: ${list}. Normal right after installing or updating it.`,
      });
    } else {
      const known = Object.keys(g.app.dests).length - g.dests.length;
      if (known >= BROWSER_LIKE) continue;   // talks to everyone — new networks aren't signal
      events.push({
        ...g.sample,
        type:     `${g.name} connected to ${g.dests.length === 1 ? 'a network' : `${g.dests.length} networks`} it has never used`,
        severity: g.trusted ? 'LOW' : 'MEDIUM',
        action:   'ALERT',
        detail:   `${g.name} normally talks to ${known} known network${known === 1 ? '' : 's'}. New: ${list}.`,
      });
    }
  }

  save();
  // Strongest first; cap per scan so a burst (e.g. after a big update) can't flood the feed
  const rank = { HIGH: 3, MEDIUM: 2, LOW: 1 };
  return events.sort((a, b) => rank[b.severity] - rank[a.severity]).slice(0, MAX_ALERTS_PER_SCAN);
}

/** Summary for the UI: learning progress + every app seen on the network. */
export function summary() {
  load();
  const now = Date.now();
  const apps = Object.values(state.apps)
    .map(a => ({
      name: a.name, path: a.path, signer: a.signer,
      firstSeen: a.firstSeen, lastSeen: a.lastSeen,
      networks: Object.keys(a.dests).length,
      browserLike: Object.keys(a.dests).length > BROWSER_LIKE,
      topNetworks: Object.values(a.dests).sort((x, y) => y.lastSeen - x.lastSeen).slice(0, 5).map(d => d.name),
    }))
    .sort((a, b) => b.lastSeen - a.lastSeen);
  return {
    startedAt:  state.startedAt,
    learning:   now - state.startedAt < LEARNING_MS,
    learningEndsAt: state.startedAt + LEARNING_MS,
    asn: asnDb.status(),
    apps,
  };
}
