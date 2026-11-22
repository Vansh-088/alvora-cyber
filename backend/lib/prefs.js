/**
 * prefs.js — small backend preferences that must survive restarts
 * (e.g. how long to keep history). UI-only settings live in Electron.
 */

import fs   from 'fs';
import os   from 'os';
import path from 'path';

const DATA_DIR = process.env.ALVORA_DATA_DIR || path.join(os.homedir(), '.alvora-cyber');
const FILE     = path.join(DATA_DIR, 'preferences.json');

const DEFAULTS = { retentionDays: 90 };
export const RETENTION_CHOICES = [30, 90, 365, 0];   // 0 = keep forever

let cache = null;

export function get() {
  if (cache) return cache;
  try { cache = { ...DEFAULTS, ...JSON.parse(fs.readFileSync(FILE, 'utf8')) }; }
  catch { cache = { ...DEFAULTS }; }
  return cache;
}

export function set(patch) {
  cache = { ...get(), ...patch };
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(FILE, JSON.stringify(cache, null, 2), 'utf8');
  return cache;
}
