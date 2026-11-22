/**
 * trustList.js — things the user has told Alvora are fine.
 *
 * "Trust this app" / "Trust this address" from an alert lands here. Monitors
 * check it before raising an alert, so a known-good tool stays quiet for good.
 * Threat-intel hits (known malware / botnet addresses) are never silenced by
 * this list — only Alvora's own judgement calls (unsigned code, new networks,
 * high CPU, community reputation).
 */

import fs   from 'fs';
import os   from 'os';
import path from 'path';

const DATA_DIR = process.env.ALVORA_DATA_DIR || path.join(os.homedir(), '.alvora-cyber');
const FILE     = path.join(DATA_DIR, 'trusted.json');

let state = null;   // { apps: { [path]: { name, at } }, ips: { [ip]: { at } } }

function load() {
  if (state) return state;
  try { state = JSON.parse(fs.readFileSync(FILE, 'utf8')); }
  catch { state = {}; }
  state.apps ??= {};
  state.ips  ??= {};
  return state;
}

function save() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(FILE, JSON.stringify(state, null, 2), 'utf8');
}

const validPath = p => typeof p === 'string' && p.startsWith('/') && p.length < 1024;
const validIp   = ip => typeof ip === 'string' && /^[\d.]{7,15}$|^[0-9a-f:]{2,39}$/i.test(ip);

export const isTrustedApp = p  => validPath(p) && !!load().apps[p];
export const isTrustedIp  = ip => validIp(ip) && !!load().ips[ip];

export function trustApp(p, name) {
  if (!validPath(p)) return false;
  load().apps[p] = { name: String(name ?? path.basename(p)).slice(0, 120), at: Date.now() };
  save();
  return true;
}

export function trustIp(ip) {
  if (!validIp(ip)) return false;
  load().ips[ip] = { at: Date.now() };
  save();
  return true;
}

export function untrust({ app, ip }) {
  load();
  if (app) delete state.apps[app];
  if (ip)  delete state.ips[ip];
  save();
}

export function list() {
  load();
  return {
    apps: Object.entries(state.apps).map(([p, v]) => ({ path: p, ...v })),
    ips:  Object.entries(state.ips).map(([ip, v]) => ({ ip, ...v })),
  };
}
