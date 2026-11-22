/**
 * realNetworkMonitor.js — Actual network threat detection
 *
 * Replaces the random NVIDIA simulator with genuine system data:
 *  - Scans active TCP/UDP connections via netstat/lsof
 *  - Flags suspicious remote ports (Telnet, SMB, RDP, Metasploit, etc.)
 *  - Flags suspicious process names (miners, tunnelers, scanners)
 *  - Checks remote IPs against a local threat intelligence list
 *  - Returns real threat events — nothing is fabricated
 *  - Detect-and-alert only: action is 'ALERT', never 'BLOCKED' (nothing is cut off)
 */

import { exec }     from 'child_process';
import { promisify } from 'util';
import * as intel   from './threatIntel.js';
import * as codeSign from './codeSign.js';
import { executablePaths } from './processPaths.js';
import { isTrustedApp } from './trustList.js';

const execAsync = promisify(exec);

// ── Threat Intelligence (local, no API key needed) ────────────────────────────

// Ports that should NEVER be seen going outbound from a normal workstation
const HIGH_RISK_PORTS = new Map([
  [23,    { type: 'Insecure remote login to your computer',     severity: 'CRITICAL', desc: 'Something is connecting over an old, unencrypted remote-control channel. Anyone on the network could read it.' }],
  [4444,  { type: 'Possible hacker backdoor',                   severity: 'CRITICAL', desc: 'A connection on a port commonly used by hacking tools to secretly control a computer. Your device may be compromised.' }],
  [31337, { type: 'Possible remote-control malware',            severity: 'CRITICAL', desc: 'A connection on a port used by classic remote-access malware. Treat this as a likely infection.' }],
  [6667,  { type: 'Possible botnet check-in',                   severity: 'CRITICAL', desc: 'Traffic to a chat channel of the kind botnets use to receive commands. Your device may be part of a botnet.' }],
  [445,   { type: 'Windows file-sharing exposed to internet',  severity: 'HIGH',     desc: 'File-sharing traffic is reaching an outside computer — a common way ransomware spreads.' }],
  [3389,  { type: 'Remote Desktop session to an outside computer', severity: 'HIGH', desc: 'Someone may be remotely controlling a machine over the internet. Confirm you authorized this.' }],
  [135,   { type: 'Unusual Windows networking traffic',         severity: 'HIGH',     desc: 'Low-level Windows networking is talking to an outside computer — unusual and worth checking.' }],
  [5900,  { type: 'Screen-sharing session detected',            severity: 'HIGH',     desc: 'A screen-sharing connection is active. Make sure you started it and it\'s not someone watching your screen.' }],
  [21,    { type: 'Insecure file transfer',                     severity: 'MEDIUM',   desc: 'Files are being sent over an old method that exposes your password in plain text.' }],
  [1080,  { type: 'Traffic being routed through a proxy',       severity: 'MEDIUM',   desc: 'Your traffic is passing through a relay — sometimes used to hide where data is really going.' }],
  [8888,  { type: 'A developer tool is open to the network',    severity: 'MEDIUM',   desc: 'A coding/dev server is reachable from outside. Fine if you started it, risky if you didn\'t.' }],
  [27017, { type: 'A database is exposed to the network',       severity: 'MEDIUM',   desc: 'A MongoDB database port is reachable from outside — a common cause of data leaks.' }],
  [6379,  { type: 'A database is exposed to the network',       severity: 'MEDIUM',   desc: 'A Redis database port is reachable from outside — usually a misconfiguration.' }],
]);

// Medium-risk ports (unusual but not immediately critical)
const MEDIUM_RISK_PORTS = new Map([
  [25,   'Email-sending channel that could be abused for spam'],
  [109,  'Old, insecure email connection'],
  [110,  'Email being received without encryption'],
  [143,  'Email being received without encryption'],
  [3306, 'A database (MySQL) is reachable from the network'],
  [5432, 'A database (PostgreSQL) is reachable from the network'],
  [9200, 'A search database (Elasticsearch) is exposed — data leak risk'],
]);

// Suspicious process name patterns (cryptocurrency miners, RATs, tunnelers, scanners)
// Matched against the program's OWN NAME — not its whole command line, where
// innocent words matched ("Phoenix Code" editor → "phoenix" miner; Chrome's
// "--enable-features=…Concat…" → "ncat").
const SUSPICIOUS_PROCESS_PATTERNS = [
  { pattern: /^(?:xmrig|xmr-stak|cpuminer(?:-\w+)?|cgminer|bfgminer|nbminer|t-rex|lolminer|phoenixminer|teamredminer|gminer)$/i, type: 'A program is secretly mining cryptocurrency on your computer', severity: 'CRITICAL' },
  { pattern: /^(?:nicehash\w*|excavator|claymore\w*|ethminer)$/i, type: 'A cryptocurrency-mining program is running',                 severity: 'HIGH' },
  { pattern: /^(?:ngrok|frpc|frps|chisel|ligolo(?:-ng)?)$/i,    type: 'A program is opening a hidden tunnel out of your computer',  severity: 'HIGH' },
  { pattern: /^(?:ncat|netcat|socat)$/i,                       type: 'A raw networking tool is active',                            severity: 'MEDIUM' },
  { pattern: /^(?:masscan|nmap|zmap|rustscan)$/i,              type: 'A program is scanning the network for open doors',           severity: 'HIGH' },
  { pattern: /^(?:meterpreter|mimikatz|lazagne)$/i,            type: 'A known hacking tool is running on your computer',           severity: 'CRITICAL' },
  { pattern: /keylogger|keysniff|spyware/i,                    type: 'Possible spyware recording what you type',                   severity: 'CRITICAL' },
  { pattern: /^(?:torify|torsocks|tor|torbrowser)$/i,          type: 'Anonymous (Tor) network software is running',                severity: 'MEDIUM' },
];

// Command-line arguments that only miners use — catches a miner however its
// binary has been renamed (the classic way to hide one)
const SUSPICIOUS_CMD_PATTERNS = [
  { pattern: /stratum\+(?:tcp|ssl|tls):\/\/|--donate-level\b|--coin[= ](?:monero|xmr)\b|--algo[= ](?:rx\/0|randomx|cn\/)/i, type: 'A program is secretly mining cryptocurrency on your computer', severity: 'CRITICAL' },
];

function ipToInt(ip) {
  return ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct, 10), 0) >>> 0;
}

function isPrivateIP(ip) {
  const n = ipToInt(ip);
  return (
    (n >= ipToInt('10.0.0.0')    && n <= ipToInt('10.255.255.255'))  ||
    (n >= ipToInt('172.16.0.0')  && n <= ipToInt('172.31.255.255'))  ||
    (n >= ipToInt('192.168.0.0') && n <= ipToInt('192.168.255.255')) ||
    (n >= ipToInt('127.0.0.0')   && n <= ipToInt('127.255.255.255')) ||
    ip === '0.0.0.0' || ip === '::1' || ip === 'localhost'
  );
}

// ── System Commands ────────────────────────────────────────────────────────────

async function getEstablishedConnections() {
  try {
    // macOS: netstat -an -p tcp shows all TCP connections
    const { stdout } = await execAsync('netstat -an -p tcp 2>/dev/null | grep -E "ESTABLISHED|CLOSE_WAIT"', {
      timeout: 5000,
    });
    return parseNetstatOutput(stdout);
  } catch {
    return [];
  }
}

function parseNetstatOutput(raw) {
  const conns = [];
  for (const line of raw.trim().split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 5) continue;

    // macOS format: tcp4 recv-q send-q local foreign state
    const localRaw   = parts[3] || '';
    const foreignRaw = parts[4] || '';
    const state      = parts[5] || 'UNKNOWN';

    // Parse IPv4 addresses (format: 1.2.3.4.port)
    const localParts   = localRaw.split('.');
    const foreignParts = foreignRaw.split('.');

    if (foreignParts.length < 5) continue;

    const foreignPort = parseInt(foreignParts[foreignParts.length - 1], 10);
    const foreignIP   = foreignParts.slice(0, -1).join('.');
    const localPort   = parseInt(localParts[localParts.length - 1], 10);

    if (!foreignIP || isNaN(foreignPort) || foreignPort === 0) continue;
    if (foreignIP.includes('*') || foreignIP === '0') continue;

    conns.push({ localPort, foreignIP, foreignPort, state });
  }
  return conns;
}

/** Which app owns each established TCP connection: "ip:port" → "AppName (pid)". */
async function getConnectionOwners() {
  const owners = new Map();
  try {
    const { stdout } = await execAsync('lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null', { timeout: 5000 });
    for (const line of stdout.split('\n').slice(1)) {
      const parts = line.trim().split(/\s+/);
      const m = (parts[8] || '').match(/->\[?([\d.]+)\]?:(\d+)$/);
      if (m) owners.set(`${m[1]}:${m[2]}`, `${parts[0].replace(/\\x20/g, ' ')} (pid ${parts[1]})`);
    }
  } catch { /* lsof unavailable — attribution is best-effort */ }
  return owners;
}

async function getRunningProcesses() {
  try {
    // `ps aux` gives CPU/MEM/args; `comm` gives the full executable path, which
    // (unlike the args' first word) survives spaces like "Claude Helper (Renderer)".
    const [aux, comm] = await Promise.all([
      execAsync('ps aux 2>/dev/null | tail -n +2', { timeout: 5000 }),
      execAsync('ps -axww -o pid=,ppid=,comm= 2>/dev/null', { timeout: 5000 }),
    ]);
    const exe = new Map();
    for (const line of comm.stdout.split('\n')) {
      const m = line.match(/^\s*(\d+)\s+(\d+)\s+(.+)$/);
      if (m) exe.set(parseInt(m[1], 10), { ppid: parseInt(m[2], 10), path: m[3].trim() });
    }
    return aux.stdout.trim().split('\n').map(line => {
      const parts = line.trim().split(/\s+/);
      const pid   = parseInt(parts[1], 10);
      const cpu   = parseFloat(parts[2]);
      const mem   = parseFloat(parts[3]);
      const cmd   = parts.slice(10).join(' ');
      const path  = exe.get(pid)?.path ?? parts[10] ?? '';
      const name  = path.split('/').pop();
      return { pid, ppid: exe.get(pid)?.ppid ?? 0, cpu, mem, name, path, cmd };
    }).filter(p => p.pid && p.name);
  } catch {
    return [];
  }
}

// ── Threat Assessment ─────────────────────────────────────────────────────────

function assessConnection(conn) {
  const { foreignIP, foreignPort } = conn;

  // Skip private/loopback IPs
  if (isPrivateIP(foreignIP)) return null;

  // Live threat-intelligence feeds — strongest signal, checked first
  const ipThreat = intel.lookup(foreignIP);
  if (ipThreat) {
    const portInfo = HIGH_RISK_PORTS.get(foreignPort);
    return {
      type:     ipThreat.label,
      severity: ipThreat.severity,
      action:   ipThreat.severity === 'CRITICAL' ? 'ALERT' : 'MONITORING',
      source:   foreignIP,
      port:     foreignPort,
      detail:   portInfo ? `${ipThreat.detail} It is also using port ${foreignPort}: ${portInfo.desc}` : ipThreat.detail,
      intel:    ipThreat.feeds,
    };
  }

  // Check high-risk ports first
  if (HIGH_RISK_PORTS.has(foreignPort)) {
    const info = HIGH_RISK_PORTS.get(foreignPort);
    return {
      type:     info.type,
      severity: info.severity,
      action:   info.severity === 'CRITICAL' ? 'ALERT' : 'MONITORING',
      source:   foreignIP,
      port:     foreignPort,
      detail:   info.desc,
    };
  }

  // Check medium-risk ports
  if (MEDIUM_RISK_PORTS.has(foreignPort)) {
    return {
      type:     MEDIUM_RISK_PORTS.get(foreignPort),
      severity: 'MEDIUM',
      action:   'MONITORING',
      source:   foreignIP,
      port:     foreignPort,
      detail:   `Unusual port ${foreignPort} connected to external IP`,
    };
  }

  return null; // Clean connection
}

function assessProcess(proc) {
  const match = SUSPICIOUS_PROCESS_PATTERNS.find(p => p.pattern.test(proc.name))
             ?? SUSPICIOUS_CMD_PATTERNS.find(p => p.pattern.test(proc.cmd));
  if (!match) return null;
  return {
    type:     match.type,
    severity: match.severity,
    action:   match.severity === 'CRITICAL' ? 'ALERT' : 'MONITORING',
    source:   `PID:${proc.pid}`,
    port:     0,
    detail:   `Suspicious process: ${proc.name} (CPU: ${proc.cpu}%, MEM: ${proc.mem}%)`,
  };
}

// ── Sustained high CPU from unsigned code (possible hidden miner) ────────────
//
// High CPU alone is normal (WindowServer, Spotlight, compilers, local AI).
// Miners are almost never Apple-shipped or validly code-signed, so we only
// flag a process that (1) stays above HIGH_CPU_PCT for HIGH_CPU_SCANS scans in
// a row, (2) isn't Alvora itself, (3) isn't an Apple system binary, and
// (4) fails code-signature verification.

const HIGH_CPU_PCT   = 85;
const HIGH_CPU_SCANS = 2;
const APPLE_SYSTEM_PREFIXES = ['/System/', '/usr/libexec/', '/usr/sbin/', '/usr/bin/', '/sbin/', '/bin/', '/Library/Apple/'];

const highCpuStreak = new Map();   // pid → consecutive high-CPU scans
const highCpuAlerted = new Map();  // executable → when it was last reported
const HIGH_CPU_REALERT_MS = 24 * 60 * 60 * 1000;   // one alert per program per day, not one per scan

function isSelf(proc) {
  if (proc.pid === process.pid || proc.pid === process.ppid) return true;
  // Inside the desktop app the backend is an Electron utility process: its
  // siblings (GPU / renderer helpers) share our parent.
  if (process.env.ELECTRON_APP === '1' && proc.ppid === process.ppid) return true;
  return proc.path.includes('/Alvora Cyber.app/');
}

async function assessHighCpu(procs) {
  const seen = new Set();
  const candidates = [];
  for (const proc of procs) {
    if (proc.cpu <= HIGH_CPU_PCT || isSelf(proc)) continue;
    seen.add(proc.pid);
    const streak = (highCpuStreak.get(proc.pid) ?? 0) + 1;
    highCpuStreak.set(proc.pid, streak);
    if (streak >= HIGH_CPU_SCANS) candidates.push(proc);
  }

  // `ps` shows self-chosen titles (e.g. "npm exec …"); judge the real executable file
  const exe = candidates.length ? await executablePaths(candidates.map(p => p.pid)) : new Map();
  const threats = [];
  for (const proc of candidates) {
    const file = exe.get(proc.pid);
    if (!file) continue;   // exited, or not ours to read — try again next scan
    if (APPLE_SYSTEM_PREFIXES.some(p => file.startsWith(p))) continue;
    if (isTrustedApp(file)) continue;   // the user marked it as fine
    if (Date.now() - (highCpuAlerted.get(file) ?? 0) < HIGH_CPU_REALERT_MS) continue;
    const sig = await codeSign.inspect(file);
    if (sig.trusted || ['unknown', 'unreadable'].includes(sig.status)) continue;   // unknown → re-checked next scan
    const name = file.split('/').pop();
    highCpuAlerted.set(file, Date.now());
    threats.push({
      type:     sig.status === 'missing'
        ? 'A program whose file was deleted is using a lot of your computer\'s power'
        : 'An unsigned program is using a suspicious amount of your computer\'s power',
      severity: 'MEDIUM',
      action:   'MONITORING',
      source:   `PID:${proc.pid}`,
      port:     0,
      appPath:  file,
      detail:   sig.status === 'missing'
        ? `"${name}" has used over ${HIGH_CPU_PCT}% CPU for a while, but its file (${file}) no longer exists — a trick hidden crypto-miners use.`
        : `"${name}" has used over ${HIGH_CPU_PCT}% CPU for a while and isn't signed by a known developer — a common trait of hidden crypto-miners. Path: ${file}`,
    });
  }
  for (const pid of highCpuStreak.keys()) if (!seen.has(pid)) highCpuStreak.delete(pid);
  return threats;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Run a full network + process scan.
 * Returns an array of real threat events (may be empty if system is clean).
 */
export async function scanForThreats() {
  const threats = [];

  // Scan network connections
  intel.refreshAll().catch(() => {});   // no-op unless feeds are >24h old
  const conns = await getEstablishedConnections();
  const connThreats = conns.map(assessConnection).filter(Boolean);
  if (connThreats.length) {
    const owners = await getConnectionOwners();
    for (const t of connThreats) {
      const app = owners.get(`${t.source}:${t.port}`);
      if (app) { t.app = app; t.detail = `${app} made this connection. ${t.detail}`; }
    }
  }
  threats.push(...connThreats);

  // Scan running processes
  const procs = await getRunningProcesses();
  for (const proc of procs) {
    const threat = assessProcess(proc);
    if (threat) threats.push(threat);
  }
  threats.push(...await assessHighCpu(procs));

  return threats;
}

/**
 * Get a summary of network posture (clean connections count, suspicious count).
 */
export async function getNetworkSummary() {
  const conns  = await getEstablishedConnections();
  const procs  = await getRunningProcesses();

  const externalConns  = conns.filter(c => !isPrivateIP(c.foreignIP));
  const suspiciousConns = conns.filter(c => assessConnection(c) !== null);
  const suspiciousProcs = procs.filter(p => assessProcess(p) !== null);

  return {
    totalConnections:     conns.length,
    externalConnections:  externalConns.length,
    suspiciousConnections: suspiciousConns.length,
    suspiciousProcesses:  suspiciousProcs.length,
    cleanConnections:     externalConns.length - suspiciousConns.length,
    topExternalIPs:       [...new Set(externalConns.map(c => c.foreignIP))].slice(0, 5),
  };
}
