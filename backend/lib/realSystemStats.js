/**
 * Alvora Cyber — Real System Stats via systeminformation
 *
 * Pulls live hardware telemetry from the host machine.
 * Falls back gracefully if systeminformation isn't available.
 *
 * PLUG-IN POINT: Add EDR integration here (CrowdStrike, SentinelOne)
 * to pull real threat intel alongside local telemetry.
 */

import { exec }      from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

let si;

// Lazy-load systeminformation
async function getSi() {
  if (!si) {
    try {
      si = await import('systeminformation');
    } catch {
      si = null;
    }
  }
  return si;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Returns real CPU temperature, or null when the sensor isn't readable.
 * Note: macOS often hides CPU temp without extra permissions.
 */
export async function getCpuTemp() {
  try {
    const lib = await getSi();
    if (!lib) return null;
    const data = await lib.cpuTemperature();
    const temp = data?.main ?? data?.max ?? null;
    if (temp && temp > 0) return parseFloat(temp.toFixed(1));
    // macOS often returns 0 for temp without SMC access
    return null;
  } catch {
    return null;
  }
}

/**
 * Returns real memory stats.
 */
export async function getMemStats() {
  try {
    const lib = await getSi();
    if (!lib) return null;
    const data = await lib.mem();
    // `used` counts file cache macOS hands back instantly, so it sits near 100%
    // on any busy Mac. Report what macOS itself considers in use instead.
    let usePct = data.total > 0 ? ((data.total - data.available) / data.total) * 100 : 0;
    if (process.platform === 'darwin') {
      const out = await execAsync('memory_pressure', { timeout: 3000 }).then(r => r.stdout).catch(() => '');
      const free = out.match(/free percentage:\s*(\d+)%/i)?.[1];
      if (free != null) usePct = 100 - Number(free);
    }
    return {
      total:     data.total ?? 0,
      used:      data.used ?? 0,
      available: data.available ?? 0,
      usePct:    parseFloat(usePct.toFixed(1)),
    };
  } catch {
    return null;
  }
}

/**
 * Returns real CPU load percentage.
 */
export async function getCpuLoad() {
  try {
    const lib = await getSi();
    if (!lib) return null;
    const data = await lib.currentLoad();
    return {
      currentLoad: parseFloat((data.currentLoad ?? 0).toFixed(1)),
      cores:       (data.cpus ?? []).map(c => parseFloat((c.load ?? 0).toFixed(1))),
    };
  } catch {
    return null;
  }
}

/**
 * Returns list of active network interfaces and stats.
 */
export async function getNetworkStats() {
  try {
    const lib = await getSi();
    if (!lib) return [];
    const ifaces = await lib.networkInterfaces();
    return (Array.isArray(ifaces) ? ifaces : [ifaces])
      .filter(i => i.operstate === 'up' && !i.internal)
      .map(i => ({
        iface:   i.iface,
        ip4:     i.ip4,
        ip6:     i.ip6,
        mac:     i.mac,
        speed:   i.speed,
        dhcp:    i.dhcp,
      }));
  } catch {
    return [];
  }
}

/**
 * Returns top processes by memory usage.
 */
export async function getTopProcesses(limit = 8) {
  try {
    const lib = await getSi();
    if (!lib) return [];
    const data = await lib.processes();
    const list = (data?.list ?? [])
      .sort((a, b) => (b.mem ?? 0) - (a.mem ?? 0))
      .slice(0, limit)
      .map(p => ({
        pid:     p.pid,
        name:    p.name,
        cpu:     parseFloat((p.cpu ?? 0).toFixed(1)),
        mem:     parseFloat((p.mem ?? 0).toFixed(1)),
        started: p.started,
      }));
    return list;
  } catch {
    return [];
  }
}

/**
 * Returns open network sockets (approximation via network stats).
 */
export async function getOpenConnections() {
  try {
    const lib = await getSi();
    if (!lib) return [];
    const data = await lib.networkConnections();
    return (data ?? [])
      .filter(c => c.state === 'ESTABLISHED')
      .slice(0, 20)
      .map(c => ({
        localAddress:  c.localAddress,
        localPort:     c.localPort,
        peerAddress:   c.peerAddress,
        peerPort:      c.peerPort,
        protocol:      c.protocol,
        state:         c.state,
        process:       c.process,
      }));
  } catch {
    return [];
  }
}

/**
 * Full system snapshot — used for the dashboard and hardening baseline.
 */
export async function getFullSnapshot() {
  const [cpuTemp, memStats, cpuLoad, network, processes] = await Promise.all([
    getCpuTemp(),
    getMemStats(),
    getCpuLoad(),
    getNetworkStats(),
    getTopProcesses(5),
  ]);

  return { cpuTemp, memStats, cpuLoad, network, processes, timestamp: new Date().toISOString() };
}
