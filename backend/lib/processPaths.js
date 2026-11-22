/**
 * processPaths.js — the real executable file behind a process.
 *
 * `ps -o comm=` is not reliable for this: programs can rename themselves
 * (Node sets its title to e.g. "npm exec wrangler@4 dev --port 5180"), and
 * the renamed title isn't a file. Judging signatures on that string made
 * every such tool look unsigned. lsof's "txt" entry is the mapped executable
 * image, which a process cannot rename.
 */

import { exec }      from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);
const CHUNK = 200;   // keep each lsof command line short

/**
 * @param {number[]} pids
 * @returns {Promise<Map<number, string>>} pid → absolute executable path (missing pids couldn't be resolved)
 */
export async function executablePaths(pids) {
  const out = new Map();
  const list = [...new Set(pids)].filter(p => Number.isInteger(p) && p > 0);
  for (let i = 0; i < list.length; i += CHUNK) {
    const batch = list.slice(i, i + CHUNK).join(',');
    let stdout = '';
    try {
      ({ stdout } = await execAsync(`lsof -a -d txt -Fpn -p ${batch} 2>/dev/null`, { timeout: 8000, maxBuffer: 16 * 1024 * 1024 }));
    } catch (err) {
      stdout = err.stdout ?? '';   // lsof exits 1 if any pid vanished; the rest is still valid
    }
    let pid = null;
    for (const line of stdout.split('\n')) {
      if (line[0] === 'p') pid = parseInt(line.slice(1), 10);
      else if (line[0] === 'n' && pid != null && !out.has(pid) && line[1] === '/') {
        out.set(pid, line.slice(1));   // first txt entry is the executable itself
      }
    }
  }
  return out;
}
