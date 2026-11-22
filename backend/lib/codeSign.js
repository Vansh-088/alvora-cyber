/**
 * codeSign.js — Who signed this binary? (macOS `codesign`)
 *
 * Malware on macOS is overwhelmingly unsigned, ad-hoc signed, or carries a
 * broken signature; legitimate software is signed by Apple or a Developer ID
 * that Apple can revoke. Results are cached per path (binaries rarely change
 * while we're running; the cache is invalidated when the file's mtime changes).
 */

import fs   from 'fs';
import { exec }      from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);
const cache = new Map();   // path → { mtimeMs, info }

/**
 * @returns {Promise<{
 *   status: 'apple'|'developer-id'|'app-store'|'adhoc'|'unsigned'|'invalid'|'missing'|'unreadable'|'unknown',
 *   signer: string|null,   // e.g. "Developer ID Application: Google LLC (EQHXZ8M8AV)"
 *   team:   string|null,
 *   trusted: boolean       // apple / developer-id / app-store with a valid signature
 * }>}
 */
export async function inspect(path) {
  let mtimeMs;
  try { mtimeMs = fs.statSync(path).mtimeMs; }
  catch { return { status: 'missing', signer: null, team: null, trusted: false }; }
  // Root-only helpers (e.g. /Library/PrivilegedHelperTools) can't be checked
  // without admin rights — that's "unknown", not "tampered".
  try { fs.accessSync(path, fs.constants.R_OK); }
  catch { return { status: 'unreadable', signer: null, team: null, trusted: false }; }

  const hit = cache.get(path);
  if (hit && hit.mtimeMs === mtimeMs) return hit.info;

  let info;
  try {
    const { stderr } = await execAsync(`codesign -dv --verbose=2 ${JSON.stringify(path)}`, { timeout: 15000 });
    const authority = stderr.match(/^Authority=(.+)$/m)?.[1] ?? null;
    // Only call it ad-hoc when codesign says so. Partial output (seen under heavy
    // load at app start-up) is "unknown": not trusted, not cached, never alarmed on.
    if (!authority && !/^Signature=adhoc$/m.test(stderr)) {
      return { status: 'unknown', signer: null, team: null, trusted: false };
    }
    const team      = stderr.match(/^TeamIdentifier=(.+)$/m)?.[1] ?? null;
    // Verify the whole app bundle when the binary lives inside one — verifying
    // Contents/MacOS/<exe> on its own fails for perfectly valid apps.
    const target = path.match(/^(.*?\.app)\/Contents\/MacOS\//)?.[1] ?? path;
    let valid = true;
    try { await execAsync(`codesign --verify ${JSON.stringify(target)}`, { timeout: 15000 }); }
    catch { valid = false; }

    let status;
    if (!authority)                                      status = 'adhoc';
    else if (!valid)                                     status = 'invalid';
    else if (/^Apple Mac OS Application Signing/.test(authority)) status = 'app-store';
    else if (/Software Signing$|^Apple /.test(authority)) status = 'apple';
    else if (/^Developer ID Application/.test(authority)) status = 'developer-id';
    else                                                 status = 'developer-id';
    info = {
      status,
      signer:  authority,
      team:    team && team !== 'not set' ? team : null,
      trusted: ['apple', 'developer-id', 'app-store'].includes(status),
    };
  } catch (err) {
    const text = `${err.stderr ?? ''}${err.message ?? ''}`;
    if (/not signed/i.test(text))                         info = { status: 'unsigned', signer: null, team: null, trusted: false };
    else if (err.killed || /timed out|ETIMEDOUT|EAGAIN/i.test(text)) return { status: 'unknown', signer: null, team: null, trusted: false };   // retry next time
    else                                                  info = { status: 'invalid', signer: null, team: null, trusted: false };
  }
  cache.set(path, { mtimeMs, info });
  return info;
}
