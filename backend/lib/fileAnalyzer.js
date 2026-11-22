/**
 * fileAnalyzer.js — Is this downloaded file dangerous? (on-device)
 *
 * Built around how Mac malware actually arrives — fake installers in disk
 * images (Atomic/AMOS stealer and friends), "invoice.pdf" that is really a
 * script, password-protected zips that dodge scanners, macro documents, and
 * downloads from phishing sites. Signals, all computed locally:
 *
 *   • Origin       — the URL macOS recorded for the download, checked against
 *                    the Link Guard phishing/malware feeds
 *   • True type    — magic bytes vs. the extension (a "PDF" that is a Mach-O)
 *   • Name tricks  — double extensions, right-to-left override, padding
 *   • Gatekeeper   — spctl / codesign verdicts for apps, installers, and the
 *                    apps INSIDE disk images (mounted read-only) and zips
 *   • Scripts      — behaviour signatures (curl | sh, fake password dialogs,
 *                    quarantine removal, keychain / wallet theft, persistence)
 *   • Archives     — encrypted entries, executables hidden inside
 *   • Documents    — Office macros
 *   • EICAR        — the standard antivirus test file
 *   • MalwareBazaar hash lookup — only if an abuse.ch key is configured, and
 *                    only the SHA-256 is sent (never the file)
 *
 * Read-only: nothing here moves, deletes, opens or executes the file.
 */

import fs     from 'fs';
import os     from 'os';
import path   from 'path';
import crypto from 'crypto';
import { execFile } from 'child_process';
import { promisify } from 'util';
import * as codeSign from './codeSign.js';
import * as urlIntel from './urlIntel.js';

const run = promisify(execFile);
const SEV = { OK: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const MAX_SCRIPT_BYTES = 1024 * 1024;

// ── Type detection ────────────────────────────────────────────────────────────

const DOC_EXTS  = new Set(['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'csv', 'png', 'jpg', 'jpeg', 'gif', 'heic', 'webp', 'mp3', 'mp4', 'mov', 'pages', 'numbers', 'key', 'odt', 'html', 'htm']);
const EXEC_KINDS = new Set(['macho', 'script', 'pe', 'elf', 'applescript', 'pkg', 'dmg']);
const SCRIPT_EXTS = new Set(['command', 'sh', 'bash', 'zsh', 'tool', 'py', 'pl', 'rb', 'applescript', 'scpt', 'js', 'terminal']);
const RISKY_SECOND_EXTS = 'app|command|sh|tool|pkg|dmg|exe|scr|msi|js|jar|scpt|applescript|terminal|zip|iso';

async function readHead(file, n = 64) {
  const fh = await fs.promises.open(file, 'r');
  try {
    const { size } = await fh.stat();
    const head = Buffer.alloc(Math.min(n, size));
    await fh.read(head, 0, head.length, 0);
    let tail = Buffer.alloc(0);
    if (size >= 512) { tail = Buffer.alloc(512); await fh.read(tail, 0, 512, size - 512); }
    return { head, tail, size };
  } finally { await fh.close(); }
}

function detectKind(head, tail) {
  const hex = head.subarray(0, 8).toString('hex');
  if (/^(feedface|feedfacf|cefaedfe|cffaedfe)/.test(hex)) return 'macho';
  if (hex.startsWith('cafebabe')) return head.readUInt32BE(4) < 40 ? 'macho' : 'java';   // fat Mach-O vs Java class
  if (head.subarray(0, 2).toString() === '#!') return 'script';
  if (head.subarray(0, 2).toString() === 'MZ') return 'pe';
  if (hex.startsWith('7f454c46')) return 'elf';
  if (hex.startsWith('504b0304') || hex.startsWith('504b0506')) return 'zip';
  if (head.subarray(0, 4).toString() === '%PDF') return 'pdf';
  if (hex.startsWith('d0cf11e0a1b11ae1')) return 'ole';
  if (head.subarray(0, 4).toString() === 'xar!') return 'pkg';
  if (tail.length === 512 && tail.subarray(0, 4).toString() === 'koly') return 'dmg';
  if (hex.startsWith('1f8b')) return 'gzip';
  if (hex.startsWith('377abcaf271c')) return '7z';
  if (head.subarray(0, 4).toString() === 'Rar!') return 'rar';
  if (head.subarray(0, 7).toString() === 'FasdUAS') return 'applescript';
  if (head.subarray(0, 8).toString() === 'bplist00') return 'plist';
  if (hex.startsWith('89504e47') || hex.startsWith('ffd8ff') || head.subarray(0, 3).toString() === 'GIF') return 'image';
  return 'other';
}

// ── Name tricks ───────────────────────────────────────────────────────────────

function nameFindings(name) {
  const out = [];
  if (/[‮‭⁦-⁩]/.test(name)) {
    out.push({ severity: 'CRITICAL', title: 'Hidden right-to-left trick in the file name', detail: 'The name contains an invisible character that reverses text, so "evil.app" can be shown as "ppa.pdf". Only malware does this.' });
  }
  const dbl = name.match(new RegExp(`\\.(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|gif|mp4|mov|csv|rtf)(\\s*)\\.(${RISKY_SECOND_EXTS})$`, 'i'));
  if (dbl) {
    out.push({ severity: 'HIGH', title: `Pretends to be a .${dbl[1].toLowerCase()} but is a .${dbl[3].toLowerCase()}`, detail: `Double extensions like "${name.slice(-30)}" are made to look like documents while actually being something that runs.` });
  } else if (/\s{4,}\.[a-z0-9]{2,5}$/i.test(name)) {
    out.push({ severity: 'HIGH', title: 'Real file type hidden behind spaces', detail: 'Many spaces before the extension push the real type out of view in Finder.' });
  }
  return out;
}

// ── Origin (where macOS says it was downloaded from) ──────────────────────────

async function readXattr(file, name) {
  try { return (await run('xattr', ['-px', name, file], { timeout: 5000 })).stdout.replace(/\s+/g, ''); }
  catch { return null; }
}

async function origin(file) {
  const quarantine = !!(await readXattr(file, 'com.apple.quarantine'));
  const hex = await readXattr(file, 'com.apple.metadata:kMDItemWhereFroms');
  let urls = [];
  if (hex) {
    const tmp = path.join(os.tmpdir(), `alvora-wherefrom-${process.pid}-${Date.now()}.plist`);
    try {
      fs.writeFileSync(tmp, Buffer.from(hex, 'hex'));
      urls = JSON.parse((await run('plutil', ['-convert', 'json', '-o', '-', tmp], { timeout: 5000 })).stdout);
    } catch { /* unreadable */ } finally { fs.rmSync(tmp, { force: true }); }
  }
  return { quarantine, url: urls[0] ?? null, referrer: urls[1] ?? null };
}

function originFindings(o) {
  const out = [];
  for (const [label, u] of [['download link', o.url], ['page that offered it', o.referrer]]) {
    if (!u) continue;
    const r = urlIntel.check(u);
    if (r.verdict === 'malicious') {
      out.push({ severity: 'CRITICAL', title: `Downloaded from a known phishing/malware site (${r.host})`, detail: `The ${label} is on public blocklists${r.sources?.length ? ` (${r.sources.join(', ')})` : ''}. Don't open this file.` });
    } else if (r.verdict === 'suspicious') {
      out.push({ severity: 'HIGH', title: `Downloaded from a look-alike site (${r.host})`, detail: r.reason });
    }
  }
  return out;
}

// ── Gatekeeper / signing ──────────────────────────────────────────────────────

async function gatekeeper(target, type) {
  try {
    const { stdout, stderr } = await run('spctl', ['-a', '-vv', '-t', type, target], { timeout: 30000 });
    return { accepted: true, text: `${stdout}${stderr}` };
  } catch (e) {
    return { accepted: false, text: `${e.stdout ?? ''}${e.stderr ?? ''}` };
  }
}

function gkSource(text) { return text.match(/source=(.+)/)?.[1]?.trim() ?? ''; }

async function appFindings(appPath, label = 'This app') {
  const exeDir = path.join(appPath, 'Contents', 'MacOS');
  let exe = null;
  try {
    const info = JSON.parse((await run('plutil', ['-convert', 'json', '-o', '-', path.join(appPath, 'Contents', 'Info.plist')], { timeout: 5000 })).stdout);
    if (info.CFBundleExecutable) exe = path.join(exeDir, info.CFBundleExecutable);
  } catch { /* no Info.plist */ }
  const signer = exe ? await codeSign.inspect(exe) : { status: 'missing', signer: null };
  const gk = await gatekeeper(appPath, 'exec');
  const src = gkSource(gk.text);
  const out = [];
  const apple = /Software Signing$|^Apple /.test(signer.signer ?? '');
  if (gk.accepted) {
    out.push({ severity: 'OK', title: `${label} passes Gatekeeper`, detail: `${src || 'Accepted'}${signer.signer ? ` · ${signer.signer}` : ''}` });
  } else if (apple && /custom omit rules/.test(gk.text)) {
    // Built-in macOS apps only validate on the sealed system volume; a copy is still Apple's
    out.push({ severity: 'OK', title: `${label} is an Apple app copied from macOS`, detail: 'Signed by Apple. Gatekeeper only fully validates built-in apps in their original location.' });
  } else if (signer.status === 'unknown') {
    out.push({ severity: 'LOW', title: `${label}'s signature couldn't be checked right now`, detail: 'Alvora will check it again on the next scan.' });
  } else if (['unsigned', 'adhoc', 'missing'].includes(signer.status)) {
    out.push({ severity: 'HIGH', title: `${label} is unsigned`, detail: `Gatekeeper rejects it (${src || signer.status}). Unsigned apps that ask you to right-click → Open are the most common way Mac password stealers get installed.` });
  } else if (signer.status === 'invalid' || !signer.trusted) {
    out.push({ severity: 'HIGH', title: `${label} has a broken signature`, detail: `It was signed${signer.signer ? ` by ${signer.signer}` : ''}, but has been modified since — a sign of tampering (${src || 'rejected'}).` });
  } else {
    out.push({ severity: 'MEDIUM', title: `${label} isn't notarized by Apple`, detail: `Signed by ${signer.signer}, but Apple hasn't checked it (${src || 'rejected'}). Only open it if you trust the developer.` });
  }
  return { out, signer, gatekeeper: { accepted: gk.accepted, source: src } };
}

async function pkgFindings(file) {
  const gk = await gatekeeper(file, 'install');
  const src = gkSource(gk.text);
  if (gk.accepted) return [{ severity: 'OK', title: 'Installer passes Gatekeeper', detail: src }];
  let signed = false;
  try { signed = /Status: signed/.test((await run('pkgutil', ['--check-signature', file], { timeout: 15000 })).stdout); } catch { /* unsigned */ }
  return [signed
    ? { severity: 'MEDIUM', title: 'Installer isn\'t notarized by Apple', detail: `Signed but not checked by Apple (${src || 'rejected'}). Installers run with admin rights — only continue if you trust the source.` }
    : { severity: 'HIGH', title: 'Unsigned installer package', detail: 'Installers run with administrator rights. An unsigned one can do anything to your Mac.' }];
}

// ── Script behaviour signatures ───────────────────────────────────────────────

const SCRIPT_SIGNATURES = [
  { sev: 'CRITICAL', title: 'Downloads and runs code from the internet', rx: /\b(?:curl|wget)\b[^|\n]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/i },
  { sev: 'CRITICAL', title: 'Decodes and runs hidden code',              rx: /base64\s+(?:-d|-D|--decode)[^|\n]{0,200}\|\s*(?:ba|z)?sh\b|eval\s*\(?\s*["'`]?\$\(\s*echo\s+[A-Za-z0-9+/=]{40,}/i },
  { sev: 'CRITICAL', title: 'Shows a fake password prompt',               rx: /display dialog[^\n]{0,300}(?:password|passcode|mot de passe)[^\n]{0,300}hidden answer|display dialog[^\n]{0,300}hidden answer[^\n]{0,300}(?:password|passcode)/i },
  { sev: 'CRITICAL', title: 'Checks your Mac login password',             rx: /dscl\s+(?:\/Local\/Default|\.)\s+-?authonly/i },
  { sev: 'CRITICAL', title: 'Reads saved passwords from the keychain',    rx: /security\s+(?:find-generic-password|find-internet-password|dump-keychain)|login\.keychain(?:-db)?/i },
  { sev: 'HIGH',     title: 'Removes macOS download protection',          rx: /xattr\s+[^\n]{0,40}com\.apple\.quarantine|xattr\s+-(?:c|cr|rc)\b/i },
  { sev: 'HIGH',     title: 'Turns off Gatekeeper / system protection',   rx: /spctl\s+--master-disable|spctl\s+--global-disable|csrutil\s+disable/i },
  { sev: 'HIGH',     title: 'Targets crypto wallets or browser data',     rx: /(?:Exodus|Electrum|Atomic|Coinomi|Guarda|Wasabi|Ledger Live|MetaMask|nkbihfbeogaeaoehlefnkodbefgpgknn)[^\n]{0,80}|Library\/Application Support\/(?:Google\/Chrome|BraveSoftware|Firefox)\/[^\n]{0,60}(?:Login Data|Cookies|key4\.db)/ },
  { sev: 'HIGH',     title: 'Installs itself to run at every startup',    rx: /launchctl\s+(?:load|bootstrap|submit)|Library\/LaunchAgents\//i },
  { sev: 'HIGH',     title: 'Asks for administrator rights',              rx: /with administrator privileges|\bsudo\s+(?:-S\s+)?(?:rm|chmod|chown|cp|mv|launchctl|installer)\b/i },
  { sev: 'MEDIUM',   title: 'Makes a hidden file executable',             rx: /chmod\s+(?:\+x|[0-7]*7[0-7]{2})\s+["']?(?:\/(?:private\/)?tmp|\/var\/tmp|\$TMPDIR|~?\/\.[A-Za-z0-9_-]+)/ },
  { sev: 'MEDIUM',   title: 'Uploads files to a server',                  rx: /\bcurl\b[^\n]{0,200}(?:-F\s|--form\s|--upload-file\s|-T\s|--data-binary\s+@)/i },
];

const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

function scriptFindings(text, where = 'This script') {
  const out = [];
  for (const s of SCRIPT_SIGNATURES) {
    const m = text.match(s.rx);
    if (m) out.push({ severity: s.sev, title: s.title, detail: `${where} contains: “${m[0].slice(0, 120).replace(/\s+/g, ' ')}”` });
  }
  return out;
}

async function readText(file) {
  const fh = await fs.promises.open(file, 'r');
  try {
    const buf = Buffer.alloc(Math.min(MAX_SCRIPT_BYTES, (await fh.stat()).size));
    await fh.read(buf, 0, buf.length, 0);
    return buf.toString('utf8');
  } finally { await fh.close(); }
}

async function compiledAppleScript(file) {
  try { return (await run('osadecompile', [file], { timeout: 10000, maxBuffer: MAX_SCRIPT_BYTES })).stdout; }
  catch { return ''; }
}

// ── Zip (central directory, no extraction) ────────────────────────────────────

async function zipEntries(file) {
  const fh = await fs.promises.open(file, 'r');
  try {
    const { size } = await fh.stat();
    const tailLen = Math.min(size, 65557);
    const tail = Buffer.alloc(tailLen);
    await fh.read(tail, 0, tailLen, size - tailLen);
    const eocd = tail.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    if (eocd < 0) return null;
    const count = tail.readUInt16LE(eocd + 10), cdSize = tail.readUInt32LE(eocd + 12), cdOff = tail.readUInt32LE(eocd + 16);
    if (count === 0xffff || cdOff === 0xffffffff || cdSize > 64 * 1024 * 1024) return null;   // zip64 / huge → skip
    const cd = Buffer.alloc(cdSize);
    await fh.read(cd, 0, cdSize, cdOff);
    const entries = [];
    for (let p = 0; p + 46 <= cd.length && entries.length < 20000;) {
      if (cd.readUInt32LE(p) !== 0x02014b50) break;
      const flags = cd.readUInt16LE(p + 8), nameLen = cd.readUInt16LE(p + 28), extra = cd.readUInt16LE(p + 30), comment = cd.readUInt16LE(p + 32);
      entries.push({ name: cd.toString('utf8', p + 46, p + 46 + nameLen), encrypted: !!(flags & 1), size: cd.readUInt32LE(p + 24) });
      p += 46 + nameLen + extra + comment;
    }
    return entries;
  } finally { await fh.close(); }
}

async function zipFindings(file) {
  const entries = await zipEntries(file);
  if (!entries) return { out: [], apps: [], entries: 0 };
  const out = [];
  const names = entries.map(e => e.name);
  const apps = [...new Set(names.map(n => n.match(/^(?:[^/]+\/)*?([^/]+\.app)\//)?.[1]).filter(Boolean))];
  const scripts = names.filter(n => new RegExp(`\\.(?:${[...SCRIPT_EXTS].join('|')}|pkg|dmg|exe)$`, 'i').test(n) && !/\.app\//.test(n));
  const encrypted = entries.some(e => e.encrypted);
  for (const n of names) out.push(...nameFindings(path.basename(n)).map(f => ({ ...f, title: `Inside the archive: ${f.title}` })));

  if (/\.(?:docm|xlsm|pptm)$/i.test(file) || names.some(n => /vbaProject\.bin$/i.test(n))) {
    out.push({ severity: 'HIGH', title: 'Office document with macros', detail: 'Macros are programs inside the document. Phishing documents use them to install malware when you click "Enable content".' });
  }
  if (encrypted) {
    out.push({ severity: apps.length || scripts.length ? 'HIGH' : 'MEDIUM', title: 'Password-protected archive', detail: `Encrypted archives can't be scanned — attackers send them (with the password in the email) to slip malware past security tools.${apps.length || scripts.length ? ' This one contains programs.' : ''}` });
  }
  if (scripts.length) {
    out.push({ severity: 'MEDIUM', title: `Contains ${scripts.length} script or installer file${scripts.length === 1 ? '' : 's'}`, detail: scripts.slice(0, 5).join(', ') });
    // Read small, unencrypted scripts straight from the archive (no extraction to disk)
    for (const s of scripts.slice(0, 5)) {
      const e = entries.find(x => x.name === s);
      if (e.encrypted || e.size > MAX_SCRIPT_BYTES || /\.(?:pkg|dmg|exe|scpt)$/i.test(s)) continue;
      try {
        const { stdout } = await run('unzip', ['-p', file, s], { timeout: 10000, maxBuffer: MAX_SCRIPT_BYTES, encoding: 'utf8' });
        out.push(...scriptFindings(stdout, path.basename(s)));
      } catch { /* unreadable */ }
    }
  }
  return { out, apps, entries: entries.length };
}

/** Extract only the apps from a zip into a temp dir to run Gatekeeper on them. */
async function zipAppFindings(file, apps) {
  const out = [];
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'alvora-zip-'));
  try {
    await run('ditto', ['-x', '-k', file, dir], { timeout: 60000 });
    for (const name of apps.slice(0, 3)) {
      const found = (await run('find', [dir, '-maxdepth', '3', '-name', name, '-type', 'd'], { timeout: 10000 })).stdout.split('\n').filter(Boolean)[0];
      if (found) out.push(...(await appFindings(found, `The app inside (${name})`)).out);
    }
  } catch { out.push({ severity: 'LOW', title: 'Couldn\'t unpack the archive to check the app inside', detail: 'Treat any app in it with caution.' }); }
  finally { fs.rmSync(dir, { recursive: true, force: true }); }
  return out;
}

// ── Disk images (mounted read-only, never auto-opened) ────────────────────────

async function dmgFindings(file) {
  const out = [];
  const mountRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'alvora-dmg-'));
  let mountPoint = null;
  try {
    const { stdout } = await run('hdiutil', ['attach', '-readonly', '-nobrowse', '-noautoopen', '-noverify', '-mountrandom', mountRoot, '-plist', file], { timeout: 60000 });
    mountPoint = stdout.match(/<key>mount-point<\/key>\s*<string>([^<]+)<\/string>/)?.[1] ?? null;
  } catch (e) {
    const msg = `${e.stderr ?? ''}`;
    out.push(/passphrase|encrypt|authentication/i.test(msg)
      ? { severity: 'MEDIUM', title: 'Encrypted disk image', detail: 'It needs a password to open, so it can\'t be checked. Be careful if a stranger sent you the password.' }
      : { severity: 'LOW', title: 'Couldn\'t open the disk image to check it', detail: 'Treat any app inside with caution.' });
    fs.rmSync(mountRoot, { recursive: true, force: true });
    return out;
  }
  try {
    if (!mountPoint) return out;
    const items = fs.readdirSync(mountPoint).filter(n => !n.startsWith('.'));
    let checked = 0;
    for (const n of items) {
      if (checked >= 5) break;
      const p = path.join(mountPoint, n);
      if (n.endsWith('.app')) { out.push(...(await appFindings(p, `The app inside (${n})`)).out); checked++; }
      else if (/\.pkg$/i.test(n)) { out.push(...(await pkgFindings(p)).map(f => ({ ...f, title: `Inside the disk image: ${f.title}` }))); checked++; }
      else if (new RegExp(`\\.(?:${[...SCRIPT_EXTS].join('|')})$`, 'i').test(n)) {
        const text = n.endsWith('.scpt') ? await compiledAppleScript(p) : await readText(p).catch(() => '');
        out.push({ severity: 'MEDIUM', title: `Disk image contains a script (${n})`, detail: 'Real apps don\'t ship as scripts you double-click.' });
        out.push(...scriptFindings(text, n));
        checked++;
      }
      out.push(...nameFindings(n).map(f => ({ ...f, title: `Inside the disk image: ${f.title}` })));
    }
  } finally {
    await run('hdiutil', ['detach', mountPoint ?? mountRoot, '-force'], { timeout: 30000 }).catch(() => {});
    fs.rmSync(mountRoot, { recursive: true, force: true });
  }
  return out;
}

// ── Optional: MalwareBazaar (hash only) ───────────────────────────────────────

async function malwareBazaar(sha256) {
  const key = process.env.ABUSECH_KEY;
  if (!key) return null;
  try {
    const res = await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Auth-Key': key, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ query: 'get_info', hash: sha256 }),
      signal: AbortSignal.timeout(10000),
    });
    const json = await res.json();
    if (json.query_status === 'ok' && json.data?.[0]) {
      const d = json.data[0];
      return { severity: 'CRITICAL', title: `Known malware${d.signature ? `: ${d.signature}` : ''}`, detail: `This exact file is in the MalwareBazaar malware database${d.tags?.length ? ` (tags: ${d.tags.slice(0, 5).join(', ')})` : ''}. Delete it.` };
    }
  } catch { /* offline / bad key */ }
  return null;
}

// ── Public API ────────────────────────────────────────────────────────────────

async function sha256(file) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256');
    fs.createReadStream(file).on('data', d => h.update(d)).on('end', () => resolve(h.digest('hex'))).on('error', reject);
  });
}

/**
 * @returns {Promise<{ path, name, size, sha256, kind, origin, findings, severity, verdict, ms }>}
 *   verdict: 'dangerous' (HIGH/CRITICAL) | 'caution' (LOW/MEDIUM) | 'clean'
 */
export async function analyzeFile(file) {
  const t0 = Date.now();
  const name = path.basename(file);
  const st = fs.statSync(file);
  const isApp = st.isDirectory() && name.endsWith('.app');
  const ext = isApp ? 'app' : (name.match(/\.([a-z0-9]{1,10})$/i)?.[1] ?? '').toLowerCase();
  const findings = [...nameFindings(name)];
  let kind = isApp ? 'app' : 'other', hash = null;

  const o = await origin(file);
  findings.push(...originFindings(o));

  if (isApp) {
    findings.push(...(await appFindings(file)).out);
  } else if (st.isFile()) {
    const { head, tail } = await readHead(file);
    kind = detectKind(head, tail);
    hash = await sha256(file);

    // Extension says "document", content says "program"
    if (DOC_EXTS.has(ext) && EXEC_KINDS.has(kind)) {
      findings.push({ severity: 'CRITICAL', title: `Disguised file: named .${ext} but is really a ${kind === 'macho' ? 'Mac program' : kind === 'pe' ? 'Windows program' : kind}`, detail: 'Its contents don\'t match its name — a trick to get you to open a program you think is a document.' });
    }

    if (kind === 'macho') {
      const s = await codeSign.inspect(file);
      findings.push(s.trusted
        ? { severity: 'OK', title: 'Signed program', detail: s.signer }
        : { severity: 'HIGH', title: 'Unsigned Mac program', detail: `Not signed by Apple or an identified developer (${s.status}).` });
    } else if (kind === 'pkg') {
      findings.push(...await pkgFindings(file));
    } else if (kind === 'dmg') {
      findings.push(...await dmgFindings(file));
    } else if (kind === 'zip') {
      const z = await zipFindings(file);
      if (z.out) {
        findings.push(...z.out);
        if (z.apps.length && !z.out.some(f => f.title === 'Password-protected archive')) findings.push(...await zipAppFindings(file, z.apps));
      }
    } else if (kind === 'pe' && !DOC_EXTS.has(ext)) {
      findings.push({ severity: 'LOW', title: 'Windows program', detail: 'It can\'t run on your Mac. If you expected a document or a Mac app, the site that gave you this may be a scam.' });
    } else if (kind === 'ole') {
      const text = await readText(file).catch(() => '');
      if (/_VBA_PROJECT|VBA\b.*Macros|\bMacros\b/s.test(text.replace(/\0/g, ''))) {
        findings.push({ severity: 'HIGH', title: 'Office document with macros', detail: 'Macros are programs inside the document. Phishing documents use them to install malware when you click "Enable content".' });
      }
    }

    // Scripts: by type or extension (.command files open in Terminal when double-clicked)
    if (kind === 'script' || kind === 'applescript' || SCRIPT_EXTS.has(ext)) {
      const text = kind === 'applescript' || ext === 'scpt' ? await compiledAppleScript(file) : await readText(file).catch(() => '');
      if (['command', 'tool', 'terminal'].includes(ext)) {
        findings.push({ severity: 'LOW', title: 'Runs in Terminal when opened', detail: 'Double-clicking this file runs its commands. Only open it if you know exactly what it does.' });
      }
      findings.push(...scriptFindings(text));
    }

    if (st.size < 4 * 1024 * 1024 && (await readText(file).catch(() => '')).includes(EICAR)) {
      findings.push({ severity: 'HIGH', title: 'Antivirus test file (EICAR)', detail: 'A harmless file used to check that security tools work. Safe to delete.' });
    }

    if (['macho', 'pkg', 'dmg', 'zip', 'pe', 'elf', 'script', 'applescript', 'ole', '7z', 'rar'].includes(kind)) {
      const mb = await malwareBazaar(hash);
      if (mb) findings.push(mb);
    }
  }

  // De-duplicate identical titles, strongest first
  const seen = new Set();
  const unique = findings.sort((a, b) => SEV[b.severity] - SEV[a.severity]).filter(f => (seen.has(f.title) ? false : seen.add(f.title)));
  const top = unique[0]?.severity ?? 'OK';
  return {
    path: file, name, size: st.isFile() ? st.size : null, sha256: hash, kind, ext,
    origin: { quarantined: o.quarantine, url: o.url, referrer: o.referrer },
    findings: unique,
    severity: top,
    verdict: SEV[top] >= SEV.HIGH ? 'dangerous' : SEV[top] >= SEV.LOW ? 'caution' : 'clean',
    scannedAt: new Date().toISOString(),
    ms: Date.now() - t0,
  };
}
