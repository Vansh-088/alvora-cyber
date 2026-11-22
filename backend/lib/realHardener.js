/**
 * realHardener.js — macOS Security Posture Assessment
 *
 * Reads real system settings with macOS built-in tools. No admin rights are
 * needed and nothing is changed. Each check reports one of:
 *   pass · warn · fail · unknown   (unknown = couldn't be read; never penalised)
 *
 * Every check also carries a plain-language `guide` (why it matters + steps to
 * fix it) and `points` — how much the score rises once it's fixed.
 *
 * Sources are the ones current macOS actually uses. Older approaches (e.g.
 * /Library/Preferences/com.apple.alf, `systemsetup`, unscoped screensaver
 * prefs) silently return nothing on recent releases and used to show up as
 * false failures.
 */

import { exec }      from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

/** stdout+stderr, trimmed; `null` when the command failed or timed out. */
async function run(cmd, { timeout = 5000 } = {}) {
  try {
    const { stdout, stderr } = await execAsync(cmd, { timeout });
    return `${stdout}\n${stderr}`.trim();
  } catch (err) {
    // `defaults read` exits 1 for a missing key — that's information, not an error
    const text = `${err.stdout ?? ''}\n${err.stderr ?? ''}`.trim();
    return err.killed ? null : (text || null);
  }
}

const readDefault = async (args) => {
  const out = await run(`defaults ${args} 2>&1`);
  if (out == null || /does not exist|not found|Could not find/i.test(out)) return null;
  return out.trim();
};

/** TCP ports with a listening socket (netstat sees every user's sockets without admin). */
async function listeningPorts() {
  const out = await run('netstat -an -p tcp');
  if (out == null) return null;
  const ports = new Set();
  for (const line of out.split('\n')) {
    if (!/LISTEN/.test(line)) continue;
    const m = line.trim().split(/\s+/)[3]?.match(/\.(\d+)$/);
    if (m) ports.add(Number(m[1]));
  }
  return ports;
}

const unknown = (base, why) => ({
  ...base, status: 'unknown', value: 'Couldn\'t check',
  detail: `Alvora couldn't read this setting (${why}). It isn't counted against your score.`,
});

// ── Individual checks ─────────────────────────────────────────────────────────

async function checkFileVault() {
  const base = {
    id: 'filevault', name: 'FileVault Disk Encryption', impact: 'CRITICAL', settings: 'filevault',
    guide: {
      title: 'Turn on FileVault',
      why: 'FileVault scrambles everything on your disk. If your Mac is lost or stolen, nobody can read your files without your password.',
      steps: [
        'Open System Settings → Privacy & Security.',
        'Scroll down to FileVault and click Turn On.',
        'Choose how to save your recovery key (your iCloud account is easiest). Keep it safe — it\'s the only way back in if you forget your password.',
        'Leave your Mac plugged in. Encryption runs in the background and you can keep working.',
      ],
    },
  };
  const out = await run('fdesetup status');
  if (out == null) return unknown(base, 'fdesetup did not respond');
  const on = /FileVault is On/i.test(out);
  const busy = /Encryption in progress/i.test(out);
  return {
    ...base,
    status: on ? 'pass' : 'fail',
    value:  busy ? 'Encrypting…' : on ? 'On' : 'Off',
    detail: on
      ? 'Your disk is encrypted. Your files are safe if the Mac is lost or stolen.'
      : 'Your disk is not encrypted. Anyone who gets hold of this Mac could read your files.',
  };
}

async function checkFirewall() {
  const base = {
    id: 'firewall', name: 'Firewall', impact: 'HIGH', settings: 'firewall',
    guide: {
      title: 'Turn on the firewall',
      why: 'The firewall blocks other devices on the same Wi-Fi from connecting into your Mac uninvited — important on café, hotel and airport networks.',
      steps: [
        'Open System Settings → Network → Firewall.',
        'Switch Firewall on.',
        'Optional extra: click Options… and turn on "Enable stealth mode" so your Mac doesn\'t answer strangers\' probes.',
      ],
    },
  };
  const out = await run('/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate');
  const state = out?.match(/State = (\d)/)?.[1];
  if (state == null) return unknown(base, 'the firewall tool did not answer');
  const stealth = /enabled/i.test(await run('/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode') ?? '');
  const on = Number(state) >= 1;
  return {
    ...base,
    status: on ? 'pass' : 'fail',
    value:  !on ? 'Off' : stealth ? 'On (stealth mode)' : 'On',
    detail: on
      ? `The firewall is filtering incoming connections${stealth ? ' and your Mac is hidden from probes' : ''}.`
      : 'The firewall is off, so devices on the same network can try to connect to your Mac.',
  };
}

async function checkGatekeeper() {
  const base = {
    id: 'gatekeeper', name: 'Gatekeeper (App Checks)', impact: 'HIGH', settings: 'security',
    guide: {
      title: 'Turn Gatekeeper back on',
      why: 'Gatekeeper checks that apps come from identified developers and have been scanned by Apple before they open. With it off, malware can run without any warning.',
      steps: [
        'Open the Terminal app (Applications → Utilities → Terminal).',
        'Type: sudo spctl --global-enable   and press Return.',
        'Enter your Mac password when asked (nothing appears as you type — that\'s normal).',
        'Then open System Settings → Privacy & Security and, under "Allow applications from", choose "App Store & Known Developers".',
      ],
    },
  };
  const out = await run('spctl --status');
  if (out == null) return unknown(base, 'spctl did not respond');
  const on = /assessments enabled/i.test(out);
  return {
    ...base,
    status: on ? 'pass' : 'fail',
    value:  on ? 'On' : 'Off',
    detail: on
      ? 'Apps are checked by Apple before they\'re allowed to open.'
      : 'App checks are off, so unsigned or tampered apps can open without warning.',
  };
}

async function checkUpdates() {
  const base = {
    id: 'autoupdate', name: 'Automatic Security Updates', impact: 'MEDIUM', settings: 'updates',
    guide: {
      title: 'Turn on automatic security updates',
      why: 'Apple regularly patches security holes that attackers already know about. Automatic updates close them without you having to remember.',
      steps: [
        'Open System Settings → General → Software Update.',
        'Click the ⓘ next to "Automatic updates".',
        'Turn on "Check for updates" and "Install Security Responses and system files".',
        'Recommended: also turn on "Download new updates when available" and "Install macOS updates".',
      ],
    },
  };
  // A missing key means the macOS default, which is ON for both
  const dom = '/Library/Preferences/com.apple.SoftwareUpdate';
  const [check, security, macos] = await Promise.all([
    readDefault(`read ${dom} AutomaticCheckEnabled`),
    readDefault(`read ${dom} CriticalUpdateInstall`),
    readDefault(`read ${dom} AutomaticallyInstallMacOSUpdates`),
  ]);
  const checkOn    = check !== '0';
  const securityOn = security !== '0';
  const macosOn    = macos === '1';
  const ok = checkOn && securityOn;
  return {
    ...base,
    status: ok ? 'pass' : (checkOn || securityOn ? 'warn' : 'fail'),
    value:  !checkOn ? 'Off' : !securityOn ? 'Security fixes off' : macosOn ? 'On (installs automatically)' : 'On',
    detail: ok
      ? 'Your Mac checks for updates and installs security fixes automatically.'
      : !checkOn
        ? 'Your Mac isn\'t checking for updates, so known security holes stay open.'
        : 'Your Mac checks for updates but won\'t install security fixes by itself.',
  };
}

async function checkScreenLock() {
  const base = {
    id: 'screenlock', name: 'Screen Lock', impact: 'MEDIUM', settings: 'lockscreen',
    guide: {
      title: 'Lock your screen quickly when you step away',
      why: 'If your Mac stays unlocked while you\'re away, anyone nearby can read your messages or use your accounts in seconds.',
      steps: [
        'Open System Settings → Lock Screen.',
        'Set "Turn display off when inactive" to 5 minutes or less (on battery and on power adapter).',
        'Set "Require password after screen saver begins or display is turned off" to "Immediately" or 1 minute.',
        'Habit tip: press Control-Command-Q to lock instantly whenever you get up.',
      ],
    },
  };
  // sysadminctl prints e.g. "screenLock delay is 60 seconds" / "screenLock is off" (to stderr)
  const lockOut = await run('sysadminctl -screenLock status');
  const offMatch = /screenLock is off/i.test(lockOut ?? '');
  const delayMatch = lockOut?.match(/screenLock (?:delay is (\d+) seconds|is immediate)/i);
  if (!offMatch && !delayMatch) return unknown(base, 'the lock setting could not be read');
  const delay = delayMatch?.[1] != null ? Number(delayMatch[1]) : 0;

  // The screen locks at whichever comes first: screen saver or display sleep.
  // Judge the slowest power profile (battery vs adapter); 0 means "never".
  const saverSecs = Number(await readDefault('-currentHost read com.apple.screensaver idleTime') ?? 0);
  const pm = await run('pmset -g custom') ?? '';
  const displaySecs = [...pm.matchAll(/displaysleep\s+(\d+)/g)].map(m => Number(m[1]) * 60 || Infinity);
  const slowestDisplay = displaySecs.length ? Math.max(...displaySecs) : Infinity;
  const total = Math.min(saverSecs || Infinity, slowestDisplay) + delay;
  const mins = s => (s < 60 ? `${s} sec` : `${Math.round(s / 60)} min`);

  if (offMatch) {
    return { ...base, status: 'fail', value: 'No password',
      detail: 'Your Mac doesn\'t ask for a password when it wakes, so anyone can use it.' };
  }
  if (!Number.isFinite(total)) {
    return { ...base, status: 'warn', value: 'Never locks by itself',
      detail: 'Your screen never turns off on its own, so it stays unlocked until you lock it yourself.' };
  }
  const good = total <= 600;
  return {
    ...base,
    status: good ? 'pass' : 'warn',
    value:  `Locks after ~${mins(total)}`,
    detail: good
      ? `Your screen locks about ${mins(total)} after you stop using it.`
      : `Your screen stays unlocked for about ${mins(total)} after you walk away. 5 minutes or less is safer.`,
  };
}

const SHARING_PORTS = {
  22:   { label: 'Remote Login (SSH)',                setting: 'Remote Login' },
  445:  { label: 'File Sharing',                      setting: 'File Sharing' },
  548:  { label: 'File Sharing (AFP)',                setting: 'File Sharing' },
  5900: { label: 'Screen Sharing / Remote Management', setting: 'Screen Sharing and Remote Management' },
  3283: { label: 'Remote Management',                 setting: 'Remote Management' },
};

async function checkSharing(portsPromise) {
  const base = {
    id: 'sharing', name: 'Remote Access & Sharing', impact: 'HIGH', settings: 'sharing',
    guide: {
      title: 'Switch off sharing you don\'t use',
      why: 'Each sharing service is a door other computers can knock on. If you don\'t use it, closing it removes a way in.',
      steps: [
        'Open System Settings → General → Sharing.',
        'Turn off anything you don\'t actively use — usually Remote Login, Screen Sharing, Remote Management and File Sharing.',
        'If you do need one, use a strong Mac password and turn it off again when you\'re done.',
      ],
    },
  };
  const ports = await portsPromise;
  if (ports == null) return unknown(base, 'open network ports could not be listed');
  const open = [...new Set(Object.entries(SHARING_PORTS).filter(([p]) => ports.has(Number(p))).map(([, v]) => v.label))];
  const settingsToTurnOff = [...new Set(Object.entries(SHARING_PORTS).filter(([p]) => ports.has(Number(p))).map(([, v]) => v.setting))];
  return {
    ...base,
    status: open.length === 0 ? 'pass' : 'warn',
    value:  open.length === 0 ? 'All off' : open.join(', '),
    detail: open.length === 0
      ? 'No remote login or sharing services are accepting connections.'
      : `These are accepting connections from other computers: ${open.join(', ')}. Make sure you meant to turn them on.`,
    ...(open.length && { guide: { ...base.guide, steps: [
      'Open System Settings → General → Sharing.',
      `Turn off: ${settingsToTurnOff.join(', ')} — unless you use it on purpose.`,
      'If you do need it, use a strong Mac password and switch it off again when you\'re done.',
    ] } }),
  };
}

async function checkSIP() {
  const base = {
    id: 'sip', name: 'System Integrity Protection', impact: 'CRITICAL', settings: null,
    guide: {
      title: 'Turn System Integrity Protection back on',
      why: 'SIP stops anything — including malware with your password — from changing the core of macOS. It should only ever be off for specialist development work.',
      steps: [
        'Shut down your Mac.',
        'Apple silicon: press and hold the power button until "Loading startup options" appears, then choose Options → Continue. Intel: hold Command-R while it starts.',
        'From the menu bar choose Utilities → Terminal.',
        'Type: csrutil enable   and press Return, then restart.',
      ],
    },
  };
  const out = await run('csrutil status');
  if (out == null || !/status:/i.test(out)) return unknown(base, 'csrutil did not respond');
  const on = /status:\s*enabled/i.test(out) && !/disabled/i.test(out);
  return {
    ...base,
    status: on ? 'pass' : 'fail',
    value:  on ? 'On' : 'Off or reduced',
    detail: on
      ? 'Core macOS files are locked against tampering.'
      : 'Core macOS protection is off, so malware could alter the system itself.',
  };
}

async function checkAutoLogin() {
  const base = {
    id: 'autologin', name: 'Automatic Login', impact: 'HIGH', settings: 'users',
    guide: {
      title: 'Turn off automatic login',
      why: 'With automatic login, anyone who turns on your Mac goes straight to your desktop — no password needed.',
      steps: [
        'Open System Settings → Users & Groups.',
        'Set "Automatically log in as" to Off.',
        'Restart once to check that your Mac now asks for your password.',
      ],
    },
  };
  const user = await readDefault('read /Library/Preferences/com.apple.loginwindow autoLoginUser');
  const on = !!user;
  return {
    ...base,
    status: on ? 'fail' : 'pass',
    value:  on ? `On (${user})` : 'Off',
    detail: on
      ? 'Your Mac logs in by itself at startup, skipping the password.'
      : 'Your Mac asks for a password when it starts up.',
  };
}

async function checkGuest() {
  const base = {
    id: 'guest', name: 'Guest Account', impact: 'LOW', settings: 'users',
    guide: {
      title: 'Turn off the Guest account',
      why: 'The Guest account lets anyone use your Mac without a password. It\'s rarely needed and is one less way in.',
      steps: [
        'Open System Settings → Users & Groups.',
        'Click the ⓘ next to Guest User.',
        'Turn off "Allow guests to log in to this computer".',
      ],
    },
  };
  const out = await run('sysadminctl -guestAccount status');
  if (out == null || !/guest account (enabled|disabled)/i.test(out)) return unknown(base, 'the Guest setting could not be read');
  const on = /guest account enabled/i.test(out);
  return {
    ...base,
    status: on ? 'warn' : 'pass',
    value:  on ? 'On' : 'Off',
    detail: on ? 'Anyone can sign in as a guest without a password.' : 'Guest sign-in is turned off.',
  };
}

// ── Scoring ───────────────────────────────────────────────────────────────────

const WEIGHTS   = { CRITICAL: 30, HIGH: 20, MEDIUM: 10, LOW: 5 };
const PENALTIES = { fail: 1.0, warn: 0.4, pass: 0, unknown: 0 };

const penaltyOf = c => (WEIGHTS[c.impact] ?? 10) * (PENALTIES[c.status] ?? 0);

function calculateScore(checks) {
  return Math.max(0, Math.round(100 - checks.reduce((sum, c) => sum + penaltyOf(c), 0)));
}

// ── Public API ────────────────────────────────────────────────────────────────

export async function runSecurityAudit() {
  const ports = listeningPorts();
  const raw = await Promise.all([
    checkSIP(),
    checkFileVault(),
    checkFirewall(),
    checkGatekeeper(),
    checkAutoLogin(),
    checkSharing(ports),
    checkUpdates(),
    checkScreenLock(),
    checkGuest(),
  ]);

  const checks = raw.map(c => ({
    ...c,
    points: Math.round(penaltyOf(c)),   // score gained once this is fixed
    fix: c.status === 'warn' || c.status === 'fail' ? c.guide.steps[0] : null,
  }));

  const score    = calculateScore(checks);
  const failures = checks.filter(c => c.status === 'fail');
  const warnings = checks.filter(c => c.status === 'warn');
  const toFix    = [...failures, ...warnings].sort((a, b) => b.points - a.points);
  const threatLevel = score >= 80 ? 'Low' : score >= 55 ? 'Elevated' : 'Critical';

  return {
    score,
    threatLevel,
    checkedAt: new Date().toISOString(),
    checks,
    summary: {
      pass:    checks.filter(c => c.status === 'pass').length,
      warn:    warnings.length,
      fail:    failures.length,
      unknown: checks.filter(c => c.status === 'unknown').length,
      total:   checks.length,
    },
    criticalIssues: failures.filter(c => c.impact === 'CRITICAL').map(c => c.name),
    // Biggest score gains first
    fixes: toFix.map(c => ({ id: c.id, name: c.name, fix: c.fix, points: c.points })),
  };
}
