/**
 * Alvora Cyber — License Manager
 *
 * Validates license keys and manages trial state.
 *
 * Key format: ALVY-XXXX-XXXX-XXXX  (where X is A-Z0-9)
 *
 * Validation tiers:
 *   TRIAL     — 30-day, no key required
 *   STANDARD  — Single-seat license, any valid key
 *   PRO       — Multi-seat / team license (reserved, not yet sold)
 *
 * PLUG-IN POINT: Replace validateKeyRemote() with a real API call to
 * your license server (Gumroad, LemonSqueezy, or Paddle) for production.
 */

import crypto from 'crypto';

// ─── Key format regex ──────────────────────────────────────────────────────────

const KEY_REGEX = /^ALVY-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/;

// ─── Pre-issued keys for waitlist / demo ──────────────────────────────────────
// These are hardcoded for the MVP. Replace with DB/API lookup in production.

const VALID_KEYS = new Set([
  'ALVY-WAIT-LIST-2024',
  'ALVY-DEMO-TEST-XXXX',
  'ALVY-BETA-0001-VAND',
  'ALVY-BETA-0002-VAND',
  'ALVY-BETA-0003-VAND',
  'ALVY-BETA-0004-VAND',
  'ALVY-BETA-0005-VAND',
  'ALVY-BETA-0006-VAND',
  'ALVY-BETA-0007-VAND',
  'ALVY-BETA-0008-VAND',
  'ALVY-BETA-0009-VAND',
  'ALVY-BETA-0010-VAND',
]);

// ─── Checksum validation (simple, local) ─────────────────────────────────────
// A key is "structurally valid" if:
//   1. Matches the format regex
//   2. The sum of all char codes of the 12 alnum chars is divisible by 7
//   OR it's in the explicit VALID_KEYS set

function keyChecksum(key) {
  const stripped = key.replace(/ALVY-|-/g, '').toUpperCase();
  return stripped.split('').reduce((s, c) => s + c.charCodeAt(0), 0);
}

function isStructurallyValid(key) {
  if (!KEY_REGEX.test(key) && !key.startsWith('ALVY-')) return false;
  // Allow any ALVY- prefixed key during beta — lenient for waitlist
  return key.startsWith('ALVY-') && key.length >= 14;
}

// ─── PLUG-IN: remote validation (future) ─────────────────────────────────────
async function validateKeyRemote(_key) {
  // PLUG-IN POINT: POST key to license server
  // const res = await fetch('https://api.alvoracyber.com/license/validate', { ... });
  // return res.json();
  return { valid: true, tier: 'STANDARD', seats: 1 };
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Validate a license key.
 * Returns a license object if valid, or an error object.
 */
export async function validateKey(key) {
  if (!key || typeof key !== 'string') {
    return { valid: false, error: 'No key provided' };
  }

  const normalised = key.trim().toUpperCase();

  // Check explicit valid key set first
  if (VALID_KEYS.has(normalised)) {
    return {
      valid:       true,
      key:         normalised,
      tier:        'STANDARD',
      activatedAt: new Date().toISOString(),
      seats:       1,
    };
  }

  // Structural validation (lenient for beta)
  if (!isStructurallyValid(normalised)) {
    return { valid: false, error: 'Invalid key format. Expected: ALVY-XXXX-XXXX-XXXX' };
  }

  // Checksum check — divisible by 7 OR 11 (two valid moduli for more keys)
  const cs = keyChecksum(normalised);
  if (cs % 7 !== 0 && cs % 11 !== 0) {
    return { valid: false, error: 'Invalid license key. Please check your key and try again.' };
  }

  // (Optional) remote validation
  try {
    const remote = await validateKeyRemote(normalised);
    if (!remote.valid) {
      return { valid: false, error: 'Key revoked or already in use.' };
    }
  } catch {
    // Network unavailable — allow offline activation with local validation
    console.warn('[License] Remote validation unavailable — using local validation');
  }

  return {
    valid:       true,
    key:         normalised,
    tier:        'STANDARD',
    activatedAt: new Date().toISOString(),
    seats:       1,
  };
}

/**
 * Create a trial license (no key required).
 */
export function createTrial() {
  const now     = new Date();
  const expires = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000); // 30 days

  return {
    valid:       true,
    key:         null,
    tier:        'TRIAL',
    activatedAt: now.toISOString(),
    expiresAt:   expires.toISOString(),
    daysLeft:    30,
    seats:       1,
  };
}

/**
 * Check if an existing license record is still valid.
 */
export function checkLicenseState(record) {
  if (!record) return { active: false, reason: 'No license found' };

  if (record.tier === 'TRIAL') {
    const now     = Date.now();
    const expires = new Date(record.expiresAt).getTime();
    const daysLeft = Math.max(0, Math.ceil((expires - now) / (24 * 60 * 60 * 1000)));

    if (now > expires) {
      return { active: false, reason: 'Trial expired', daysLeft: 0 };
    }
    return { active: true, tier: 'TRIAL', daysLeft, expiresAt: record.expiresAt };
  }

  // Standard / Pro license
  return { active: true, tier: record.tier ?? 'STANDARD', key: record.key };
}

/**
 * Generate a batch of demo license keys (for waitlist distribution).
 * These are all structurally valid with checksum divisible by 7.
 */
export function generateDemoKeys(count = 10) {
  const keys = [];
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Avoid I, O, 0, 1 (confusing)

  while (keys.length < count) {
    const groups = Array.from({ length: 3 }, () =>
      Array.from({ length: 4 }, () => chars[Math.floor(Math.random() * chars.length)]).join('')
    );
    const candidate = `ALVY-${groups.join('-')}`;
    const cs = keyChecksum(candidate);
    if (cs % 7 === 0) keys.push(candidate);
  }

  return keys;
}
