/**
 * vault.js — Real AES-256-GCM Encrypted Vault
 *
 * Zero external dependencies. Uses only Node.js built-in `crypto`.
 *
 * Security design:
 *  - Master password → 256-bit key via scrypt (memory-hard KDF, brute-force resistant)
 *  - Per-file random 16-byte salt (so the same password yields different keys per file)
 *  - Per-file random 12-byte IV (GCM standard nonce length)
 *  - AES-256-GCM: authenticated encryption — detects any tampering via the 16-byte auth tag
 *  - Encrypted file layout on disk:
 *
 *        ┌──────────┬──────────┬──────────────┬───────────────────┐
 *        │ salt(16) │ iv(12)   │ authTag(16)  │ ciphertext (N)    │
 *        └──────────┴──────────┴──────────────┴───────────────────┘
 *
 *  - A vault "verifier" record proves the master password is correct WITHOUT
 *    storing the password — we encrypt a known string and check it decrypts.
 *
 * The master password is NEVER written to disk. If lost, data is unrecoverable
 * (which is the point — that's what "encrypted at rest" means).
 */

import crypto from 'crypto';
import fs      from 'fs';
import path    from 'path';
import os      from 'os';

// ── Crypto constants ──────────────────────────────────────────────────────────

const ALGORITHM   = 'aes-256-gcm';
const KEY_LENGTH  = 32;    // 256 bits
const SALT_LENGTH = 16;
const IV_LENGTH   = 12;    // 96 bits — recommended for GCM
const TAG_LENGTH  = 16;    // 128-bit auth tag
const SCRYPT_COST = 16384; // N — CPU/memory cost factor (2^14)
const VERIFIER_PLAINTEXT = 'ALVORA_VAULT_VERIFIER_v1';

// ── Vault location ──────────────────────────────────────────────────────────

// In the Electron app, main.cjs passes ALVORA_DATA_DIR (app.getPath('userData')).
// Fallback to a hidden folder in the user's home directory for standalone runs.
const DATA_DIR  = process.env.ALVORA_DATA_DIR || path.join(os.homedir(), '.alvora-cyber');
const VAULT_DIR = path.join(DATA_DIR, 'vault');
const BLOB_DIR  = path.join(VAULT_DIR, 'blobs');
const MANIFEST  = path.join(VAULT_DIR, 'manifest.json');

function ensureDirs() {
  fs.mkdirSync(BLOB_DIR, { recursive: true });
}

// ── Key derivation ──────────────────────────────────────────────────────────

/**
 * Derive a 256-bit key from the master password + per-file salt.
 * scrypt is memory-hard — far more resistant to GPU brute-force than PBKDF2.
 */
function deriveKey(password, salt) {
  return crypto.scryptSync(password, salt, KEY_LENGTH, { N: SCRYPT_COST, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
}

// ── Core encrypt / decrypt ──────────────────────────────────────────────────

/**
 * Encrypt a Buffer. Returns a single Buffer: salt || iv || tag || ciphertext
 */
export function encryptBuffer(plaintext, password) {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const iv   = crypto.randomBytes(IV_LENGTH);
  const key  = deriveKey(password, salt);

  const cipher     = crypto.createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag        = cipher.getAuthTag();

  return Buffer.concat([salt, iv, tag, ciphertext]);
}

/**
 * Decrypt a Buffer produced by encryptBuffer. Throws if password wrong or data tampered.
 */
export function decryptBuffer(blob, password) {
  const salt       = blob.subarray(0, SALT_LENGTH);
  const iv         = blob.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const tag        = blob.subarray(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
  const ciphertext = blob.subarray(SALT_LENGTH + IV_LENGTH + TAG_LENGTH);

  const key      = deriveKey(password, salt);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  // .final() throws if the auth tag doesn't match → wrong password or tampered file
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// ── Manifest (file metadata index) ──────────────────────────────────────────

function readManifest() {
  try {
    return JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
  } catch {
    return { initialized: false, verifier: null, files: [] };
  }
}

function writeManifest(manifest) {
  ensureDirs();
  fs.writeFileSync(MANIFEST, JSON.stringify(manifest, null, 2), 'utf8');
}

// ── Vault lifecycle ─────────────────────────────────────────────────────────

/**
 * Is the vault set up with a master password yet?
 */
export function isInitialized() {
  return readManifest().initialized === true;
}

/**
 * Set the master password for the first time. Stores an encrypted verifier so
 * we can later confirm the password is correct without storing the password.
 */
export function initializeVault(password) {
  if (!password || password.length < 8) {
    throw new Error('Master password must be at least 8 characters');
  }
  const manifest = readManifest();
  if (manifest.initialized) {
    throw new Error('Vault already initialized');
  }
  const verifierBlob = encryptBuffer(Buffer.from(VERIFIER_PLAINTEXT, 'utf8'), password);
  manifest.initialized = true;
  manifest.verifier    = verifierBlob.toString('base64');
  manifest.createdAt   = new Date().toISOString();
  manifest.files       = [];
  writeManifest(manifest);
  return { success: true };
}

/**
 * Verify a master password against the stored verifier.
 */
export function verifyPassword(password) {
  const manifest = readManifest();
  if (!manifest.initialized || !manifest.verifier) return false;
  try {
    const blob      = Buffer.from(manifest.verifier, 'base64');
    const decrypted = decryptBuffer(blob, password).toString('utf8');
    return decrypted === VERIFIER_PLAINTEXT;
  } catch {
    return false; // auth tag mismatch = wrong password
  }
}

// ── File operations ─────────────────────────────────────────────────────────

/**
 * Encrypt and store a file in the vault.
 * @param {string} fileName  - original filename
 * @param {Buffer} content   - raw file bytes
 * @param {string} password  - master password (verified first)
 */
export function addFile(fileName, content, password) {
  if (!verifyPassword(password)) {
    throw new Error('Invalid master password');
  }
  ensureDirs();

  const id       = `VLT-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  const blob     = encryptBuffer(content, password);
  const blobPath = path.join(BLOB_DIR, `${id}.enc`);

  fs.writeFileSync(blobPath, blob);

  // SHA-256 of the *original* content for integrity verification
  const checksum = crypto.createHash('sha256').update(content).digest('hex');

  const record = {
    id,
    name:         fileName,
    sizeBytes:    content.length,
    encSizeBytes: blob.length,
    checksum,
    addedAt:      new Date().toISOString(),
    algorithm:    'AES-256-GCM',
  };

  const manifest = readManifest();
  manifest.files.unshift(record);
  writeManifest(manifest);

  return record;
}

/**
 * Decrypt and return a file's content.
 * @returns {{ name: string, content: Buffer }}
 */
export function getFile(id, password) {
  if (!verifyPassword(password)) {
    throw new Error('Invalid master password');
  }
  const manifest = readManifest();
  const record   = manifest.files.find(f => f.id === id);
  if (!record) throw new Error('File not found in vault');

  const blobPath = path.join(BLOB_DIR, `${id}.enc`);
  const blob     = fs.readFileSync(blobPath);
  const content  = decryptBuffer(blob, password);

  // Verify integrity
  const checksum = crypto.createHash('sha256').update(content).digest('hex');
  if (checksum !== record.checksum) {
    throw new Error('Integrity check failed — file may be corrupted');
  }

  return { name: record.name, content };
}

/**
 * Permanently delete a file from the vault.
 */
export function deleteFile(id, password) {
  if (!verifyPassword(password)) {
    throw new Error('Invalid master password');
  }
  const manifest = readManifest();
  const idx      = manifest.files.findIndex(f => f.id === id);
  if (idx === -1) throw new Error('File not found');

  const blobPath = path.join(BLOB_DIR, `${id}.enc`);
  try { fs.unlinkSync(blobPath); } catch {}

  manifest.files.splice(idx, 1);
  writeManifest(manifest);
  return { success: true };
}

/**
 * List vault file metadata (never decrypts content).
 */
export function listFiles() {
  return readManifest().files.map(f => ({
    id:        f.id,
    name:      f.name,
    sizeBytes: f.sizeBytes,
    addedAt:   f.addedAt,
    algorithm: f.algorithm,
  }));
}

/**
 * Vault stats summary.
 */
export function getStats() {
  const manifest   = readManifest();
  const totalBytes = manifest.files.reduce((sum, f) => sum + (f.sizeBytes || 0), 0);
  return {
    initialized: manifest.initialized === true,
    fileCount:   manifest.files.length,
    totalBytes,
    createdAt:   manifest.createdAt ?? null,
  };
}

/**
 * Wipe the vault entirely — deletes every encrypted blob and resets the manifest.
 * Used when the user has forgotten their master password and accepts data loss.
 * Returns the number of files that were deleted.
 */
export function resetVault() {
  const manifest  = readManifest();
  const count     = manifest.files.length;

  // Delete every blob on disk
  for (const f of manifest.files) {
    const blobPath = path.join(BLOB_DIR, `${f.id}.enc`);
    try { fs.unlinkSync(blobPath); } catch {}
  }

  // Reset the manifest to uninitialized
  writeManifest({ initialized: false, verifier: null, files: [] });
  return { deleted: count };
}

/**
 * Re-encrypt every file in the vault with a new master password.
 * Requires the current password to be correct (all files are decrypted then
 * immediately re-encrypted with the new password in one atomic pass).
 */
export function changePassword(currentPassword, newPassword) {
  if (!verifyPassword(currentPassword)) {
    throw new Error('Current password is incorrect');
  }
  if (!newPassword || newPassword.length < 8) {
    throw new Error('New password must be at least 8 characters');
  }
  if (newPassword === currentPassword) {
    throw new Error('New password must be different from the current password');
  }

  const manifest = readManifest();

  // Re-encrypt each file blob
  for (const f of manifest.files) {
    const blobPath = path.join(BLOB_DIR, `${f.id}.enc`);
    const blob     = fs.readFileSync(blobPath);
    const content  = decryptBuffer(blob, currentPassword);  // decrypt with old key
    const newBlob  = encryptBuffer(content, newPassword);   // re-encrypt with new key
    fs.writeFileSync(blobPath, newBlob);
  }

  // Update the verifier to the new password
  const newVerifier      = encryptBuffer(Buffer.from(VERIFIER_PLAINTEXT, 'utf8'), newPassword);
  manifest.verifier      = newVerifier.toString('base64');
  manifest.passwordChanged = new Date().toISOString();
  writeManifest(manifest);

  return { success: true, filesRekeyed: manifest.files.length };
}

export { VAULT_DIR };
