#!/usr/bin/env node
'use strict';

/**
 * build-backend.cjs — Produce a minified copy of the backend for packaging.
 *
 * Why minify instead of aggressive obfuscation:
 *   • Strips all comments + shortens local identifiers → source is not casually
 *     readable if someone unpacks the .app.
 *   • Per-file transform (NOT bundling) keeps `import` statements and dynamic
 *     import() intact, so better-sqlite3 (native) and systeminformation (lazy
 *     dynamic import) keep working. Aggressive control-flow obfuscation tends to
 *     break exactly those, which is unacceptable for a security tool.
 *
 * Output: ./backend-build (mirrors ./backend, JS minified, node_modules copied).
 * electron-builder ships backend-build as the app's "backend" resource.
 */

const fs      = require('fs');
const path    = require('path');
const esbuild = require('esbuild');
const { execSync } = require('child_process');

const SRC  = path.join(__dirname, '..', 'backend');
const OUT  = path.join(__dirname, '..', 'backend-build');

function rmrf(p) { fs.rmSync(p, { recursive: true, force: true }); }

function copyDir(from, to) {
  fs.mkdirSync(to, { recursive: true });
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    const s = path.join(from, entry.name);
    const d = path.join(to, entry.name);
    if (entry.isDirectory()) copyDir(s, d);
    else fs.copyFileSync(s, d);
  }
}

function minifyJsTree(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules') continue; // never touch deps
      minifyJsTree(p);
    } else if (entry.name.endsWith('.js')) {
      const code = fs.readFileSync(p, 'utf8');
      const out  = esbuild.transformSync(code, {
        minify:   true,
        format:   'esm',     // backend is ESM ("type":"module")
        platform: 'node',
        target:   'node18',
        legalComments: 'none',
      });
      fs.writeFileSync(p, out.code, 'utf8');
    }
  }
}

console.log('[build-backend] cleaning…');
rmrf(OUT);

console.log('[build-backend] copying backend → backend-build…');
copyDir(SRC, OUT);

console.log('[build-backend] minifying backend JS (comments stripped, locals shortened)…');
minifyJsTree(OUT);

// ── Native-module signing for hardened runtime ───────────────────────────────
// The backend ships in extraResources, and electron-builder does NOT re-sign
// Mach-O files there. better-sqlite3's .node arrives ad-hoc signed (which breaks
// the app-signing pass) — so we RE-SIGN it ourselves with the Developer ID +
// hardened-runtime option. A same-team, runtime-signed library loads cleanly
// under hardened runtime; stripping it (leaving it unsigned) makes hardened
// runtime refuse to dlopen it at startup (ERR_DLOPEN_FAILED).
const nativeFiles = [];
const bsq = path.join(OUT, 'node_modules', 'better-sqlite3');
if (fs.existsSync(bsq)) {
  // Prune C++ source + deps not needed at runtime (the compiled .node is all we ship)
  for (const junk of ['deps', 'src', 'build/Release/.forge-meta', 'build/Release/obj.target', 'build/Release/.deps']) {
    rmrf(path.join(bsq, junk));
  }
  const f = path.join(bsq, 'build', 'Release', 'better_sqlite3.node');
  if (fs.existsSync(f)) nativeFiles.push(f);
}

// onnxruntime-node (on-device injection classifier) ships binaries for every
// OS/arch (~290 MB). Keep only macOS, and sign its .node + dylibs like sqlite's.
const ortBin = path.join(OUT, 'node_modules', 'onnxruntime-node', 'bin');
if (fs.existsSync(ortBin)) {
  for (const napi of fs.readdirSync(ortBin)) {
    for (const plat of fs.readdirSync(path.join(ortBin, napi))) {
      if (plat !== 'darwin') rmrf(path.join(ortBin, napi, plat));
    }
    const darwin = path.join(ortBin, napi, 'darwin');
    if (!fs.existsSync(darwin)) continue;
    for (const arch of fs.readdirSync(darwin)) {
      for (const f of fs.readdirSync(path.join(darwin, arch))) {
        const full = path.join(darwin, arch, f);
        if (/\.(node|dylib)$/.test(f) && !fs.lstatSync(full).isSymbolicLink()) nativeFiles.push(full);
      }
    }
  }
  console.log('[build-backend] pruned onnxruntime-node to macOS binaries');
}

// Clear extended attributes / resource forks across the whole backend payload FIRST
// (these embedded forks trip codesign's resource-seal checks).
try {
  execSync(`xattr -cr "${OUT}"`, { stdio: 'ignore' });
  console.log('[build-backend] cleared extended attributes on backend-build');
} catch { /* non-fatal */ }

// Then re-sign the native module LAST, so nothing strips the fresh signature.
// electron-builder does NOT sign Mach-O inside extraResources, so we must — and
// hardened runtime refuses to dlopen an unsigned library (ERR_DLOPEN_FAILED).
if (nativeFiles.length) {
  let identity = null;
  try {
    identity = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'electron-builder.json'), 'utf8'))?.mac?.identity;
  } catch {}
  if (identity) {
    for (const file of nativeFiles) {
      try {
        // --force replaces the stale ad-hoc signature; --options runtime = hardened
        // compatible; --timestamp is required for notarization.
        execSync(`codesign --force --options runtime --timestamp --sign "${identity}" "${file}"`, { stdio: 'ignore' });
        console.log(`[build-backend] re-signed ${path.basename(file)} with Developer ID (hardened runtime)`);
      } catch (e) {
        console.warn(`[build-backend] WARNING: could not sign ${path.basename(file)} — hardened build will fail to load it:`, e.message);
      }
    }
  } else {
    console.warn('[build-backend] WARNING: no mac.identity in electron-builder.json — native module left unsigned');
  }
}

console.log('[build-backend] done.');
