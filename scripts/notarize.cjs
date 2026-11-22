'use strict';

/**
 * notarize.cjs — electron-builder afterSign hook
 *
 * After electron-builder code-signs the .app with the Developer ID Application
 * certificate, this submits it to Apple's notary service and staples the ticket
 * so Gatekeeper accepts it with no right-click workaround.
 *
 * Credential resolution (first that's fully set wins):
 *   1. App Store Connect API key  — APPLE_API_KEY (path to .p8) + APPLE_API_KEY_ID + APPLE_API_ISSUER
 *   2. Apple ID + app-specific pw — APPLE_ID + APPLE_APP_SPECIFIC_PASSWORD + APPLE_TEAM_ID
 *   3. Keychain profile (fallback) — "alvora-notary"
 *
 * Env-var auth (1 or 2) is deterministic and keychain-independent — the secret
 * lives only in your shell session, never in the repo or this file.
 */

const { execSync } = require('child_process');

const KEYCHAIN_PROFILE = 'alvora-notary';

function resolveCreds() {
  const e = process.env;
  // Use ALVORA_* names (not APPLE_*) so electron-builder doesn't detect them
  // and try its own notarization path, which crashes with "options is undefined"
  // when there's no matching mac.notarize config block.
  if (e.ALVORA_APPLE_ID && e.ALVORA_APP_PWD && e.ALVORA_TEAM_ID) {
    return {
      how: `Apple ID (${e.ALVORA_APPLE_ID})`,
      opts: {
        appleId:         e.ALVORA_APPLE_ID,
        appleIdPassword: e.ALVORA_APP_PWD,
        teamId:          e.ALVORA_TEAM_ID,
      },
    };
  }
  return {
    how: `keychain profile "${KEYCHAIN_PROFILE}"`,
    opts: { keychainProfile: KEYCHAIN_PROFILE },
  };
}

exports.default = async function notarizing(context) {
  const { electronPlatformName, appOutDir } = context;
  if (electronPlatformName !== 'darwin') return;

  if (process.env.SKIP_NOTARIZE === '1') {
    console.log('[notarize] SKIP_NOTARIZE=1 — skipping notarization');
    return;
  }

  const appName = context.packager.appInfo.productFilename;
  const appPath = `${appOutDir}/${appName}.app`;
  const { how, opts } = resolveCreds();

  console.log(`[notarize] Submitting "${appName}.app" to Apple via ${how}…`);
  console.log('[notarize] This typically takes 2–15 minutes while Apple scans the app.');

  const { notarize } = require('@electron/notarize');
  await notarize({ tool: 'notarytool', appPath, ...opts });

  console.log('[notarize] Notarization succeeded. Stapling ticket onto the app…');
  execSync(`xcrun stapler staple "${appPath}"`, { stdio: 'inherit' });
  console.log('[notarize] Stapled. The app will open with no right-click workaround.');
};
