/**
 * Alvora Cyber — Extension Popup Script
 */

async function init() {
  // Fetch stats from background worker
  let stats = { scanned: 0, blocked: 0, pii: 0, injections: 0, redacted: 0, linksBlocked: 0, backendOk: false };

  try {
    const res = await chrome.runtime.sendMessage({ type: 'GET_STATS' });
    if (res?.stats) stats = res.stats;
  } catch {
    // Background worker unavailable
  }

  // Update stat cards
  document.getElementById('statScanned').textContent = stats.scanned;
  document.getElementById('statBlocked').textContent = stats.blocked;
  document.getElementById('statPii').textContent     = stats.pii;
  document.getElementById('statInject').textContent  = stats.injections;
  document.getElementById('statRedacted').textContent = stats.redacted ?? 0;
  document.getElementById('statLinks').textContent    = stats.linksBlocked ?? 0;

  // Backend status
  const dot     = document.getElementById('statusDot');
  const backVal = document.getElementById('backendVal');

  if (stats.backendOk) {
    dot.classList.replace('offline', 'online');
    backVal.textContent = 'Connected ●';
    backVal.classList.replace('error', 'ok');
  } else {
    backVal.textContent = 'Offline — start desktop app';
  }
}

// Reset stats
document.getElementById('btnReset').addEventListener('click', async () => {
  try {
    await chrome.runtime.sendMessage({ type: 'RESET_STATS' });
    document.getElementById('statScanned').textContent = '0';
    document.getElementById('statBlocked').textContent = '0';
    document.getElementById('statPii').textContent     = '0';
    document.getElementById('statInject').textContent  = '0';
    document.getElementById('statRedacted').textContent = '0';
    document.getElementById('statLinks').textContent    = '0';
  } catch {}
});

// The desktop app registers the alvora:// scheme; macOS hands the link to it
// (Chrome asks once whether to open Alvora Cyber). Handing an external-scheme
// link to the current tab doesn't navigate it — the page stays where it was.
document.getElementById('btnOpenApp').addEventListener('click', async () => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id !== undefined) await chrome.tabs.update(tab.id, { url: 'alvora://dashboard' });
    else await chrome.tabs.create({ url: 'alvora://dashboard' });
  } catch {}
  window.close();
});

init();
