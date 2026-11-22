/**
 * Alvora Cyber — Link Guard warning page
 *
 * Shown in place of a site on phishing/malware blocklists (or a look-alike
 * domain). Every value comes from the query string, so it's only ever set via
 * textContent — never as HTML.
 */

const params  = new URLSearchParams(location.search);
const url     = params.get('u') ?? '';
const verdict = params.get('v') === 'suspicious' ? 'suspicious' : 'malicious';
const reason  = params.get('r') ?? '';
const sources = params.get('s') ?? '';

let host = url;
try { host = new URL(url).hostname; } catch { /* show raw */ }

document.documentElement.dataset.verdict = verdict;
document.getElementById('iconSvg').style.color = verdict === 'suspicious' ? '#f59e0b' : '#ef4444';
document.getElementById('title').textContent = verdict === 'suspicious'
  ? 'This site may be imitating another one'
  : 'Dangerous site blocked';
document.title = `${document.getElementById('title').textContent} — Alvora Cyber`;
document.getElementById('host').textContent = host;
document.getElementById('reason').textContent = reason || 'This site appears on public lists of phishing and malware sites.';
document.getElementById('sources').textContent = sources ? `Listed by: ${sources}` : '';

document.getElementById('back').addEventListener('click', () => {
  chrome.runtime.sendMessage({ type: 'LINK_BACK' });
});

document.getElementById('proceed').addEventListener('click', () => {
  if (!/^https?:\/\//i.test(url)) return;   // only ever navigate to web URLs
  chrome.runtime.sendMessage({ type: 'LINK_PROCEED', url });
});
