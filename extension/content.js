/**
 * Alvora Cyber — Content Script
 *
 * Intercepts AI prompts on supported platforms BEFORE they are sent.
 * If PII or injection threats are found → shows an overlay and blocks submission.
 * User can edit the prompt, send a placeholder-redacted copy ("Redact & Send"),
 * or send anyway (with risk acknowledged).
 *
 * Supported: ChatGPT, Claude.ai, Gemini, Perplexity, Grok, Copilot
 */

(function () {
  'use strict';

  // ── Site detection ──────────────────────────────────────────────────────────

  const SITE_CONFIGS = {
    'chatgpt.com': {
      name: 'ChatGPT',
      getPrompt: () => {
        const el = document.querySelector('#prompt-textarea, [data-id="root"] textarea, textarea[placeholder*="message"]');
        return el ? (el.value || el.innerText || '').trim() : '';
      },
      getSendBtn: () =>
        document.querySelector('button[data-testid="send-button"], button[aria-label*="Send"]'),
    },
    'chat.openai.com': {
      name: 'ChatGPT',
      getPrompt: () => {
        const el = document.querySelector('#prompt-textarea, textarea[placeholder*="message"]');
        return el ? (el.value || el.innerText || '').trim() : '';
      },
      getSendBtn: () =>
        document.querySelector('button[data-testid="send-button"], button[aria-label*="Send"]'),
    },
    'claude.ai': {
      name: 'Claude',
      getPrompt: () => {
        const el = document.querySelector('[contenteditable="true"][data-testid*="chat"], .ProseMirror, [contenteditable="true"]');
        return el ? el.innerText.trim() : '';
      },
      getSendBtn: () =>
        document.querySelector('button[aria-label*="Send"], button[type="submit"]'),
    },
    'gemini.google.com': {
      name: 'Gemini',
      getPrompt: () => {
        const el = document.querySelector('rich-textarea .ql-editor, textarea.input-area, [contenteditable="true"]');
        return el ? el.innerText.trim() : '';
      },
      getSendBtn: () =>
        document.querySelector('button.send-button, button[aria-label*="Send"], mat-icon[data-mat-icon-name="send"]')
          ?.closest('button'),
    },
    'perplexity.ai': {
      name: 'Perplexity',
      getPrompt: () => {
        const el = document.querySelector('textarea[placeholder*="Ask"], textarea');
        return el ? el.value.trim() : '';
      },
      getSendBtn: () =>
        document.querySelector('button[aria-label*="Submit"], button[type="submit"]'),
    },
    'grok.com': {
      name: 'Grok',
      getPrompt: () => {
        const el = document.querySelector('textarea');
        return el ? el.value.trim() : '';
      },
      getSendBtn: () =>
        document.querySelector('button[aria-label*="Send"], button[type="submit"]'),
    },
    'copilot.microsoft.com': {
      name: 'Copilot',
      getPrompt: () => {
        const el = document.querySelector('textarea#userInput, textarea[name="q"], textarea');
        return el ? el.value.trim() : '';
      },
      getSendBtn: () =>
        document.querySelector('button#submit-button, button[aria-label*="Send"], button[type="submit"]'),
    },
  };

  // The prompt box itself (textarea or contenteditable) — used to write back a
  // redacted prompt. Same selectors as each site's getPrompt().
  const INPUT_SELECTORS = {
    'chatgpt.com':           '#prompt-textarea, [data-id="root"] textarea, textarea[placeholder*="message"]',
    'chat.openai.com':       '#prompt-textarea, textarea[placeholder*="message"]',
    'claude.ai':             '[contenteditable="true"][data-testid*="chat"], .ProseMirror, [contenteditable="true"]',
    'gemini.google.com':     'rich-textarea .ql-editor, textarea.input-area, [contenteditable="true"]',
    'perplexity.ai':         'textarea[placeholder*="Ask"], textarea',
    'grok.com':              'textarea',
    'copilot.microsoft.com': 'textarea#userInput, textarea[name="q"], textarea',
  };

  function getInputEl() {
    for (const [host, sel] of Object.entries(INPUT_SELECTORS)) {
      if (window.location.hostname.includes(host)) return document.querySelector(sel);
    }
    return null;
  }

  function getSiteConfig() {
    for (const [host, cfg] of Object.entries(SITE_CONFIGS)) {
      if (window.location.hostname.includes(host)) return cfg;
    }
    return null;
  }

  const SITE = getSiteConfig();
  if (!SITE) return; // Not an AI platform we cover

  // ── State ───────────────────────────────────────────────────────────────────

  let scanning      = false;
  let overlayActive = false;

  // ── Overlay UI ──────────────────────────────────────────────────────────────

  // Everything interpolated into HTML here is escaped: values can carry pieces
  // of the user's prompt or model-written text, and this runs inside the chat
  // site's page — unescaped, that's script injection into ChatGPT/Claude/etc.
  function esc(value) {
    return String(value ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  }

  function buildOverlay(scanResult, prompt) {
    const { pii, injection, finalAction, classifier, ai, redaction, lockedDown } = scanResult;
    const riskScore = scanResult.combinedRisk ?? scanResult.riskScore ?? 0;   // backend field is combinedRisk

    const piiCount  = pii?.totalFindings ?? 0;
    const injThreats = injection?.threats ?? [];
    const isBlock   = finalAction === 'BLOCK';
    const isReview  = finalAction === 'REVIEW' || finalAction === 'FLAG';

    const accentColor = isBlock ? '#ef4444' : '#f59e0b';
    const accentLight = isBlock ? 'rgba(239,68,68,0.1)' : 'rgba(245,158,11,0.1)';

    const overlay = document.createElement('div');
    overlay.id = 'alvora-overlay';
    overlay.style.cssText = `
      position: fixed; inset: 0; z-index: 2147483647;
      background: rgba(0,0,0,0.75); backdrop-filter: blur(4px);
      display: flex; align-items: center; justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    `;

    const card = document.createElement('div');
    card.style.cssText = `
      background: #0f1623; border: 1px solid ${accentColor}40;
      border-radius: 16px; padding: 28px; width: 480px; max-width: 92vw;
      box-shadow: 0 0 60px ${accentColor}20, 0 24px 64px rgba(0,0,0,0.6);
      color: #e2e8f0;
    `;

    // Header
    const header = document.createElement('div');
    header.style.cssText = 'display:flex; align-items:center; gap:12px; margin-bottom:20px;';
    header.innerHTML = `
      <div style="width:40px;height:40px;border-radius:10px;background:${accentLight};border:1px solid ${accentColor}40;display:flex;align-items:center;justify-content:center;flex-shrink:0;">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="${accentColor}" stroke-width="2.5">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          ${isBlock ? '<line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>' : '<path d="M12 9v4"/><circle cx="12" cy="17" r="1"/>'}
        </svg>
      </div>
      <div>
        <div style="font-size:15px;font-weight:700;color:#fff;">
          ${isBlock ? 'Prompt Blocked' : 'Security Warning'}
        </div>
        <div style="font-size:12px;color:#64748b;margin-top:2px;">
          Alvora Cyber • ${esc(SITE.name)} • Risk Score: ${Math.round(riskScore * 100)}%
        </div>
      </div>
    `;
    card.appendChild(header);

    // Findings
    const findings = document.createElement('div');
    findings.style.cssText = `
      background: rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.07);
      border-radius: 10px; padding:14px; margin-bottom:16px;
    `;

    let findingsHTML = '';

    if (piiCount > 0) {
      findingsHTML += `
        <div style="margin-bottom:10px;">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#94a3b8;margin-bottom:6px;">
            PII Detected (${piiCount} issue${piiCount !== 1 ? 's' : ''})
          </div>
          ${(pii.findings ?? []).slice(0, 3).map(f => `
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
              <span style="width:6px;height:6px;border-radius:50%;background:#ef4444;flex-shrink:0;"></span>
              <span style="font-size:12px;color:#cbd5e1;">${esc(f.label ?? f.type)}</span>
              <code style="font-size:11px;color:#64748b;background:rgba(255,255,255,0.05);padding:1px 6px;border-radius:4px;">${esc(f.redacted ?? '—')}</code>
            </div>
          `).join('')}
          ${(pii.findings?.length ?? 0) > 3 ? `<div style="font-size:11px;color:#64748b;margin-top:4px;">…and ${pii.findings.length - 3} more</div>` : ''}
        </div>
      `;
    }

    if (injThreats.length > 0) {
      findingsHTML += `
        <div>
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#94a3b8;margin-bottom:6px;">
            Injection Threats (${injThreats.length})
          </div>
          ${injThreats.slice(0, 2).map(t => `
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
              <span style="width:6px;height:6px;border-radius:50%;background:#f59e0b;flex-shrink:0;"></span>
              <span style="font-size:12px;color:#cbd5e1;">${esc(t.name ?? t.rule)}</span>
              <span style="font-size:11px;color:#64748b;">${esc(t.severity ?? '')}</span>
            </div>
          `).join('')}
        </div>
      `;
    }

    if (classifier?.attack) {
      findingsHTML += `
        <div style="margin-top:${findingsHTML ? 10 : 0}px;">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#94a3b8;margin-bottom:6px;">
            Hidden instructions (on-device classifier · ${Math.round((classifier.score ?? 0) * 100)}%)
          </div>
          <div style="font-size:12px;color:#cbd5e1;">${piiCount > 0 && !injThreats.length
            ? 'The classifier rated this text as instruction-like. It often over-reacts to card or account numbers — if you are only sharing your own details, this is likely a false alarm, and Redact &amp; Send removes them.'
            : 'This text looks like it\'s trying to give the AI new instructions — a common way to hijack it or leak data.'}</div>
        </div>
      `;
    }

    if (ai?.sensitive && ai.reason) {
      findingsHTML += `
        <div style="margin-top:${findingsHTML ? 10 : 0}px;">
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#94a3b8;margin-bottom:6px;">AI review</div>
          <div style="font-size:12px;color:#cbd5e1;">${esc(ai.reason)}</div>
        </div>
      `;
    }

    if (!findingsHTML) {
      findingsHTML = `<div style="font-size:12px;color:#94a3b8;">Suspicious pattern detected. Review before sending.</div>`;
    }

    findings.innerHTML = findingsHTML;
    card.appendChild(findings);

    // Recommendation — follows the final verdict, not the rule engine alone
    const recommendation = isBlock
      ? 'This prompt was stopped before reaching the AI. Edit it, or send anyway if you are sure.'
      : 'Held for your review — check it before sending.';
    const rec = document.createElement('div');
    rec.style.cssText = `font-size:12px;color:#94a3b8;margin-bottom:18px;line-height:1.5;`;
    rec.textContent = recommendation;
    card.appendChild(rec);

    // Action buttons
    const actions = document.createElement('div');
    actions.style.cssText = 'display:flex; gap:10px; justify-content:flex-end;';

    const editBtn = document.createElement('button');
    editBtn.textContent = 'Edit Prompt';
    editBtn.style.cssText = `
      padding: 9px 18px; border-radius: 9px; border: 1px solid rgba(255,255,255,0.12);
      background: transparent; color: #94a3b8; font-size: 13px; font-weight: 500;
      cursor: pointer; transition: all .15s;
    `;
    editBtn.onmouseenter = () => { editBtn.style.borderColor = 'rgba(255,255,255,0.25)'; editBtn.style.color = '#e2e8f0'; };
    editBtn.onmouseleave = () => { editBtn.style.borderColor = 'rgba(255,255,255,0.12)'; editBtn.style.color = '#94a3b8'; };
    editBtn.onclick = () => dismissOverlay();

    const sendAnywayBtn = document.createElement('button');
    sendAnywayBtn.textContent = isBlock ? 'Send Anyway (Risk)' : 'Send';
    sendAnywayBtn.style.cssText = `
      padding: 9px 18px; border-radius: 9px; border: 1px solid ${accentColor}40;
      background: ${accentLight}; color: ${accentColor}; font-size: 13px; font-weight: 600;
      cursor: pointer; transition: all .15s;
    `;
    sendAnywayBtn.onmouseenter = () => { sendAnywayBtn.style.background = `${accentColor}20`; };
    sendAnywayBtn.onmouseleave = () => { sendAnywayBtn.style.background = accentLight; };
    sendAnywayBtn.onclick = () => {
      dismissOverlay();
      forceSubmit();
    };

    actions.appendChild(editBtn);

    // Redact & Send — offered whenever personal info was found: sending the
    // placeholder copy is never less safe than "Send anyway". (Not in lockdown,
    // which means "send nothing".)
    if (redaction?.items?.length && !lockedDown) {
      const redactBtn = document.createElement('button');
      redactBtn.textContent = `Redact & Send`;
      redactBtn.title = redaction.items.map(i => `${i.placeholder} — ${i.label}`).join('\n');
      redactBtn.style.cssText = `
        padding: 9px 18px; border-radius: 9px; border: 0;
        background: #10b981; color: #04130d; font-size: 13px; font-weight: 700;
        cursor: pointer; transition: all .15s;
      `;
      redactBtn.onmouseenter = () => { redactBtn.style.background = '#34d399'; };
      redactBtn.onmouseleave = () => { redactBtn.style.background = '#10b981'; };
      redactBtn.onclick = () => redactAndSend(prompt, pii.findings ?? [], redaction);
      actions.appendChild(redactBtn);

      const preview = document.createElement('div');
      preview.style.cssText = 'font-size:11px;color:#64748b;margin:-8px 0 14px;line-height:1.5;';
      preview.textContent = `Redact & Send replaces: ${redaction.items.map(i => `${i.label} → ${i.placeholder}`).join(', ')}`;
      card.appendChild(preview);   // sits above the button row, which is appended next
    }

    actions.appendChild(sendAnywayBtn);
    card.appendChild(actions);

    // Branding footer
    const footer = document.createElement('div');
    footer.style.cssText = 'margin-top:14px;text-align:center;';
    footer.innerHTML = `<span style="font-size:10px;color:#334155;">Protected by <strong style="color:#00e5ff;">Alvora Cyber</strong></span>`;
    card.appendChild(footer);

    overlay.appendChild(card);
    return overlay;
  }

  function showOverlay(scanResult, prompt) {
    if (overlayActive) return;
    let el;
    try {
      el = buildOverlay(scanResult, prompt);
    } catch (err) {
      // Never leave the page in "overlay active" (which swallows all keys) if
      // rendering fails. Fail safe: the flagged prompt is still NOT sent.
      console.error('[Alvora] overlay failed:', err);
      overlayActive = false;
      scanning = false;
      pendingSubmitFn = null;
      showToast('Alvora flagged this prompt and held it — edit it or try sending again.', 'block');
      return;
    }
    overlayActive = true;
    document.body.appendChild(el);
    // Close on background click
    el.addEventListener('click', (e) => {
      if (e.target === el) dismissOverlay();
    });
  }

  function dismissOverlay() {
    const el = document.getElementById('alvora-overlay');
    if (el) el.remove();
    overlayActive = false;
    scanning = false;
  }

  // ── Toast notification (for allowed prompts with warnings) ──────────────────

  function showToast(message, type = 'info') {
    const existing = document.getElementById('alvora-toast');
    if (existing) existing.remove();

    const colors = { info: '#00e5ff', warn: '#f59e0b', block: '#ef4444' };
    const color  = colors[type] || colors.info;

    const toast = document.createElement('div');
    toast.id = 'alvora-toast';
    toast.style.cssText = `
      position: fixed; bottom: 24px; right: 24px; z-index: 2147483646;
      background: #0f1623; border: 1px solid ${color}40; border-left: 3px solid ${color};
      border-radius: 10px; padding: 12px 16px; max-width: 320px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 13px; color: #cbd5e1;
      box-shadow: 0 8px 32px rgba(0,0,0,0.4);
      animation: alvoraSlideIn 0.2s ease;
    `;
    toast.innerHTML = `
      <div style="display:flex;align-items:center;gap:8px;">
        <span style="color:${color};font-weight:700;font-size:11px;text-transform:uppercase;">Alvora</span>
        <span>${esc(message)}</span>
      </div>
    `;

    document.body.appendChild(toast);
    setTimeout(() => toast?.remove(), 4000);
  }

  // ── Force submit (after user clicks "Send Anyway") ──────────────────────────

  let pendingSubmitFn = null;

  function forceSubmit() {
    if (pendingSubmitFn) {
      pendingSubmitFn();
      pendingSubmitFn = null;
    }
  }

  // ── Redact & Send ───────────────────────────────────────────────────────────

  /** Replace the prompt box's content with `text`, the way a user edit would. */
  function setComposerText(el, text) {
    el.focus();
    if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) {
      // Native setter so React/Vue state sees the change
      const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), 'value').set;
      setter.call(el, text);
      el.dispatchEvent(new Event('input', { bubbles: true }));
      return;
    }
    // contenteditable editors (ProseMirror, Quill, Lexical) handle insertText
    // as a real edit, keeping their internal document in sync
    const range = document.createRange();
    range.selectNodeContents(el);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    document.execCommand('insertText', false, text);
  }

  async function redactAndSend(prompt, findings, redaction) {
    // Values that must NOT be sent — taken from the exact text that was scanned
    const secrets = findings.map(f => prompt.slice(f.position, f.position + f.length)).filter(v => v.trim().length >= 3);
    const el = getInputEl();
    if (!el) {
      dismissOverlay();
      showToast('Couldn\'t find the message box to redact — nothing was sent.', 'warn');
      return;
    }
    setComposerText(el, redaction.text);
    await new Promise(r => setTimeout(r, 150));   // let the editor/framework settle

    // Safety check: never send if any original value survived the rewrite
    const now = SITE.getPrompt();
    const leaked = secrets.filter(v => now.includes(v));
    if (!now || leaked.length) {
      dismissOverlay();
      showToast('Redaction didn\'t apply cleanly — nothing was sent. Please remove the personal info yourself.', 'block');
      return;
    }

    dismissOverlay();
    chrome.runtime.sendMessage({ type: 'REDACTED_SEND' }).catch(() => {});
    forceSubmit();
    showToast(`Sent with ${redaction.items.length} item${redaction.items.length !== 1 ? 's' : ''} replaced: ${redaction.items.map(i => i.placeholder).join(', ')}`, 'info');
  }

  // ── Intercept logic ─────────────────────────────────────────────────────────

  async function interceptAndScan(promptText, originalSubmitFn) {
    if (scanning || !promptText || promptText.length < 5) {
      originalSubmitFn();
      return;
    }

    scanning = true;

    // Ask background worker to scan
    let result;
    try {
      result = await chrome.runtime.sendMessage({
        type:    'SCAN_PROMPT',
        text:    promptText,
        context: 'browser_extension',
        site:    SITE.name,
      });
    } catch {
      // Extension context invalidated or backend offline — fail open
      scanning = false;
      originalSubmitFn();
      return;
    }

    if (!result?.ok || !result?.data) {
      // Backend offline — fail open with a quiet toast
      showToast('Backend offline — prompt sent unscanned', 'warn');
      scanning = false;
      originalSubmitFn();
      return;
    }

    const { data } = result;
    const action   = data.finalAction;

    if (action === 'BLOCK' || action === 'REVIEW') {
      // Show blocking overlay — don't call originalSubmitFn yet
      pendingSubmitFn = originalSubmitFn;
      showOverlay(data, promptText);
      // scanning = false is handled inside dismissOverlay
    } else {
      // Safe — allow through, maybe show a quick toast if score > 0
      const risk = data.combinedRisk ?? data.riskScore ?? 0;
      if (risk > 0.1) {
        showToast(`Scan passed (risk: ${Math.round(risk * 100)}%)`, 'info');
      }
      scanning = false;
      originalSubmitFn();
    }
  }

  // ── Event wiring ────────────────────────────────────────────────────────────

  let wired = false;

  function wireInterceptors() {
    if (wired) return;

    // Intercept keyboard Enter (submit)
    document.addEventListener('keydown', (e) => {
      // Our own re-dispatched Enter (after a scan passes) is synthetic — let it
      // through, or it would be intercepted and re-scanned forever.
      if (!e.isTrusted) return;
      if (overlayActive) { e.stopPropagation(); e.preventDefault(); return; }
      if (e.key !== 'Enter' || e.shiftKey || e.isComposing) return;

      const prompt = SITE.getPrompt();
      if (!prompt) return;

      // Don't intercept if focused on a textarea for line-break (shiftKey already handled)
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();

      interceptAndScan(prompt, () => {
        // Simulate the original Enter press
        const target = e.target;
        if (target) {
          target.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: false }));
        }
      });
    }, true);

    // Intercept send button clicks
    document.addEventListener('click', (e) => {
      if (!e.isTrusted) return;   // our own re-dispatched click — see keydown note
      if (overlayActive) return;

      const sendBtn = SITE.getSendBtn();
      if (!sendBtn) return;
      if (!sendBtn.contains(e.target) && e.target !== sendBtn) return;

      const prompt = SITE.getPrompt();
      if (!prompt) return;

      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();

      interceptAndScan(prompt, () => {
        // Re-click (synthetic, so our listener lets it pass). Re-query: the app
        // may have re-rendered the button while the overlay was open.
        (SITE.getSendBtn() ?? sendBtn).dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
      });
    }, true);

    wired = true;
  }

  // Wire after a short delay (SPA may not have rendered yet)
  setTimeout(wireInterceptors, 1500);

  // Re-wire on SPA navigation (MutationObserver)
  const navObserver = new MutationObserver(() => {
    if (!wired) wireInterceptors();
  });
  navObserver.observe(document.body, { childList: true, subtree: false });

})();
