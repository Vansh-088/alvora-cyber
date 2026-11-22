/**
 * Alvora Cyber — Real PII Detection Engine
 *
 * Scans arbitrary text for Personally Identifiable Information and
 * sensitive credentials. This is a core real-security feature —
 * patterns are production-grade, not simulated.
 *
 * PLUG-IN POINT: extend PATTERNS array with domain-specific patterns
 * for healthcare (HIPAA), finance (PCI-DSS), or EU/GDPR contexts.
 */

// ─── Pattern Registry ─────────────────────────────────────────────────────────

const PATTERNS = [
  // ── Critical credentials ────────────────────────────────────────────────────
  {
    id:       'PII-001',
    type:     'SSN',
    label:    'Your Social Security Number',
    severity: 'CRITICAL',
    // Skip SSN-shaped strings that are clearly reference/error codes, not real SSNs
    regex:    /(?<!\b(?:code|error|order|ref|reference|ticket|invoice|case|tracking|no)\s)\b(\d{3}-\d{2}-\d{4})\b/gi,
    category: 'Identity',
  },
  {
    id:       'PII-002',
    type:     'CREDIT_CARD',
    label:    'A credit card number',
    severity: 'CRITICAL',
    // Matches contiguous OR space/dash-separated 4x4 groups (e.g. 4111 1111 1111 1111)
    regex:    /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:\d{4}[ -]){3}\d{4})\b/g,
    category: 'Financial',
  },
  {
    id:       'PII-003',
    type:     'API_KEY_OPENAI',
    label:    'An OpenAI key (password to your AI account)',
    severity: 'CRITICAL',
    regex:    /sk-[a-zA-Z0-9]{20,60}/g,
    category: 'Credentials',
  },
  {
    id:       'PII-004',
    type:     'API_KEY_ANTHROPIC',
    label:    'An Anthropic/Claude key (password to your AI account)',
    severity: 'CRITICAL',
    regex:    /sk-ant-[a-zA-Z0-9\-_]{40,100}/g,
    category: 'Credentials',
  },
  {
    id:       'PII-005',
    type:     'AWS_ACCESS_KEY',
    label:    'An Amazon cloud (AWS) access key',
    severity: 'CRITICAL',
    regex:    /\bAKIA[0-9A-Z]{16}\b/g,
    category: 'Credentials',
  },
  {
    id:       'PII-006',
    type:     'AWS_SECRET_KEY',
    label:    'An Amazon cloud (AWS) secret key',
    severity: 'CRITICAL',
    regex:    /\b[a-zA-Z0-9/+]{40}\b(?=.*aws|.*secret)/gi,
    category: 'Credentials',
  },
  {
    id:       'PII-007',
    type:     'GITHUB_TOKEN',
    label:    'A GitHub access token (password to your code)',
    severity: 'CRITICAL',
    regex:    /ghp_[a-zA-Z0-9]{36}/g,
    category: 'Credentials',
  },
  {
    id:       'PII-008',
    type:     'GITHUB_OAUTH',
    label:    'A GitHub login token',
    severity: 'CRITICAL',
    regex:    /gho_[a-zA-Z0-9]{36}/g,
    category: 'Credentials',
  },
  {
    id:       'PII-009',
    type:     'PRIVATE_KEY',
    label:    'A private security key',
    severity: 'CRITICAL',
    regex:    /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g,
    category: 'Credentials',
  },
  {
    id:       'PII-010',
    type:     'PASSWORD_INLINE',
    label:    'A password written in the text',
    severity: 'HIGH',
    regex:    /(?:password|passwd|pwd|secret|token)\s*[=:]\s*["']?([^\s"']{8,})/gi,
    category: 'Credentials',
  },
  {
    id:       'PII-011',
    type:     'STRIPE_KEY',
    label:    'A Stripe payment key',
    severity: 'CRITICAL',
    regex:    /(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}/g,
    category: 'Credentials',
  },

  // ── Personal information ────────────────────────────────────────────────────
  {
    id:       'PII-012',
    type:     'EMAIL',
    label:    'An email address',
    severity: 'MEDIUM',
    regex:    /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g,
    category: 'Contact',
  },
  {
    id:       'PII-013',
    type:     'PHONE_US',
    label:    'A phone number',
    severity: 'LOW',
    regex:    /\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b/g,
    category: 'Contact',
  },
  {
    id:       'PII-014',
    type:     'IP_ADDRESS',
    label:    'A network (IP) address',
    severity: 'LOW',
    regex:    /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    category: 'Network',
  },
  {
    id:       'PII-015',
    type:     'DOB',
    label:    'A date of birth',
    severity: 'MEDIUM',
    regex:    /\b(?:born|dob|date of birth)\s*[:=]?\s*\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}/gi,
    category: 'Identity',
  },
  {
    id:       'PII-016',
    type:     'PASSPORT',
    label:    'A passport number',
    severity: 'HIGH',
    // Allows filler between the word "passport" and the ID (e.g. "passport number is A12345678")
    regex:    /\bpassport(?:\s+(?:no|number|#|id))?(?:\s+(?:is|was|:))?\s*[:=]?\s*([A-Z]{1,2}[0-9]{6,9})\b/gi,
    category: 'Identity',
  },
];

// ─── Severity weights for risk scoring ────────────────────────────────────────

const SEV_WEIGHTS = { CRITICAL: 1.0, HIGH: 0.65, MEDIUM: 0.3, LOW: 0.1 };

// ─── Redaction helper ─────────────────────────────────────────────────────────

function redactMatch(raw) {
  if (raw.length <= 8) return '*'.repeat(raw.length);
  const visible = Math.min(4, Math.floor(raw.length * 0.2));
  return `${raw.slice(0, visible)}${'*'.repeat(Math.min(raw.length - visible * 2, 16))}${raw.slice(-visible)}`;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Scan text for PII / sensitive data.
 *
 * @param {string} text
 * @returns {{
 *   findings: Array<{id, type, label, severity, category, redacted, position}>,
 *   riskScore: number,
 *   hasCritical: boolean,
 *   totalFindings: number,
 *   categorySummary: Record<string, number>
 * }}
 */
export function scanForPII(text) {
  if (!text || typeof text !== 'string') {
    return { findings: [], riskScore: 0, hasCritical: false, totalFindings: 0, categorySummary: {} };
  }

  const findings       = [];
  const seenPositions  = new Set();

  for (const p of PATTERNS) {
    // Clone regex to reset lastIndex
    const rx = new RegExp(p.regex.source, p.regex.flags);
    let match;

    while ((match = rx.exec(text)) !== null) {
      // Prevent duplicate overlapping matches
      const key = `${match.index}-${match[0].length}`;
      if (seenPositions.has(key)) continue;
      seenPositions.add(key);

      findings.push({
        id:       p.id,
        type:     p.type,
        label:    p.label,
        severity: p.severity,
        category: p.category,
        redacted: redactMatch(match[0]),
        position: match.index,
        length:   match[0].length,
      });
    }
  }

  // Sort by position
  findings.sort((a, b) => a.position - b.position);

  // Risk score: capped sum of weights
  const rawScore = findings.reduce((s, f) => s + (SEV_WEIGHTS[f.severity] ?? 0), 0);
  const riskScore = parseFloat(Math.min(1.0, rawScore / Math.max(1, findings.length + 1) + (findings.length > 0 ? 0.2 : 0)).toFixed(3));

  // Category summary
  const categorySummary = {};
  for (const f of findings) {
    categorySummary[f.category] = (categorySummary[f.category] ?? 0) + 1;
  }

  return {
    findings,
    riskScore,
    hasCritical:    findings.some(f => f.severity === 'CRITICAL'),
    totalFindings:  findings.length,
    categorySummary,
  };
}

/**
 * Redact all PII from text (replaces matches with [REDACTED]).
 * @param {string} text
 * @returns {string}
 */
export function redactPII(text) {
  if (!text) return text;
  let result = text;
  for (const p of PATTERNS) {
    const rx = new RegExp(p.regex.source, p.regex.flags);
    result = result.replace(rx, `[${p.type}]`);
  }
  return result;
}

const SEV_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

/**
 * Replace each piece of PII with a numbered placeholder so the prompt can be
 * sent safely: "mail jane@x.com and jane@x.com" → "mail [EMAIL_1] and [EMAIL_1]".
 * Overlapping matches keep the more severe (then longer) one; the same value
 * always gets the same placeholder so the AI can still reason about it.
 *
 * @param {string} text
 * @param {Array} [findings]  scanForPII(text).findings (re-scanned if omitted)
 * @returns {{ text: string, items: Array<{ placeholder, type, label, severity }> }}
 *          `items` never contains the original values.
 */
export function redactForSend(text, findings = scanForPII(text).findings) {
  // Resolve overlaps: walk by position, keep the stronger of any two that collide
  const chosen = [];
  for (const f of [...findings].sort((a, b) => a.position - b.position || b.length - a.length)) {
    const last = chosen[chosen.length - 1];
    if (last && f.position < last.position + last.length) {
      const stronger = (SEV_RANK[f.severity] ?? 0) - (SEV_RANK[last.severity] ?? 0) || f.length - last.length;
      if (stronger > 0) chosen[chosen.length - 1] = f;
      continue;
    }
    chosen.push(f);
  }

  const byValue = new Map();   // "TYPE\u0000value" → placeholder
  const counters = {};
  const items = [];
  let out = '', cursor = 0;
  for (let f of chosen) {
    // "(212) 555-0198" is matched from "212)" — swallow the opening paren too
    if (text[f.position - 1] === '(' && text.slice(f.position, f.position + f.length).includes(')') && f.position - 1 >= cursor) {
      f = { ...f, position: f.position - 1, length: f.length + 1 };
    }
    const value = text.slice(f.position, f.position + f.length);
    const key = `${f.type}\u0000${value}`;
    let placeholder = byValue.get(key);
    if (!placeholder) {
      counters[f.type] = (counters[f.type] ?? 0) + 1;
      placeholder = `[${f.type}_${counters[f.type]}]`;
      byValue.set(key, placeholder);
      items.push({ placeholder, type: f.type, label: f.label, severity: f.severity });
    }
    out += text.slice(cursor, f.position) + placeholder;
    cursor = f.position + f.length;
  }
  out += text.slice(cursor);
  return { text: out, items };
}
