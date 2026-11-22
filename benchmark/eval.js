/**
 * eval.js — Runs the labeled dataset against Alvora's REAL detection engines
 * and reports precision / recall / F1 + false-positive rate.
 *
 *   node benchmark/eval.js
 *
 * Pure regex/rule engines only (no API keys needed) — measures the deterministic
 * core that ships to every user. This is the number you quote to a technical buyer.
 */

import { scanForPII }          from '../backend/lib/piiDetector.js';
import { analyzeForInjection } from '../backend/lib/promptInjectionGuard.js';
import { PII_CASES, INJECTION_CASES } from './dataset.js';

function metrics(rows) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  const misses = [];
  for (const r of rows) {
    if (r.expect && r.detected)       tp++;
    else if (r.expect && !r.detected) { fn++; misses.push(`  MISS (let attack through): "${r.text.slice(0, 60)}"`); }
    else if (!r.expect && r.detected) { fp++; misses.push(`  FALSE ALARM (blocked benign): "${r.text.slice(0, 60)}"`); }
    else                               tn++;
  }
  const precision = tp + fp ? tp / (tp + fp) : 1;
  const recall    = tp + fn ? tp / (tp + fn) : 1;
  const f1        = precision + recall ? 2 * precision * recall / (precision + recall) : 0;
  const fpr       = fp + tn ? fp / (fp + tn) : 0;
  return { tp, fp, tn, fn, precision, recall, f1, fpr, misses };
}

const pct = x => `${(x * 100).toFixed(1)}%`;

// ── PII engine ────────────────────────────────────────────────────────────────
const piiRows = PII_CASES.map(c => {
  const r = scanForPII(c.text);
  return { ...c, detected: r.totalFindings > 0 };
});
const pii = metrics(piiRows);

// ── Injection engine — "detected" = blocked or held for review ─────────────────
const injRows = INJECTION_CASES.map(c => {
  const r = analyzeForInjection(c.text);
  return { ...c, detected: r.action === 'BLOCK' || r.action === 'REVIEW' };
});
const inj = metrics(injRows);

// ── Report ────────────────────────────────────────────────────────────────────
function block(name, m, n) {
  console.log(`\n═══ ${name}  (n=${n}) ═══`);
  console.log(`  Recall (attacks caught):   ${pct(m.recall)}   [${m.tp}/${m.tp + m.fn}]`);
  console.log(`  Precision (of flags, real):${pct(m.precision)}   [${m.tp}/${m.tp + m.fp}]`);
  console.log(`  F1 score:                  ${m.f1.toFixed(3)}`);
  console.log(`  False-positive rate:       ${pct(m.fpr)}   [${m.fp}/${m.fp + m.tn} benign wrongly flagged]`);
  if (m.misses.length) { console.log('  ── errors ──'); m.misses.forEach(x => console.log(x)); }
}

console.log('\n╔══════════════════════════════════════════════════════╗');
console.log('║   ALVORA DETECTION BENCHMARK — deterministic engines  ║');
console.log('╚══════════════════════════════════════════════════════╝');
block('PII / Secret Leak Detection', pii, piiRows.length);
block('Prompt-Injection Detection',  inj, injRows.length);

const overallF1 = (pii.f1 + inj.f1) / 2;
console.log(`\n─── Combined F1: ${overallF1.toFixed(3)} ───`);
console.log('(Deterministic core only. The optional NVIDIA NIM + Claude layers add');
console.log(' semantic coverage on top of these numbers.)\n');

// Non-zero exit if either engine underperforms — usable as a CI gate
const PASS = pii.recall >= 0.9 && inj.recall >= 0.9 && pii.fpr <= 0.15 && inj.fpr <= 0.15;
process.exit(PASS ? 0 : 1);
