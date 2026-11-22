/**
 * tune-threshold.mjs — Pick the classifier's decision threshold on a TUNING
 * set that never overlaps the evaluation suites (see fetch-public.mjs).
 *
 *   node benchmark/tune-threshold.mjs
 *
 * Objective: best F1 for the combined (rules + classifier) verdict, subject
 * to a false-alarm rate ≤ MAX_FPR on benign prompts — false alarms are what
 * make people switch a security tool off.
 *
 * The false-alarm budget is measured on the CLEAN-label sources (deepset,
 * SafeGuard). The in-the-wild "regular" prompts are scraped and noisy: they
 * contain real jailbreaks labelled benign and SEO templates that literally say
 * "ignore all previous instructions", so they're reported but not used to pick.
 */

import fs   from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { analyzeForInjection } from '../backend/lib/promptInjectionGuard.js';
import { openScorer } from './scoreCache.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MAX_FPR = 0.01;

const { cases } = JSON.parse(fs.readFileSync(path.join(__dirname, '.cache', 'tune.json'), 'utf8'));
const scorer = await openScorer();
if (!scorer) { console.error('classifier model not installed'); process.exit(1); }

const rows = [];
let i = 0;
for (const c of cases) {
  const rules = analyzeForInjection(c.text);
  rows.push({ attack: c.attack, source: c.source ?? 'unknown', rules, p: await scorer.score(c.text), rulesHit: ['BLOCK', 'REVIEW'].includes(rules.action) });
  if (++i % 200 === 0) console.log(`  scored ${i}/${cases.length}`);
}
const { fuse } = scorer.classifier;
await scorer.close();
// The real verdict pipeline (fuse), not an approximation of it
const hit = (r, t, veto) => ['BLOCK', 'REVIEW'].includes(fuse(r.rules, { score: r.p }, { threshold: t, veto }).action);

const CLEAN = new Set(['deepset', 'safeguard']);

function metrics(pred, filter = () => true) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  rows.filter(filter).forEach((r, k) => { const h = pred(r, k); if (r.attack && h) tp++; else if (r.attack) fn++; else if (h) fp++; else tn++; });
  const precision = tp + fp ? tp / (tp + fp) : 1, recall = tp / (tp + fn);
  return { precision, recall, f1: precision + recall ? 2 * precision * recall / (precision + recall) : 0, fpr: fp / (fp + tn) };
}

const pct = x => `${(x * 100).toFixed(1)}%`.padStart(6);
console.log(`\nTuning set: ${rows.length} prompts (${rows.filter(r => r.attack).length} attacks)\n`);
console.log('threshold   recall  precis.   F1    false-alarm(clean)  false-alarm(in-the-wild)   (combined = rules OR classifier)');
let best = null;
for (const t of [0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.98, 0.99, 0.995, 0.999]) {
  const pred  = r => hit(r, t, 0);
  const m     = metrics(pred);
  const clean = metrics(pred, r => CLEAN.has(r.source));
  const wild  = metrics(pred, r => r.source === 'in-the-wild');
  const ok = clean.fpr <= MAX_FPR;
  console.log(`  ${String(t).padEnd(8)} ${pct(m.recall)}  ${pct(m.precision)}  ${m.f1.toFixed(3)}      ${pct(clean.fpr)}            ${pct(wild.fpr)}${ok ? '' : '     ✗ over budget'}`);
  if (ok && (!best || m.f1 > best.f1)) best = { t, ...m, cleanFpr: clean.fpr, wildFpr: wild.fpr };
}
const r0 = metrics(r => r.rulesHit), rc = metrics(r => r.rulesHit, r => CLEAN.has(r.source));
console.log(`\nRules alone: recall ${pct(r0.recall).trim()}, F1 ${r0.f1.toFixed(3)}, false alarms clean ${pct(rc.fpr).trim()}`);
for (const src of ['deepset', 'safeguard', 'in-the-wild']) {
  const t = best?.t ?? 0.5;
  const m = metrics(r => hit(r, t, 0), r => r.source === src);
  console.log(`  ${src.padEnd(12)} @${t}: recall ${pct(m.recall)}, false alarms ${pct(m.fpr)}`);
}
// Phrase-only veto: what does trusting a confident "benign" verdict over the
// "ignore previous instructions" regex cost (missed attacks) and save (false alarms)?
const T = best?.t ?? 0.5;
console.log(`\nPhrase-rule veto @ threshold ${T}:`);
const VETOS = [0, 0.001, 0.01, 0.05, 0.1];
for (const veto of VETOS) {
  const m = metrics(r => hit(r, T, veto)), c = metrics(r => hit(r, T, veto), r => CLEAN.has(r.source)), w = metrics(r => hit(r, T, veto), r => r.source === 'in-the-wild');
  console.log(`  veto <${String(veto).padEnd(6)} recall ${pct(m.recall)}  F1 ${m.f1.toFixed(3)}  false alarms clean ${pct(c.fpr)}  in-the-wild ${pct(w.fpr)}`);
}

// Veto pick: the LARGEST veto (fewest false alarms on "ignore previous
// instructions" templates) whose F1 is within VETO_SLACK of the best veto —
// differences smaller than that are noise on a set this size.
const VETO_SLACK = 0.005;
const vetoF1 = VETOS.map(v => ({ v, f1: metrics(r => hit(r, T, v)).f1 }));
const bestVetoF1 = Math.max(...vetoF1.map(x => x.f1));
const VETO_PICK = vetoF1.filter(x => x.f1 >= bestVetoF1 - VETO_SLACK).sort((a, b) => b.v - a.v)[0].v;

// Final pick, veto on: the most conservative (highest) threshold whose F1 is
// within F1_SLACK of the best — very low cut-offs are fragile on new data.
const F1_SLACK = 0.01;
const sweep = [0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.98].map(t => ({
  t, ...metrics(r => hit(r, t, VETO_PICK)), cleanFpr: metrics(r => hit(r, t, VETO_PICK), r => CLEAN.has(r.source)).fpr,
})).filter(x => x.cleanFpr <= MAX_FPR);
const bestF1 = Math.max(...sweep.map(x => x.f1));
const pick = sweep.filter(x => x.f1 >= bestF1 - F1_SLACK).sort((a, b) => b.t - a.t)[0];
console.log(`\nWith veto <${VETO_PICK}: best F1 ${bestF1.toFixed(3)}; thresholds within ${F1_SLACK}: ${sweep.filter(x => x.f1 >= bestF1 - F1_SLACK).map(x => x.t).join(', ')}`);
console.log(`\n→ Chosen: threshold ${pick.t}, veto ${VETO_PICK} — F1 ${pick.f1.toFixed(3)}, recall ${pct(pick.recall).trim()}, false alarms ${pct(pick.cleanFpr).trim()} on clean-label data`);
