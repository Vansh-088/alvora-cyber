/**
 * eval-public.mjs — Score Alvora's prompt-attack detectors on PUBLIC data.
 *
 *   node benchmark/fetch-public.mjs     (once — downloads the datasets)
 *   node benchmark/eval-public.mjs [detector ...]
 *
 * Detectors: rules (regex engine), classifier (local ML model), combined
 * (what /api/scan actually uses). Defaults to all that are available.
 * Classifier scores are cached (benchmark/.cache/scores.json), so re-runs are instant.
 *
 * "Detected" = the prompt would be stopped or held (BLOCK / REVIEW), the same
 * bar the internal benchmark uses. Reports precision, recall, F1, false-alarm
 * rate and latency per dataset.
 */

import fs   from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { analyzeForInjection } from '../backend/lib/promptInjectionGuard.js';
import { openScorer } from './scoreCache.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA = path.join(__dirname, '.cache', 'public.json');

if (!fs.existsSync(DATA)) {
  console.error('No dataset cache. Run: node benchmark/fetch-public.mjs');
  process.exit(1);
}
const { suites, fetchedAt } = JSON.parse(fs.readFileSync(DATA, 'utf8'));

// ── Detectors: text → Promise<boolean> ───────────────────────────────────────

const detectors = {
  rules: async text => ['BLOCK', 'REVIEW'].includes(analyzeForInjection(text).action),
};

const scorer = await openScorer();
if (scorer) {
  const { THRESHOLD, fuse } = scorer.classifier;
  detectors.classifier = async text => (await scorer.score(text)) >= THRESHOLD;
  detectors.combined   = async text => ['BLOCK', 'REVIEW'].includes(fuse(analyzeForInjection(text), { score: await scorer.score(text) }).action);
  console.log(`Classifier: ${scorer.classifier.info().model}, threshold ${THRESHOLD}`);
} else {
  console.warn('(classifier model not installed — skipping classifier/combined)');
}

const wanted = process.argv.slice(2).length ? process.argv.slice(2) : Object.keys(detectors);

// ── Scoring ───────────────────────────────────────────────────────────────────

function score(results) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (const r of results) {
    if (r.attack && r.hit) tp++;
    else if (r.attack) fn++;
    else if (r.hit) fp++;
    else tn++;
  }
  const precision = tp + fp ? tp / (tp + fp) : 1;
  const recall    = tp + fn ? tp / (tp + fn) : 1;
  return {
    tp, fp, tn, fn, precision, recall,
    f1:  precision + recall ? (2 * precision * recall) / (precision + recall) : 0,
    fpr: fp + tn ? fp / (fp + tn) : 0,
  };
}

const pct = x => `${(x * 100).toFixed(1)}%`.padStart(6);

console.log(`\nPublic benchmark — datasets fetched ${fetchedAt.slice(0, 10)}\n`);
const table = [];
for (const name of wanted) {
  const detect = detectors[name];
  if (!detect) { console.warn(`unknown detector: ${name}`); continue; }
  const all = [];
  for (const suite of suites) {
    const results = [];
    const t0 = performance.now();
    for (const c of suite.cases) results.push({ ...c, hit: await detect(c.text) });
    const ms = (performance.now() - t0) / suite.cases.length;
    const s = score(results);
    all.push(...results);
    table.push({ detector: name, suite: suite.name, n: suite.cases.length, ...s, ms });
  }
  table.push({ detector: name, suite: 'ALL', n: all.length, ...score(all), ms: NaN });
}

console.log('detector    dataset                                              n   recall  precis.   F1   false-alarm  ms/prompt');
for (const r of table) {
  console.log(
    `${r.detector.padEnd(11)} ${r.suite.padEnd(50)} ${String(r.n).padStart(5)}  ${pct(r.recall)}  ${pct(r.precision)}  ${r.f1.toFixed(3)}    ${pct(r.fpr)}     ${Number.isNaN(r.ms) ? '' : r.ms.toFixed(1)}`,
  );
}

const out = path.join(__dirname, '.cache', 'results.json');
fs.writeFileSync(out, JSON.stringify({ at: new Date().toISOString(), table }, null, 1));
await scorer?.close();
