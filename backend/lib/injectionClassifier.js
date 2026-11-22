/**
 * injectionClassifier.js — On-device ML prompt-injection detector
 *
 * Model: ProtectAI deberta-v3-base-prompt-injection-v2 (Apache-2.0), quantized
 * to int8 (244 MB, ~3× smaller than fp32). Runs fully locally via
 * onnxruntime-node — prompts never leave the machine.
 *
 * The rule engine catches known phrasings; this catches paraphrases and
 * indirect injections the rules miss. Long texts are scanned as overlapping
 * 512-token windows so an injection buried at the end of a long paste still
 * counts (score = the most suspicious window).
 *
 * Model files live in <data dir>/models/prompt-injection-v2/ (installed by
 * scripts/install-classifier.mjs). If they're missing, ready() is false and
 * the scan pipeline simply runs without this layer.
 */

import fs   from 'fs';
import os   from 'os';
import path from 'path';

const DATA_DIR = process.env.ALVORA_DATA_DIR || path.join(os.homedir(), '.alvora-cyber');
// Desktop app data dir first, then the shared dev/CLI location — one install serves both
const MODEL_DIRS = [
  process.env.ALVORA_CLASSIFIER_DIR,
  path.join(DATA_DIR, 'models', 'prompt-injection-v2'),
  path.join(os.homedir(), '.alvora-cyber', 'models', 'prompt-injection-v2'),
].filter(Boolean);
const MODEL_DIR = MODEL_DIRS.find(d => fs.existsSync(path.join(d, 'tokenizer.json'))) ?? MODEL_DIRS[1];

const MAX_TOKENS  = 512;          // model limit, incl. [CLS]/[SEP]
const WINDOW      = MAX_TOKENS - 2;
const STRIDE      = 384;          // windows overlap by 126 tokens
const MAX_WINDOWS = 3;            // start, middle, end — ~0.5 s per window on Apple Silicon
const CLS = 1, SEP = 2, PAD = 0;

// Decision threshold on P(injection). Chosen by benchmark/tune-threshold.mjs on
// a tuning set disjoint from the evaluation data: the most conservative value
// within 0.01 F1 of the best, with ≤1% false alarms on clean-label prompts.
// (Scores are near-bimodal, so low cut-offs only catch borderline attacks.)
export const THRESHOLD = parseFloat(process.env.ALVORA_CLASSIFIER_THRESHOLD) || 0.1;

let loading = null;
let model   = null;   // { session, tokenizer, ort, file }
let loadError = null;

function modelFile() {
  for (const f of ['model.int8.onnx', 'model.onnx']) {
    const p = path.join(MODEL_DIR, f);
    if (fs.existsSync(p)) return p;
  }
  return null;
}

async function load() {
  if (model || loadError) return model;
  if (!loading) {
    loading = (async () => {
      const file = modelFile();
      if (!file) throw new Error(`model not installed (${MODEL_DIR})`);
      const [ort, { Tokenizer }] = await Promise.all([import('onnxruntime-node'), import('@huggingface/tokenizers')]);
      const tokenizer = new Tokenizer(
        JSON.parse(fs.readFileSync(path.join(MODEL_DIR, 'tokenizer.json'), 'utf8')),
        JSON.parse(fs.readFileSync(path.join(MODEL_DIR, 'tokenizer_config.json'), 'utf8')),
      );
      const session = await ort.InferenceSession.create(file, {
        intraOpNumThreads: 2,               // stay light — this runs beside the user's work
        graphOptimizationLevel: 'all',
      });
      model = { session, tokenizer, ort, file: path.basename(file) };
      return model;
    })().catch(err => {
      loadError = err;
      console.warn(`[Classifier] unavailable: ${err.message}`);
      return null;
    });
  }
  return loading;
}

/** Free the native session (avoids an onnxruntime crash when the process exits). */
export async function release() {
  if (model) { await model.session.release().catch(() => {}); model = null; }
}

/** True when the model is installed and loaded. */
export async function ready() {
  return !!(await load());
}

export function info() {
  return {
    installed: !!modelFile(),
    loaded:    !!model,
    file:      model?.file ?? null,
    error:     loadError?.message ?? null,
    threshold: THRESHOLD,
    model:     'protectai/deberta-v3-base-prompt-injection-v2 (int8)',
  };
}

function windowsFor(ids) {
  // ids without [CLS]/[SEP]
  if (ids.length <= WINDOW) return [ids];
  const starts = [];
  for (let s = 0; s < ids.length; s += STRIDE) {
    starts.push(s);
    if (s + WINDOW >= ids.length) break;
  }
  let chosen = starts;
  if (starts.length > MAX_WINDOWS) {
    // Keep the beginning and the end (where injections usually sit) plus evenly spaced middles
    const keep = new Set([0, starts.length - 1]);
    for (let i = 1; keep.size < MAX_WINDOWS; i++) keep.add(Math.round((i * (starts.length - 1)) / (MAX_WINDOWS - 1)));
    chosen = [...keep].sort((a, b) => a - b).map(i => starts[i]);
  }
  return chosen.map(s => ids.slice(s, s + WINDOW));
}

/**
 * @returns {Promise<{ attack: boolean, score: number, windows: number, ms: number } | null>}
 *   score = P(injection) of the most suspicious window; null if the model is unavailable.
 */
export async function classify(text) {
  const m = await load();
  if (!m || !text || !text.trim()) return null;
  const t0 = performance.now();

  const all  = m.tokenizer.encode(text, { add_special_tokens: false }).ids;
  const wins = windowsFor(all);
  const len  = Math.max(...wins.map(w => w.length)) + 2;

  const ids  = new BigInt64Array(wins.length * len);
  const mask = new BigInt64Array(wins.length * len);
  wins.forEach((w, r) => {
    const row = [CLS, ...w, SEP];
    for (let i = 0; i < len; i++) {
      ids[r * len + i]  = BigInt(i < row.length ? row[i] : PAD);
      mask[r * len + i] = i < row.length ? 1n : 0n;
    }
  });

  const out = await m.session.run({
    input_ids:      new m.ort.Tensor('int64', ids,  [wins.length, len]),
    attention_mask: new m.ort.Tensor('int64', mask, [wins.length, len]),
  });
  const logits = out.logits.data;   // [windows, 2] → (SAFE, INJECTION)
  let score = 0;
  for (let r = 0; r < wins.length; r++) {
    const a = logits[r * 2], b = logits[r * 2 + 1];
    const p = 1 / (1 + Math.exp(a - b));   // softmax over 2 classes
    if (p > score) score = p;
  }
  return { attack: score >= THRESHOLD, score, windows: wins.length, ms: performance.now() - t0 };
}

// Rules that match attack *phrasing* only. "Please ignore all previous
// instructions. Act as an SEO expert…" is a hugely common harmless template —
// when the classifier is confident the text is benign, these hits are vetoed
// down to FLAG instead of holding/blocking the prompt.
const PHRASE_ONLY_RULES = new Set(['INJ-001', 'INJ-011']);
// Tuning chose veto = threshold, i.e. when the ONLY evidence is attack-ish
// phrasing, the classifier has the final say (see benchmark/tune-threshold.mjs).
export const VETO = parseFloat(process.env.ALVORA_CLASSIFIER_VETO) || THRESHOLD;

/**
 * Combine the rule engine's verdict with the classifier's.
 * Rules are precise but narrow; the model is broad. A confident model hit
 * holds the prompt for review; when both agree, it is blocked outright. A
 * phrasing-only rule hit on text the model is sure is benign is downgraded.
 *
 * @param {{action:string, threats:Array<{id:string}>}} rules  result of analyzeForInjection()
 * @param {{score:number}|null} ml                             result of classify()
 * @param {{threshold?:number, veto?:number}} [opts]           overrides (benchmarking)
 * @returns {{ action: 'BLOCK'|'REVIEW'|'FLAG'|'ALLOW', source: 'rules'|'classifier'|'classifier-veto' }}
 */
export function fuse(rules, ml, { threshold = THRESHOLD, veto = VETO } = {}) {
  if (!ml) return { action: rules.action, source: 'rules' };
  const rank = { ALLOW: 0, FLAG: 1, REVIEW: 2, BLOCK: 3 };

  if (ml.score >= threshold) {
    const mlAction = rules.action !== 'ALLOW' ? 'BLOCK' : 'REVIEW';   // corroborated → block
    return rank[mlAction] > rank[rules.action] ? { action: mlAction, source: 'classifier' } : { action: rules.action, source: 'rules' };
  }

  const phraseOnly = rules.threats?.length && rules.threats.every(t => PHRASE_ONLY_RULES.has(t.id));
  if (phraseOnly && ml.score < veto && rank[rules.action] > rank.FLAG) {
    return { action: 'FLAG', source: 'classifier-veto' };
  }
  return { action: rules.action, source: 'rules' };
}
