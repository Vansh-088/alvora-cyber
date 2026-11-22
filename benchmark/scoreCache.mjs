/**
 * scoreCache.mjs — Classifier scores cached on disk, keyed by model + text, so
 * the evaluation and threshold tuning never re-run the model on the same prompt.
 */

import fs     from 'fs';
import path   from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FILE = path.join(__dirname, '.cache', 'scores.json');

export async function openScorer() {
  const classifier = await import('../backend/lib/injectionClassifier.js');
  if (!(await classifier.ready())) return null;
  const key = classifier.info().file;
  let cache = {};
  try { cache = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch { /* first run */ }
  cache[key] ??= {};
  const scores = cache[key];
  let dirty = 0;

  const save = () => { fs.mkdirSync(path.dirname(FILE), { recursive: true }); fs.writeFileSync(FILE, JSON.stringify(cache)); dirty = 0; };

  return {
    classifier,
    /** P(injection) for text (cached). */
    async score(text) {
      const h = crypto.createHash('sha1').update(text).digest('hex');
      if (scores[h] === undefined) {
        scores[h] = (await classifier.classify(text))?.score ?? 0;
        if (++dirty >= 50) save();
      }
      return scores[h];
    },
    async close() { save(); await classifier.release(); },
  };
}
