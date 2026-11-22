/**
 * fetch-public.mjs — Download public, labelled prompt-attack datasets for an
 * honest benchmark (data the detectors were NOT written against).
 *
 *   node benchmark/fetch-public.mjs        → benchmark/.cache/public.json
 *
 * Sources (via the Hugging Face datasets-server API, no Python needed):
 *   • deepset/prompt-injections (test)           — injections vs benign      (Apache-2.0)
 *   • xTRam1/safe-guard-prompt-injection (test)  — injections vs benign
 *   • TrustAIRLab/in-the-wild-jailbreak-prompts  — real jailbreaks collected from
 *     Reddit/Discord/websites vs regular prompts from the same communities (MIT).
 *     Deterministic evenly-spaced sample so runs are comparable.
 */

import fs   from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, '.cache', 'public.json');
const API = 'https://datasets-server.huggingface.co/rows';
const SAMPLE_PER_CLASS = 400;

async function rows(dataset, config, split, offset, length) {
  const url = `${API}?dataset=${encodeURIComponent(dataset)}&config=${config}&split=${split}&offset=${offset}&length=${length}`;
  for (let attempt = 1; attempt <= 6; attempt++) {
    const res = await fetch(url, { signal: AbortSignal.timeout(30_000) });
    if (res.ok) return (await res.json()).rows.map(r => r.row);
    if (attempt === 6) throw new Error(`${dataset} ${config}: HTTP ${res.status}`);
    // Rate limited → honour Retry-After, else back off exponentially
    const wait = (parseInt(res.headers.get('retry-after'), 10) || 2 ** attempt * 2) * 1000;
    console.log(`  (HTTP ${res.status}, retrying in ${Math.round(wait / 1000)}s)`);
    await new Promise(r => setTimeout(r, wait));
  }
}

async function all(dataset, config, split, total) {
  const out = [];
  for (let off = 0; off < total; off += 100) out.push(...await rows(dataset, config, split, off, Math.min(100, total - off)));
  return out;
}

/** Deterministic sample: n rows taken as evenly spaced pages of 50 across the split. */
async function spaced(dataset, config, split, total, n) {
  const PAGE = 50;
  const pages = Math.ceil(n / PAGE);
  const step = total / pages;
  const out = [];
  for (let i = 0; i < pages; i++) out.push(...await rows(dataset, config, split, Math.floor(i * step), Math.min(PAGE, n - out.length)));
  return out;
}

async function sizeOf(dataset, config) {
  const res = await fetch(`https://datasets-server.huggingface.co/size?dataset=${encodeURIComponent(dataset)}&config=${config}`);
  return (await res.json()).size.config.num_rows;
}

const suites = [];

console.log('deepset/prompt-injections …');
suites.push({
  id: 'deepset', name: 'deepset prompt-injections (test)', kind: 'injection',
  cases: (await all('deepset/prompt-injections', 'default', 'test', 116)).map(r => ({ text: r.text, attack: r.label === 1 })),
});

console.log('xTRam1/safe-guard-prompt-injection …');
suites.push({
  id: 'safeguard', name: 'SafeGuard prompt-injection (test)', kind: 'injection',
  cases: (await all('xTRam1/safe-guard-prompt-injection', 'default', 'test', 2060)).map(r => ({ text: r.text, attack: r.label === 1 })),
});

console.log('TrustAIRLab in-the-wild jailbreaks (sampled) …');
const jbTotal  = await sizeOf('TrustAIRLab/in-the-wild-jailbreak-prompts', 'jailbreak_2023_12_25');
const regTotal = await sizeOf('TrustAIRLab/in-the-wild-jailbreak-prompts', 'regular_2023_12_25');
const jb  = await spaced('TrustAIRLab/in-the-wild-jailbreak-prompts', 'jailbreak_2023_12_25', 'train', jbTotal, SAMPLE_PER_CLASS);
const reg = await spaced('TrustAIRLab/in-the-wild-jailbreak-prompts', 'regular_2023_12_25', 'train', regTotal, SAMPLE_PER_CLASS);
suites.push({
  id: 'in-the-wild', name: 'In-the-wild jailbreaks vs regular prompts (sample)', kind: 'jailbreak',
  cases: [
    ...jb.map(r => ({ text: r.prompt, attack: true })),
    ...reg.map(r => ({ text: r.prompt, attack: false })),
  ],
});

for (const s of suites) s.cases = s.cases.filter(c => typeof c.text === 'string' && c.text.trim());
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify({ fetchedAt: new Date().toISOString(), suites }, null, 1));
for (const s of suites) {
  const pos = s.cases.filter(c => c.attack).length;
  console.log(`  ${s.name}: ${s.cases.length} (${pos} attacks, ${s.cases.length - pos} benign)`);
}
console.log(`→ ${path.relative(process.cwd(), OUT)}`);

// ── Separate tuning set (threshold selection) — never overlaps the test suites ──
console.log('Tuning set: deepset train + SafeGuard train + in-the-wild May-2023 snapshot …');
const testTexts = new Set(suites.flatMap(s => s.cases.map(c => c.text.trim())));
const tune = [
  ...(await all('deepset/prompt-injections', 'default', 'train', 546)).map(r => ({ text: r.text, attack: r.label === 1, source: 'deepset' })),
  ...(await spaced('xTRam1/safe-guard-prompt-injection', 'default', 'train', 8236, 600)).map(r => ({ text: r.text, attack: r.label === 1, source: 'safeguard' })),
  ...(await spaced('TrustAIRLab/in-the-wild-jailbreak-prompts', 'jailbreak_2023_05_07', 'train',
        await sizeOf('TrustAIRLab/in-the-wild-jailbreak-prompts', 'jailbreak_2023_05_07'), 300)).map(r => ({ text: r.prompt, attack: true, source: 'in-the-wild' })),
  ...(await spaced('TrustAIRLab/in-the-wild-jailbreak-prompts', 'regular_2023_05_07', 'train',
        await sizeOf('TrustAIRLab/in-the-wild-jailbreak-prompts', 'regular_2023_05_07'), 300)).map(r => ({ text: r.prompt, attack: false, source: 'in-the-wild' })),
].filter(c => typeof c.text === 'string' && c.text.trim() && !testTexts.has(c.text.trim()));
fs.writeFileSync(path.join(__dirname, '.cache', 'tune.json'), JSON.stringify({ fetchedAt: new Date().toISOString(), cases: tune }));
console.log(`  tuning cases: ${tune.length} (${tune.filter(c => c.attack).length} attacks) — overlap with test removed`);
