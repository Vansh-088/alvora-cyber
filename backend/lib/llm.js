/**
 * llm.js — Provider-agnostic LLM layer ("the brain")
 *
 * One call — completeJSON() — that every AI feature goes through. Behind it sits
 * an ordered chain of providers; the first one that is available and answers
 * wins. Nothing above this file knows (or cares) which model replied.
 *
 * Providers:
 *   • ollama    — LOCAL, free, private. Default first choice. Text never leaves
 *                 the machine. Auto-picks an installed model (prefers small/fast).
 *   • nvidia    — NVIDIA NIM (build.nvidia.com), OpenAI-compatible. Two models:
 *                   fast → NVIDIA_NIM_MODEL       (default meta/llama-3.1-8b-instruct)
 *                   deep → NVIDIA_NIM_DEEP_MODEL  (default Nemotron 3 Ultra 550B)
 *   • openrouter — OpenRouter (openrouter.ai), OpenAI-compatible. Deep tier only,
 *                 default Nemotron 3 Ultra's FREE endpoint. That endpoint is logged
 *                 by NVIDIA, so it never receives prompt text from real-time scans —
 *                 only the security-event details an "Explain with AI" sends.
 *   • anthropic — Claude Haiku (paid).
 *
 * Tiers:
 *   • fast — real-time paths (prompt scans, connection triage): ollama → nvidia → anthropic
 *   • deep — on-demand reasoning (explain a threat): openrouter → nvidia (Nemotron Ultra) → anthropic → ollama
 *
 * Env:
 *   OLLAMA_HOST            default http://127.0.0.1:11434
 *   ALVORA_OLLAMA_MODEL    force a specific local model (else auto-pick)
 *   NVIDIA_NIM_KEY / NVIDIA_NIM_MODEL / NVIDIA_NIM_DEEP_MODEL
 *   OPENROUTER_KEY / OPENROUTER_DEEP_MODEL   (default nvidia/nemotron-3-ultra-550b-a55b:free)
 *   ANTHROPIC_KEY
 *   ALVORA_LLM_FAST / ALVORA_LLM_DEEP   comma-separated chain overrides, e.g. "ollama,anthropic"
 */

import os from 'os';
import { consume as rateConsume } from './rateLimiter.js';

const OLLAMA_HOST     = (process.env.OLLAMA_HOST || 'http://127.0.0.1:11434').replace(/\/$/, '');
const NIM_URL         = 'https://integrate.api.nvidia.com/v1/chat/completions';
const NIM_FAST_MODEL  = process.env.NVIDIA_NIM_MODEL      || 'meta/llama-3.1-8b-instruct';
const NIM_DEEP_MODEL  = process.env.NVIDIA_NIM_DEEP_MODEL || 'nvidia/nemotron-3-ultra-550b-a55b';
const OPENROUTER_URL  = 'https://openrouter.ai/api/v1/chat/completions';
const OPENROUTER_DEEP_MODEL = process.env.OPENROUTER_DEEP_MODEL || 'nvidia/nemotron-3-ultra-550b-a55b:free';
const ANTHROPIC_URL   = 'https://api.anthropic.com/v1/messages';
const ANTHROPIC_MODEL = 'claude-haiku-4-5';

const DEFAULT_CHAINS = {
  fast: ['ollama', 'nvidia', 'anthropic'],
  deep: ['openrouter', 'nvidia', 'anthropic', 'ollama'],
};

function chainFor(tier) {
  const override = process.env[`ALVORA_LLM_${tier.toUpperCase()}`];
  return override ? override.split(',').map(s => s.trim()).filter(Boolean) : DEFAULT_CHAINS[tier];
}

// ── Ollama discovery ──────────────────────────────────────────────────────────

// Smaller models first — the fast tier sits in front of every prompt send.
const OLLAMA_PREFERENCE = [
  /^qwen3:(0\.6|1\.7|4)b/, /^gemma3:(1|4)b/, /^llama3\.2/, /^phi4-mini/, /^qwen2\.5:(0\.5|1\.5|3|7)b/,
  /^gemma4/, /^qwen3/, /^gemma3/, /^llama3\.1:8b/, /^mistral/,
];

// Models bigger than this share of RAM would swap the whole machine — skip them.
const MAX_MODEL_BYTES = os.totalmem() * 0.4;

let ollamaCache = { at: 0, available: false, models: [], model: null };

async function ollamaInfo({ force = false } = {}) {
  if (!force && Date.now() - ollamaCache.at < 30_000) return ollamaCache;
  let installed = [];   // [{ name, size }]
  let available = false;
  try {
    const res = await fetch(`${OLLAMA_HOST}/api/tags`, { signal: AbortSignal.timeout(1500) });
    if (res.ok) {
      installed = ((await res.json()).models ?? [])
        .filter(m => !/embed/i.test(m.name))
        .map(m => ({ name: m.name, size: m.size ?? 0 }));
      available = installed.length > 0;
    }
  } catch { /* Ollama not running */ }
  const models = installed.map(m => m.name);

  let model = process.env.ALVORA_OLLAMA_MODEL || null;
  if (!model) {
    // Smallest model of the most-preferred family that fits in memory
    const fits = installed.filter(m => m.size <= MAX_MODEL_BYTES).sort((a, b) => a.size - b.size);
    for (const rx of OLLAMA_PREFERENCE) {
      model = fits.find(m => rx.test(m.name))?.name;
      if (model) break;
    }
    model = model ?? fits[0]?.name ?? null;
  }
  ollamaCache = { at: Date.now(), available: available && !!model, models, model };
  return ollamaCache;
}

// ── Provider calls — each returns { text, model, usage } or throws ─────────────

async function callOllama({ system, user, maxTokens, timeoutMs, schema }) {
  const info = await ollamaInfo();
  if (!info.available) throw new Error('ollama_unavailable');

  const body = {
    model:      info.model,
    stream:     false,
    // A JSON schema makes Ollama constrain decoding to exactly these fields —
    // small models otherwise drift (e.g. echo the input back).
    format:     schema ?? 'json',
    think:      false,
    keep_alive: '15m',
    options:    { temperature: 0.1, num_predict: maxTokens },
    messages:   [{ role: 'system', content: system }, { role: 'user', content: user }],
  };
  let res = await fetch(`${OLLAMA_HOST}/api/chat`, {
    method: 'POST', body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs),
  });
  // Older models reject the `think` flag — retry without it
  if (res.status === 400) {
    const err = await res.text().catch(() => '');
    if (!/think/i.test(err)) throw new Error(`ollama HTTP 400 ${err.slice(0, 120)}`);
    delete body.think;
    res = await fetch(`${OLLAMA_HOST}/api/chat`, {
      method: 'POST', body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs),
    });
  }
  if (!res.ok) throw new Error(`ollama HTTP ${res.status}`);
  const json = await res.json();
  return {
    text:  json.message?.content ?? '',
    model: info.model,
    usage: { input_tokens: json.prompt_eval_count, output_tokens: json.eval_count },
  };
}

async function callNvidia({ system, user, maxTokens, timeoutMs, tier }) {
  const key = process.env.NVIDIA_NIM_KEY;
  if (!key) throw new Error('nvidia_no_key');
  if (!rateConsume('nvidia', a => console.warn(`[LLM:nvidia] ${a.pct}% of per-minute budget used`)).allowed) {
    throw new Error('nvidia_rate_limited');
  }
  const model = tier === 'deep' ? NIM_DEEP_MODEL : NIM_FAST_MODEL;
  const res = await fetch(NIM_URL, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json', 'Accept': 'application/json' },
    signal: AbortSignal.timeout(timeoutMs),
    body: JSON.stringify({
      model,
      temperature: 0.1,
      max_tokens:  maxTokens,
      stream:      false,
      messages:    [{ role: 'system', content: system }, { role: 'user', content: user }],
    }),
  });
  if (!res.ok) throw new Error(`nvidia HTTP ${res.status} ${(await res.text().catch(() => '')).slice(0, 160)}`);
  const json = await res.json();
  const msg  = json.choices?.[0]?.message ?? {};
  // Reasoning models (Nemotron) may put the answer after a thinking trace
  return { text: msg.content || msg.reasoning_content || '', model: json.model ?? model, usage: json.usage ?? null };
}

async function callOpenRouter({ system, user, maxTokens, timeoutMs, tier }) {
  const key = process.env.OPENROUTER_KEY;
  if (!key) throw new Error('openrouter_no_key');
  // Deep tier only — see the privacy note in the header
  if (tier !== 'deep') throw new Error('openrouter_unavailable');
  if (!rateConsume('openrouter', a => console.warn(`[LLM:openrouter] ${a.pct}% of per-minute budget used`)).allowed) {
    throw new Error('openrouter_rate_limited');
  }
  const res = await fetch(OPENROUTER_URL, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${key}`,
      'Content-Type':  'application/json',
      'X-Title':       'Alvora Cyber',
    },
    signal: AbortSignal.timeout(timeoutMs),
    body: JSON.stringify({
      model:       OPENROUTER_DEEP_MODEL,
      temperature: 0.1,
      // Reasoning models spend tokens thinking first — leave room for the answer
      max_tokens:  Math.max(maxTokens, 4000),
      reasoning:   { effort: 'low', exclude: true },   // think briefly; return only the answer
      messages:    [{ role: 'system', content: system }, { role: 'user', content: user }],
    }),
  });
  if (!res.ok) throw new Error(`openrouter HTTP ${res.status} ${(await res.text().catch(() => '')).slice(0, 160)}`);
  const json = await res.json();
  if (json.error) throw new Error(`openrouter ${json.error.code ?? ''} ${json.error.message ?? ''}`.trim());
  const msg = json.choices?.[0]?.message ?? {};
  return { text: msg.content || msg.reasoning || '', model: json.model ?? OPENROUTER_DEEP_MODEL, usage: json.usage ?? null };
}

async function callAnthropic({ system, user, maxTokens, timeoutMs }) {
  const key = process.env.ANTHROPIC_KEY;
  if (!key) throw new Error('anthropic_no_key');
  const gate = rateConsume('anthropic', a =>
    console.warn(`[LLM:anthropic] ⚠ ${a.pct}% of daily budget used (${a.used}/${a.max})`));
  if (!gate.allowed) throw new Error('anthropic_rate_limited');

  const res = await fetch(ANTHROPIC_URL, {
    method: 'POST',
    headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
    signal: AbortSignal.timeout(timeoutMs),
    body: JSON.stringify({
      model:      ANTHROPIC_MODEL,
      max_tokens: maxTokens,
      system:     [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }],
      messages:   [{ role: 'user', content: user }],
    }),
  });
  if (!res.ok) throw new Error(`anthropic HTTP ${res.status} ${(await res.text().catch(() => '')).slice(0, 160)}`);
  const json = await res.json();
  return {
    text:  (json.content ?? []).filter(b => b.type === 'text').map(b => b.text).join(''),
    model: ANTHROPIC_MODEL,
    usage: json.usage ?? null,
  };
}

const PROVIDERS = { ollama: callOllama, nvidia: callNvidia, openrouter: callOpenRouter, anthropic: callAnthropic };

// ── JSON extraction (models wrap JSON in fences / thinking traces) ─────────────

export function extractJSON(text) {
  if (!text) return null;
  const cleaned = text
    .replace(/<think>[\s\S]*?<\/think>/gi, '')
    .replace(/```(?:json)?/gi, '')
    .trim();
  try { return JSON.parse(cleaned); } catch { /* fall through */ }
  const match = cleaned.match(/\{[\s\S]*\}/);
  if (!match) return null;
  try { return JSON.parse(match[0]); } catch { return null; }
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Ask the first available provider in the tier's chain for a JSON answer.
 * @param {object} [opts.schema]  JSON schema for the answer (enforced by Ollama; others rely on the prompt)
 * @returns {{ data, provider, model, usage, ms } | null}  null if every provider failed
 */
export async function completeJSON({ tier = 'fast', system, user, maxTokens = 300, timeoutMs, schema }) {
  const timeout = timeoutMs ?? (tier === 'deep' ? 90_000 : 30_000);
  for (const name of chainFor(tier)) {
    const call = PROVIDERS[name];
    if (!call) continue;
    const started = Date.now();
    try {
      const r    = await call({ system, user, maxTokens, timeoutMs: timeout, tier, schema });
      const data = extractJSON(r.text);
      if (!data) { console.error(`[LLM:${name}] unparseable:`, (r.text || '').slice(0, 120)); continue; }
      return { data, provider: name, model: r.model, usage: r.usage, ms: Date.now() - started };
    } catch (err) {
      const quiet = /unavailable|no_key/.test(err.message);
      if (!quiet) console.error(`[LLM:${name}]`, err.name === 'TimeoutError' ? 'timed out' : err.message);
    }
  }
  return null;
}

// ── Conversation (Alvora AI) ──────────────────────────────────────────────────

/**
 * Multi-turn chat in plain text (not JSON).
 *   mode 'private' — local Ollama only, streamed token by token. Never falls
 *                    back to a cloud model: the user chose privacy.
 *   mode 'cloud'   — the deep chain's cloud providers (OpenRouter → NVIDIA →
 *                    Anthropic); answers arrive in one piece.
 * @param {(text: string) => void} onDelta  receives text as it is produced
 * @returns {Promise<{ provider, model } | { error }>}
 */
export async function chat({ mode = 'private', system, messages, onDelta, signal, maxTokens = 900 }) {
  if (mode === 'private') {
    const info = await ollamaInfo({ force: true });
    if (!info.available) return { error: 'local_unavailable' };
    // Reasoning models (e.g. qwen3) reason regardless. With `think: true` Ollama
    // returns that reasoning in a separate field, which we never show; with
    // `think: false` some builds mix it into the answer untagged. The budget
    // covers reasoning plus the answer so replies aren't cut short.
    const body = {
      model: info.model, stream: true, think: true, keep_alive: '15m',
      options: { temperature: 0.4, num_predict: maxTokens + 2048, num_ctx: 8192 },
      messages: [{ role: 'system', content: system }, ...messages],
    };
    let res = await fetch(`${OLLAMA_HOST}/api/chat`, { method: 'POST', body: JSON.stringify(body), signal });
    if (res.status === 400) {   // models without reasoning support reject `think`
      delete body.think;
      res = await fetch(`${OLLAMA_HOST}/api/chat`, { method: 'POST', body: JSON.stringify(body), signal });
    }
    if (!res.ok) return { error: `local_http_${res.status}` };

    // Reasoning must never reach the user. Models that inline it (with or
    // without an opening <think> tag) are handled too: when a closing tag shows
    // up, everything sent so far was reasoning — reset and keep what follows.
    const decoder = new TextDecoder();
    let buf = '', sent = '', thinkingSignalled = false;
    for await (const chunk of res.body) {
      buf += decoder.decode(chunk, { stream: true });
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        let msg;
        try { msg = JSON.parse(line).message ?? {}; } catch { continue; }
        if (msg.thinking && !thinkingSignalled && !sent) {
          thinkingSignalled = true;
          onDelta(null, { thinking: true });
        }
        const piece = msg.content ?? '';
        if (!piece) continue;
        const combined = sent + piece;
        const close = combined.lastIndexOf('</think>');
        if (close >= 0) {
          sent = combined.slice(close + '</think>'.length).replace(/^\s+/, '');
          onDelta(null, { reset: true });
          if (sent) onDelta(sent);
          continue;
        }
        let clean = piece.replace(/<think>/g, '');
        if (!sent) clean = clean.replace(/^\s+/, '');   // no blank lines before the answer
        sent += clean;
        if (clean) onDelta(clean);
      }
    }
    return { provider: 'ollama', model: info.model };
  }

  // Cloud: flatten the conversation into one request for the deep providers
  const transcript = messages.map(m => `${m.role === 'user' ? 'User' : 'Alvora AI'}: ${m.content}`).join('\n\n');
  const user = `${transcript}\n\nAlvora AI:`;
  for (const name of chainFor('deep').filter(n => n !== 'ollama')) {
    const call = PROVIDERS[name];
    try {
      const r = await call({ system, user, maxTokens, timeoutMs: 90_000, tier: 'deep' });
      const text = (r.text || '').replace(/<think>[\s\S]*?<\/think>/gi, '').trim();
      if (!text) continue;
      onDelta(text);
      return { provider: name, model: r.model };
    } catch (err) {
      if (!/unavailable|no_key/.test(err.message)) console.error(`[LLM:${name}] chat:`, err.message);
    }
  }
  return { error: 'cloud_unavailable' };
}

/** True if at least one provider in the tier could answer right now. */
export async function isAvailable(tier = 'fast') {
  for (const name of chainFor(tier)) {
    if (name === 'ollama' && (await ollamaInfo()).available) return true;
    if (name === 'nvidia' && process.env.NVIDIA_NIM_KEY) return true;
    if (name === 'openrouter' && process.env.OPENROUTER_KEY && tier === 'deep') return true;
    if (name === 'anthropic' && process.env.ANTHROPIC_KEY) return true;
  }
  return false;
}

/** Snapshot for the settings UI / integrations endpoint. */
export async function status() {
  const o = await ollamaInfo({ force: true });
  const providers = {
    ollama:    { available: o.available, host: OLLAMA_HOST, model: o.model, installed: o.models, local: true },
    nvidia:    { available: !!process.env.NVIDIA_NIM_KEY, model: NIM_FAST_MODEL, deepModel: NIM_DEEP_MODEL, local: false },
    openrouter: { available: !!process.env.OPENROUTER_KEY, model: OPENROUTER_DEEP_MODEL, deepModel: OPENROUTER_DEEP_MODEL, deepOnly: true, local: false },
    anthropic: { available: !!process.env.ANTHROPIC_KEY, model: ANTHROPIC_MODEL, local: false },
  };
  const active = tier => chainFor(tier).find(n => providers[n]?.available && !(tier === 'fast' && providers[n].deepOnly)) ?? null;
  return {
    providers,
    chains: { fast: chainFor('fast'), deep: chainFor('deep') },
    active: { fast: active('fast'), deep: active('deep') },
  };
}
