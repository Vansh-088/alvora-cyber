/**
 * AlvoraAI — chat with a security advisor that knows this Mac.
 *
 * Private mode runs on the local model (nothing leaves the Mac); Cloud mode
 * uses the configured cloud model with personal info hidden first. Replies
 * stream in; the conversation lives only in memory for this app session.
 */

import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { Sparkles, Send, Square, RotateCcw, Lock, Cloud, Loader2, ShieldCheck } from 'lucide-react';

const API_BASE = (typeof window !== 'undefined' && window.location.protocol === 'file:')
  ? 'http://localhost:3001/api'
  : '/api';

const SUGGESTIONS = [
  'How can I make my Mac more secure?',
  'Explain my most recent alert',
  'Is it safe to use public Wi-Fi?',
  'How do I spot a phishing email?',
];

// Survives switching tabs; cleared when the app quits
let savedConversation = [];

// ─── Minimal, safe markdown (bold, italics, code, lists, paragraphs) ──────────

function inline(text, keyBase) {
  const parts = [];
  const rx = /(\*\*[^*]+\*\*|`[^`]+`|\*[^*\s][^*]*\*)/g;
  let last = 0, m, i = 0;
  while ((m = rx.exec(text))) {
    if (m.index > last) parts.push(text.slice(last, m.index));
    const t = m[0];
    const k = `${keyBase}-${i++}`;
    if (t.startsWith('**'))     parts.push(<strong key={k} className="text-white font-semibold">{t.slice(2, -2)}</strong>);
    else if (t.startsWith('`')) parts.push(<code key={k} className="px-1 py-0.5 rounded bg-white/10 text-[11px] font-mono">{t.slice(1, -1)}</code>);
    else                        parts.push(<em key={k}>{t.slice(1, -1)}</em>);
    last = m.index + t.length;
  }
  if (last < text.length) parts.push(text.slice(last));
  // Unbalanced markers the model left behind ("network**") aren't formatting
  return parts.map(p => (typeof p === 'string' ? p.replace(/\*\*|`/g, '') : p));
}

// Small models sometimes append "(Word count: 120)" — never useful to the reader
const tidy = text => text.replace(/^\s*\*?\(?\s*(word count:?\s*\d+|\d+\s+words)\s*\)?\*?\s*$/gim, '').trimEnd();

function Markdown({ text }) {
  const blocks = [];
  let list = null;
  tidy(text).split('\n').forEach((raw, idx) => {
    const line = raw.trimEnd();
    const ol = line.match(/^\s*(\d+)[.)]\s+(.*)$/);
    const ul = line.match(/^\s*[-*•]\s+(.*)$/);
    if (ol || ul) {
      const type = ol ? 'ol' : 'ul';
      if (!list || list.type !== type) { list = { type, items: [] }; blocks.push(list); }
      list.items.push((ol ? ol[2] : ul[1]));
      return;
    }
    list = null;
    if (!line.trim()) { blocks.push({ type: 'gap' }); return; }
    const h = line.match(/^#{1,4}\s+(.*)$/);
    blocks.push({ type: h ? 'h' : 'p', text: h ? h[1] : line, idx });
  });

  return (
    <div className="space-y-2 text-[13px] leading-relaxed text-white/80">
      {blocks.map((b, i) => {
        if (b.type === 'gap') return null;
        if (b.type === 'h') return <p key={i} className="text-white font-semibold">{inline(b.text, i)}</p>;
        if (b.type === 'p') return <p key={i}>{inline(b.text, i)}</p>;
        const Tag = b.type;
        return (
          <Tag key={i} className={`${b.type === 'ol' ? 'list-decimal' : 'list-disc'} pl-5 space-y-1 marker:text-cobalt/70`}>
            {b.items.map((it, j) => <li key={j}>{inline(it, `${i}-${j}`)}</li>)}
          </Tag>
        );
      })}
    </div>
  );
}

// ─── Screen ───────────────────────────────────────────────────────────────────

export default function AlvoraAI() {
  const [messages, setMessages] = useState(savedConversation);   // [{ role, content, meta? }]
  const [input,    setInput]    = useState('');
  const [mode,     setMode]     = useState('private');
  const [status,   setStatus]   = useState(null);
  const [busy,     setBusy]     = useState(false);
  const [thinking, setThinking] = useState(false);
  const [elapsed,  setElapsed]  = useState(0);
  const [error,    setError]    = useState('');
  const abortRef  = useRef(null);
  const listRef   = useRef(null);
  const inputRef  = useRef(null);

  useEffect(() => { savedConversation = messages; }, [messages]);

  useEffect(() => {
    fetch(`${API_BASE}/assistant/status`).then(r => r.json()).then(setStatus).catch(() => setStatus(null));
  }, []);

  // Keep the newest text in view
  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: 'smooth' });
  }, [messages, thinking]);

  // Elapsed-time counter while waiting, so a slow local model never looks frozen
  useEffect(() => {
    if (!busy) return;
    setElapsed(0);
    const t0 = Date.now();
    const t = setInterval(() => setElapsed(Math.round((Date.now() - t0) / 1000)), 1000);
    return () => clearInterval(t);
  }, [busy]);

  useEffect(() => () => abortRef.current?.abort(), []);   // leaving the screen stops the request

  async function send(text) {
    const question = (text ?? input).trim();
    if (!question || busy) return;
    setError('');
    setInput('');
    const history = [...messages, { role: 'user', content: question }];
    setMessages([...history, { role: 'assistant', content: '' }]);
    setBusy(true);
    setThinking(false);

    const controller = new AbortController();
    abortRef.current = controller;
    let answer = '';
    const update = (patch) => setMessages(prev => {
      const next = [...prev];
      next[next.length - 1] = { ...next[next.length - 1], ...patch };
      return next;
    });

    try {
      const res = await fetch(`${API_BASE}/assistant/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode, messages: history.map(({ role, content }) => ({ role, content })) }),
        signal: controller.signal,
      });
      if (!res.ok || !res.body) throw new Error((await res.json().catch(() => ({}))).error || 'Alvora AI isn\'t responding.');

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let nl;
        while ((nl = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, nl).trim();
          buf = buf.slice(nl + 1);
          if (!line) continue;
          let evt;
          try { evt = JSON.parse(line); } catch { continue; }
          if (evt.thinking)      setThinking(true);
          else if (evt.reset)    { answer = ''; update({ content: '' }); }
          else if (evt.notice)   update({ notice: evt.notice });
          else if (evt.delta)    { setThinking(false); answer += evt.delta; update({ content: answer }); }
          else if (evt.error)    setError(evt.error);
          else if (evt.done)     update({ meta: { provider: evt.provider, model: evt.model } });
        }
      }
    } catch (err) {
      if (err.name !== 'AbortError') setError(err.message || 'Alvora AI isn\'t responding.');
    } finally {
      setBusy(false);
      setThinking(false);
      abortRef.current = null;
      // Drop an empty reply bubble (stopped or failed before any text)
      setMessages(prev => (prev.at(-1)?.role === 'assistant' && !prev.at(-1).content ? prev.slice(0, -1) : prev));
      inputRef.current?.focus();
    }
  }

  function stop() { abortRef.current?.abort(); }

  function newChat() {
    stop();
    setMessages([]);
    setError('');
  }

  const privateOk = status?.private?.available;
  const cloudOk   = status?.cloud?.available;
  const modeReady = mode === 'private' ? privateOk : cloudOk;

  return (
    <motion.div
      key="assistant"
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="flex flex-col w-full h-full"
    >
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-6 pt-6 pb-4 border-b border-white/5">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-cobalt/15 border border-cobalt/30 flex items-center justify-center">
            <Sparkles className="w-5 h-5 text-cobalt" />
          </div>
          <div>
            <h2 className="text-base font-bold text-white leading-tight">Alvora AI</h2>
            <p className="text-[11px] text-slate/50">Security advice based on your Mac's current status</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex rounded-lg border border-white/10 overflow-hidden text-[11px]" role="radiogroup" aria-label="Where Alvora AI runs">
            <button
              role="radio" aria-checked={mode === 'private'}
              onClick={() => setMode('private')} disabled={busy}
              className={`flex items-center gap-1.5 px-3 py-1.5 whitespace-nowrap transition-colors ${mode === 'private' ? 'bg-cobalt/15 text-cobalt' : 'text-slate/50 hover:text-white/80'}`}
              title={privateOk ? `Runs on this Mac (${status.private.model}). Nothing leaves your computer.` : 'The local AI (Ollama) isn\'t running'}
            >
              <Lock className="w-3.5 h-3.5" /> Private
            </button>
            <button
              role="radio" aria-checked={mode === 'cloud'}
              onClick={() => setMode('cloud')} disabled={busy || !cloudOk}
              className={`flex items-center gap-1.5 px-3 py-1.5 whitespace-nowrap border-l border-white/10 transition-colors disabled:opacity-40 ${mode === 'cloud' ? 'bg-cobalt/15 text-cobalt' : 'text-slate/50 hover:text-white/80'}`}
              title={cloudOk ? `Faster, more capable cloud model (${status.cloud.model})` : 'Add an OpenRouter or NVIDIA key in Settings to enable'}
            >
              <Cloud className="w-3.5 h-3.5" /> Cloud
            </button>
          </div>
          <button
            onClick={newChat} disabled={!messages.length}
            className="flex items-center gap-1.5 px-3 py-1.5 whitespace-nowrap rounded-lg border border-white/10 text-[11px] text-slate/60 hover:text-white/80 hover:bg-white/5 disabled:opacity-30 transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" /> New chat
          </button>
        </div>
      </div>

      {/* Mode note */}
      <div className="px-6 py-2 text-[11px] border-b border-white/5 flex items-center gap-1.5 text-slate/45">
        {mode === 'private'
          ? <><Lock className="w-3 h-3" /> Private: runs on this Mac{privateOk ? ` (${status.private.model})` : ''}. Nothing leaves your computer. Replies can take up to a minute.</>
          : <><Cloud className="w-3 h-3" /> Cloud: your questions and a summary of your security status go to {status?.cloud?.provider ?? 'the cloud provider'}. Personal info is hidden first.</>}
      </div>

      {/* Conversation */}
      <div ref={listRef} className="flex-1 overflow-y-auto px-6 py-5 space-y-5">
        {messages.length === 0 && (
          <div className="h-full flex flex-col items-center justify-center text-center gap-5">
            <ShieldCheck className="w-10 h-10 text-cobalt/60" />
            <div>
              <p className="text-white/90 text-sm font-medium">Ask anything about keeping your Mac and accounts safe</p>
              <p className="text-slate/50 text-xs mt-1">Answers use your real Security Check results and recent alerts.</p>
            </div>
            <div className="grid grid-cols-2 gap-2 max-w-lg w-full">
              {SUGGESTIONS.map(s => (
                <button
                  key={s}
                  onClick={() => send(s)}
                  disabled={!modeReady}
                  className="text-left text-xs text-white/75 bg-black/30 hover:bg-black/40 border border-white/5 hover:border-cobalt/30 rounded-xl px-4 py-3 transition-colors disabled:opacity-40"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((m, i) => (
          m.role === 'user' ? (
            <div key={i} className="flex justify-end">
              <div className="max-w-[75%] bg-cobalt/15 border border-cobalt/25 rounded-2xl rounded-br-md px-4 py-2.5 text-[13px] text-white/90 whitespace-pre-wrap">
                {m.content}
              </div>
            </div>
          ) : (
            <div key={i} className="flex gap-3">
              <div className="w-7 h-7 rounded-lg bg-cobalt/10 border border-cobalt/25 flex items-center justify-center flex-shrink-0 mt-0.5">
                <Sparkles className="w-3.5 h-3.5 text-cobalt" />
              </div>
              <div className="flex-1 min-w-0 max-w-[85%]">
                {m.notice && <p className="text-[10px] text-emerald-400/70 mb-1.5">{m.notice}</p>}
                {m.content
                  ? <Markdown text={m.content} />
                  : (busy && i === messages.length - 1) && (
                    <div className="flex items-center gap-2 text-xs text-slate/50 py-1">
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      {thinking ? 'Thinking through your Mac\'s security' : 'Reading your security status'}… {elapsed > 2 && `${elapsed}s`}
                    </div>
                  )}
                {m.meta && (
                  <p className="text-[10px] text-slate/30 mt-2 font-mono">
                    {m.meta.provider === 'ollama' ? 'on this Mac' : m.meta.provider} · {m.meta.model}
                  </p>
                )}
              </div>
            </div>
          )
        ))}

        {error && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-lg px-4 py-2.5 text-xs text-red-300">{error}</div>
        )}
      </div>

      {/* Composer */}
      <div className="px-6 pb-5 pt-3 border-t border-white/5">
        {!modeReady && status && (
          <p className="text-[11px] text-yellow-400/80 mb-2">
            {mode === 'private'
              ? 'The private AI isn\'t running. Open the Ollama app, or switch to Cloud.'
              : 'No cloud AI is set up. Add an OpenRouter or NVIDIA key in Settings.'}
          </p>
        )}
        <div className="flex items-end gap-2 bg-black/30 border border-white/10 focus-within:border-cobalt/40 rounded-xl px-3 py-2 transition-colors">
          <textarea
            ref={inputRef}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) { e.preventDefault(); send(); }
            }}
            rows={1}
            maxLength={4000}
            placeholder="Ask Alvora AI about your security…"
            aria-label="Message Alvora AI"
            className="flex-1 bg-transparent resize-none text-[13px] text-white placeholder:text-slate/40 focus:outline-none max-h-32 py-1.5"
          />
          {busy ? (
            <button onClick={stop} aria-label="Stop" className="p-2 rounded-lg bg-white/10 hover:bg-white/15 text-white/80 transition-colors">
              <Square className="w-4 h-4" />
            </button>
          ) : (
            <button
              onClick={() => send()} disabled={!input.trim() || !modeReady} aria-label="Send"
              className="p-2 rounded-lg bg-cobalt text-obsidian hover:bg-cobalt/90 disabled:opacity-30 transition-colors"
            >
              <Send className="w-4 h-4" />
            </button>
          )}
        </div>
        <p className="text-[10px] text-slate/30 mt-2">
          Alvora AI can make mistakes and can't change settings for you. Never paste passwords or card numbers.
        </p>
      </div>
    </motion.div>
  );
}
