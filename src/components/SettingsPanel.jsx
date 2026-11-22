/**
 * SettingsPanel — App configuration and license management
 */

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Settings, Bell, Shield, Key, Info, ExternalLink, Trash2, CheckCircle2, RefreshCw, Plug, Loader2, Database, BadgeCheck } from 'lucide-react';
import { useElectron } from '../hooks/useElectron.js';

const API_BASE = (typeof window !== 'undefined' && window.location.protocol === 'file:')
  ? 'http://localhost:3001/api'
  : '/api';

// ─── Local AI (Ollama) ────────────────────────────────────────────────────────

// No key needed — Ollama runs on this Mac, so scanned prompts never leave it.
function LocalAiRow({ ollama, onRefresh }) {
  return (
    <div className="bg-black/20 rounded-lg p-3">
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          <span className="text-sm text-white/80">Local AI (Ollama)</span>
          {ollama?.configured ? (
            <span className="text-[10px] text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3" /> Running · {ollama.model}
            </span>
          ) : (
            <span className="text-[10px] text-slate/40">Not running</span>
          )}
        </div>
        <button onClick={onRefresh} className="text-[10px] text-cobalt/70 hover:text-cobalt flex items-center gap-1">
          Re-check <RefreshCw className="w-3 h-3" />
        </button>
      </div>
      <p className="text-[10px] text-slate/40">
        {ollama?.configured
          ? 'Default brain for prompt scans and threat triage. Private and free.'
          : 'Install Ollama (ollama.com) and pull a small model, e.g. "ollama pull qwen3:4b". Alvora picks it up automatically.'}
      </p>
    </div>
  );
}

// ─── API Integrations (encrypted keys) ────────────────────────────────────────

function ApiKeysSection() {
  const { isElectron, listApiKeys, setApiKey, removeApiKey, openExternal } = useElectron();
  const [status,  setStatus]  = useState(null);   // backend integration status
  const [inputs,  setInputs]  = useState({ abuseipdb: '', nvidia: '', openrouter: '', anthropic: '', abusech: '' });
  const [busy,    setBusy]    = useState('');
  const [msg,     setMsg]     = useState('');

  const refresh = () => fetch(`${API_BASE}/integrations/status`)
    .then(r => r.json()).then(setStatus).catch(() => setStatus(null));

  useEffect(() => { refresh(); }, []);

  async function save(name) {
    const value = inputs[name]?.trim();
    if (!value) return;
    setBusy(name);
    setMsg('');
    try {
      const r = await setApiKey(name, value);
      if (r?.error) throw new Error(r.error);
      setInputs(prev => ({ ...prev, [name]: '' }));
      setMsg(r?.note || 'Saved. Restart the app for the security engine to use it.');
      await listApiKeys();
      refresh();
    } catch (e) { setMsg(e.message); }
    finally { setBusy(''); }
  }

  async function remove(name) {
    setBusy(name);
    try { await removeApiKey(name); setMsg('Removed. Restart to apply.'); refresh(); }
    finally { setBusy(''); }
  }

  const rows = [
    { id: 'abuseipdb', label: 'AbuseIPDB', desc: 'Real IP reputation checks (free — abuseipdb.com)', url: 'https://www.abuseipdb.com/account/api', window: 'hour' },
    { id: 'nvidia',    label: 'NVIDIA NIM', desc: `Deep "Explain with AI" on ${status?.nvidia?.deepModel ?? 'Nemotron Ultra'}; backup for real-time triage (free credits — build.nvidia.com)`, url: 'https://build.nvidia.com', window: 'minute' },
    { id: 'openrouter', label: 'OpenRouter', desc: `"Explain with AI" on ${status?.openrouter?.model ?? 'Nemotron 3 Ultra (free)'}. Free; NVIDIA logs what the free model receives, so Alvora only sends it security-event details — never your prompts.`, url: 'https://openrouter.ai/settings/keys', window: 'minute' },
    { id: 'abusech',   label: 'abuse.ch (MalwareBazaar)', desc: 'Optional: look up downloaded programs in a known-malware database. Only the file fingerprint (SHA-256) is sent, never the file. Free key.', url: 'https://auth.abuse.ch/', window: null },
    { id: 'anthropic', label: 'Anthropic (Claude)', desc: 'Backup AI when local and NVIDIA are unavailable (paid — console.anthropic.com)', url: 'https://console.anthropic.com/settings/keys', window: 'day' },
  ];

  if (!isElectron) {
    return (
      <Section title="API Integrations" icon={Plug}>
        <p className="text-xs text-slate/40">API keys are stored in the macOS Keychain — available in the desktop app only.</p>
      </Section>
    );
  }

  return (
    <Section title="API Integrations" icon={Plug}>
      <p className="text-xs text-slate/40 -mt-1 mb-1">
        Keys are encrypted in your device's secure storage (Keychain) — never saved as plain text.
      </p>
      <LocalAiRow ollama={status?.ollama} onRefresh={refresh} />
      {rows.map(row => {
        const configured = status?.[row.id]?.configured;
        const limit = status?.rateLimits?.[row.id];
        return (
          <div key={row.id} className="bg-black/20 rounded-lg p-3">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <span className="text-sm text-white/80">{row.label}</span>
                {configured ? (
                  <span className="text-[10px] text-emerald-400 flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" /> Connected
                  </span>
                ) : (
                  <span className="text-[10px] text-slate/40">Not connected</span>
                )}
              </div>
              <button onClick={() => openExternal(row.url)} className="text-[10px] text-cobalt/70 hover:text-cobalt flex items-center gap-1">
                Get key <ExternalLink className="w-3 h-3" />
              </button>
            </div>
            <p className="text-[10px] text-slate/40 mb-2">{row.desc}</p>
            <div className="flex gap-2">
              <input
                type="password"
                value={inputs[row.id]}
                onChange={e => setInputs(prev => ({ ...prev, [row.id]: e.target.value }))}
                placeholder={configured ? '•••••••• (replace)' : 'Paste API key'}
                className="flex-1 bg-black/40 border border-white/10 rounded-lg px-3 py-1.5 text-white text-xs focus:outline-none focus:border-cobalt/40"
              />
              <button
                onClick={() => save(row.id)}
                disabled={busy === row.id || !inputs[row.id]?.trim()}
                className="px-3 py-1.5 bg-cobalt text-obsidian text-xs font-semibold rounded-lg hover:bg-cobalt/90 disabled:opacity-40"
              >
                {busy === row.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Save'}
              </button>
              {configured && (
                <button onClick={() => remove(row.id)} disabled={busy === row.id}
                  className="px-2 py-1.5 text-red-400/70 hover:text-red-400 rounded-lg">
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
            {limit && (
              <p className="text-[10px] text-slate/30 mt-1.5 font-mono">
                Usage: {limit.used}/{limit.max} ({limit.pct}%) this {row.window}
              </p>
            )}
          </div>
        );
      })}
      {msg && <p className="text-[10px] text-cobalt/70 mt-1">{msg}</p>}
    </Section>
  );
}

// ─── Your data: history size, clearing, auto-cleanup, trusted items ──────────

const RETENTION_LABEL = { 30: '30 days', 90: '90 days', 365: '1 year', 0: 'Forever' };

// Two-step button so history is never wiped by a stray click
function ConfirmButton({ label, confirmLabel, onConfirm, disabled }) {
  const [armed, setArmed] = useState(false);
  const [busy,  setBusy]  = useState(false);
  useEffect(() => {
    if (!armed) return;
    const t = setTimeout(() => setArmed(false), 4000);
    return () => clearTimeout(t);
  }, [armed]);
  return (
    <button
      disabled={disabled || busy}
      onClick={async () => {
        if (!armed) return setArmed(true);
        setBusy(true);
        await onConfirm();
        setBusy(false);
        setArmed(false);
      }}
      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border transition-colors disabled:opacity-40 ${
        armed ? 'border-red-500/40 text-red-400 bg-red-500/10' : 'border-white/10 text-slate/70 hover:bg-white/5'
      }`}
    >
      {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
      {armed ? confirmLabel : label}
    </button>
  );
}

function DataSection({ onClearAlerts, onClearScans }) {
  const [data, setData] = useState(null);
  const [note, setNote] = useState('');

  const load = () => fetch(`${API_BASE}/data/summary`).then(r => r.json()).then(setData).catch(() => {});
  useEffect(() => { load(); }, []);

  const done = (res, what) => {
    setNote(res?.success ? `${what} cleared. A backup was saved first.` : 'Couldn\'t clear that — Alvora\'s engine isn\'t responding.');
    load();
  };

  async function setRetention(days) {
    const res = await fetch(`${API_BASE}/data/retention`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ days }),
    }).then(r => r.json()).catch(() => null);
    if (res?.success) {
      const n = (res.pruned?.threats ?? 0) + (res.pruned?.scans ?? 0);
      setNote(n ? `Removed ${n} record${n === 1 ? '' : 's'} older than ${RETENTION_LABEL[days]}.` : 'Saved.');
    }
    load();
  }

  async function untrust(body) {
    await fetch(`${API_BASE}/trust`, {
      method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    }).catch(() => {});
    load();
  }

  if (!data) {
    return <Section title="Your Data" icon={Database}><p className="text-xs text-slate/40">Loading…</p></Section>;
  }
  const trusted = [...(data.trusted?.apps ?? []).map(a => ({ key: a.path, label: a.name, sub: a.path, body: { appPath: a.path } })),
                   ...(data.trusted?.ips ?? []).map(i => ({ key: i.ip, label: i.ip, sub: 'Network address', body: { ip: i.ip } }))];

  return (
    <Section title="Your Data" icon={Database}>
      <p className="text-[11px] text-slate/40 -mt-2">Everything below is stored only on this Mac.</p>

      <SettingRow label="Alert history" description={`${data.threats} alert${data.threats === 1 ? '' : 's'} saved`}>
        <ConfirmButton label="Clear" confirmLabel="Clear all alerts?" disabled={!data.threats}
          onConfirm={async () => done(await onClearAlerts(), 'Alert history')} />
      </SettingRow>

      <SettingRow label="AI scan history" description={`${data.scans} scan${data.scans === 1 ? '' : 's'} saved (AI Monitor counters)`}>
        <ConfirmButton label="Clear" confirmLabel="Clear all scans?" disabled={!data.scans}
          onConfirm={async () => done(await onClearScans(), 'Scan history')} />
      </SettingRow>

      <SettingRow label="Keep history for" description="Older alerts and scans are deleted automatically">
        <select
          value={data.retentionDays}
          onChange={e => setRetention(Number(e.target.value))}
          className="bg-black/40 border border-white/10 rounded-lg px-3 py-1.5 text-white text-xs focus:outline-none focus:border-cobalt/40"
        >
          {data.choices.map(d => <option key={d} value={d}>{RETENTION_LABEL[d] ?? `${d} days`}</option>)}
        </select>
      </SettingRow>

      <div>
        <div className="text-xs text-white/80 mb-1">Trusted apps & addresses</div>
        <p className="text-[11px] text-slate/40 mb-2">
          Alvora won't alert about these. Add them with "Trust" on any alert. Known-malware warnings always show.
        </p>
        {trusted.length === 0 ? (
          <p className="text-[11px] text-slate/30">Nothing trusted yet.</p>
        ) : (
          <div className="space-y-1.5">
            {trusted.map(t => (
              <div key={t.key} className="flex items-center gap-2 bg-black/20 rounded-lg px-3 py-2">
                <BadgeCheck className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="text-xs text-white/80 truncate">{t.label}</div>
                  <div className="text-[10px] text-slate/40 truncate">{t.sub}</div>
                </div>
                <button onClick={() => untrust(t.body)} className="text-[11px] text-slate/50 hover:text-red-400 transition-colors flex-shrink-0">
                  Remove
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {note && <p className="text-[11px] text-emerald-400/80">{note}</p>}
    </Section>
  );
}

function Toggle({ checked, onChange }) {
  return (
    <button
      onClick={() => onChange(!checked)}
      className={`relative w-10 h-5 rounded-full transition-colors ${checked ? 'bg-cobalt' : 'bg-white/20'}`}
    >
      <motion.div
        animate={{ x: checked ? 20 : 2 }}
        transition={{ type: 'spring', stiffness: 500, damping: 30 }}
        className="absolute top-0.5 w-4 h-4 bg-white rounded-full shadow"
      />
    </button>
  );
}

function Section({ title, icon: Icon, children }) {
  return (
    <div className="bg-black/30 border border-white/5 rounded-xl p-5">
      <div className="flex items-center gap-2 mb-4">
        <Icon className="w-4 h-4 text-cobalt" />
        <h3 className="text-sm font-semibold text-white">{title}</h3>
      </div>
      <div className="space-y-4">{children}</div>
    </div>
  );
}

function SettingRow({ label, description, children }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <div>
        <p className="text-sm text-white/80">{label}</p>
        {description && <p className="text-xs text-slate/40 mt-0.5">{description}</p>}
      </div>
      <div className="flex-shrink-0">{children}</div>
    </div>
  );
}

const DEFAULT_SETTINGS = {
  notifications: true,
  minimizeToTray: true,
  autoLaunch: false,
  scanInterval: 10,
};

export default function SettingsPanel({ licenseInfo, onDeactivate, onClearAlerts, onClearScans }) {
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);
  const [saved,    setSaved]    = useState(false);
  const { isElectron, readSettings, writeSettings, openExternal, version } = useElectron();

  useEffect(() => {
    readSettings().then(s => {
      if (s) setSettings(prev => ({ ...prev, ...s }));
    }).catch(() => {});
  }, [readSettings]);

  async function handleSave() {
    await writeSettings(settings);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  function update(key, value) {
    setSettings(prev => ({ ...prev, [key]: value }));
  }

  const daysLeft = licenseInfo?.tier === 'TRIAL'
    ? Math.max(0, Math.ceil((new Date(licenseInfo.expiresAt) - Date.now()) / (24 * 60 * 60 * 1000)))
    : null;

  return (
    <motion.div
      key="settings"
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="flex flex-col w-full h-full p-6 gap-5 overflow-y-auto"
    >
      <div className="flex items-center gap-2">
        <Settings className="w-5 h-5 text-cobalt" />
        <h2 className="text-base font-bold text-white">Settings</h2>
      </div>

      {/* License */}
      <Section title="License" icon={Key}>
        <div className="bg-cobalt/5 border border-cobalt/20 rounded-lg p-4">
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold font-mono px-2 py-0.5 rounded bg-cobalt/20 text-cobalt border border-cobalt/30">
              Free Beta
            </span>
            <span className="text-xs text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> All features unlocked
            </span>
          </div>
          <p className="text-xs text-slate/40 mt-2">
            {settings.email
              ? `Registered as ${settings.email}. Every feature is active, free, during the beta.`
              : 'Free beta — every feature is active, no subscription, no expiry.'}
          </p>
        </div>
      </Section>

      {/* Notifications */}
      <Section title="Notifications" icon={Bell}>
        <SettingRow label="Threat Alerts" description="Native OS notifications for critical threats">
          <Toggle checked={settings.notifications} onChange={v => update('notifications', v)} />
        </SettingRow>
      </Section>

      {/* App behavior */}
      {isElectron && (
        <Section title="Application" icon={Shield}>
          <SettingRow label="Minimize to Tray" description="Keep running in background when window is closed">
            <Toggle checked={settings.minimizeToTray} onChange={v => update('minimizeToTray', v)} />
          </SettingRow>
          <SettingRow label="Launch at Login" description="Start Alvora Cyber automatically on login">
            <Toggle checked={settings.autoLaunch} onChange={v => update('autoLaunch', v)} />
          </SettingRow>
        </Section>
      )}

      {/* Your data */}
      <DataSection onClearAlerts={onClearAlerts} onClearScans={onClearScans} />

      {/* API Integrations */}
      <ApiKeysSection />

      {/* About */}
      <Section title="About" icon={Info}>
        <div className="grid grid-cols-2 gap-3 text-xs font-mono">
          {[
            ['Version', `v${version}`],
            ['Platform', isElectron ? 'Desktop (Electron)' : 'Web'],
            ['Engine', 'Alvora Threat Engine'],
            ['License', licenseInfo?.tier ?? 'Personal'],
          ].map(([k, v]) => (
            <div key={k} className="bg-black/20 rounded px-3 py-2">
              <div className="text-slate/40 text-[9px] uppercase">{k}</div>
              <div className="text-white/70 mt-0.5">{v}</div>
            </div>
          ))}
        </div>
        <button
          onClick={() => openExternal('https://alvoracyber.com')}
          className="text-xs text-cobalt/60 hover:text-cobalt flex items-center gap-1 transition-colors"
        >
          <ExternalLink className="w-3 h-3" /> Visit alvoracyber.com
        </button>
      </Section>

      {/* Save button */}
      <button
        onClick={handleSave}
        className="flex items-center justify-center gap-2 w-full py-3 bg-cobalt text-obsidian font-semibold rounded-xl hover:bg-cobalt/90 transition-all text-sm"
      >
        {saved ? (
          <><CheckCircle2 className="w-4 h-4" /> Saved</>
        ) : (
          <><RefreshCw className="w-4 h-4" /> Save Settings</>
        )}
      </button>
    </motion.div>
  );
}
