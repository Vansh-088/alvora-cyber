/**
 * VaultView — Real AES-256-GCM Encrypted Vault
 *
 * Flow:
 *   1. First run  → set a master password (initializes the vault)
 *   2. Locked     → enter master password to unlock
 *   3. Unlocked   → drag-drop to encrypt files, download to decrypt, delete
 *
 * The master password is held only in component state during the session.
 * It is sent to the local backend per-operation and never persisted in the UI.
 */

import React, { useState, useRef, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Database, Upload, CheckCircle2, Lock, Unlock, KeyRound, FileText, Download, Trash2, ShieldAlert, Loader2, RefreshCw, AlertTriangle, KeySquare } from 'lucide-react';

const API_BASE = (typeof window !== 'undefined' && window.location.protocol === 'file:')
  ? 'http://localhost:3001/api'
  : '/api';

function fmtSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export default function VaultView() {
  const [status,       setStatus]       = useState(null);
  const [password,     setPassword]     = useState('');
  const [confirm,      setConfirm]      = useState('');
  const [unlocked,     setUnlocked]     = useState(false);
  const [files,        setFiles]        = useState([]);
  const [error,        setError]        = useState('');
  const [busy,         setBusy]         = useState(false);
  const [uploading,    setUploading]    = useState(false);
  const [success,      setSuccess]      = useState(null);
  const [dragging,     setDragging]     = useState(false);

  // Reset vault modal
  const [showReset,    setShowReset]    = useState(false);
  const [resetConfirm, setResetConfirm] = useState('');
  const [resetBusy,    setResetBusy]    = useState(false);
  const [resetError,   setResetError]   = useState('');

  // Change password modal
  const [showChangePw,  setShowChangePw]  = useState(false);
  const [newPw,         setNewPw]         = useState('');
  const [newPwConfirm,  setNewPwConfirm]  = useState('');
  const [changePwBusy,  setChangePwBusy]  = useState(false);
  const [changePwError, setChangePwError] = useState('');

  const inputRef = useRef(null);

  // ── Load vault status on mount ──────────────────────────────────────────────
  useEffect(() => {
    fetch(`${API_BASE}/vault/status`)
      .then(r => r.json())
      .then(setStatus)
      .catch(() => setStatus({ initialized: false, fileCount: 0 }));
  }, []);

  const refreshFiles = useCallback(async () => {
    try {
      const res  = await fetch(`${API_BASE}/vault/list`);
      const data = await res.json();
      setFiles(data.files ?? []);
    } catch { setFiles([]); }
  }, []);

  // ── Initialize (first run) ──────────────────────────────────────────────────
  async function handleInit() {
    setError('');
    if (password.length < 8)      return setError('Master password must be at least 8 characters');
    if (password !== confirm)     return setError('Passwords do not match');
    setBusy(true);
    try {
      const res  = await fetch(`${API_BASE}/vault/init`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setUnlocked(true);
      setConfirm('');
      await refreshFiles();
      const st = await fetch(`${API_BASE}/vault/status`).then(r => r.json());
      setStatus(st);
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  // ── Unlock ──────────────────────────────────────────────────────────────────
  async function handleUnlock() {
    setError('');
    setBusy(true);
    try {
      const res  = await fetch(`${API_BASE}/vault/unlock`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      const data = await res.json();
      if (!data.success) throw new Error('Incorrect master password');
      setUnlocked(true);
      await refreshFiles();
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  function lock() {
    setUnlocked(false);
    setPassword('');
    setFiles([]);
    setError('');
  }

  // ── Reset vault (forgot password) ──────────────────────────────────────────
  async function handleReset() {
    if (resetConfirm !== 'RESET') return setResetError('Type RESET to confirm');
    setResetBusy(true);
    setResetError('');
    try {
      const res  = await fetch(`${API_BASE}/vault/reset`, { method: 'POST' });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setShowReset(false);
      setResetConfirm('');
      setPassword('');
      const st = await fetch(`${API_BASE}/vault/status`).then(r => r.json());
      setStatus(st);
    } catch (e) { setResetError(e.message); }
    finally { setResetBusy(false); }
  }

  // ── Change password (while unlocked) ───────────────────────────────────────
  async function handleChangePassword() {
    if (newPw.length < 8)       return setChangePwError('New password must be at least 8 characters');
    if (newPw !== newPwConfirm) return setChangePwError('Passwords do not match');
    setChangePwBusy(true);
    setChangePwError('');
    try {
      const res  = await fetch(`${API_BASE}/vault/change-password`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword: password, newPassword: newPw }),
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setPassword(newPw);   // keep session unlocked with new password
      setShowChangePw(false);
      setNewPw('');
      setNewPwConfirm('');
      setSuccess(`Password changed · ${data.filesRekeyed} file${data.filesRekeyed !== 1 ? 's' : ''} re-encrypted`);
      setTimeout(() => setSuccess(null), 4000);
    } catch (e) { setChangePwError(e.message); }
    finally { setChangePwBusy(false); }
  }

  // ── Encrypt + upload a file ─────────────────────────────────────────────────
  async function handleFile(file) {
    if (!file) return;
    setUploading(true);
    setError('');
    try {
      const buf       = await file.arrayBuffer();
      const base64     = btoa(String.fromCharCode(...new Uint8Array(buf)));
      const res        = await fetch(`${API_BASE}/vault/add`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password, fileName: file.name, contentBase64: base64 }),
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setSuccess(file.name);
      setTimeout(() => setSuccess(null), 3000);
      await refreshFiles();
    } catch (e) { setError(e.message); }
    finally { setUploading(false); }
  }

  // ── Decrypt + download a file ─────────────────────────────────────────────────
  async function handleDownload(id, name) {
    setError('');
    try {
      const res  = await fetch(`${API_BASE}/vault/get`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password, id }),
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      // Decode base64 → Blob → trigger download
      const bytes = Uint8Array.from(atob(data.contentBase64), c => c.charCodeAt(0));
      const blob  = new Blob([bytes]);
      const url   = URL.createObjectURL(blob);
      const a     = document.createElement('a');
      a.href = url; a.download = data.name || name;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) { setError(e.message); }
  }

  // ── Delete a file ─────────────────────────────────────────────────────────────
  async function handleDelete(id) {
    setError('');
    try {
      const res  = await fetch(`${API_BASE}/vault/delete`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password, id }),
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      await refreshFiles();
    } catch (e) { setError(e.message); }
  }

  // ─── Render: loading ──────────────────────────────────────────────────────────
  if (!status) {
    return (
      <div className="flex items-center justify-center w-full h-full">
        <Loader2 className="w-6 h-6 text-cobalt animate-spin" />
      </div>
    );
  }

  // ─── Render: setup or unlock gate ─────────────────────────────────────────────
  if (!unlocked) {
    const isSetup = !status.initialized;
    return (
      <motion.div
        key="vault-gate"
        initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
        className="flex flex-col items-center justify-center w-full h-full p-8"
      >
        <div className="w-full max-w-sm">
          <div className="flex flex-col items-center mb-6">
            <div className="w-16 h-16 rounded-2xl bg-cobalt/10 border border-cobalt/30 flex items-center justify-center mb-4">
              {isSetup ? <KeyRound className="w-8 h-8 text-cobalt" /> : <Lock className="w-8 h-8 text-cobalt" />}
            </div>
            <h2 className="text-lg font-bold text-white">
              {isSetup ? 'Create Master Password' : 'Unlock Vault'}
            </h2>
            <p className="text-xs text-slate/50 mt-1 text-center">
              {isSetup
                ? 'This password encrypts every file with AES-256-GCM. It is never stored — if lost, your files cannot be recovered.'
                : 'Enter your master password to decrypt the vault.'}
            </p>
          </div>

          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && !isSetup && handleUnlock()}
            placeholder="Master password"
            autoFocus
            className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white text-sm focus:outline-none focus:border-cobalt/40 mb-3"
          />

          {isSetup && (
            <input
              type="password"
              value={confirm}
              onChange={e => setConfirm(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleInit()}
              placeholder="Confirm master password"
              className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white text-sm focus:outline-none focus:border-cobalt/40 mb-3"
            />
          )}

          <AnimatePresence>
            {error && (
              <motion.div
                initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                className="flex items-center gap-2 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2 mb-3"
              >
                <ShieldAlert className="w-4 h-4 text-red-400 flex-shrink-0" />
                <span className="text-red-400 text-xs">{error}</span>
              </motion.div>
            )}
          </AnimatePresence>

          <button
            onClick={isSetup ? handleInit : handleUnlock}
            disabled={busy || !password}
            className="w-full flex items-center justify-center gap-2 py-3 bg-cobalt text-obsidian font-semibold rounded-xl hover:bg-cobalt/90 disabled:opacity-40 transition-all text-sm"
          >
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : isSetup ? <KeyRound className="w-4 h-4" /> : <Unlock className="w-4 h-4" />}
            {isSetup ? 'Create Vault' : 'Unlock'}
          </button>

          {!isSetup && (
            <div className="mt-4 flex flex-col items-center gap-1">
              <p className="text-[10px] text-slate/30 font-mono">
                {status.fileCount} encrypted file{status.fileCount !== 1 ? 's' : ''} in vault
              </p>
              <button
                onClick={() => { setShowReset(true); setResetConfirm(''); setResetError(''); }}
                className="text-[11px] text-red-400/50 hover:text-red-400 transition-colors mt-1"
              >
                Forgot password? Reset vault
              </button>
            </div>
          )}
        </div>
      </motion.div>

      {/* ── Reset vault modal ──────────────────────────────────────────────── */}
      <AnimatePresence>
        {showReset && (
          <motion.div
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
            onClick={e => e.target === e.currentTarget && setShowReset(false)}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.95, opacity: 0 }}
              className="w-full max-w-sm bg-[#0d1117] border border-red-500/30 rounded-2xl p-6 shadow-2xl"
            >
              <div className="flex flex-col items-center mb-5">
                <div className="w-12 h-12 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center mb-3">
                  <AlertTriangle className="w-6 h-6 text-red-400" />
                </div>
                <h3 className="text-white font-bold text-base">Reset Vault</h3>
                <p className="text-slate/50 text-xs text-center mt-2">
                  This will <span className="text-red-400 font-semibold">permanently delete all {status.fileCount} encrypted file{status.fileCount !== 1 ? 's' : ''}</span> in your vault.
                  They <span className="text-red-400">cannot be recovered</span> without your master password.
                </p>
              </div>

              <p className="text-slate/40 text-xs mb-2 text-center">Type <span className="text-white font-mono">RESET</span> to confirm</p>
              <input
                type="text"
                value={resetConfirm}
                onChange={e => setResetConfirm(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleReset()}
                placeholder="RESET"
                autoFocus
                className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white text-sm font-mono text-center focus:outline-none focus:border-red-500/40 mb-3"
              />

              <AnimatePresence>
                {resetError && (
                  <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                    className="flex items-center gap-2 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2 mb-3">
                    <ShieldAlert className="w-4 h-4 text-red-400 flex-shrink-0" />
                    <span className="text-red-400 text-xs">{resetError}</span>
                  </motion.div>
                )}
              </AnimatePresence>

              <div className="flex gap-2">
                <button
                  onClick={() => setShowReset(false)}
                  className="flex-1 py-2.5 rounded-xl border border-white/10 text-slate/50 hover:text-white hover:border-white/20 text-sm transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleReset}
                  disabled={resetBusy || resetConfirm !== 'RESET'}
                  className="flex-1 flex items-center justify-center gap-2 py-2.5 bg-red-500 text-white font-semibold rounded-xl hover:bg-red-600 disabled:opacity-40 text-sm transition-all"
                >
                  {resetBusy ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
                  Reset Vault
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    );
  }

  // ─── Render: unlocked vault ───────────────────────────────────────────────────
  return (
    <motion.div
      key="vault"
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="flex flex-col w-full h-full p-8 gap-6"
    >
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Database className="w-5 h-5 text-cobalt" />
            Encrypted Vault
          </h2>
          <p className="text-xs text-slate/50 mt-1">AES-256-GCM · scrypt key derivation · zero-knowledge</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => { setShowChangePw(true); setNewPw(''); setNewPwConfirm(''); setChangePwError(''); }}
            className="flex items-center gap-1.5 text-xs text-slate/50 hover:text-cobalt border border-white/10 rounded-lg px-3 py-1.5 transition-colors"
          >
            <KeySquare className="w-3.5 h-3.5" /> Change Password
          </button>
          <button
            onClick={lock}
            className="flex items-center gap-1.5 text-xs text-slate/50 hover:text-cobalt border border-white/10 rounded-lg px-3 py-1.5 transition-colors"
          >
            <Lock className="w-3.5 h-3.5" /> Lock
          </button>
        </div>
      </div>

      {/* Drop zone */}
      <div
        onDragOver={e => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={e => { e.preventDefault(); setDragging(false); handleFile(e.dataTransfer.files[0]); }}
        onClick={() => inputRef.current?.click()}
        className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
          dragging ? 'border-cobalt/60 bg-cobalt/10' : 'border-white/10 hover:border-cobalt/30 hover:bg-cobalt/5'
        }`}
      >
        <input ref={inputRef} type="file" className="hidden" onChange={e => handleFile(e.target.files?.[0])} />
        {uploading ? (
          <div className="flex flex-col items-center gap-2">
            <motion.div animate={{ rotate: 360 }} transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}>
              <Upload className="w-8 h-8 text-cobalt" />
            </motion.div>
            <p className="text-cobalt text-sm">Encrypting with AES-256-GCM…</p>
          </div>
        ) : (
          <>
            <Upload className="w-8 h-8 text-slate/30 mx-auto mb-2" />
            <p className="text-white/60 text-sm">Drop file here or click to browse</p>
            <p className="text-slate/40 text-xs mt-1">Any file · encrypted before it touches disk</p>
          </>
        )}
      </div>

      <AnimatePresence>
        {success && (
          <motion.div
            initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            className="flex items-center gap-2 bg-emerald-500/20 border border-emerald-500/30 rounded-lg px-4 py-2"
          >
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span className="text-emerald-400 text-sm">{success} encrypted and stored.</span>
          </motion.div>
        )}
        {error && (
          <motion.div
            initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            className="flex items-center gap-2 bg-red-500/10 border border-red-500/20 rounded-lg px-4 py-2"
          >
            <ShieldAlert className="w-4 h-4 text-red-400" />
            <span className="text-red-400 text-sm">{error}</span>
          </motion.div>
        )}
      </AnimatePresence>

      {/* File list */}
      <div className="flex-1 overflow-y-auto space-y-2">
        <p className="text-[10px] uppercase text-slate/40 font-mono mb-3">
          {files.length} encrypted item{files.length !== 1 ? 's' : ''}
        </p>
        {files.length === 0 && (
          <p className="text-slate/30 text-xs text-center py-8">Vault is empty. Drop a file above to encrypt it.</p>
        )}
        {files.map((f, i) => (
          <motion.div
            key={f.id}
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.04 }}
            className="flex items-center gap-3 bg-black/30 rounded-lg px-4 py-3 border border-white/5 hover:border-cobalt/20 transition-all group"
          >
            <div className="p-2 bg-white/5 rounded-lg"><FileText className="w-4 h-4 text-cobalt" /></div>
            <div className="flex-1 min-w-0">
              <p className="text-white/80 text-sm truncate">{f.name}</p>
              <p className="text-slate/40 text-[10px] font-mono">{fmtSize(f.sizeBytes)} · {f.addedAt?.slice(0, 10)} · {f.algorithm}</p>
            </div>
            <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
              <button onClick={() => handleDownload(f.id, f.name)} title="Decrypt & download"
                className="p-1.5 rounded-lg hover:bg-cobalt/10 text-cobalt/70 hover:text-cobalt transition-colors">
                <Download className="w-4 h-4" />
              </button>
              <button onClick={() => handleDelete(f.id)} title="Delete permanently"
                className="p-1.5 rounded-lg hover:bg-red-500/10 text-red-400/70 hover:text-red-400 transition-colors">
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
            <Lock className="w-3 h-3 text-cobalt/40 flex-shrink-0" />
          </motion.div>
        ))}
      </div>

      {/* ── Change password modal ──────────────────────────────────────────── */}
      <AnimatePresence>
        {showChangePw && (
          <motion.div
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
            onClick={e => e.target === e.currentTarget && setShowChangePw(false)}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.95, opacity: 0 }}
              className="w-full max-w-sm bg-[#0d1117] border border-cobalt/20 rounded-2xl p-6 shadow-2xl"
            >
              <div className="flex flex-col items-center mb-5">
                <div className="w-12 h-12 rounded-xl bg-cobalt/10 border border-cobalt/30 flex items-center justify-center mb-3">
                  <KeySquare className="w-6 h-6 text-cobalt" />
                </div>
                <h3 className="text-white font-bold text-base">Change Master Password</h3>
                <p className="text-slate/50 text-xs text-center mt-2">
                  All encrypted files will be seamlessly re-keyed to the new password.
                </p>
              </div>

              <input
                type="password"
                value={newPw}
                onChange={e => setNewPw(e.target.value)}
                placeholder="New password (min 8 chars)"
                autoFocus
                className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white text-sm focus:outline-none focus:border-cobalt/40 mb-3"
              />
              <input
                type="password"
                value={newPwConfirm}
                onChange={e => setNewPwConfirm(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleChangePassword()}
                placeholder="Confirm new password"
                className="w-full bg-black/40 border border-white/10 rounded-xl px-4 py-3 text-white text-sm focus:outline-none focus:border-cobalt/40 mb-3"
              />

              <AnimatePresence>
                {changePwError && (
                  <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                    className="flex items-center gap-2 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2 mb-3">
                    <ShieldAlert className="w-4 h-4 text-red-400 flex-shrink-0" />
                    <span className="text-red-400 text-xs">{changePwError}</span>
                  </motion.div>
                )}
              </AnimatePresence>

              <div className="flex gap-2">
                <button
                  onClick={() => setShowChangePw(false)}
                  className="flex-1 py-2.5 rounded-xl border border-white/10 text-slate/50 hover:text-white hover:border-white/20 text-sm transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleChangePassword}
                  disabled={changePwBusy || !newPw || !newPwConfirm}
                  className="flex-1 flex items-center justify-center gap-2 py-2.5 bg-cobalt text-obsidian font-semibold rounded-xl hover:bg-cobalt/90 disabled:opacity-40 text-sm transition-all"
                >
                  {changePwBusy ? <Loader2 className="w-4 h-4 animate-spin" /> : <KeySquare className="w-4 h-4" />}
                  Update Password
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
