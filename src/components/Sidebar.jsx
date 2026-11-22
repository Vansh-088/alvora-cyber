import { motion, AnimatePresence } from 'framer-motion';
import {
  LayoutDashboard,
  Sparkles,
  Zap,
  Database,
  Globe,
  Cpu,
  Flame,
  FileBarChart,
  Settings,
  Shield,
  ShieldOff,
  Wifi,
  WifiOff,
} from 'lucide-react';

// ─── Nav item definitions ──────────────────────────────────────────────────

const NAV_ITEMS = [
  { id: 'dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { id: 'assistant', icon: Sparkles,        label: 'Alvora AI', badge: 'NEW' },
  { id: 'ai-monitor', icon: Zap,            label: 'AI Monitor' },
  { id: 'vault',      icon: Database,       label: 'Vault' },
  { id: 'threat',     icon: Globe,          label: 'Threat Map' },
  { id: 'kernel',     icon: Cpu,            label: 'Kernel' },
  { id: 'firewall',   icon: Flame,          label: 'Firewall' },
  { id: 'reports',    icon: FileBarChart,   label: 'Reports' },
  { id: 'settings',   icon: Settings,       label: 'Settings' },
];

// ─── Single nav button ────────────────────────────────────────────────────

function NavButton({ item, isActive, onClick }) {
  const Icon = item.icon;

  return (
    <div className="relative group">
      <motion.button
        onClick={() => onClick(item.id)}
        whileHover={{ scale: 1.08 }}
        whileTap={{ scale: 0.94 }}
        className={`
          relative w-12 h-12 flex items-center justify-center rounded-xl
          transition-colors duration-200 cursor-pointer outline-none
          ${isActive
            ? 'text-white'
            : 'text-slate-400 hover:text-white/80'}
        `}
        style={isActive ? {
          background: 'rgba(0,229,255,0.12)',
          boxShadow: '0 0 16px rgba(0,229,255,0.25), inset 0 0 8px rgba(0,229,255,0.08)',
        } : {}}
      >
        {/* Active left-edge indicator */}
        {isActive && (
          <motion.div
            layoutId="active-indicator"
            className="absolute -left-3 top-1/2 -translate-y-1/2 w-0.5 h-6 rounded-r-full"
            style={{ background: '#00E5FF', boxShadow: '0 0 8px #00E5FF' }}
            transition={{ type: 'spring', stiffness: 380, damping: 30 }}
          />
        )}

        <Icon
          size={20}
          strokeWidth={isActive ? 2 : 1.6}
          color={isActive ? '#00E5FF' : undefined}
        />

        {/* NEW badge */}
        {item.badge && (
          <span
            className="absolute -top-1 -right-1 text-[8px] font-mono font-bold leading-none
                       px-1 py-0.5 rounded-sm tracking-wider"
            style={{
              background: 'rgba(0,229,255,0.18)',
              color: '#00E5FF',
              border: '1px solid rgba(0,229,255,0.3)',
            }}
          >
            {item.badge}
          </span>
        )}
      </motion.button>

      {/* Tooltip on hover */}
      <div
        className="absolute left-14 top-1/2 -translate-y-1/2 z-50
                   pointer-events-none opacity-0 group-hover:opacity-100
                   transition-opacity duration-150"
      >
        <div
          className="px-2.5 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap"
          style={{
            background: 'rgba(17,24,39,0.95)',
            border: '1px solid rgba(0,229,255,0.2)',
            color: '#e2e8f0',
            boxShadow: '0 4px 16px rgba(0,0,0,0.4)',
          }}
        >
          {item.label}
        </div>
      </div>
    </div>
  );
}

// ─── License tier badge ───────────────────────────────────────────────────

function LicenseBadge({ licenseInfo }) {
  if (!licenseInfo) return null;

  const tier = licenseInfo.tier?.toUpperCase() || 'TRIAL';
  const label = tier === 'PROFESSIONAL' ? 'PRO' : tier === 'STANDARD' ? 'STD' : tier.slice(0, 5);
  const color = label === 'PRO' ? '#00E5FF' : label === 'STD' ? '#94a3b8' : '#fbbf24';
  const borderColor = label === 'PRO'
    ? 'rgba(0,229,255,0.3)'
    : label === 'STD'
    ? 'rgba(148,163,184,0.3)'
    : 'rgba(251,191,36,0.3)';

  return (
    <span
      className="font-mono text-[9px] font-bold tracking-widest px-1.5 py-0.5 rounded-sm"
      style={{ color, border: `1px solid ${borderColor}`, background: `${color}18` }}
    >
      {label}
    </span>
  );
}

// ─── Sidebar ──────────────────────────────────────────────────────────────

export default function Sidebar({
  activeTab,
  setActiveTab,
  lockdownActive,
  onLockdown,
  backendConnected,
  licenseInfo,
}) {
  return (
    <aside
      className="glass-panel relative flex flex-col items-center h-full z-30 select-none"
      style={{
        width: 72,
        minWidth: 72,
        maxWidth: 72,
        background: '#111827',
        borderRight: '1px solid rgba(255,255,255,0.06)',
      }}
    >
      {/* ── Logo ───────────────────────────────────────────────────────── */}
      <div
        className="drag-region w-full flex flex-col items-center pt-4 pb-3 gap-1"
        style={{ minHeight: 64 }}
      >
        <div className="flex items-center justify-center">
          <Shield size={22} color="#00E5FF" strokeWidth={2} />
        </div>
        <span
          className="font-mono font-bold text-[11px] tracking-widest"
          style={{ color: '#00E5FF', letterSpacing: '0.2em' }}
        >
          AC
        </span>

        {/* Lockdown warning label */}
        <AnimatePresence>
          {lockdownActive && (
            <motion.span
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.8 }}
              className="font-mono text-[8px] font-bold tracking-widest"
              style={{ color: '#ef4444', letterSpacing: '0.15em' }}
            >
              LOCKDOWN
            </motion.span>
          )}
        </AnimatePresence>
      </div>

      {/* ── Divider ────────────────────────────────────────────────────── */}
      <div
        className="w-8 mb-3"
        style={{ height: 1, background: 'rgba(255,255,255,0.06)' }}
      />

      {/* ── Nav Items ──────────────────────────────────────────────────── */}
      <nav className="flex flex-col items-center gap-1.5 flex-1 w-full px-3">
        {NAV_ITEMS.map((item) => (
          <NavButton
            key={item.id}
            item={item}
            isActive={activeTab === item.id}
            onClick={setActiveTab}
          />
        ))}
      </nav>

      {/* ── Bottom section ─────────────────────────────────────────────── */}
      <div className="flex flex-col items-center gap-3 pb-4 w-full px-3">

        {/* Lockdown button */}
        <motion.button
          onClick={onLockdown}
          whileHover={{ scale: 1.1 }}
          whileTap={{ scale: 0.92 }}
          title={lockdownActive ? 'Disengage Lockdown' : 'Engage Lockdown'}
          className="w-12 h-12 flex items-center justify-center rounded-xl
                     transition-colors duration-200 outline-none cursor-pointer"
          style={lockdownActive ? {
            background: 'rgba(239,68,68,0.18)',
            boxShadow: '0 0 20px rgba(239,68,68,0.35)',
            border: '1px solid rgba(239,68,68,0.35)',
          } : {
            background: 'rgba(0,229,255,0.08)',
            border: '1px solid rgba(0,229,255,0.18)',
          }}
        >
          <AnimatePresence mode="wait" initial={false}>
            {lockdownActive ? (
              <motion.span
                key="lockdown-on"
                initial={{ opacity: 0, rotate: -15 }}
                animate={{ opacity: 1, rotate: 0 }}
                exit={{ opacity: 0, rotate: 15 }}
                transition={{ duration: 0.18 }}
              >
                <ShieldOff size={20} color="#ef4444" strokeWidth={2} />
              </motion.span>
            ) : (
              <motion.span
                key="lockdown-off"
                initial={{ opacity: 0, rotate: 15 }}
                animate={{ opacity: 1, rotate: 0 }}
                exit={{ opacity: 0, rotate: -15 }}
                transition={{ duration: 0.18 }}
              >
                <Shield size={20} color="#00E5FF" strokeWidth={1.8} />
              </motion.span>
            )}
          </AnimatePresence>
        </motion.button>

        {/* Backend status dot */}
        <div className="flex flex-col items-center gap-1">
          <div className="relative flex items-center justify-center">
            {backendConnected ? (
              <Wifi size={14} color="#10b981" strokeWidth={1.8} />
            ) : (
              <WifiOff size={14} color="#fbbf24" strokeWidth={1.8} />
            )}
            <motion.span
              animate={{ opacity: [1, 0.3, 1] }}
              transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
              className="absolute -top-0.5 -right-0.5 w-1.5 h-1.5 rounded-full"
              style={{
                background: backendConnected ? '#10b981' : '#fbbf24',
                boxShadow: backendConnected
                  ? '0 0 6px #10b981'
                  : '0 0 6px #fbbf24',
              }}
            />
          </div>
          <span
            className="font-mono text-[8px] tracking-wide"
            style={{ color: backendConnected ? '#10b981' : '#fbbf24' }}
          >
            {backendConnected ? 'LIVE' : 'OFFLINE'}
          </span>
        </div>

        {/* License tier badge */}
        <LicenseBadge licenseInfo={licenseInfo} />
      </div>
    </aside>
  );
}
