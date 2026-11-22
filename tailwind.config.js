/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        obsidian: '#0a0f1a',
        charcoal: '#111827',
        slate:    '#94a3b8',
        cobalt:   '#00E5FF',
        neon:     '#39FF14',
        crimson:  '#ef4444',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        'glow':        '0 0 20px rgba(0,229,255,0.15)',
        'glow-strong': '0 0 40px rgba(0,229,255,0.25)',
        'glow-red':    '0 0 20px rgba(239,68,68,0.3)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4,0,0.6,1) infinite',
      },
    },
  },
  plugins: [],
}
