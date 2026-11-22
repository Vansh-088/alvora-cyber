import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  // Don't inherit the desktop app's Tailwind/PostCSS config from the parent folder
  css: { postcss: { plugins: [] } },
  server: { port: 5180 },
  preview: { port: 5180 },
});