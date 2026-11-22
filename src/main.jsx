import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'

// ── Attach the per-install API token to every backend request ─────────────────
// The token is injected by Electron's preload (window.alvoraBridge.apiToken).
// We wrap fetch once here so every existing call automatically carries the
// X-Alvora-Token header — external processes without the token are rejected.
(function installApiTokenInterceptor() {
  const token = window.alvoraBridge?.apiToken;
  if (!token) return; // web/dev mode: no token, backend runs open locally

  const origFetch = window.fetch.bind(window);
  window.fetch = (input, init = {}) => {
    const url = typeof input === 'string' ? input : input?.url ?? '';
    const isApi = url.includes('/api') || url.includes('localhost:3001');
    if (isApi) {
      const headers = new Headers(init.headers || (typeof input !== 'string' ? input.headers : undefined));
      headers.set('X-Alvora-Token', token);
      init = { ...init, headers };
    }
    return origFetch(input, init);
  };

  // Expose token for EventSource (SSE) which can't set headers — uses ?token=
  window.__ALVORA_TOKEN__ = token;
})();

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
