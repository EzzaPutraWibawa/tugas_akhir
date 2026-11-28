// Konfigurasi koneksi Frontend -> Backend ServerPulse
// Saat deploy ke Netlify + Render:
// 1. Pastikan netlify.toml mem-proxy /api/* ke URL Render Anda, ATAU isi API_BASE.
// 2. Isi WS_URL dengan wss://<nama-app-render>.onrender.com/ws agar WebSocket live berjalan.
window.SERVERPULSE_CONFIG = {
  API_BASE: '',
  WS_URL: ''
};
