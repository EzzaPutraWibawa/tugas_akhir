// ServerPulse Cyber-SOC Frontend Application Logic
// Real-time Netdata Observability, Attacker Device Forensics, and 3-Level Mitigation
// Admin Authentication & Session Management

let state = {
  activeTab: 'overview',
  selectedTimeRange: -900, // default 15 minutes, matching the user's reference link
  selectedOsFilter: 'all',
  searchQuery: '',
  closedLoopMode: 'auto',
  adminToken: localStorage.getItem('serverpulse_admin_token') || null,
  adminUser: null,
  isInitialized: false,
  socket: null,
  charts: {
    netdataCpu: null,
    netdataNet: null,
    deviceDistribution: null,
    hourlyAttacks: null
  }
};

// Authenticated Fetch Helper
function authFetch(url, options = {}) {
  const headers = options.headers || {};
  if (state.adminToken) {
    headers['Authorization'] = `Bearer ${state.adminToken}`;
  }
  return fetch(url, { ...options, headers });
}

// -------------------------------------------------------------------
// INITIALIZATION & AUTHENTICATION CHECK
// -------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  if (window.location.protocol === 'file:') {
    const fileWarn = document.getElementById('file-protocol-warning');
    if (fileWarn) fileWarn.classList.remove('hidden');
  }
  checkAdminAuth();
});

async function checkAdminAuth() {
  if (!state.adminToken) {
    showLoginScreen();
    return;
  }

  try {
    const res = await authFetch('/api/auth/me');
    if (res.ok) {
      const data = await res.json();
      state.adminUser = data.user;
      revealDashboard(data.user);
    } else {
      // Token invalid or expired
      localStorage.removeItem('serverpulse_admin_token');
      state.adminToken = null;
      showLoginScreen();
    }
  } catch (err) {
    showLoginScreen();
  }
}

function showLoginScreen() {
  document.getElementById('login-screen').classList.remove('hidden');
  document.getElementById('app-dashboard').classList.add('hidden');
  document.getElementById('login-password').value = '';
}

function revealDashboard(user) {
  document.getElementById('login-screen').classList.add('hidden');
  document.getElementById('app-dashboard').classList.remove('hidden');

  if (user) {
    document.getElementById('header-admin-name').textContent = user.username || 'admin';
  }

  if (!state.isInitialized) {
    state.isInitialized = true;
    initWebSocket();
    initThemeCharts();

    // Initial Data Loads
    syncNetdataNow();
    loadNetdataHistory(state.selectedTimeRange);
    fetchDdosIntel();
    fetchSettings();
    fetchIncidentsHistory();
    refreshAnsibleLogs();

    // Periodic polling loops
    setInterval(fetchNetdataLiveMetrics, 3000); // 3s telemetry heartbeat
    setInterval(fetchDdosIntel, 10000);         // 10s threat intelligence poll
  }
}

// -------------------------------------------------------------------
// ADMIN SIGN IN & SIGN OUT HANDLERS
// -------------------------------------------------------------------
async function handleAdminLogin(event) {
  event.preventDefault();
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const remember = document.getElementById('login-remember').checked;
  const btn = document.getElementById('btn-submit-login');
  const btnText = document.getElementById('text-login-btn');
  const btnIcon = document.getElementById('icon-login-btn');
  const errorAlert = document.getElementById('login-error-alert');
  const errorText = document.getElementById('login-error-text');
  const loginCard = document.querySelector('#login-screen .glass-panel-glow');

  // Loading state
  btn.disabled = true;
  btnIcon.className = 'fa-solid fa-circle-notch fa-spin';
  btnText.textContent = 'Memverifikasi...';
  errorAlert.classList.add('hidden');

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    let data = null;
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      data = await res.json();
    } else {
      const rawText = await res.text();
      throw new Error(`Respon server non-JSON (${res.status}): ${rawText.slice(0, 80)}`);
    }

    if (res.ok && data.success) {
      state.adminToken = data.token;
      state.adminUser = data.user;
      localStorage.setItem('serverpulse_admin_token', data.token);

      revealDashboard(data.user);
      showToast('Otentikasi Berhasil', `Selamat datang kembali, ${data.user.full_name || data.user.username}!`, 'success');
    } else {
      errorText.textContent = data.error || 'Username atau Password salah!';
      errorAlert.classList.remove('hidden');

      // Shake card animation
      loginCard.classList.remove('animate-shake');
      void loginCard.offsetWidth; // trigger reflow
      loginCard.classList.add('animate-shake');
    }
  } catch (err) {
    if (window.location.protocol === 'file:') {
      errorText.textContent = 'Aplikasi dibuka via file://! Harap buka di browser: http://localhost:3000';
    } else {
      errorText.textContent = 'Gagal menghubungi server. Pastikan backend aktif (jalankan start-server.bat) di http://localhost:3000.';
    }
    errorAlert.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btnIcon.className = 'fa-solid fa-right-to-bracket';
    btnText.textContent = 'Masuk ke Konsol SOC';
  }
}

async function handleAdminLogout() {
  try {
    await authFetch('/api/auth/logout', { method: 'POST' });
  } catch (_) {}

  localStorage.removeItem('serverpulse_admin_token');
  state.adminToken = null;
  state.adminUser = null;
  showLoginScreen();
  showToast('Sign Out', 'Sesi administrator berhasil diakhiri.', 'info');
}

function togglePasswordVisibility() {
  const pwInput = document.getElementById('login-password');
  const icon = document.getElementById('icon-toggle-pw');
  if (pwInput.type === 'password') {
    pwInput.type = 'text';
    icon.className = 'fa-solid fa-eye-slash text-cyan-400';
  } else {
    pwInput.type = 'password';
    icon.className = 'fa-solid fa-eye';
  }
}

async function handleChangePassword(event) {
  event.preventDefault();
  const oldPw = document.getElementById('pw-old').value;
  const newPw = document.getElementById('pw-new').value;

  try {
    const res = await authFetch('/api/auth/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ old_password: oldPw, new_password: newPw })
    });
    const result = await res.json();
    if (res.ok && result.success) {
      showToast('Berhasil', 'Kata sandi administrator berhasil diperbarui.', 'success');
      document.getElementById('form-change-password').reset();
    } else {
      showToast('Gagal', result.error || 'Gagal mengubah kata sandi.', 'danger');
    }
  } catch (err) {
    showToast('Error', 'Gagal memproses penggantian kata sandi.', 'danger');
  }
}

// -------------------------------------------------------------------
// WEBSOCKET REAL-TIME STREAMING
// -------------------------------------------------------------------
function initWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws`;

  state.socket = new WebSocket(wsUrl);

  state.socket.onopen = () => {
    updateWsStatus(true);
  };

  state.socket.onclose = () => {
    updateWsStatus(false);
    setTimeout(initWebSocket, 3000); // Auto reconnect
  };

  state.socket.onerror = () => {
    updateWsStatus(false);
  };

  state.socket.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      handleSocketMessage(data);
    } catch (e) {
      console.error('WS Parse Error:', e);
    }
  };
}

function updateWsStatus(isConnected) {
  const badge = document.getElementById('ws-badge');
  const text = document.getElementById('ws-status-text');
  if (isConnected) {
    badge.className = 'flex items-center gap-2 px-3 py-1.5 rounded-xl bg-emerald-950/60 border border-emerald-800/60 text-emerald-400 text-xs font-mono font-medium';
    text.textContent = 'Live Connected';
  } else {
    badge.className = 'flex items-center gap-2 px-3 py-1.5 rounded-xl bg-rose-950/60 border border-rose-800/60 text-rose-400 text-xs font-mono font-medium';
    text.textContent = 'Reconnecting...';
  }
}

function handleSocketMessage(msg) {
  if (msg.type === 'ddos_incident_alert' || msg.type === 'ddos_attack_detected') {
    fetchDdosIntel();
    fetchIncidentsHistory();
    refreshAnsibleLogs();

    const isManual = msg.data.mode === 'manual' || msg.data.status === 'DETECTED';
    if (isManual) {
      showToast(
        `🚨 PERINGATAN SERANGAN TERDETEKSI (Mode Manual)`,
        `${msg.data.attack_type} aktif terdeteksi! Silakan picu Mitigasi Level ${msg.data.mitigation_level} di tab Mitigasi.`,
        'danger'
      );
    } else {
      showToast(
        `🛡️ Closed-Loop: Serangan Termitigasi (Level ${msg.data.mitigation_level})`,
        `${msg.data.attack_type} - ${msg.data.attackers_count || 1} penyerang berhasil diisolasi secara mandiri.`,
        'danger'
      );
    }
  } else if (msg.type === 'ddos_status_reset') {
    fetchDdosIntel();
    refreshAnsibleLogs();
    showToast('Pertahanan Dinormalkan', 'Status sistem kembali ke Level 0 Normal.', 'info');
  } else if (msg.type === 'closed_loop_mode_changed') {
    updateModeUI(msg.mode);
    showToast('Mode Berubah', `Mode Closed-Loop diatur ke: ${msg.mode.toUpperCase()}`, 'info');
  } else if (msg.type === 'ddos_mitigation_triggered') {
    fetchDdosIntel();
    refreshAnsibleLogs();
    showToast('Mitigasi Aktif', `Playbook Level ${msg.data.level} sukses dijalankan.`, 'success');
  }
}

// -------------------------------------------------------------------
// TAB NAVIGATION
// -------------------------------------------------------------------
function switchTab(tabId) {
  state.activeTab = tabId;
  const tabs = ['overview', 'ddos', 'mitigation', 'incidents', 'settings'];

  tabs.forEach(t => {
    const btn = document.getElementById(`nav-${t}`);
    const container = document.getElementById(`tab-${t}`);
    if (t === tabId) {
      btn.className = 'px-4 py-2 rounded-xl text-sm font-semibold bg-cyan-600/20 text-cyan-300 border border-cyan-500/30 flex items-center gap-2 transition whitespace-nowrap shadow-sm';
      container.classList.remove('hidden');
    } else {
      btn.className = 'px-4 py-2 rounded-xl text-sm font-medium text-slate-400 hover:text-white hover:bg-slate-800/60 flex items-center gap-2 transition whitespace-nowrap';
      container.classList.add('hidden');
    }
  });

  if (tabId === 'overview') {
    loadNetdataHistory(state.selectedTimeRange);
  } else if (tabId === 'ddos') {
    fetchDdosIntel();
  } else if (tabId === 'mitigation') {
    refreshAnsibleLogs();
  } else if (tabId === 'incidents') {
    fetchIncidentsHistory();
  }
}

// -------------------------------------------------------------------
// NETDATA OBSERVABILITY (zaa-virtualbox @ 192.168.56.104:19999)
// -------------------------------------------------------------------
async function syncNetdataNow() {
  const icon = document.getElementById('icon-sync');
  icon.classList.add('fa-spin');

  try {
    const res = await fetch('/api/netdata/live');
    const data = await res.json();
    if (data.success) {
      renderNetdataHostInfo(data.host_info);
      renderNetdataLiveTelemetry(data.telemetry);
    }
  } catch (err) {
    console.error('Error syncing Netdata:', err);
  } finally {
    setTimeout(() => icon.classList.remove('fa-spin'), 600);
  }
}

async function fetchNetdataLiveMetrics() {
  if (state.activeTab !== 'overview' || !state.adminToken) return;
  try {
    const res = await fetch('/api/netdata/live');
    const data = await res.json();
    if (data.success) {
      renderNetdataLiveTelemetry(data.telemetry);
    }
  } catch (err) {
    // Fail silently on polling
  }
}

function renderNetdataHostInfo(info) {
  if (!info) return;
  document.getElementById('header-target-host').textContent = `${info.hostname} (192.168.56.104)`;
  document.getElementById('nd-hostname').textContent = info.hostname;
  document.getElementById('nd-os-name').textContent = `${info.os_name} ${info.os_version}`;
  document.getElementById('nd-kernel-info').textContent = info.kernel || 'Kernel 6.8.0 x86_64';
  document.getElementById('nd-cores-info').textContent = `${info.cores_total} Core (Linux VirtualBox)`;
  document.getElementById('nd-ram-total').textContent = `${info.ram_total_gb} GB RAM Total`;
  document.getElementById('nd-version-tag').textContent = `${info.version} (1-sec sampling)`;
}

function renderNetdataLiveTelemetry(telemetry) {
  if (!telemetry) return;

  // CPU
  const cpu = telemetry.cpu || { total: 0, user: 0, system: 0, softirq: 0 };
  document.getElementById('nd-cpu-val').textContent = `${cpu.total}%`;
  document.getElementById('nd-cpu-bar').style.width = `${Math.min(100, Math.max(5, cpu.total))}%`;
  document.getElementById('nd-cpu-user').textContent = `${cpu.user}%`;
  document.getElementById('nd-cpu-sys').textContent = `${cpu.system}%`;
  document.getElementById('nd-cpu-softirq').textContent = `${cpu.softirq}%`;

  // Memory
  const ram = telemetry.ram || { percent: 0, used_gb: 0, total_gb: 3.7, free_gb: 0 };
  document.getElementById('nd-ram-val').textContent = `${ram.percent}%`;
  document.getElementById('nd-ram-bar').style.width = `${Math.min(100, Math.max(5, ram.percent))}%`;
  document.getElementById('nd-ram-used-num').textContent = `${ram.used_gb} GB`;
  document.getElementById('nd-ram-free-num').textContent = `${ram.free_gb} GB`;
  document.getElementById('nd-ram-used-detail').textContent = `Used: ${ram.used_gb} GB | Free: ${ram.free_gb} GB`;

  // Network
  const net = telemetry.net || { rx_kbps: 0, tx_kbps: 0 };
  document.getElementById('nd-net-rx').textContent = `${net.rx_kbps.toLocaleString()} KB/s`;
  document.getElementById('nd-net-tx').textContent = `${net.tx_kbps.toLocaleString()} KB/s`;

  // Alarms
  const alarms = telemetry.active_alarms || [];
  const countBadge = document.getElementById('nd-alarms-count-badge');
  const summaryBox = document.getElementById('nd-alarms-summary');
  const statusLabel = document.getElementById('nd-alarm-status');

  const criticals = alarms.filter(a => a.status === 'CRITICAL');
  if (criticals.length > 0) {
    countBadge.className = 'px-2 py-0.5 rounded-full text-[10px] font-mono bg-rose-950 text-rose-400 border border-rose-800 animate-pulse font-bold';
    countBadge.textContent = `${criticals.length} CRITICAL`;
    statusLabel.innerHTML = `<i class="fa-solid fa-triangle-exclamation text-xs text-rose-400"></i> <span class="text-rose-400">Serangan Terdeteksi (${criticals.length} Alarm)</span>`;

    summaryBox.innerHTML = criticals.map(a => `
      <div class="text-[11px] font-mono text-rose-300 flex items-center justify-between">
        <span class="truncate max-w-[200px]">${a.name}</span>
        <span class="bg-rose-900/60 px-1.5 py-0.5 rounded">${a.value || 'CRITICAL'}</span>
      </div>
    `).join('');
  } else {
    countBadge.className = 'px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800';
    countBadge.textContent = '0 Critical';
    statusLabel.innerHTML = `<i class="fa-solid fa-circle-check text-xs text-emerald-400"></i> <span class="text-emerald-400">Normal (Semua Metrik Aman)</span>`;
    summaryBox.innerHTML = `
      <div class="flex items-center gap-2 text-emerald-400 font-semibold text-xs">
        <i class="fa-solid fa-shield-heart text-sm"></i>
        <span>Seluruh threshold lalu lintas dalam batas wajar</span>
      </div>
    `;
  }
}

// -------------------------------------------------------------------
// TIME RANGE SCRUBBER (-5m, -15m, -1h, -6h, -24h)
// -------------------------------------------------------------------
function switchTimeRange(seconds) {
  state.selectedTimeRange = seconds;
  const ranges = [-300, -900, -3600, -21600, -86400];

  ranges.forEach(r => {
    const btn = document.getElementById(`btn-range-${Math.abs(r)}`);
    if (btn) {
      if (r === seconds) {
        btn.className = 'px-3 py-1.5 rounded-xl text-xs font-semibold bg-cyan-600 text-white shadow-lg shadow-cyan-600/30 transition';
      } else {
        btn.className = 'px-3 py-1.5 rounded-xl text-xs font-medium text-slate-400 hover:text-white transition';
      }
    }
  });

  loadNetdataHistory(seconds);
}

async function loadNetdataHistory(afterSeconds) {
  try {
    const [cpuRes, netRes] = await Promise.all([
      fetch(`/api/netdata/history?chart=system.cpu&after=${afterSeconds}&points=40`),
      fetch(`/api/netdata/history?chart=system.net&after=${afterSeconds}&points=40`)
    ]);

    const cpuData = await cpuRes.json();
    const netData = await netRes.json();

    updateNetdataCpuChart(cpuData);
    updateNetdataNetChart(netData);
  } catch (err) {
    console.error('Failed to load Netdata history charts:', err);
  }
}

// -------------------------------------------------------------------
// CLOSED-LOOP MODE TOGGLE (AUTO vs MANUAL)
// -------------------------------------------------------------------
async function toggleClosedLoopMode() {
  const newMode = state.closedLoopMode === 'auto' ? 'manual' : 'auto';
  try {
    const res = await authFetch('/api/ddos/mode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: newMode })
    });
    const result = await res.json();
    if (res.ok && result.success) {
      updateModeUI(result.mode);
      showToast('Mode Diperbarui', result.message, 'success');
    } else {
      showToast('Akses Ditolak', result.error || 'Autentikasi admin diperlukan.', 'danger');
    }
  } catch (err) {
    showToast('Error', 'Gagal mengubah mode Closed-Loop.', 'danger');
  }
}

function updateModeUI(mode) {
  state.closedLoopMode = mode;
  const btn = document.getElementById('btn-toggle-mode');
  const textState = document.getElementById('text-mode-state');
  const bannerPill = document.getElementById('banner-mode-pill');

  if (mode === 'auto') {
    btn.className = 'px-3.5 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-2 transition border bg-emerald-950/60 border-emerald-600/40 text-emerald-300 hover:bg-emerald-900/60 active:scale-95 shadow-sm';
    textState.textContent = 'CLOSED-LOOP OTOMATIS';
    bannerPill.className = 'text-xs font-mono px-2.5 py-0.5 bg-emerald-950 text-emerald-300 border border-emerald-800 rounded-full';
    bannerPill.textContent = 'Mode: OTOMATIS';
  } else {
    btn.className = 'px-3.5 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-2 transition border bg-amber-950/60 border-amber-600/40 text-amber-300 hover:bg-amber-900/60 active:scale-95 shadow-sm';
    textState.textContent = 'MANUAL OVERRIDE';
    bannerPill.className = 'text-xs font-mono px-2.5 py-0.5 bg-amber-950 text-amber-300 border border-amber-800 rounded-full';
    bannerPill.textContent = 'Mode: MANUAL OVERRIDE';
  }
}

// -------------------------------------------------------------------
// ATTACKER INTEL & DEVICE FORENSICS
// -------------------------------------------------------------------
async function fetchDdosIntel() {
  try {
    const [statsRes, deviceRes, hourlyRes] = await Promise.all([
      fetch('/api/ddos/stats'),
      fetch('/api/ddos/device-stats'),
      fetch('/api/ddos/hourly-stats')
    ]);

    const stats = await statsRes.json();
    const deviceStats = await deviceRes.json();
    const hourlyStats = await hourlyRes.json();

    renderDdosKpiStats(stats, deviceStats);
    renderDeviceDistributionChart(deviceStats);
    renderHourlyAttacksChart(hourlyStats);
    fetchAttackersTable();
  } catch (err) {
    console.error('Failed to fetch DDoS Threat Intel:', err);
  }
}

function renderDdosKpiStats(stats, deviceStats) {
  // KPI Cards
  document.getElementById('stat-ddos-total-incidents').textContent = (stats.total_incidents || 0).toLocaleString();
  document.getElementById('stat-ddos-blocked-attackers').textContent = (stats.total_attackers_blocked || 0).toLocaleString();
  
  // Top Device
  if (deviceStats && deviceStats.distribution && deviceStats.distribution.length > 0) {
    const top = deviceStats.distribution[0];
    document.getElementById('stat-ddos-top-device').textContent = top.os || 'Windows 11';
    document.getElementById('stat-ddos-device-percent').textContent = `${top.percentage}% dari seluruh serangan`;
  }

  // Active Mitigation Level
  const lvl = stats.current_defense_level || 0;
  document.getElementById('stat-ddos-active-level').textContent = `Level ${lvl}`;
  const descEl = document.getElementById('stat-ddos-active-level-desc');

  const pill = document.getElementById('ddos-status-pill');
  const badgeLevel = document.getElementById('badge-ddos-level');

  if (lvl === 0) {
    pill.className = 'px-4 py-2.5 rounded-2xl bg-emerald-950/70 border border-emerald-800 text-emerald-400 flex items-center gap-2.5 text-sm font-bold shadow-lg';
    pill.innerHTML = `<span class="w-3 h-3 rounded-full bg-emerald-400 animate-ping"></span><span>STATUS: NORMAL (LEVEL 0)</span>`;
    descEl.textContent = 'Pertahanan Pasif Normal';
    badgeLevel.classList.add('hidden');
  } else if (lvl === 1) {
    pill.className = 'px-4 py-2.5 rounded-2xl bg-cyan-950/70 border border-cyan-800 text-cyan-300 flex items-center gap-2.5 text-sm font-bold shadow-lg';
    pill.innerHTML = `<span class="w-3 h-3 rounded-full bg-cyan-400 animate-ping"></span><span>MITIGASI: LEVEL 1 (L3 RATE-LIMIT)</span>`;
    descEl.textContent = 'IPTables ICMP Rate-Limit Aktif';
    badgeLevel.textContent = 'L1';
    badgeLevel.classList.remove('hidden');
  } else if (lvl === 2) {
    pill.className = 'px-4 py-2.5 rounded-2xl bg-rose-950/70 border border-rose-800 text-rose-300 flex items-center gap-2.5 text-sm font-bold shadow-lg';
    pill.innerHTML = `<span class="w-3 h-3 rounded-full bg-rose-400 animate-ping"></span><span>MITIGASI: LEVEL 2 (SYN DROP)</span>`;
    descEl.textContent = 'Kernel ipset Dropping SYN Malicious IPs';
    badgeLevel.textContent = 'L2';
    badgeLevel.classList.remove('hidden');
  } else if (lvl === 3) {
    pill.className = 'px-4 py-2.5 rounded-2xl bg-purple-950/70 border border-purple-800 text-purple-300 flex items-center gap-2.5 text-sm font-bold shadow-lg animate-pulse';
    pill.innerHTML = `<span class="w-3 h-3 rounded-full bg-purple-400 animate-ping"></span><span>MITIGASI: LEVEL 3 (L7 THROTTLE)</span>`;
    descEl.textContent = 'Nginx Dynamic Throttling & Self-Healing Active';
    badgeLevel.textContent = 'L3';
    badgeLevel.classList.remove('hidden');
  }
}

async function fetchAttackersTable() {
  try {
    const params = new URLSearchParams();
    if (state.selectedOsFilter !== 'all') params.append('os', state.selectedOsFilter);
    if (state.searchQuery.trim().length > 0) params.append('search', state.searchQuery.trim());
    params.append('limit', 100);

    const res = await fetch(`/api/ddos/attackers?${params.toString()}`);
    const attackers = await res.json();
    renderAttackersTable(attackers);
  } catch (err) {
    console.error('Error fetching attackers table:', err);
  }
}

function renderAttackersTable(attackers) {
  const tbody = document.getElementById('attackers-table-body');
  if (!attackers || attackers.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="9" class="py-12 text-center text-slate-500 font-sans">
          <i class="fa-solid fa-shield-check text-3xl text-emerald-500 mb-3 block"></i>
          Sistem dalam status aman. Tidak ada profil penyerang yang cocok dengan kriteria filter.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = attackers.map(a => {
    // OS Badge Styling
    let badgeClass = 'badge-os badge-windows';
    let iconClass = 'fa-brands fa-windows text-sky-400';
    const osName = a.device_os || 'Windows 11';

    if (osName.includes('Linux') || osName.includes('Ubuntu')) {
      badgeClass = 'badge-os badge-linux';
      iconClass = 'fa-brands fa-linux text-amber-400';
    } else if (osName.includes('macOS') || osName.includes('Mac')) {
      badgeClass = 'badge-os badge-macos';
      iconClass = 'fa-brands fa-apple text-purple-400';
    } else if (osName.includes('Android')) {
      badgeClass = 'badge-os badge-android';
      iconClass = 'fa-brands fa-android text-emerald-400';
    } else if (osName.includes('Bot') || osName.includes('Script') || osName.includes('hping') || osName.includes('LOIC')) {
      badgeClass = 'badge-os badge-bot';
      iconClass = 'fa-solid fa-robot text-rose-400';
    }

    // Country Flag Emoji Helper
    const flag = getFlagEmoji(a.country_code);

    // Relative Time calculation
    const elapsedMinutes = Math.max(0, Math.round((Date.now() - a.created_at) / 60000));
    const relTime = elapsedMinutes < 1 ? 'Baru saja' : `${elapsedMinutes} mnt lalu`;

    return `
      <tr class="hover:bg-slate-800/40 transition">
        <td class="py-3 px-4 text-slate-200">
          <div class="font-bold text-xs text-white">${a.day_name || 'Rabu'}</div>
          <div class="text-[11px] text-slate-400 font-sans">${a.attack_date || '-'}</div>
        </td>
        <td class="py-3 px-4">
          <div class="font-bold text-rose-300 font-mono text-xs">${a.attack_time || '-'}</div>
          <span class="text-[10px] text-slate-500 font-sans">${relTime}</span>
        </td>
        <td class="py-3 px-4 font-bold text-white flex items-center gap-1.5 pt-4">
          <i class="fa-solid fa-ban text-rose-500 text-xs"></i>
          <span class="text-rose-400 font-mono">${a.ip_address}</span>
        </td>
        <td class="py-3 px-4">
          <span class="${badgeClass}">
            <i class="${iconClass}"></i> <span>${osName}</span>
          </span>
        </td>
        <td class="py-3 px-4">
          <span class="px-2 py-0.5 rounded-md bg-slate-900 border border-slate-700/80 text-cyan-300 font-mono text-[11px] font-semibold">
            Port ${a.target_port || 80}
          </span>
        </td>
        <td class="py-3 px-4 font-sans text-xs">
          <div class="text-slate-200 font-medium flex items-center gap-1">
            <span>${flag}</span> <span>${a.country || 'Unknown'}</span>
          </div>
          <div class="text-[10px] text-slate-400 truncate max-w-[160px]" title="${a.asn_org || a.isp}">
            ${a.asn_number || ''} ${a.asn_org || a.isp || ''}
          </div>
        </td>
        <td class="py-3 px-4 text-amber-300 font-sans text-xs font-medium">
          ${a.attack_vector || 'HTTP Flood'}
        </td>
        <td class="py-3 px-4 text-right text-white font-mono font-bold text-xs">
          ${(a.request_count || 1).toLocaleString()}
        </td>
        <td class="py-3 px-4 text-center">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-950 text-rose-300 border border-rose-800">
            ${a.action_taken || 'BLOCKED_IPSET'}
          </span>
        </td>
      </tr>
    `;
  }).join('');
}

function getFlagEmoji(countryCode) {
  if (!countryCode || countryCode === 'XX') return '🌐';
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map(char => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

// OS Filter buttons
function filterByOs(osType) {
  state.selectedOsFilter = osType;
  const osButtons = ['all', 'Windows', 'Linux', 'macOS', 'Android', 'Bot'];

  osButtons.forEach(os => {
    const btn = document.getElementById(`btn-os-${os}`);
    if (btn) {
      if (os === osType) {
        btn.className = 'px-2.5 py-1 rounded-lg text-xs font-semibold bg-cyan-600 text-white transition';
      } else {
        btn.className = 'px-2.5 py-1 rounded-lg text-xs font-medium text-slate-400 hover:text-white bg-slate-900 border border-slate-800 transition';
      }
    }
  });

  fetchAttackersTable();
}

let searchTimer = null;
function handleAttackerSearch(event) {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    state.searchQuery = event.target.value;
    fetchAttackersTable();
  }, 250);
}

// -------------------------------------------------------------------
// FORENSIC DATA EXPORT (CSV / JSON)
// -------------------------------------------------------------------
function exportForensicLogs(format = 'csv') {
  showToast('Mengunduh Laporan', `Menyiapkan berkas forensik .${format.toUpperCase()}...`, 'info');
  const url = `/api/ddos/export?format=${format}`;
  
  const a = document.createElement('a');
  a.href = url;
  a.download = `forensik_penyerang_ddos.${format}`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

// -------------------------------------------------------------------
// SIMULATION & DEFENSE RESET (REQUIRES AUTH)
// -------------------------------------------------------------------
async function simulateDdosAttack() {
  try {
    showToast('Memulai Simulasi', 'Menginjeksi skenario serangan multi-perangkat...', 'info');
    const res = await authFetch('/api/ddos/simulate', { method: 'POST' });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast('Simulasi Berhasil!', `Insiden ${data.incident_id} terdeteksi. 6 IP penyerang heterogen diisolasi.`, 'success');
      fetchDdosIntel();
      refreshAnsibleLogs();
    } else {
      showToast('Akses Ditolak', data.error || 'Sesi admin tidak valid. Silakan login kembali.', 'danger');
    }
  } catch (err) {
    showToast('Error', 'Gagal memicu simulasi serangan.', 'danger');
  }
}

async function resetDdosDefense() {
  try {
    const res = await authFetch('/api/ddos/recovery', { method: 'POST' });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast('Pertahanan Dinormalkan', 'Seluruh rule sementara dibersihkan. Status kembali ke Level 0.', 'success');
      fetchDdosIntel();
      refreshAnsibleLogs();
    } else {
      showToast('Akses Ditolak', data.error || 'Sesi admin tidak valid.', 'danger');
    }
  } catch (err) {
    showToast('Error', 'Gagal mereset pertahanan.', 'danger');
  }
}

// -------------------------------------------------------------------
// 3-LEVEL MITIGATION CONTROL PANEL (REQUIRES AUTH)
// -------------------------------------------------------------------
async function triggerManualMitigation(level) {
  try {
    showToast('Mengeksekusi Playbook', `Menjalankan remedi mitigasi Level ${level} via Ansible...`, 'info');
    const res = await authFetch('/api/ddos/mitigate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ level })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast('Mitigasi Berhasil!', `Level ${level} aktif. Playbook ${data.mitigation.playbook} selesai.`, 'success');
      fetchDdosIntel();
      refreshAnsibleLogs();
    } else {
      showToast('Akses Ditolak', data.error || 'Autentikasi admin diperlukan.', 'danger');
    }
  } catch (err) {
    showToast('Error', 'Gagal mengeksekusi mitigasi.', 'danger');
  }
}

async function triggerRecoveryLoop() {
  await resetDdosDefense();
}

async function refreshAnsibleLogs() {
  try {
    const res = await fetch('/api/ddos/logs');
    const logs = await res.json();
    const container = document.getElementById('ansible-terminal-log');

    if (!logs || logs.length === 0) {
      container.innerHTML = `<div class="text-slate-500">Belum ada aktivitas Ansible yang tercatat. Sistem siap memitigasi.</div>`;
      return;
    }

    container.innerHTML = logs.map(l => {
      let color = 'text-slate-300';
      if (l.level === 1) color = 'text-cyan-400';
      else if (l.level === 2) color = 'text-rose-400';
      else if (l.level === 3) color = 'text-purple-400';
      else if (l.level === 0) color = 'text-emerald-400';

      return `
        <div class="flex items-start gap-2">
          <span class="text-slate-500 font-mono text-[11px] whitespace-nowrap">[${l.timeStr}]</span>
          <span class="${color} font-mono text-xs leading-relaxed">${escapeHtml(l.message)}</span>
        </div>
      `;
    }).join('');
  } catch (err) {
    console.error('Error fetching Ansible logs:', err);
  }
}

// -------------------------------------------------------------------
// INCIDENTS HISTORY
// -------------------------------------------------------------------
async function fetchIncidentsHistory() {
  try {
    const res = await fetch('/api/ddos/incidents?limit=25');
    const incidents = await res.json();
    const tbody = document.getElementById('incidents-history-table-body');

    if (!incidents || incidents.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="py-10 text-center text-slate-500 font-sans">Belum ada riwayat insiden tercatat.</td></tr>`;
      return;
    }

    tbody.innerHTML = incidents.map(inc => {
      let lvlBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-cyan-950 text-cyan-400 border border-cyan-800">Level 1</span>';
      if (inc.mitigation_level === 2) {
        lvlBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-rose-950 text-rose-400 border border-rose-800 font-bold">Level 2 (ipset)</span>';
      } else if (inc.mitigation_level === 3) {
        lvlBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-purple-950 text-purple-400 border border-purple-800 font-bold">Level 3 (Self-Heal)</span>';
      }

      const statusBadge = inc.status === 'SELF_HEALED'
        ? `<span class="text-emerald-400 font-semibold"><i class="fa-solid fa-circle-check mr-1"></i> Self-Healed</span>`
        : `<span class="text-rose-400 font-bold animate-pulse"><i class="fa-solid fa-triangle-exclamation mr-1"></i> Active</span>`;

      return `
        <tr class="hover:bg-slate-800/40 transition">
          <td class="py-3 px-6 text-white font-bold font-mono">${inc.incident_id}</td>
          <td class="py-3 px-6 text-slate-300 font-sans">${inc.attack_type}</td>
          <td class="py-3 px-6">${lvlBadge}</td>
          <td class="py-3 px-6 text-purple-300 font-mono">${inc.confidence_score}%</td>
          <td class="py-3 px-6 font-sans">${statusBadge}</td>
          <td class="py-3 px-6 text-slate-300 font-mono">${inc.attackers ? inc.attackers.length : 0} IP</td>
          <td class="py-3 px-6 text-slate-400 font-sans">${new Date(inc.created_at).toLocaleString('id-ID')}</td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.error('Error fetching incidents:', err);
  }
}

// -------------------------------------------------------------------
// SETTINGS
// -------------------------------------------------------------------
async function fetchSettings() {
  try {
    const res = await fetch('/api/settings');
    const cfg = await res.json();
    if (cfg.netdata_host) document.getElementById('setting-netdata-host').value = cfg.netdata_host;
    if (cfg.telegram_bot_token) document.getElementById('setting-tg-token').value = cfg.telegram_bot_token;
    if (cfg.telegram_chat_id) document.getElementById('setting-tg-chatid').value = cfg.telegram_chat_id;
    if (cfg.discord_webhook_url) document.getElementById('setting-discord-url').value = cfg.discord_webhook_url;
    if (cfg.closed_loop_mode) updateModeUI(cfg.closed_loop_mode);
  } catch (err) {
    console.error('Failed to fetch settings:', err);
  }
}

async function saveAllSettings() {
  const payload = {
    netdata_host: document.getElementById('setting-netdata-host').value.trim(),
    telegram_bot_token: document.getElementById('setting-tg-token').value.trim(),
    telegram_chat_id: document.getElementById('setting-tg-chatid').value.trim(),
    discord_webhook_url: document.getElementById('setting-discord-url').value.trim()
  };

  try {
    const res = await authFetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const result = await res.json();
    if (res.ok && result.message) {
      showToast('Berhasil', 'Pengaturan berhasil disimpan ke basis data.', 'success');
    } else {
      showToast('Akses Ditolak', result.error || 'Autentikasi admin diperlukan.', 'danger');
    }
  } catch (err) {
    showToast('Error', 'Gagal menyimpan pengaturan.', 'danger');
  }
}

async function testNotificationAlert() {
  try {
    showToast('Mengirim Notifikasi Uji Coba...', 'Menghubungi Telegram & Discord Webhook...', 'info');
    const res = await fetch('/api/alerts/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        telegram_token: document.getElementById('setting-tg-token').value.trim(),
        telegram_chat_id: document.getElementById('setting-tg-chatid').value.trim(),
        discord_url: document.getElementById('setting-discord-url').value.trim()
      })
    });
    const result = await res.json();
    if (result.telegram || result.discord) {
      showToast('Terkirim!', `Notifikasi berhasil dikirim (Telegram: ${result.telegram ? 'OK' : 'No'}, Discord: ${result.discord ? 'OK' : 'No'})`, 'success');
    } else {
      showToast('Gagal', result.errors ? result.errors.join(', ') : 'Periksa kembali Token atau URL Webhook Anda.', 'danger');
    }
  } catch (err) {
    showToast('Error', 'Gagal menguji notifikasi.', 'danger');
  }
}

// -------------------------------------------------------------------
// CHART.JS INITIALIZATION & UPDATES
// -------------------------------------------------------------------
function initThemeCharts() {
  Chart.defaults.color = '#94a3b8';
  Chart.defaults.font.family = "'JetBrains Mono', monospace";
  Chart.defaults.font.size = 11;
  Chart.defaults.borderColor = 'rgba(30, 41, 59, 0.4)';

  // 1. Netdata CPU Chart
  const ctxNdCpu = document.getElementById('chart-netdata-cpu').getContext('2d');
  state.charts.netdataCpu = new Chart(ctxNdCpu, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'User Space (%)',
          data: [],
          borderColor: '#06b6d4',
          backgroundColor: 'rgba(6, 182, 212, 0.1)',
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 0
        },
        {
          label: 'System Kernel (%)',
          data: [],
          borderColor: '#3b82f6',
          backgroundColor: 'rgba(59, 130, 246, 0.05)',
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 0
        },
        {
          label: 'SoftIRQ (DDoS Traffic) (%)',
          data: [],
          borderColor: '#f43f5e',
          backgroundColor: 'rgba(244, 63, 94, 0.15)',
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 0
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'top', labels: { boxWidth: 12, color: '#cbd5e1' } },
        tooltip: { mode: 'index', intersect: false }
      },
      scales: {
        y: { beginAtZero: true, max: 100, grid: { color: 'rgba(30, 41, 59, 0.5)' } },
        x: { grid: { display: false } }
      }
    }
  });

  // 2. Netdata Network Chart
  const ctxNdNet = document.getElementById('chart-netdata-net').getContext('2d');
  state.charts.netdataNet = new Chart(ctxNdNet, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Inbound / RX (KB/s)',
          data: [],
          borderColor: '#10b981',
          backgroundColor: 'rgba(16, 185, 129, 0.15)',
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 0
        },
        {
          label: 'Outbound / TX (KB/s)',
          data: [],
          borderColor: '#8b5cf6',
          backgroundColor: 'rgba(139, 92, 246, 0.05)',
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 0
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'top', labels: { boxWidth: 12, color: '#cbd5e1' } },
        tooltip: { mode: 'index', intersect: false }
      },
      scales: {
        y: { beginAtZero: true, grid: { color: 'rgba(30, 41, 59, 0.5)' } },
        x: { grid: { display: false } }
      }
    }
  });

  // 3. Attacker Device Distribution Doughnut
  const ctxDevice = document.getElementById('chart-device-distribution').getContext('2d');
  state.charts.deviceDistribution = new Chart(ctxDevice, {
    type: 'doughnut',
    data: {
      labels: ['Windows', 'Linux', 'macOS', 'Android', 'Bots & Scripts'],
      datasets: [{
        data: [40, 25, 15, 10, 10],
        backgroundColor: [
          '#38bdf8', // Windows Sky
          '#fbbf24', // Linux Amber
          '#c084fc', // macOS Purple
          '#34d399', // Android Emerald
          '#fb7185'  // Bots Rose
        ],
        borderWidth: 0,
        hoverOffset: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '72%',
      plugins: {
        legend: { position: 'bottom', labels: { boxWidth: 10, color: '#cbd5e1', padding: 12 } }
      }
    }
  });

  // 4. Hourly Attack Distribution Bar Chart
  const ctxHourly = document.getElementById('chart-hourly-attacks').getContext('2d');
  state.charts.hourlyAttacks = new Chart(ctxHourly, {
    type: 'bar',
    data: {
      labels: Array.from({ length: 24 }, (_, i) => `${String(i).padStart(2, '0')}:00`),
      datasets: [{
        label: 'Frekuensi Serangan (Hits)',
        data: Array(24).fill(0),
        backgroundColor: 'rgba(244, 63, 94, 0.65)',
        hoverBackgroundColor: '#f43f5e',
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            title: (items) => `Waktu Penyerangan: ${items[0].label} WIB`,
            label: (item) => `Total Insiden / Hits: ${item.formattedValue}`
          }
        }
      },
      scales: {
        y: { beginAtZero: true, grid: { color: 'rgba(30, 41, 59, 0.5)' } },
        x: { grid: { display: false }, ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 12 } }
      }
    }
  });
}

function updateNetdataCpuChart(data) {
  if (!state.charts.netdataCpu || !data.labels) return;
  state.charts.netdataCpu.data.labels = data.labels;
  
  if (data.series) {
    state.charts.netdataCpu.data.datasets[0].data = data.series.user || [];
    state.charts.netdataCpu.data.datasets[1].data = data.series.system || [];
    state.charts.netdataCpu.data.datasets[2].data = data.series.softirq || [];
  }
  state.charts.netdataCpu.update();
}

function updateNetdataNetChart(data) {
  if (!state.charts.netdataNet || !data.labels) return;
  state.charts.netdataNet.data.labels = data.labels;

  if (data.series) {
    const inData = data.series.InOctets || data.series.received || [];
    const outData = data.series.OutOctets || data.series.sent || [];
    state.charts.netdataNet.data.datasets[0].data = inData.map(v => Math.abs(v));
    state.charts.netdataNet.data.datasets[1].data = outData.map(v => Math.abs(v));
  }
  state.charts.netdataNet.update();
}

function renderDeviceDistributionChart(deviceStats) {
  if (!state.charts.deviceDistribution || !deviceStats) return;

  const labels = [];
  const counts = [];
  const dist = deviceStats.distribution || [];

  let winPct = 0, linPct = 0, macPct = 0;

  for (const d of dist) {
    labels.push(d.os);
    counts.push(d.count);
    if (d.os === 'Windows') winPct = d.percentage;
    if (d.os === 'Linux') linPct = d.percentage;
    if (d.os === 'macOS') macPct = d.percentage;
  }

  document.getElementById('sum-os-windows').textContent = `${winPct}%`;
  document.getElementById('sum-os-linux').textContent = `${linPct}%`;
  document.getElementById('sum-os-macos').textContent = `${macPct}%`;

  if (counts.length > 0) {
    state.charts.deviceDistribution.data.labels = labels;
    state.charts.deviceDistribution.data.datasets[0].data = counts;
    state.charts.deviceDistribution.update();
  }
}

function renderHourlyAttacksChart(hourlyStats) {
  if (!state.charts.hourlyAttacks || !Array.isArray(hourlyStats)) return;

  const labels = hourlyStats.map(h => h.hour);
  const data = hourlyStats.map(h => h.hits);

  state.charts.hourlyAttacks.data.labels = labels;
  state.charts.hourlyAttacks.data.datasets[0].data = data;
  state.charts.hourlyAttacks.update();
}

// -------------------------------------------------------------------
// UTILITIES: TOAST NOTIFICATIONS & SANITIZATION
// -------------------------------------------------------------------
function showToast(title, message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');

  let borderColor = 'border-cyan-500/50 text-cyan-300';
  let icon = 'fa-circle-info';
  if (type === 'success') {
    borderColor = 'border-emerald-500/50 text-emerald-300';
    icon = 'fa-circle-check';
  } else if (type === 'danger') {
    borderColor = 'border-rose-500/50 text-rose-300';
    icon = 'fa-triangle-exclamation';
  }

  toast.className = `p-4 rounded-2xl bg-[#0d1322]/95 border ${borderColor} backdrop-blur-md shadow-2xl flex items-start gap-3 pointer-events-auto transition transform animate-scaleUp`;
  toast.innerHTML = `
    <i class="fa-solid ${icon} text-base mt-0.5"></i>
    <div class="flex-1">
      <h5 class="text-xs font-bold text-white">${escapeHtml(title)}</h5>
      <p class="text-[11px] text-slate-300 mt-0.5 leading-snug">${escapeHtml(message)}</p>
    </div>
  `;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => toast.remove(), 300);
  }, 4500);
}

function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
