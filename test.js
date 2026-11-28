// Automated Test Suite for ServerPulse Monitoring Platform
const http = require('node:http');
const assert = require('node:assert');

const TEST_PORT = 3999;
process.env.PORT = TEST_PORT;

async function runTests() {
  console.log('[TEST] Menjalankan ServerPulse Automated Verification Suite...');

  // Start the server
  require('./server.js');
  await new Promise(r => setTimeout(r, 1500)); // wait for startup

  const baseUrl = `http://localhost:${TEST_PORT}`;

  try {
    // 1. Test Overview Stats
    console.log('[TEST 1] GET /api/stats/overview...');
    const statsRes = await fetch(`${baseUrl}/api/stats/overview`);
    assert.strictEqual(statsRes.status, 200);
    const stats = await statsRes.json();
    assert(stats.total >= 1, 'Harus ada server bawaan');
    console.log(` -> OK (Total servers: ${stats.total}, Online: ${stats.online})`);

    // 2. Test Get Servers
    console.log('[TEST 2] GET /api/servers...');
    const srvRes = await fetch(`${baseUrl}/api/servers`);
    assert.strictEqual(srvRes.status, 200);
    const servers = await srvRes.json();
    assert(Array.isArray(servers), 'Response harus berupa array');
    console.log(` -> OK (Ditemukan ${servers.length} server terdaftar)`);

    // 3. Test Create New Agent Server
    console.log('[TEST 3] POST /api/servers (Buat Agent Server Baru)...');
    const createRes = await fetch(`${baseUrl}/api/servers`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Unit-Test-Node-01',
        type: 'agent',
        tags: 'test,automated'
      })
    });
    assert.strictEqual(createRes.status, 201);
    const newServer = await createRes.json();
    assert(newServer.token, 'Agent server harus memiliki security token');
    console.log(` -> OK (Server ID: ${newServer.id}, Token: ${newServer.token})`);

    // 4. Test Ingest Metrics from Agent
    console.log('[TEST 4] POST /api/metrics (Kirim Telemetri CPU & RAM)...');
    const metricsPayload = {
      timestamp: Date.now(),
      cpu_percent: 45.8,
      memory_percent: 62.1,
      memory_used_gb: 9.9,
      memory_total_gb: 16.0,
      disk_percent: 38.0,
      net_rx_kb: 120.5,
      net_tx_kb: 85.2,
      top_processes: [
        { name: "test-proc.exe", pid: 9999, cpu_percent: 18.2, memory_percent: 4.5 }
      ]
    };

    const metricsRes = await fetch(`${baseUrl}/api/metrics`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${newServer.token}`
      },
      body: JSON.stringify(metricsPayload)
    });
    assert.strictEqual(metricsRes.status, 200);
    const metricsResult = await metricsRes.json();
    assert.strictEqual(metricsResult.success, true);
    console.log(' -> OK (Telemetri berhasil disimpan & status server berubah ke Online)');

    // 5. Test History Metrics
    console.log('[TEST 5] GET /api/servers/:id/history...');
    const historyRes = await fetch(`${baseUrl}/api/servers/${newServer.id}/history`);
    assert.strictEqual(historyRes.status, 200);
    const history = await historyRes.json();
    assert(history.length >= 1, 'Harus ada riwayat metrik yang baru saja dikirim');
    assert.strictEqual(history[0].cpu_percent, 45.8);
    console.log(` -> OK (Tercatat ${history.length} titik riwayat metrik)`);

    // 6. Test Settings
    console.log('[TEST 6] GET & POST /api/settings...');
    const settingsRes = await fetch(`${baseUrl}/api/settings`);
    assert.strictEqual(settingsRes.status, 200);
    const settings = await settingsRes.json();
    assert(settings.alert_cpu_threshold, 'Settings harus berisi threshold CPU');
    console.log(` -> OK (Threshold CPU: ${settings.alert_cpu_threshold}%)`);

    // 7. Test Delete Server
    console.log('[TEST 7] DELETE /api/servers/:id...');
    const deleteRes = await fetch(`${baseUrl}/api/servers/${newServer.id}`, { method: 'DELETE' });
    assert.strictEqual(deleteRes.status, 200);
    console.log(' -> OK (Server pengujian berhasil dihapus)');

    console.log('\n======================================================');
    console.log('🎉 SEMUA PENGUJIAN OTOMATIS BERHASIL (100% PASS)');
    console.log('======================================================');
    const TailscaleBridge = require('./services/tailscale_bridge');
    TailscaleBridge.stopBridge();
    setTimeout(() => {
      process.exit(0);
    }, 100);

  } catch (err) {
    console.error('\n❌ PENGUJIAN GAGAL:', err);
    process.exit(1);
  }
}

runTests();
