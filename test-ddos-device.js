// Comprehensive Verification Test Suite
// Verifies Netdata Telemetry, Multi-Device Attacker Forensics (Windows, Linux, Mac, Bot),
// Precise Timestamps (Hari, Tanggal, Jam WIB), 3-Level Mitigation & Export

const assert = require('node:assert');

const TEST_PORT = 3995;
process.env.PORT = TEST_PORT;

async function runTests() {
  console.log('================================================================');
  console.log('🧪 Memulai Pengujian Sistem ServerPulse Cyber-SOC & Forensik DDoS');
  console.log('================================================================');

  // Start the server
  require('./server.js');
  await new Promise(r => setTimeout(r, 2000)); // wait for server startup

  const baseUrl = `http://localhost:${TEST_PORT}`;

  try {
    // -------------------------------------------------------------
    // TEST 1: Netdata Live Telemetry Endpoint
    // -------------------------------------------------------------
    console.log('\n[TEST 1] GET /api/netdata/live (Koneksi & Telemetri Netdata VM)...');
    const ndLiveRes = await fetch(`${baseUrl}/api/netdata/live`);
    assert.strictEqual(ndLiveRes.status, 200, 'Status harus 200 OK');
    const ndLive = await ndLiveRes.json();
    assert.strictEqual(ndLive.success, true);
    assert(ndLive.host_info, 'Harus memiliki host_info');
    assert(ndLive.telemetry, 'Harus memiliki data telemetri live');
    console.log(` -> OK (Host: ${ndLive.host_info.hostname}, OS: ${ndLive.host_info.os_name}, CPU: ${ndLive.telemetry.cpu.total}%)`);

    // -------------------------------------------------------------
    // TEST 2: Netdata Historical Scrubbing (15-min -900s)
    // -------------------------------------------------------------
    console.log('\n[TEST 2] GET /api/netdata/history?after=-900 (Scrubbing 15 Menit)...');
    const ndHistRes = await fetch(`${baseUrl}/api/netdata/history?chart=system.cpu&after=-900&points=30`);
    assert.strictEqual(ndHistRes.status, 200);
    const ndHist = await ndHistRes.json();
    assert(Array.isArray(ndHist.labels), 'Labels harus berupa array');
    console.log(` -> OK (Terkumpul ${ndHist.labels.length} titik sampel historis)`);

    // -------------------------------------------------------------
    // TEST 3: Ingest Multi-Device Attack Incident
    // -------------------------------------------------------------
    console.log('\n[TEST 3] POST /api/ddos/incident (Ingest Multi-Device Attacker Forensics)...');
    const incidentPayload = {
      incident_id: 'TEST-SOC-001',
      attack_type: 'Distributed Heterogeneous DDoS Flood (L3, L4, L7)',
      mitigation_level: 2,
      confidence_score: 99.7,
      status: 'SELF_HEALED',
      ai_summary: 'Gemini Threat Engine mendeteksi serangan multi-platform serentak menyasar port 80 dan 443.',
      attackers: [
        {
          ip: '198.51.100.22',
          country: 'United States',
          country_code: 'US',
          isp: 'DigitalOcean Cloud Network',
          asn_number: 'AS14061',
          asn_org: 'DigitalOcean, LLC',
          target_port: 80,
          request_count: 5500,
          attack_vector: 'HTTP GET Flood',
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
          device_os: 'Windows 11',
          device_type: 'desktop',
          action_taken: 'BLOCKED_IPSET'
        },
        {
          ip: '203.0.113.44',
          country: 'Russia',
          country_code: 'RU',
          isp: 'Rostelecom',
          asn_number: 'AS12389',
          asn_org: 'Rostelecom Backbone',
          target_port: 443,
          request_count: 4200,
          attack_vector: 'TCP SYN Flood',
          user_agent: 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Firefox/115.0',
          device_os: 'Linux (Debian / Kali)',
          device_type: 'desktop',
          action_taken: 'BLOCKED_IPSET'
        },
        {
          ip: '114.122.99.11',
          country: 'Indonesia',
          country_code: 'ID',
          isp: 'PT Telkom Indonesia',
          asn_number: 'AS7713',
          asn_org: 'Telkomsel Mobile Network',
          target_port: 80,
          request_count: 3100,
          attack_vector: 'HTTP Flood',
          user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
          device_os: 'macOS Sonoma',
          device_type: 'desktop',
          action_taken: 'BLOCKED_IPSET'
        },
        {
          ip: '192.168.56.99',
          country: 'Local Lab',
          country_code: 'ID',
          isp: 'VirtualBox Lab Host',
          asn_number: 'AS-LAB',
          asn_org: 'Host-Only Network',
          target_port: 80,
          request_count: 9900,
          attack_vector: 'ICMP Packet Flood',
          user_agent: 'hping3 flood tool',
          device_os: 'Script / Bot (hping3)',
          device_type: 'botnet',
          action_taken: 'BLOCKED_IPSET'
        }
      ]
    };

    const ingestRes = await fetch(`${baseUrl}/api/ddos/incident`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(incidentPayload)
    });
    assert.strictEqual(ingestRes.status, 201);
    const ingestData = await ingestRes.json();
    assert.strictEqual(ingestData.incident.attackers_count, 4);
    console.log(` -> OK (Insiden: ${ingestData.incident.incident_id}, 4 Penyerang Disimpan)`);

    // -------------------------------------------------------------
    // TEST 4: Query Attacker Forensics with OS Filtering
    // -------------------------------------------------------------
    console.log('\n[TEST 4] GET /api/ddos/attackers (Filter by OS & Search)...');
    
    // Filter Windows
    const winRes = await fetch(`${baseUrl}/api/ddos/attackers?os=Windows`);
    const winAttackers = await winRes.json();
    assert(winAttackers.length >= 1, 'Harus ada penyerang Windows');
    const win = winAttackers.find(a => a.ip_address === '198.51.100.22');
    assert(win, 'IP 198.51.100.22 harus ditemukan');
    assert.strictEqual(win.device_os, 'Windows 11');
    assert(win.day_name, 'Harus memiliki nama hari');
    assert(win.attack_date, 'Harus memiliki tanggal penyerangan');
    assert(win.attack_time, 'Harus memiliki jam penyerangan');
    assert.strictEqual(win.target_port, 80);
    console.log(` -> OK (Windows: ${win.ip_address} | Hari: ${win.day_name} | Tanggal: ${win.attack_date} | Jam: ${win.attack_time})`);

    // -------------------------------------------------------------
    // TEST 5: Device Distribution & Hourly Stats
    // -------------------------------------------------------------
    console.log('\n[TEST 5] GET /api/ddos/device-stats & /api/ddos/hourly-stats...');
    const devRes = await fetch(`${baseUrl}/api/ddos/device-stats`);
    const devStats = await devRes.json();
    assert(devStats.total >= 4, 'Total penyerang harus >= 4');
    assert(devStats.distribution.length > 0, 'Distribusi harus berisi data');
    console.log(` -> OK Device Distribution: ${devStats.distribution.map(d => `${d.os}: ${d.percentage}%`).join(', ')}`);

    const hourlyRes = await fetch(`${baseUrl}/api/ddos/hourly-stats`);
    const hourlyStats = await hourlyRes.json();
    assert.strictEqual(hourlyStats.length, 24, 'Harus memiliki 24 slot jam');
    console.log(` -> OK (Hourly distribution 00:00 - 23:00 WIB siap di-render)`);

    // Obtain Admin Bearer Token for protected routes
    const authRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'admin123' })
    });
    const authData = await authRes.json();
    const adminToken = authData.token;

    // -------------------------------------------------------------
    // TEST 6: Mode Switch (Auto vs Manual)
    // -------------------------------------------------------------
    console.log('\n[TEST 6] POST /api/ddos/mode (Ubah Mode Closed-Loop)...');
    const modeRes = await fetch(`${baseUrl}/api/ddos/mode`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify({ mode: 'manual' })
    });
    const modeData = await modeRes.json();
    assert.strictEqual(modeData.mode, 'manual');
    console.log(` -> OK (Mode berhasil diubah ke: ${modeData.mode.toUpperCase()})`);

    // Restore back to auto mode for continuous self-healing
    await fetch(`${baseUrl}/api/ddos/mode`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${adminToken}` },
      body: JSON.stringify({ mode: 'auto' })
    });

    // -------------------------------------------------------------
    // TEST 7: 3-Level Mitigation & Recovery Trigger
    // -------------------------------------------------------------
    console.log('\n[TEST 7] POST /api/ddos/mitigate & /api/ddos/recovery (Pemicu Playbook Ansible)...');
    
    // Level 1
    const mit1Res = await fetch(`${baseUrl}/api/ddos/mitigate`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify({ level: 1 })
    });
    const mit1Data = await mit1Res.json();
    assert.strictEqual(mit1Data.success, true);
    assert.strictEqual(mit1Data.mitigation.playbook, 'playbook_l3.yml');
    console.log(` -> OK (Mitigasi Level 1 dieksekusi: ${mit1Data.mitigation.playbook})`);

    // Recovery
    const recRes = await fetch(`${baseUrl}/api/ddos/recovery`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    const recData = await recRes.json();
    assert.strictEqual(recData.success, true);
    assert.strictEqual(recData.recovery.level, 0);
    console.log(` -> OK (Normalisasi / Recovery dieksekusi: ${recData.recovery.playbook})`);

    // -------------------------------------------------------------
    // TEST 8: Forensic Logs Export (CSV & JSON)
    // -------------------------------------------------------------
    console.log('\n[TEST 8] GET /api/ddos/export (Ekspor Berkas Forensik)...');
    
    // CSV
    const csvRes = await fetch(`${baseUrl}/api/ddos/export?format=csv`);
    assert.strictEqual(csvRes.status, 200);
    assert(csvRes.headers.get('content-type').includes('text/csv'));
    const csvContent = await csvRes.text();
    assert(csvContent.includes('IP Penyerang'), 'Header CSV harus berisi kolom');
    assert(csvContent.includes('Hari Penyerangan'), 'Header CSV harus berisi Hari');
    assert(csvContent.includes('198.51.100.22'), 'Data IP harus ada di CSV');
    console.log(` -> OK (CSV valid, ukuran: ${csvContent.length} bytes)`);

    // JSON
    const jsonRes = await fetch(`${baseUrl}/api/ddos/export?format=json`);
    assert.strictEqual(jsonRes.status, 200);
    const jsonData = await jsonRes.json();
    assert(Array.isArray(jsonData));
    assert(jsonData.length >= 4);
    console.log(` -> OK (JSON valid, ${jsonData.length} record forensik)`);

    // -------------------------------------------------------------
    // TEST 9: Ansible Execution Logs
    // -------------------------------------------------------------
    console.log('\n[TEST 9] GET /api/ddos/logs (Ambil Log Audit Ansible)...');
    const logsRes = await fetch(`${baseUrl}/api/ddos/logs`);
    const logs = await logsRes.json();
    assert(Array.isArray(logs));
    assert(logs.length >= 2, 'Harus mencatat log mitigasi dan recovery');
    console.log(` -> OK (${logs.length} entri audit log tersimpan)`);

    console.log('\n================================================================');
    console.log('🎉 SELURUH PENGUJIAN OTOMATIS BERHASIL DENGAN SEMPURNA (100% OK)');
    console.log('================================================================');
    process.exit(0);

  } catch (err) {
    console.error('\n❌ PENGUJIAN GAGAL:', err.message);
    console.error(err.stack);
    process.exit(1);
  }
}

runTests();
