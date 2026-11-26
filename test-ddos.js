// Automated Test Suite for Closed-Loop DDoS & Attacker Intelligence
const http = require('node:http');
const assert = require('node:assert');

const TEST_PORT = 3998;
process.env.PORT = TEST_PORT;

async function runDdosTests() {
  console.log('===============================================================');
  console.log('[TEST] Memulai Verifikasi Otomatis DDoS & Attacker Intelligence');
  console.log('===============================================================');

  // Start the server
  require('./server.js');
  await new Promise(r => setTimeout(r, 1500)); // wait for startup

  const baseUrl = `http://localhost:${TEST_PORT}`;

  try {
    // 1. Test Ingest DDoS Incident with Attacker Profiles
    console.log('[TEST 1] POST /api/ddos/incident (Ingest Incident & Attacker Profiles)...');
    const incidentPayload = {
      incident_id: 'UNIT-TEST-INC-001',
      attack_type: 'Distributed L7 HTTP GET Flood & TCP SYN Flood',
      mitigation_level: 2,
      confidence_score: 99.4,
      status: 'SELF_HEALED',
      ai_summary: 'Google Gemini mendeteksi 3 IP mencurigakan membanjiri port 80. Berhasil diisolasi.',
      health_probe: { status: 'HEALTHY', http_code: 200, response_time_ms: 18.2 },
      attackers: [
        {
          ip: '198.51.100.11',
          country: 'United States',
          country_code: 'US',
          isp: 'DigitalOcean LLC',
          request_count: 5200,
          attack_vector: 'HTTP GET Flood',
          user_agent: 'GoldenEye/2.1',
          action_taken: 'BLOCKED_IPSET'
        },
        {
          ip: '203.0.113.99',
          country: 'Russia',
          country_code: 'RU',
          isp: 'JSC Rostelecom',
          request_count: 4100,
          attack_vector: 'TCP SYN Flood',
          user_agent: 'LOIC/2.0',
          action_taken: 'BLOCKED_IPSET'
        }
      ]
    };

    const ingestRes = await fetch(`${baseUrl}/api/ddos/incident`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(incidentPayload)
    });
    assert.strictEqual(ingestRes.status, 201, 'Status harus 201 Created');
    const ingestData = await ingestRes.json();
    assert.strictEqual(ingestData.success, true);
    assert.strictEqual(ingestData.incident.attackers_count, 2);
    console.log(` -> OK (Insiden: ${ingestData.incident.incident_id}, Level: ${ingestData.incident.mitigation_level})`);

    // 2. Test Get DDoS Incident History
    console.log('[TEST 2] GET /api/ddos/incidents (Ambil Riwayat Insiden)...');
    const listRes = await fetch(`${baseUrl}/api/ddos/incidents?limit=100`);
    assert.strictEqual(listRes.status, 200);
    const incidents = await listRes.json();
    assert(Array.isArray(incidents), 'Harus berupa array');
    const found = incidents.find(i => i.incident_id === 'UNIT-TEST-INC-001');
    assert(found, 'Insiden yang baru disimpan harus ditemukan');
    assert.strictEqual(found.attackers.length, 2, 'Harus memiliki 2 attacker profile terkait');
    console.log(` -> OK (Tercatat ${incidents.length} riwayat insiden)`);

    // 3. Test Get Attacker Profiles
    console.log('[TEST 3] GET /api/ddos/attackers (Ambil Profil Penyerang)...');
    const attackersRes = await fetch(`${baseUrl}/api/ddos/attackers`);
    assert.strictEqual(attackersRes.status, 200);
    const attackers = await attackersRes.json();
    assert(Array.isArray(attackers), 'Harus berupa array');
    const ipFound = attackers.find(a => a.ip_address === '198.51.100.11');
    assert(ipFound, 'IP 198.51.100.11 harus terdaftar di attacker profiles');
    assert.strictEqual(ipFound.country, 'United States');
    console.log(` -> OK (Ditemukan profil penyerang: ${ipFound.ip_address} [${ipFound.country}])`);

    // 4. Test Get DDoS Summary Stats
    console.log('[TEST 4] GET /api/ddos/stats (Ambil Statistik Ringkasan Pertahanan)...');
    const statsRes = await fetch(`${baseUrl}/api/ddos/stats`);
    assert.strictEqual(statsRes.status, 200);
    const stats = await statsRes.json();
    assert(stats.total_incidents >= 1);
    assert(stats.total_attackers_blocked >= 2);
    assert(typeof stats.current_defense_level === 'number', 'Defense level harus berupa angka');
    console.log(` -> OK (Total Blokir: ${stats.total_attackers_blocked}, Level: Level ${stats.current_defense_level})`);

    // 5. Test Reset Defense Status
    console.log('[TEST 5] POST /api/ddos/reset (Reset Status Pertahanan)...');
    const resetRes = await fetch(`${baseUrl}/api/ddos/reset`, { method: 'POST' });
    assert.strictEqual(resetRes.status, 200);
    const resetData = await resetRes.json();
    assert.strictEqual(resetData.success, true);
    console.log(' -> OK (Status pertahanan berhasil di-reset ke Normal)');

    console.log('\n===============================================================');
    console.log('🎉 SEMUA 5 PENGUJIAN DDOS & ATTACKER PROFILING LULUS 100%!');
    console.log('===============================================================');
    process.exit(0);
  } catch (err) {
    console.error('\n❌ PENGUJIAN GAGAL:', err.message);
    process.exit(1);
  }
}

runDdosTests();
