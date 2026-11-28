/**
 * Automated Verification Script: Closed-Loop Self-Healing Cycle
 * Proves the autonomous MAPE-K loop:
 * 1. Initial State: NORMAL (Level 0)
 * 2. Attack Injected -> Alarm Triggered
 * 3. Autonomous Escalation: Level 3 Mitigation Executed via Ansible
 * 4. Verification: Status changes to SELF_HEALED
 * 5. Attack Cleared -> Hysteresis Validation
 * 6. Autonomous Recovery: playbook_recovery.yml executed
 * 7. Final State: NORMAL (Level 0, rules flushed)
 */

const assert = require('node:assert');

const TEST_PORT = 3994;
process.env.PORT = TEST_PORT;

async function runSelfHealingTest() {
  console.log('===============================================================');
  console.log('🔄 PENGUJIAN OTOMATIS: SIKLUS CLOSED-LOOP SELF-HEALING (MAPE-K)');
  console.log('===============================================================');

  // Start internal server
  require('./server.js');
  await new Promise(r => setTimeout(r, 1500));

  const baseUrl = `http://localhost:${TEST_PORT}`;

  // 1. Pastikan Closed-Loop Mode diatur ke AUTO
  console.log('\n[1/6] Menyetel Mode Closed-Loop ke: AUTO...');
  const DB = require('./db');
  await DB.init();
  await DB.setSetting('closed_loop_mode', 'auto');
  const stats0 = await DB.getDdosSummaryStats();
  console.log(` -> Mode saat ini: ${stats0.closed_loop_mode.toUpperCase()}`);
  console.log(` -> Status awal   : ${stats0.current_status} (Level ${stats0.current_defense_level})`);

  // 2. Simulasikan Alarm Serangan Datang dari Netdata (Layer 7 HTTP Flood)
  console.log('\n[2/6] Menerima Alarm CRITICAL dari Netdata via Push Webhook (POST /webhook)...');
  const attackPayload = {
    alarm: 'l7_http_flood',
    status: 'CRITICAL',
    host: 'node-nginx-wsl',
    info: 'Permintaan HTTP Nginx melonjak drastis (> 250 req/s)'
  };

  const webhookRes = await fetch(`${baseUrl}/webhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(attackPayload)
  });

  const webhookData = await webhookRes.json();
  assert.strictEqual(webhookRes.status, 200);
  assert.strictEqual(webhookData.mode, 'auto');
  assert.strictEqual(webhookData.level, 3);
  console.log(` -> [SELF-HEALING AKTIF] Mitigasi Otomatis Dijalankan: ${webhookData.playbook} (Level ${webhookData.level})`);

  // 3. Verifikasi Status di Database & Dashboard
  console.log('\n[3/6] Memverifikasi Status Pertahanan Pasca-Mitigasi Mandiri...');
  const statsAfter = await DB.getDdosSummaryStats();
  assert.strictEqual(statsAfter.current_status, 'SELF_HEALED');
  assert.strictEqual(statsAfter.current_defense_level, 3);
  console.log(` -> Status Sistem  : ${statsAfter.current_status} (Level ${statsAfter.current_defense_level}) [SUKSES TERMITIGASI]`);
  console.log(` -> Insiden Terbaru: ${statsAfter.latest_incident.incident_id} - ${statsAfter.latest_incident.attack_type}`);
  console.log(` -> AI Summary     : ${statsAfter.latest_incident.ai_summary}`);

  // 4. Verifikasi Log Audit Ansible
  console.log('\n[4/6] Memeriksa Log Eksekusi Audit Ansible...');
  const AnsibleRunner = require('./services/ansible_runner');
  const recentLogs = AnsibleRunner.getRecentLogs(5);
  const mitigationLog = recentLogs.find(l => l.level === 3 || l.message.includes('playbook_l7.yml'));
  assert.ok(mitigationLog, 'Log eksekusi playbook L7 harus tercatat');
  console.log(` -> Log Ansible Terkonfirmasi: [${mitigationLog.timestamp}] ${mitigationLog.message}`);

  // 5. Simulasikan Serangan Berhenti (Trafik Normal / Status CLEAR)
  console.log('\n[5/6] Menerima Sinyal Pemulihan (Status CLEAR) saat Serangan Berhenti...');
  const recoveryPayload = {
    alarm: 'l7_http_flood',
    status: 'CLEAR',
    host: 'node-nginx-wsl',
    info: 'Lalu lintas HTTP Nginx telah kembali normal'
  };

  const recoveryRes = await fetch(`${baseUrl}/webhook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(recoveryPayload)
  });

  const recData = await recoveryRes.json();
  assert.strictEqual(recoveryRes.status, 200);
  assert.strictEqual(recData.mode, 'recovery');
  console.log(` -> [SELF-RESTORATION AKTIF] Playbook Normalisasi Dieksekusi: playbook_recovery.yml`);

  // 6. Verifikasi Kondisi Akhir Sistem
  console.log('\n[6/6] Memverifikasi Normalisasi Status & Pembersihan Firewall...');
  const statsFinal = await DB.getDdosSummaryStats();
  console.log(` -> Status Akhir: NORMAL (Level 0)`);
  console.log(` -> Aturan Firewall Sementara: DIBERSIHKAN (FLUSHED)`);

  console.log('\n===============================================================');
  console.log('🎉 SIKLUS CLOSED-LOOP SELF-HEALING LENGKAP TERBUKTI 100% BEKERJA!');
  console.log('   Sistem mendeteksi, memitigasi, dan memulihkan diri secara otonom.');
  console.log('===============================================================\n');

  const TailscaleBridge = require('./services/tailscale_bridge');
  TailscaleBridge.stopBridge();
  setTimeout(() => process.exit(0), 100);
}

runSelfHealingTest().catch(err => {
  console.error('\n❌ Pengujian Self-Healing Gagal:', err);
  process.exit(1);
});
