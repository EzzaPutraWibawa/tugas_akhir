/**
 * Migrate local serverpulse.db (SQLite) to Turso Cloud (libSQL).
 * Filters out unit-test and static simulation records by default, and
 * migrates the latest METRICS_LIMIT (default: 500) rows of metrics.
 *
 * Usage:
 *   node scripts/migrate_sqlite_to_cloud.js
 *   node scripts/migrate_sqlite_to_cloud.js --include-dummy
 */

const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const fs = require('node:fs');

const envPath = path.join(__dirname, '..', '.env');
if (fs.existsSync(envPath) && typeof process.loadEnvFile === 'function') {
  try {
    process.loadEnvFile(envPath);
  } catch (_) {}
}

const DB = require('../db');

const DUMMY_ATTACK_TYPE = 'Distributed Heterogeneous DDoS Flood (L3, L4, L7)';
const CHUNK_SIZE = 100;

async function runBatchChunked(client, statements) {
  for (let i = 0; i < statements.length; i += CHUNK_SIZE) {
    const chunk = statements.slice(i, i + CHUNK_SIZE);
    await client.batch(chunk, 'write');
  }
}

async function main() {
  const includeDummy = process.argv.includes('--include-dummy');
  const allowLocalTarget = process.argv.includes('--allow-local');
  const metricsLimit = Math.max(0, parseInt(process.env.METRICS_LIMIT || '500', 10));
  const sourcePath = path.join(__dirname, '..', 'serverpulse.db');

  if (!fs.existsSync(sourcePath)) {
    throw new Error(`File SQLite lokal tidak ditemukan: ${sourcePath}`);
  }

  const targetUrl = (process.env.TURSO_DATABASE_URL || '').trim();
  if (!targetUrl) {
    throw new Error('TURSO_DATABASE_URL belum diatur di environment atau .env');
  }
  if (targetUrl.startsWith('file:') && !allowLocalTarget) {
    throw new Error('TURSO_DATABASE_URL mengarah ke file lokal. Gunakan URL libsql:// Turso Anda (atau --allow-local untuk uji lokal).');
  }

  console.log('====================================================');
  console.log('🚀 Migrasi ServerPulse SQLite -> Turso Cloud');
  console.log(`   Source       : ${sourcePath}`);
  console.log(`   Target       : ${targetUrl.startsWith('file:') ? targetUrl : 'Turso Cloud (' + targetUrl.split('@').pop() + ')'}`);
  console.log(`   Filter Dummy : ${includeDummy ? 'Tidak (migrasi semua)' : 'Ya (hapus unit-test & simulasi)'}`);
  console.log(`   Metrics Limit: ${metricsLimit} baris terbaru`);
  console.log('====================================================');

  const src = new DatabaseSync(sourcePath, { readOnly: true });
  await DB.init();
  const client = DB.getClient();

  // 1. admin_users
  const adminUsers = src.prepare('SELECT * FROM admin_users').all();
  await runBatchChunked(
    client,
    adminUsers.map((u) => ({
      sql: `INSERT INTO admin_users (id, username, password_hash, salt, full_name, role, last_login, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
              password_hash = excluded.password_hash,
              salt = excluded.salt,
              full_name = excluded.full_name,
              role = excluded.role,
              last_login = excluded.last_login`,
      args: [u.id, u.username, u.password_hash, u.salt, u.full_name, u.role, u.last_login, u.created_at]
    }))
  );
  console.log(` -> admin_users: ${adminUsers.length} baris dimigrasi`);

  // 2. settings
  const settings = src.prepare('SELECT key, value FROM settings').all();
  await runBatchChunked(
    client,
    settings.map((s) => ({
      sql: `INSERT INTO settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
      args: [s.key, s.value]
    }))
  );
  console.log(` -> settings: ${settings.length} baris dimigrasi`);

  // 3. servers
  const servers = src.prepare('SELECT * FROM servers').all();
  await runBatchChunked(
    client,
    servers.map((s) => ({
      sql: `INSERT INTO servers (id, name, type, target, probe_type, token, status, last_heartbeat, created_at, os_info, tags, netdata_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              name = excluded.name,
              type = excluded.type,
              target = excluded.target,
              probe_type = excluded.probe_type,
              token = excluded.token,
              status = excluded.status,
              last_heartbeat = excluded.last_heartbeat,
              os_info = excluded.os_info,
              tags = excluded.tags,
              netdata_url = excluded.netdata_url`,
      args: [
        s.id, s.name, s.type, s.target, s.probe_type, s.token,
        s.status, s.last_heartbeat, s.created_at, s.os_info, s.tags, s.netdata_url
      ]
    }))
  );
  console.log(` -> servers: ${servers.length} baris dimigrasi`);

  // 4. incidents
  const incidents = src.prepare('SELECT * FROM incidents').all();
  await runBatchChunked(
    client,
    incidents.map((inc) => ({
      sql: `INSERT OR REPLACE INTO incidents (id, server_id, server_name, event_type, details, started_at, resolved_at, duration_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [inc.id, inc.server_id, inc.server_name, inc.event_type, inc.details, inc.started_at, inc.resolved_at, inc.duration_seconds]
    }))
  );
  console.log(` -> incidents: ${incidents.length} baris dimigrasi`);

  // 5. ddos_incidents
  const ddosSql = includeDummy
    ? 'SELECT * FROM ddos_incidents'
    : `SELECT * FROM ddos_incidents
       WHERE incident_id NOT LIKE 'UNIT-TEST-%'
         AND incident_id NOT LIKE 'TEST-SOC-%'
         AND attack_type != ?`;
  const ddosIncidents = includeDummy
    ? src.prepare(ddosSql).all()
    : src.prepare(ddosSql).all(DUMMY_ATTACK_TYPE);

  await runBatchChunked(
    client,
    ddosIncidents.map((d) => ({
      sql: `INSERT INTO ddos_incidents (incident_id, server_id, server_ip, attack_type, mitigation_level, confidence_score, status, ai_summary, health_probe, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(incident_id) DO UPDATE SET
              server_id = excluded.server_id,
              server_ip = excluded.server_ip,
              attack_type = excluded.attack_type,
              mitigation_level = excluded.mitigation_level,
              confidence_score = excluded.confidence_score,
              status = excluded.status,
              ai_summary = excluded.ai_summary,
              health_probe = excluded.health_probe`,
      args: [
        d.incident_id, d.server_id || 'local-host', d.server_ip || '127.0.0.1',
        d.attack_type, d.mitigation_level, d.confidence_score,
        d.status, d.ai_summary, d.health_probe, d.created_at
      ]
    }))
  );
  console.log(` -> ddos_incidents: ${ddosIncidents.length} baris dimigrasi`);

  // 6. attacker_profiles
  const allowedIncIds = new Set(ddosIncidents.map((d) => d.incident_id));
  const allAttackers = src.prepare('SELECT * FROM attacker_profiles').all();
  const attackersToMigrate = includeDummy
    ? allAttackers
    : allAttackers.filter((a) => {
        if (a.incident_id.startsWith('UNIT-TEST-') || a.incident_id.startsWith('TEST-SOC-')) return false;
        if (a.incident_id.startsWith('LIVE-')) return true;
        return allowedIncIds.has(a.incident_id);
      });

  await runBatchChunked(
    client,
    attackersToMigrate.map((a) => ({
      sql: `INSERT OR REPLACE INTO attacker_profiles (
              id, incident_id, server_id, ip_address, country, country_code, isp,
              request_count, attack_vector, user_agent, device_os, device_type,
              target_port, asn_number, asn_org, day_name, attack_date, attack_time,
              attack_hour, action_taken, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        a.id, a.incident_id, a.server_id || 'local-host', a.ip_address,
        a.country, a.country_code, a.isp, a.request_count, a.attack_vector,
        a.user_agent, a.device_os, a.device_type, a.target_port,
        a.asn_number, a.asn_org, a.day_name, a.attack_date, a.attack_time,
        a.attack_hour, a.action_taken, a.created_at
      ]
    }))
  );
  console.log(` -> attacker_profiles: ${attackersToMigrate.length} baris dimigrasi`);

  // 7. metrics (latest N)
  const metrics = metricsLimit > 0
    ? src.prepare('SELECT * FROM metrics ORDER BY timestamp DESC LIMIT ?').all(metricsLimit).reverse()
    : [];
  await runBatchChunked(
    client,
    metrics.map((m) => ({
      sql: `INSERT OR REPLACE INTO metrics (
              id, server_id, timestamp, cpu_percent, memory_percent,
              memory_used_gb, memory_total_gb, disk_percent, net_rx_kb,
              net_tx_kb, response_time_ms, top_processes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        m.id, m.server_id, m.timestamp, m.cpu_percent, m.memory_percent,
        m.memory_used_gb, m.memory_total_gb, m.disk_percent, m.net_rx_kb,
        m.net_tx_kb, m.response_time_ms, m.top_processes
      ]
    }))
  );
  console.log(` -> metrics: ${metrics.length} baris terbaru dimigrasi`);

  src.close();

  console.log('\n📊 Verifikasi jumlah baris di database target:');
  for (const tbl of ['admin_users', 'settings', 'servers', 'incidents', 'ddos_incidents', 'attacker_profiles', 'metrics']) {
    const res = await client.execute(`SELECT COUNT(*) as c FROM ${tbl}`);
    console.log(`   - ${tbl.padEnd(20)}: ${Number(res.rows[0]?.c || 0)} baris`);
  }
  console.log('\n✅ Migrasi selesai dengan sukses!');
}

main().catch((err) => {
  console.error('\n❌ Migrasi gagal:', err.message || err);
  process.exit(1);
});
