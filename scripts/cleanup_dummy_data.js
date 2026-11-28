/**
 * Cleanup script for ServerPulse database.
 * Removes unit-test and static simulation records before cloud migration.
 *
 * Usage:
 *   node scripts/cleanup_dummy_data.js --dry-run
 *   node scripts/cleanup_dummy_data.js
 */

const DB = require('../db');

const DUMMY_ATTACK_TYPE = 'Distributed Heterogeneous DDoS Flood (L3, L4, L7)';

async function main() {
  const isDryRun = process.argv.includes('--dry-run');
  await DB.init();
  const client = DB.getClient();
  const conn = DB.getConnectionInfo();

  console.log('====================================================');
  console.log(`🧹 ServerPulse Cleanup Dummy & Test Data (${conn.mode})`);
  console.log(`   Mode: ${isDryRun ? 'DRY-RUN (tidak mengubah data)' : 'EXECUTE (hapus permanen)'}`);
  console.log('====================================================');

  const testIncCountRes = await client.execute({
    sql: `SELECT COUNT(*) as c FROM ddos_incidents
          WHERE incident_id LIKE 'UNIT-TEST-%'
             OR incident_id LIKE 'TEST-SOC-%'
             OR attack_type = ?`,
    args: [DUMMY_ATTACK_TYPE]
  });

  const testAttCountRes = await client.execute({
    sql: `SELECT COUNT(*) as c FROM attacker_profiles
          WHERE incident_id LIKE 'UNIT-TEST-%'
             OR incident_id LIKE 'TEST-SOC-%'
             OR incident_id IN (
               SELECT incident_id FROM ddos_incidents WHERE attack_type = ?
             )`,
    args: [DUMMY_ATTACK_TYPE]
  });

  const expiredSessionsRes = await client.execute({
    sql: 'SELECT COUNT(*) as c FROM admin_sessions WHERE expires_at < ?',
    args: [Date.now()]
  });

  const incToDelete = Number(testIncCountRes.rows[0]?.c || 0);
  const attToDelete = Number(testAttCountRes.rows[0]?.c || 0);
  const sessToDelete = Number(expiredSessionsRes.rows[0]?.c || 0);

  console.log(` -> ddos_incidents (unit-test & simulasi): ${incToDelete} baris`);
  console.log(` -> attacker_profiles (unit-test & simulasi): ${attToDelete} baris`);
  console.log(` -> admin_sessions (kedaluwarsa): ${sessToDelete} baris`);

  if (isDryRun) {
    console.log('\n[DRY-RUN] Tidak ada perubahan yang ditulis.');
    return;
  }

  await client.batch([
    {
      sql: `DELETE FROM attacker_profiles
            WHERE incident_id LIKE 'UNIT-TEST-%'
               OR incident_id LIKE 'TEST-SOC-%'
               OR incident_id IN (
                 SELECT incident_id FROM ddos_incidents WHERE attack_type = ?
               )`,
      args: [DUMMY_ATTACK_TYPE]
    },
    {
      sql: `DELETE FROM ddos_incidents
            WHERE incident_id LIKE 'UNIT-TEST-%'
               OR incident_id LIKE 'TEST-SOC-%'
               OR attack_type = ?`,
      args: [DUMMY_ATTACK_TYPE]
    },
    {
      sql: 'DELETE FROM admin_sessions WHERE expires_at < ?',
      args: [Date.now()]
    }
  ], 'write');

  const remInc = await client.execute('SELECT COUNT(*) as c FROM ddos_incidents');
  const remAtt = await client.execute('SELECT COUNT(*) as c FROM attacker_profiles');
  console.log(`\n✅ Pembersihan selesai!`);
  console.log(`   Sisa ddos_incidents   : ${Number(remInc.rows[0]?.c || 0)} baris`);
  console.log(`   Sisa attacker_profiles: ${Number(remAtt.rows[0]?.c || 0)} baris`);
}

main().catch((err) => {
  console.error('❌ Cleanup gagal:', err);
  process.exit(1);
});
