// Automated Test Suite for Admin Authentication & Access Control
const assert = require('node:assert');

const TEST_PORT = 3993;
process.env.PORT = TEST_PORT;

async function runAuthTests() {
  console.log('================================================================');
  console.log('🔐 Memulai Pengujian Otomatis Sistem Autentikasi Admin Cyber-SOC');
  console.log('================================================================');

  // Start the server
  require('./server.js');
  await new Promise(r => setTimeout(r, 2000));

  const baseUrl = `http://localhost:${TEST_PORT}`;

  try {
    // -------------------------------------------------------------
    // TEST 1: Login attempt with missing fields
    // -------------------------------------------------------------
    console.log('\n[TEST 1] POST /api/auth/login (Validasi Input Kosong)...');
    const emptyRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    assert.strictEqual(emptyRes.status, 400, 'Harus mengembalikan 400 Bad Request');
    console.log(' -> OK (Ditolak dengan 400 saat input kosong)');

    // -------------------------------------------------------------
    // TEST 2: Login attempt with invalid credentials
    // -------------------------------------------------------------
    console.log('\n[TEST 2] POST /api/auth/login (Uji Password Salah)...');
    const wrongRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'wrongPassword999' })
    });
    assert.strictEqual(wrongRes.status, 401, 'Harus mengembalikan 401 Unauthorized');
    const wrongData = await wrongRes.json();
    assert(wrongData.error, 'Harus mengembalikan pesan error');
    console.log(` -> OK (Ditolak dengan 401: "${wrongData.error}")`);

    // -------------------------------------------------------------
    // TEST 3: Login attempt with valid default admin credentials
    // -------------------------------------------------------------
    console.log('\n[TEST 3] POST /api/auth/login (Uji Login Admin Default admin/admin123)...');
    const loginRes = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'admin123' })
    });
    assert.strictEqual(loginRes.status, 200, 'Status harus 200 OK');
    const loginData = await loginRes.json();
    assert.strictEqual(loginData.success, true);
    assert(loginData.token && loginData.token.length >= 64, 'Token sesi kriptografis harus ada');
    assert.strictEqual(loginData.user.username, 'admin');
    const adminToken = loginData.token;
    console.log(` -> OK (Login Berhasil! Token: ${adminToken.slice(0, 16)}... | User: ${loginData.user.username})`);

    // -------------------------------------------------------------
    // TEST 4: Verify Session via GET /api/auth/me
    // -------------------------------------------------------------
    console.log('\n[TEST 4] GET /api/auth/me (Verifikasi Keabsahan Sesi)...');
    const meRes = await fetch(`${baseUrl}/api/auth/me`, {
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    assert.strictEqual(meRes.status, 200);
    const meData = await meRes.json();
    assert.strictEqual(meData.authenticated, true);
    assert.strictEqual(meData.user.username, 'admin');
    console.log(` -> OK (Sesi aktif: ${meData.user.username} - ${meData.user.role})`);

    // -------------------------------------------------------------
    // TEST 5: Access Protected Endpoint WITHOUT Token
    // -------------------------------------------------------------
    console.log('\n[TEST 5] POST /api/ddos/mitigate (Uji Akses Tanpa Token)...');
    const unauthRes = await fetch(`${baseUrl}/api/ddos/mitigate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ level: 1 })
    });
    assert.strictEqual(unauthRes.status, 401, 'Endpoint sensitif harus menolak request tanpa token');
    console.log(' -> OK (Akses ditolak: 401 Unauthorized)');

    // -------------------------------------------------------------
    // TEST 6: Access Protected Endpoint WITH Valid Token
    // -------------------------------------------------------------
    console.log('\n[TEST 6] POST /api/ddos/mitigate (Uji Akses DENGAN Token Valid)...');
    const authActionRes = await fetch(`${baseUrl}/api/ddos/mitigate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify({ level: 1 })
    });
    assert.strictEqual(authActionRes.status, 200, 'Endpoint sensitif harus menerima request dengan token');
    const authActionData = await authActionRes.json();
    assert.strictEqual(authActionData.success, true);
    console.log(` -> OK (Akses diterima! Mitigasi berhasil: ${authActionData.mitigation.playbook})`);

    // -------------------------------------------------------------
    // TEST 7: Logout / Session Invalidation
    // -------------------------------------------------------------
    console.log('\n[TEST 7] POST /api/auth/logout (Uji Pencabutan Token / Sign Out)...');
    const logoutRes = await fetch(`${baseUrl}/api/auth/logout`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    assert.strictEqual(logoutRes.status, 200);
    const logoutData = await logoutRes.json();
    assert.strictEqual(logoutData.success, true);
    console.log(' -> OK (Token sesi dicabut)');

    // Verify token is now invalid
    const afterLogoutRes = await fetch(`${baseUrl}/api/auth/me`, {
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    assert.strictEqual(afterLogoutRes.status, 401, 'Token yang sudah logout harus ditolak');
    console.log(' -> OK (Token yang sudah di-logout tidak dapat digunakan lagi)');

    console.log('\n================================================================');
    console.log('🎉 SELURUH PENGUJIAN AUTENTIKASI ADMIN BERHASIL 100%!');
    console.log('================================================================');
    process.exit(0);

  } catch (err) {
    console.error('\n❌ PENGUJIAN AUTENTIKASI GAGAL:', err.message);
    console.error(err.stack);
    process.exit(1);
  }
}

runAuthTests();
