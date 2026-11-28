const { createClient } = require('@libsql/client');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

// Load .env early when db.js is imported standalone (e.g. migration/test scripts)
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath) && typeof process.loadEnvFile === 'function') {
  try {
    process.loadEnvFile(envPath);
  } catch (_) {}
}

const localDbPath = path.join(__dirname, 'serverpulse.db');
const configuredUrl = (process.env.TURSO_DATABASE_URL || '').trim();
const dbUrl = configuredUrl || `file:${localDbPath}`;
const isLocalFile = dbUrl.startsWith('file:');

const client = createClient({
  url: dbUrl,
  authToken: (process.env.TURSO_AUTH_TOKEN || '').trim() || undefined
});

async function queryAll(sql, args = []) {
  const res = await client.execute({ sql, args });
  return res.rows.map((row) => ({ ...row }));
}

async function queryGet(sql, args = []) {
  const res = await client.execute({ sql, args });
  return res.rows[0] ? { ...res.rows[0] } : null;
}

async function queryRun(sql, args = []) {
  return client.execute({ sql, args });
}

const SCHEMA_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    full_name TEXT DEFAULT 'Chief Security Officer',
    role TEXT DEFAULT 'superadmin',
    last_login INTEGER,
    created_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS admin_sessions (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_sessions_token ON admin_sessions(token)`,
  `CREATE INDEX IF NOT EXISTS idx_admin_username ON admin_users(username)`,
  `CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    target TEXT,
    probe_type TEXT DEFAULT 'http',
    token TEXT UNIQUE,
    status TEXT DEFAULT 'offline',
    last_heartbeat INTEGER,
    created_at INTEGER,
    os_info TEXT,
    tags TEXT,
    netdata_url TEXT DEFAULT 'http://localhost:19999'
  )`,
  `CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    cpu_percent REAL DEFAULT 0,
    memory_percent REAL DEFAULT 0,
    memory_used_gb REAL DEFAULT 0,
    memory_total_gb REAL DEFAULT 0,
    disk_percent REAL DEFAULT 0,
    net_rx_kb REAL DEFAULT 0,
    net_tx_kb REAL DEFAULT 0,
    response_time_ms REAL DEFAULT 0,
    top_processes TEXT,
    FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
  )`,
  `CREATE INDEX IF NOT EXISTS idx_metrics_server ON metrics(server_id, timestamp)`,
  `CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id TEXT NOT NULL,
    server_name TEXT NOT NULL,
    event_type TEXT NOT NULL,
    details TEXT,
    started_at INTEGER NOT NULL,
    resolved_at INTEGER,
    duration_seconds INTEGER
  )`,
  `CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS ddos_incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT UNIQUE NOT NULL,
    server_id TEXT DEFAULT 'local-host',
    server_ip TEXT DEFAULT '127.0.0.1',
    attack_type TEXT NOT NULL,
    mitigation_level INTEGER DEFAULT 1,
    confidence_score REAL DEFAULT 0,
    status TEXT DEFAULT 'ACTIVE',
    ai_summary TEXT,
    health_probe TEXT,
    created_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS attacker_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    server_id TEXT DEFAULT 'local-host',
    ip_address TEXT NOT NULL,
    country TEXT DEFAULT 'Unknown',
    country_code TEXT DEFAULT 'XX',
    isp TEXT DEFAULT 'Unknown ISP',
    request_count INTEGER DEFAULT 0,
    attack_vector TEXT,
    user_agent TEXT,
    device_os TEXT DEFAULT 'Windows 11',
    device_type TEXT DEFAULT 'desktop',
    target_port INTEGER DEFAULT 80,
    asn_number TEXT DEFAULT 'AS-UNKNOWN',
    asn_org TEXT DEFAULT 'Unknown Provider',
    day_name TEXT DEFAULT 'Rabu',
    attack_date TEXT DEFAULT '',
    attack_time TEXT DEFAULT '',
    attack_hour INTEGER DEFAULT 0,
    action_taken TEXT DEFAULT 'BLOCKED',
    created_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_attackers_incident ON attacker_profiles(incident_id)`,
  `CREATE INDEX IF NOT EXISTS idx_attackers_ip ON attacker_profiles(ip_address)`
];

async function ensureMissingColumns(tableName, columns) {
  const existingCols = await queryAll(`PRAGMA table_info(${tableName})`);
  const existingNames = new Set(existingCols.map((c) => c.name));

  for (const col of columns) {
    if (!existingNames.has(col.name)) {
      try {
        await queryRun(`ALTER TABLE ${tableName} ADD COLUMN ${col.name} ${col.type}`);
      } catch (_) {}
    }
  }
}

async function migrateSchema() {
  await ensureMissingColumns('attacker_profiles', [
    { name: 'device_os', type: "TEXT DEFAULT 'Windows 11'" },
    { name: 'device_type', type: "TEXT DEFAULT 'desktop'" },
    { name: 'target_port', type: 'INTEGER DEFAULT 80' },
    { name: 'asn_number', type: "TEXT DEFAULT 'AS-UNKNOWN'" },
    { name: 'asn_org', type: "TEXT DEFAULT 'Unknown Provider'" },
    { name: 'day_name', type: "TEXT DEFAULT 'Rabu'" },
    { name: 'attack_date', type: "TEXT DEFAULT ''" },
    { name: 'attack_time', type: "TEXT DEFAULT ''" },
    { name: 'attack_hour', type: 'INTEGER DEFAULT 0' },
    { name: 'server_id', type: "TEXT DEFAULT 'local-host'" }
  ]);

  await ensureMissingColumns('servers', [
    { name: 'netdata_url', type: "TEXT DEFAULT 'http://localhost:19999'" }
  ]);

  await ensureMissingColumns('ddos_incidents', [
    { name: 'server_id', type: "TEXT DEFAULT 'local-host'" },
    { name: 'server_ip', type: "TEXT DEFAULT '127.0.0.1'" }
  ]);

  await client.batch([
    'CREATE INDEX IF NOT EXISTS idx_attackers_device ON attacker_profiles(device_os)',
    'CREATE INDEX IF NOT EXISTS idx_attackers_server ON attacker_profiles(server_id)',
    'CREATE INDEX IF NOT EXISTS idx_ddos_inc_server ON ddos_incidents(server_id)'
  ], 'write');
}

// Cryptographic Password Hashing Helpers
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function verifyPassword(password, salt, storedHash) {
  try {
    const computedHash = crypto.scryptSync(password, salt, 64);
    const storedBuffer = Buffer.from(storedHash, 'hex');
    if (computedHash.length !== storedBuffer.length) return false;
    return crypto.timingSafeEqual(computedHash, storedBuffer);
  } catch (_) {
    return false;
  }
}

async function seedDefaultAdmin() {
  const existing = await queryGet('SELECT id FROM admin_users WHERE username = ?', ['admin']);
  if (!existing) {
    const defaultPassword = process.env.ADMIN_DEFAULT_PASSWORD || 'admin123';
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(defaultPassword, salt);
    await queryRun(
      `INSERT INTO admin_users (username, password_hash, salt, full_name, role, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      ['admin', hash, salt, 'Chief Security Officer', 'superadmin', Date.now()]
    );
    console.log('[Auth] Akun Administrator bawaan berhasil dibuat (admin)');
  }
}

const DEFAULT_SETTINGS = [
  ['alert_cpu_threshold', '85'],
  ['alert_ram_threshold', '90'],
  ['alert_disk_threshold', '90'],
  ['telegram_bot_token', ''],
  ['telegram_chat_id', ''],
  ['discord_webhook_url', ''],
  ['probe_interval_seconds', '10'],
  ['offline_timeout_seconds', '25'],
  ['closed_loop_mode', 'auto'],
  ['netdata_host', 'http://localhost:19999']
];

async function seedDefaultSettings() {
  const stmts = DEFAULT_SETTINGS.map(([key, val]) => ({
    sql: 'INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
    args: [key, val]
  }));
  await client.batch(stmts, 'write');
}

// Indonesian Date & Time Formatting Helper
function getIndonesianDateTime(timestamp = Date.now()) {
  const d = new Date(timestamp);
  const days = ['Minggu', 'Senin', 'Selasa', 'Rabu', 'Kamis', 'Jumat', 'Sabtu'];
  const day_name = days[d.getDay()];

  const pad = (n) => String(n).padStart(2, '0');
  const year = d.getFullYear();
  const month = pad(d.getMonth() + 1);
  const date = pad(d.getDate());
  const hours = pad(d.getHours());
  const minutes = pad(d.getMinutes());
  const seconds = pad(d.getSeconds());

  const attack_date = `${year}-${month}-${date}`;
  const attack_time = `${hours}:${minutes}:${seconds} WIB`;
  const attack_hour = d.getHours();

  return { day_name, attack_date, attack_time, attack_hour };
}

let initPromise = null;

// Database helper functions (async, dual-mode: local SQLite file or Turso cloud)
const DB = {
  getConnectionInfo() {
    return {
      mode: isLocalFile ? 'local-sqlite' : 'turso-cloud',
      isLocalFile
    };
  },

  getClient() {
    return client;
  },

  init() {
    if (!initPromise) {
      initPromise = (async () => {
        if (isLocalFile) {
          await queryRun('PRAGMA journal_mode = WAL;');
          await queryRun('PRAGMA busy_timeout = 10000;');
          await queryRun('PRAGMA synchronous = NORMAL;');
        }
        await client.batch(SCHEMA_STATEMENTS, 'write');
        await migrateSchema();
        await seedDefaultAdmin();
        await seedDefaultSettings();
      })().catch((err) => {
        initPromise = null;
        throw err;
      });
    }
    return initPromise;
  },

  async getServers() {
    return queryAll('SELECT * FROM servers ORDER BY created_at DESC');
  },

  async getServerById(id) {
    return queryGet('SELECT * FROM servers WHERE id = ?', [id]);
  },

  async getServerByToken(token) {
    if (!token) return null;
    return queryGet('SELECT * FROM servers WHERE token = ?', [token]);
  },

  async createServer(server) {
    await queryRun(
      `INSERT INTO servers (id, name, type, target, probe_type, token, status, last_heartbeat, created_at, os_info, tags, netdata_url)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        server.id,
        server.name,
        server.type,
        server.target || '',
        server.probe_type || 'http',
        server.token || null,
        server.status || 'offline',
        server.last_heartbeat || null,
        server.created_at || Date.now(),
        server.os_info ? (typeof server.os_info === 'string' ? server.os_info : JSON.stringify(server.os_info)) : null,
        server.tags || '',
        server.netdata_url || 'http://localhost:19999'
      ]
    );
    return this.getServerById(server.id);
  },

  async updateServerStatus(id, status, lastHeartbeat = Date.now(), osInfo = null) {
    if (osInfo) {
      const osStr = typeof osInfo === 'string' ? osInfo : JSON.stringify(osInfo);
      await queryRun(
        `UPDATE servers SET status = ?, last_heartbeat = ?, os_info = ? WHERE id = ?`,
        [status, lastHeartbeat, osStr, id]
      );
    } else {
      await queryRun(
        `UPDATE servers SET status = ?, last_heartbeat = ? WHERE id = ?`,
        [status, lastHeartbeat, id]
      );
    }
  },

  async deleteServer(id) {
    await client.batch([
      { sql: 'DELETE FROM metrics WHERE server_id = ?', args: [id] },
      { sql: 'DELETE FROM incidents WHERE server_id = ?', args: [id] },
      { sql: 'DELETE FROM servers WHERE id = ?', args: [id] }
    ], 'write');
  },

  // Save metrics snapshot
  async saveMetrics(serverIdOrMetrics, maybeMetrics) {
    let serverId = serverIdOrMetrics;
    let metrics = maybeMetrics;

    if (typeof serverIdOrMetrics === 'object' && serverIdOrMetrics !== null) {
      metrics = serverIdOrMetrics;
      serverId = metrics.server_id;
    }

    if (!metrics) return;

    const sevenDaysAgo = Date.now() - (7 * 24 * 3600 * 1000);
    await client.batch([
      {
        sql: `INSERT INTO metrics (
          server_id, timestamp, cpu_percent, memory_percent,
          memory_used_gb, memory_total_gb, disk_percent,
          net_rx_kb, net_tx_kb, response_time_ms, top_processes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [
          serverId,
          metrics.timestamp || Date.now(),
          metrics.cpu_percent || 0,
          metrics.memory_percent || 0,
          metrics.memory_used_gb || 0,
          metrics.memory_total_gb || 0,
          metrics.disk_percent || 0,
          metrics.net_rx_kb || 0,
          metrics.net_tx_kb || 0,
          metrics.response_time_ms || 0,
          metrics.top_processes
            ? (typeof metrics.top_processes === 'string' ? metrics.top_processes : JSON.stringify(metrics.top_processes))
            : null
        ]
      },
      {
        sql: 'DELETE FROM metrics WHERE timestamp < ?',
        args: [sevenDaysAgo]
      }
    ], 'write');
  },

  async getLatestMetrics(serverId) {
    return queryGet(
      `SELECT * FROM metrics WHERE server_id = ? ORDER BY timestamp DESC LIMIT 1`,
      [serverId]
    );
  },

  async getMetricsHistory(serverId, limit = 60) {
    const rows = await queryAll(
      `SELECT * FROM metrics WHERE server_id = ? ORDER BY timestamp DESC LIMIT ?`,
      [serverId, limit]
    );
    return rows.reverse();
  },

  // Incidents
  async createIncident(incidentOrServerId, serverName, eventType, details) {
    let incident = incidentOrServerId;
    if (typeof incidentOrServerId === 'string') {
      incident = {
        server_id: incidentOrServerId,
        server_name: serverName || 'Unknown Server',
        event_type: eventType || 'alert',
        details: details || '',
        started_at: Date.now()
      };
    }

    await queryRun(
      `INSERT INTO incidents (server_id, server_name, event_type, details, started_at, resolved_at, duration_seconds)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        incident.server_id,
        incident.server_name,
        incident.event_type,
        incident.details || '',
        incident.started_at || Date.now(),
        incident.resolved_at || null,
        incident.duration_seconds || null
      ]
    );
  },

  async resolveActiveIncident(serverId, eventType) {
    const active = await queryGet(
      `SELECT * FROM incidents
       WHERE server_id = ? AND event_type = ? AND resolved_at IS NULL
       ORDER BY started_at DESC LIMIT 1`,
      [serverId, eventType]
    );

    if (active) {
      const now = Date.now();
      const duration = Math.round((now - active.started_at) / 1000);
      await queryRun(
        `UPDATE incidents SET resolved_at = ?, duration_seconds = ? WHERE id = ?`,
        [now, duration, active.id]
      );
    }
  },

  async resolveIncident(serverId, eventType) {
    await this.resolveActiveIncident(serverId, eventType);
  },

  async getIncidents(limit = 50) {
    return queryAll('SELECT * FROM incidents ORDER BY started_at DESC LIMIT ?', [limit]);
  },

  async getSettings() {
    const rows = await queryAll('SELECT key, value FROM settings');
    const config = {};
    for (const r of rows) {
      config[r.key] = r.value;
    }
    return config;
  },

  async setSetting(key, value) {
    await queryRun(
      `INSERT INTO settings (key, value) VALUES (?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
      [key, String(value)]
    );
  },

  // ----------------------------------------------------
  // CLOSED-LOOP DDOS & ATTACKER INTELLIGENCE METHODS
  // ----------------------------------------------------
  async saveDdosIncident(data) {
    const incident_id = data.incident_id || ('INC-' + Date.now());
    const server_id = data.server_id || 'local-host';
    const server_ip = data.server_ip || '127.0.0.1';
    const attack_type = data.attack_type || 'Unknown DDoS Attack';
    const mitigation_level = parseInt(data.mitigation_level) || 1;
    const confidence_score = parseFloat(data.confidence_score) || 95.0;
    const status = data.status || 'SELF_HEALED';
    const ai_summary = data.ai_summary || '';
    const health_probe = typeof data.health_probe === 'object' ? JSON.stringify(data.health_probe) : (data.health_probe || '');
    const created_at = data.created_at || Date.now();

    const batchStmts = [
      {
        sql: `INSERT INTO ddos_incidents (incident_id, server_id, server_ip, attack_type, mitigation_level, confidence_score, status, ai_summary, health_probe, created_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
              ON CONFLICT(incident_id) DO UPDATE SET
                server_id = excluded.server_id,
                server_ip = excluded.server_ip,
                status = excluded.status,
                mitigation_level = excluded.mitigation_level,
                ai_summary = excluded.ai_summary,
                health_probe = excluded.health_probe`,
        args: [incident_id, server_id, server_ip, attack_type, mitigation_level, confidence_score, status, ai_summary, health_probe, created_at]
      },
      {
        sql: 'DELETE FROM attacker_profiles WHERE incident_id = ?',
        args: [incident_id]
      }
    ];

    const attackers = Array.isArray(data.attackers) ? data.attackers : [];
    let validAttackersCount = 0;

    for (const a of attackers) {
      if (!a.ip && !a.ip_address) continue;
      validAttackersCount++;
      const ip = a.ip || a.ip_address;
      const timeInfo = getIndonesianDateTime(a.created_at || created_at);

      batchStmts.push({
        sql: `INSERT INTO attacker_profiles (
                incident_id, server_id, ip_address, country, country_code, isp,
                request_count, attack_vector, user_agent, device_os, device_type,
                target_port, asn_number, asn_org, day_name, attack_date, attack_time, attack_hour,
                action_taken, created_at
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [
          incident_id,
          a.server_id || server_id,
          ip,
          a.country || 'Unknown',
          a.country_code || 'XX',
          a.isp || 'Unknown ISP',
          parseInt(a.request_count) || 1,
          a.attack_vector || attack_type,
          a.user_agent || 'Mozilla/5.0 Generic Attack Vector',
          a.device_os || 'Windows 11',
          a.device_type || 'desktop',
          parseInt(a.target_port) || 80,
          a.asn_number || 'AS-UNKNOWN',
          a.asn_org || a.isp || 'Unknown Provider',
          a.day_name || timeInfo.day_name,
          a.attack_date || timeInfo.attack_date,
          a.attack_time || timeInfo.attack_time,
          a.attack_hour !== undefined ? parseInt(a.attack_hour) : timeInfo.attack_hour,
          a.action_taken || 'BLOCKED_IPSET',
          a.created_at || created_at
        ]
      });
    }

    await client.batch(batchStmts, 'write');

    return {
      incident_id,
      server_id,
      server_ip,
      attack_type,
      mitigation_level,
      status,
      attackers_count: validAttackersCount
    };
  },

  async ingestLiveAttacker(data) {
    const ip = data.ip_address || data.ip || '127.0.0.1';
    const server_id = data.server_id || 'node-nginx-wsl';
    const incident_id = data.incident_id || ('LIVE-' + new Date().toISOString().slice(0, 10).replace(/-/g, ''));
    const timeInfo = getIndonesianDateTime(Date.now());

    const existing = await queryGet(
      `SELECT id, request_count FROM attacker_profiles
       WHERE ip_address = ? AND (incident_id = ? OR created_at > ?)
       ORDER BY created_at DESC LIMIT 1`,
      [ip, incident_id, Date.now() - 3600000]
    );

    if (existing) {
      await queryRun(
        `UPDATE attacker_profiles
         SET request_count = request_count + ?,
             action_taken = ?,
             device_os = COALESCE(?, device_os),
             user_agent = COALESCE(?, user_agent),
             isp = COALESCE(?, isp)
         WHERE id = ?`,
        [
          parseInt(data.request_count) || 20,
          data.action_taken || 'BLOCKED (IPTables / Nginx Limiter)',
          data.device_os || null,
          data.user_agent || null,
          data.isp || null,
          existing.id
        ]
      );
      return existing.id;
    }

    const info = await queryRun(
      `INSERT INTO attacker_profiles (
         incident_id, server_id, ip_address, country, country_code, isp,
         request_count, attack_vector, user_agent, device_os, device_type,
         target_port, asn_number, asn_org, day_name, attack_date, attack_time, attack_hour,
         action_taken, created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        incident_id,
        server_id,
        ip,
        data.country || 'Indonesia',
        data.country_code || 'ID',
        data.isp || 'Telkomsel / Indosat / XL Cellular',
        parseInt(data.request_count) || 100,
        data.attack_vector || 'Distributed DDoS Flood',
        data.user_agent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        data.device_os || 'Windows 11',
        data.device_type || 'desktop',
        parseInt(data.target_port) || 80,
        data.asn_number || 'AS17974',
        data.asn_org || 'Cellular Mobile Carrier Indonesia',
        timeInfo.day_name,
        timeInfo.attack_date,
        timeInfo.attack_time,
        timeInfo.attack_hour,
        data.action_taken || 'BLOCKED (IPTables / Nginx Limiter)',
        Date.now()
      ]
    );
    return Number(info.lastInsertRowid);
  },

  async getDdosIncidents(limit = 20, serverId = null) {
    let sql = 'SELECT * FROM ddos_incidents';
    const params = [];
    if (serverId && serverId !== 'all') {
      sql += ' WHERE server_id = ?';
      params.push(serverId);
    }
    sql += ' ORDER BY created_at DESC LIMIT ?';
    params.push(limit);

    const incidents = await queryAll(sql, params);
    if (incidents.length === 0) return [];

    const incIds = incidents.map((inc) => inc.incident_id);
    const placeholders = incIds.map(() => '?').join(', ');
    const allAttackers = await queryAll(
      `SELECT * FROM attacker_profiles WHERE incident_id IN (${placeholders})`,
      incIds
    );

    const attackersByInc = new Map();
    for (const a of allAttackers) {
      if (!attackersByInc.has(a.incident_id)) {
        attackersByInc.set(a.incident_id, []);
      }
      attackersByInc.get(a.incident_id).push(a);
    }

    return incidents.map((inc) => {
      let probe = null;
      try {
        if (inc.health_probe) probe = JSON.parse(inc.health_probe);
      } catch (_) {}
      return {
        ...inc,
        health_probe: probe,
        attackers: attackersByInc.get(inc.incident_id) || []
      };
    });
  },

  async getAttackerProfiles(limit = 100) {
    return queryAll(
      `SELECT * FROM attacker_profiles ORDER BY created_at DESC LIMIT ?`,
      [limit]
    );
  },

  async getFilteredAttackers(options = {}) {
    let sql = 'SELECT * FROM attacker_profiles WHERE 1=1';
    const params = [];

    if (options.server_id && options.server_id !== 'all') {
      sql += ' AND server_id = ?';
      params.push(options.server_id);
    }

    if (options.os && options.os !== 'all') {
      sql += ' AND device_os LIKE ?';
      params.push(`%${options.os}%`);
    }

    if (options.level && options.level !== 'all') {
      sql += ' AND action_taken LIKE ?';
      params.push(`%${options.level}%`);
    }

    if (options.search) {
      sql += ' AND (ip_address LIKE ? OR country LIKE ? OR isp LIKE ? OR attack_vector LIKE ? OR asn_number LIKE ?)';
      const term = `%${options.search}%`;
      params.push(term, term, term, term, term);
    }

    sql += ' ORDER BY created_at DESC LIMIT ?';
    params.push(options.limit || 100);

    return queryAll(sql, params);
  },

  async getDeviceStats() {
    const countRow = await queryGet('SELECT COUNT(*) as count FROM attacker_profiles');
    const total = Number(countRow?.count || 0);
    if (total === 0) {
      return {
        total: 0,
        distribution: [
          { os: 'Windows', count: 0, percentage: 0 },
          { os: 'Linux', count: 0, percentage: 0 },
          { os: 'macOS', count: 0, percentage: 0 },
          { os: 'Android', count: 0, percentage: 0 },
          { os: 'Bots & Scripts', count: 0, percentage: 0 }
        ]
      };
    }

    const rows = await queryAll(`
      SELECT
        CASE
          WHEN device_os LIKE '%Windows%' THEN 'Windows'
          WHEN device_os LIKE '%Linux%' OR device_os LIKE '%Ubuntu%' OR device_os LIKE '%Debian%' THEN 'Linux'
          WHEN device_os LIKE '%macOS%' OR device_os LIKE '%Mac%' THEN 'macOS'
          WHEN device_os LIKE '%Android%' THEN 'Android'
          ELSE 'Bots & Scripts'
        END AS os_category,
        COUNT(*) as count
      FROM attacker_profiles
      GROUP BY os_category
      ORDER BY count DESC
    `);

    const distribution = rows.map((r) => ({
      os: r.os_category,
      count: Number(r.count),
      percentage: Math.round((Number(r.count) / total) * 1000) / 10
    }));

    return { total, distribution };
  },

  async getHourlyDistribution() {
    const rows = await queryAll(`
      SELECT attack_hour, COUNT(*) as hit_count
      FROM attacker_profiles
      GROUP BY attack_hour
      ORDER BY attack_hour ASC
    `);

    const hours = Array.from({ length: 24 }, (_, i) => ({
      hour: `${String(i).padStart(2, '0')}:00`,
      hour_num: i,
      hits: 0
    }));

    for (const r of rows) {
      const idx = Number(r.attack_hour);
      if (hours[idx]) {
        hours[idx].hits = Number(r.hit_count);
      }
    }

    return hours;
  },

  async getAllAttackersForExport() {
    return queryAll(`
      SELECT
        id, incident_id, ip_address, country, country_code, isp,
        asn_number, asn_org, target_port, device_os, device_type,
        attack_vector, request_count, day_name, attack_date, attack_time,
        action_taken, user_agent
      FROM attacker_profiles
      ORDER BY created_at DESC
    `);
  },

  async getDdosSummaryStats() {
    const [
      incCountRow,
      attCountRow,
      latestIncident,
      topCountries,
      topIps,
      settings
    ] = await Promise.all([
      queryGet('SELECT COUNT(*) as count FROM ddos_incidents'),
      queryGet('SELECT COUNT(DISTINCT ip_address) as count FROM attacker_profiles'),
      queryGet('SELECT * FROM ddos_incidents ORDER BY created_at DESC LIMIT 1'),
      queryAll(`
        SELECT country, country_code, COUNT(*) as hit_count
        FROM attacker_profiles
        GROUP BY country
        ORDER BY hit_count DESC
        LIMIT 5
      `),
      queryAll(`
        SELECT ip_address, country, country_code, isp, device_os, target_port, SUM(request_count) as total_requests, action_taken
        FROM attacker_profiles
        GROUP BY ip_address
        ORDER BY total_requests DESC
        LIMIT 10
      `),
      this.getSettings()
    ]);

    const totalIncidents = Number(incCountRow?.count || 0);
    const totalAttackersBlocked = Number(attCountRow?.count || 0);
    const mode = settings.closed_loop_mode || 'auto';

    return {
      total_incidents: totalIncidents,
      total_attackers_blocked: totalAttackersBlocked,
      current_defense_level: latestIncident ? Number(latestIncident.mitigation_level) : 0,
      current_status: latestIncident ? latestIncident.status : 'NORMAL',
      closed_loop_mode: mode,
      latest_incident: latestIncident || null,
      top_countries: topCountries,
      top_ips: topIps
    };
  },

  // ----------------------------------------------------
  // ADMIN AUTHENTICATION & SESSION METHODS
  // ----------------------------------------------------
  async authenticateAdmin(username, password) {
    if (!username || !password) return null;
    const user = await queryGet('SELECT * FROM admin_users WHERE username = ?', [username]);
    if (!user) return null;

    const isValid = verifyPassword(password, user.salt, user.password_hash);
    if (!isValid) return null;

    return {
      id: user.id,
      username: user.username,
      full_name: user.full_name,
      role: user.role,
      last_login: user.last_login
    };
  },

  async createAdminSession(username) {
    const token = crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    const expiresAt = now + (24 * 3600 * 1000); // 24 Hours

    await client.batch([
      {
        sql: `INSERT INTO admin_sessions (token, username, created_at, expires_at) VALUES (?, ?, ?, ?)`,
        args: [token, username, now, expiresAt]
      },
      {
        sql: 'UPDATE admin_users SET last_login = ? WHERE username = ?',
        args: [now, username]
      },
      {
        sql: 'DELETE FROM admin_sessions WHERE expires_at < ?',
        args: [now]
      }
    ], 'write');

    return {
      token,
      expires_at: expiresAt
    };
  },

  async verifyAdminSession(token) {
    if (!token) return null;
    const now = Date.now();

    return queryGet(
      `SELECT s.token, s.username, s.expires_at, u.full_name, u.role
       FROM admin_sessions s
       JOIN admin_users u ON s.username = u.username
       WHERE s.token = ? AND s.expires_at > ?`,
      [token, now]
    );
  },

  async deleteAdminSession(token) {
    if (!token) return;
    await queryRun('DELETE FROM admin_sessions WHERE token = ?', [token]);
  },

  async changeAdminPassword(username, oldPassword, newPassword) {
    const user = await queryGet('SELECT * FROM admin_users WHERE username = ?', [username]);
    if (!user) return { success: false, error: 'User tidak ditemukan' };

    const isValid = verifyPassword(oldPassword, user.salt, user.password_hash);
    if (!isValid) return { success: false, error: 'Password lama salah' };

    const newSalt = crypto.randomBytes(16).toString('hex');
    const newHash = hashPassword(newPassword, newSalt);

    await queryRun(
      `UPDATE admin_users SET password_hash = ?, salt = ? WHERE username = ?`,
      [newHash, newSalt, username]
    );

    return { success: true };
  }
};

module.exports = DB;
