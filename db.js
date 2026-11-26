const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const dbPath = path.join(__dirname, 'serverpulse.db');
const db = new DatabaseSync(dbPath);

// WAL mode and 10s busy timeout for high-concurrency resilience
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA busy_timeout = 10000;');
db.exec('PRAGMA synchronous = NORMAL;');

// Initialize schema
db.exec(`
  CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    full_name TEXT DEFAULT 'Chief Security Officer',
    role TEXT DEFAULT 'superadmin',
    last_login INTEGER,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS admin_sessions (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_sessions_token ON admin_sessions(token);
  CREATE INDEX IF NOT EXISTS idx_admin_username ON admin_users(username);

  CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,              -- 'agent' or 'probe'
    target TEXT,                     -- URL or Host:Port for probes, Hostname for agent
    probe_type TEXT DEFAULT 'http',  -- 'http', 'tcp', 'ping'
    token TEXT UNIQUE,               -- Secret token for agent auth
    status TEXT DEFAULT 'offline',   -- 'online', 'degraded', 'offline'
    last_heartbeat INTEGER,
    created_at INTEGER,
    os_info TEXT,                    -- JSON string with platform, arch, cpu model, etc.
    tags TEXT
  );

  CREATE TABLE IF NOT EXISTS metrics (
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
    top_processes TEXT,              -- JSON string
    FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_metrics_server ON metrics(server_id, timestamp);

  CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id TEXT NOT NULL,
    server_name TEXT NOT NULL,
    event_type TEXT NOT NULL,        -- 'offline', 'high_cpu', 'high_ram', 'recovered'
    details TEXT,
    started_at INTEGER NOT NULL,
    resolved_at INTEGER,
    duration_seconds INTEGER
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  -- Closed-Loop DDoS & Attacker Intelligence Tables
  CREATE TABLE IF NOT EXISTS ddos_incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT UNIQUE NOT NULL,
    attack_type TEXT NOT NULL,
    mitigation_level INTEGER DEFAULT 1,
    confidence_score REAL DEFAULT 0,
    status TEXT DEFAULT 'ACTIVE',       -- 'ACTIVE', 'MITIGATED', 'SELF_HEALED'
    ai_summary TEXT,
    health_probe TEXT,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS attacker_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
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
  );

  CREATE INDEX IF NOT EXISTS idx_attackers_incident ON attacker_profiles(incident_id);
  CREATE INDEX IF NOT EXISTS idx_attackers_ip ON attacker_profiles(ip_address);
`);

// Safe Migration for existing databases
function migrateSchema() {
  const columns = [
    { name: 'device_os', type: 'TEXT DEFAULT "Windows 11"' },
    { name: 'device_type', type: 'TEXT DEFAULT "desktop"' },
    { name: 'target_port', type: 'INTEGER DEFAULT 80' },
    { name: 'asn_number', type: 'TEXT DEFAULT "AS-UNKNOWN"' },
    { name: 'asn_org', type: 'TEXT DEFAULT "Unknown Provider"' },
    { name: 'day_name', type: 'TEXT DEFAULT "Rabu"' },
    { name: 'attack_date', type: 'TEXT DEFAULT ""' },
    { name: 'attack_time', type: 'TEXT DEFAULT ""' },
    { name: 'attack_hour', type: 'INTEGER DEFAULT 0' }
  ];

  for (const col of columns) {
    try {
      db.exec(`ALTER TABLE attacker_profiles ADD COLUMN ${col.name} ${col.type}`);
    } catch (_) {
      // Column already exists, ignore
    }
  }

  try {
    db.exec(`CREATE INDEX IF NOT EXISTS idx_attackers_device ON attacker_profiles(device_os)`);
  } catch (_) {}
}
migrateSchema();

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

// Seed default administrator if none exists
function seedDefaultAdmin() {
  const existing = db.prepare('SELECT id FROM admin_users WHERE username = ?').get('admin');
  if (!existing) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword('admin123', salt);
    db.prepare(`
      INSERT INTO admin_users (username, password_hash, salt, full_name, role, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run('admin', hash, salt, 'Chief Security Officer', 'superadmin', Date.now());
    console.log('[Auth] Akun Administrator bawaan berhasil dibuat (admin / admin123)');
  }
}
seedDefaultAdmin();

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

// Default settings if not set
const defaultSettings = [
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

for (const [key, val] of defaultSettings) {
  const existing = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  if (!existing) {
    db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)').run(key, val);
  }
}

// Database helper functions
const DB = {
  getServers() {
    return db.prepare('SELECT * FROM servers ORDER BY created_at DESC').all();
  },

  getServerById(id) {
    return db.prepare('SELECT * FROM servers WHERE id = ?').get(id);
  },

  getServerByToken(token) {
    if (!token) return null;
    return db.prepare('SELECT * FROM servers WHERE token = ?').get(token);
  },

  createServer(server) {
    const stmt = db.prepare(`
      INSERT INTO servers (id, name, type, target, probe_type, token, status, last_heartbeat, created_at, os_info, tags)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
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
      server.tags || ''
    );
    return this.getServerById(server.id);
  },

  updateServerStatus(id, status, lastHeartbeat = Date.now(), osInfo = null) {
    if (osInfo) {
      const osStr = typeof osInfo === 'string' ? osInfo : JSON.stringify(osInfo);
      db.prepare(`
        UPDATE servers 
        SET status = ?, last_heartbeat = ?, os_info = ?
        WHERE id = ?
      `).run(status, lastHeartbeat, osStr, id);
    } else {
      db.prepare(`
        UPDATE servers 
        SET status = ?, last_heartbeat = ?
        WHERE id = ?
      `).run(status, lastHeartbeat, id);
    }
  },

  deleteServer(id) {
    db.prepare('DELETE FROM metrics WHERE server_id = ?').run(id);
    db.prepare('DELETE FROM incidents WHERE server_id = ?').run(id);
    db.prepare('DELETE FROM servers WHERE id = ?').run(id);
  },

  // Save metrics snapshot
  saveMetrics(serverIdOrMetrics, maybeMetrics) {
    let serverId = serverIdOrMetrics;
    let metrics = maybeMetrics;

    if (typeof serverIdOrMetrics === 'object' && serverIdOrMetrics !== null) {
      metrics = serverIdOrMetrics;
      serverId = metrics.server_id;
    }

    if (!metrics) return;

    const stmt = db.prepare(`
      INSERT INTO metrics (
        server_id, timestamp, cpu_percent, memory_percent, 
        memory_used_gb, memory_total_gb, disk_percent, 
        net_rx_kb, net_tx_kb, response_time_ms, top_processes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
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
      metrics.top_processes ? (typeof metrics.top_processes === 'string' ? metrics.top_processes : JSON.stringify(metrics.top_processes)) : null
    );

    // Keep database lean: purge records older than 7 days
    const sevenDaysAgo = Date.now() - (7 * 24 * 3600 * 1000);
    db.prepare('DELETE FROM metrics WHERE timestamp < ?').run(sevenDaysAgo);
  },

  getLatestMetrics(serverId) {
    return db.prepare(`
      SELECT * FROM metrics 
      WHERE server_id = ? 
      ORDER BY timestamp DESC 
      LIMIT 1
    `).get(serverId);
  },

  getMetricsHistory(serverId, limit = 60) {
    const rows = db.prepare(`
      SELECT * FROM metrics 
      WHERE server_id = ? 
      ORDER BY timestamp DESC 
      LIMIT ?
    `).all(serverId, limit);
    return rows.reverse();
  },

  // Incidents
  createIncident(incidentOrServerId, serverName, eventType, details) {
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

    const stmt = db.prepare(`
      INSERT INTO incidents (server_id, server_name, event_type, details, started_at, resolved_at, duration_seconds)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      incident.server_id,
      incident.server_name,
      incident.event_type,
      incident.details || '',
      incident.started_at || Date.now(),
      incident.resolved_at || null,
      incident.duration_seconds || null
    );
  },

  resolveActiveIncident(serverId, eventType) {
    const active = db.prepare(`
      SELECT * FROM incidents 
      WHERE server_id = ? AND event_type = ? AND resolved_at IS NULL 
      ORDER BY started_at DESC LIMIT 1
    `).get(serverId, eventType);

    if (active) {
      const now = Date.now();
      const duration = Math.round((now - active.started_at) / 1000);
      db.prepare(`
        UPDATE incidents 
        SET resolved_at = ?, duration_seconds = ? 
        WHERE id = ?
      `).run(now, duration, active.id);
    }
  },

  resolveIncident(serverId, eventType) {
    this.resolveActiveIncident(serverId, eventType);
  },

  getIncidents(limit = 50) {
    return db.prepare('SELECT * FROM incidents ORDER BY started_at DESC LIMIT ?').all(limit);
  },

  getSettings() {
    const rows = db.prepare('SELECT key, value FROM settings').all();
    const config = {};
    for (const r of rows) {
      config[r.key] = r.value;
    }
    return config;
  },

  setSetting(key, value) {
    db.prepare(`
      INSERT INTO settings (key, value) VALUES (?, ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `).run(key, String(value));
  },

  // ----------------------------------------------------
  // CLOSED-LOOP DDOS & ATTACKER INTELLIGENCE METHODS
  // ----------------------------------------------------
  saveDdosIncident(data) {
    const incident_id = data.incident_id || ('INC-' + Date.now());
    const attack_type = data.attack_type || 'Unknown DDoS Attack';
    const mitigation_level = parseInt(data.mitigation_level) || 1;
    const confidence_score = parseFloat(data.confidence_score) || 95.0;
    const status = data.status || 'SELF_HEALED';
    const ai_summary = data.ai_summary || '';
    const health_probe = typeof data.health_probe === 'object' ? JSON.stringify(data.health_probe) : (data.health_probe || '');
    const created_at = data.created_at || Date.now();

    // Simpan ke ddos_incidents
    const stmt = db.prepare(`
      INSERT INTO ddos_incidents (incident_id, attack_type, mitigation_level, confidence_score, status, ai_summary, health_probe, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(incident_id) DO UPDATE SET
        status = excluded.status,
        mitigation_level = excluded.mitigation_level,
        ai_summary = excluded.ai_summary,
        health_probe = excluded.health_probe
    `);
    stmt.run(incident_id, attack_type, mitigation_level, confidence_score, status, ai_summary, health_probe, created_at);

    // Bersihkan profil penyerang lama jika incident_id sama (idempotent)
    db.prepare('DELETE FROM attacker_profiles WHERE incident_id = ?').run(incident_id);

    // Simpan daftar profil penyerang (attacker_profiles)
    const attackers = Array.isArray(data.attackers) ? data.attackers : [];
    const insertAttacker = db.prepare(`
      INSERT INTO attacker_profiles (
        incident_id, ip_address, country, country_code, isp, 
        request_count, attack_vector, user_agent, device_os, device_type,
        target_port, asn_number, asn_org, day_name, attack_date, attack_time, attack_hour,
        action_taken, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const a of attackers) {
      if (!a.ip && !a.ip_address) continue;
      const ip = a.ip || a.ip_address;
      const timeInfo = getIndonesianDateTime(a.created_at || created_at);

      insertAttacker.run(
        incident_id,
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
      );
    }

    return {
      incident_id,
      attack_type,
      mitigation_level,
      status,
      attackers_count: attackers.length
    };
  },

  getDdosIncidents(limit = 20) {
    const incidents = db.prepare('SELECT * FROM ddos_incidents ORDER BY created_at DESC LIMIT ?').all(limit);
    return incidents.map(inc => {
      const attackers = db.prepare('SELECT * FROM attacker_profiles WHERE incident_id = ?').all(inc.incident_id);
      let probe = null;
      try {
        if (inc.health_probe) probe = JSON.parse(inc.health_probe);
      } catch (_) {}
      return {
        ...inc,
        health_probe: probe,
        attackers
      };
    });
  },

  getAttackerProfiles(limit = 100) {
    return db.prepare(`
      SELECT * FROM attacker_profiles 
      ORDER BY created_at DESC 
      LIMIT ?
    `).all(limit);
  },

  getFilteredAttackers(options = {}) {
    let sql = 'SELECT * FROM attacker_profiles WHERE 1=1';
    const params = [];

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

    return db.prepare(sql).all(...params);
  },

  getDeviceStats() {
    const total = db.prepare('SELECT COUNT(*) as count FROM attacker_profiles').get().count;
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

    const rows = db.prepare(`
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
    `).all();

    const distribution = rows.map(r => ({
      os: r.os_category,
      count: r.count,
      percentage: Math.round((r.count / total) * 1000) / 10
    }));

    return { total, distribution };
  },

  getHourlyDistribution() {
    const rows = db.prepare(`
      SELECT attack_hour, COUNT(*) as hit_count
      FROM attacker_profiles
      GROUP BY attack_hour
      ORDER BY attack_hour ASC
    `).all();

    // Map 0 - 23 hours
    const hours = Array.from({ length: 24 }, (_, i) => ({
      hour: `${String(i).padStart(2, '0')}:00`,
      hour_num: i,
      hits: 0
    }));

    for (const r of rows) {
      const idx = r.attack_hour;
      if (hours[idx]) {
        hours[idx].hits = r.hit_count;
      }
    }

    return hours;
  },

  getAllAttackersForExport() {
    return db.prepare(`
      SELECT 
        id,
        incident_id,
        ip_address,
        country,
        country_code,
        isp,
        asn_number,
        asn_org,
        target_port,
        device_os,
        device_type,
        attack_vector,
        request_count,
        day_name,
        attack_date,
        attack_time,
        action_taken,
        user_agent
      FROM attacker_profiles 
      ORDER BY created_at DESC
    `).all();
  },

  getDdosSummaryStats() {
    const totalIncidents = db.prepare('SELECT COUNT(*) as count FROM ddos_incidents').get().count;
    const totalAttackersBlocked = db.prepare('SELECT COUNT(DISTINCT ip_address) as count FROM attacker_profiles').get().count;
    const latestIncident = db.prepare('SELECT * FROM ddos_incidents ORDER BY created_at DESC LIMIT 1').get();
    
    // Top 5 Countries of attackers
    const topCountries = db.prepare(`
      SELECT country, country_code, COUNT(*) as hit_count 
      FROM attacker_profiles 
      GROUP BY country 
      ORDER BY hit_count DESC 
      LIMIT 5
    `).all();

    // Top 5 Attacker IPs by requests
    const topIps = db.prepare(`
      SELECT ip_address, country, country_code, isp, device_os, target_port, SUM(request_count) as total_requests, action_taken
      FROM attacker_profiles
      GROUP BY ip_address
      ORDER BY total_requests DESC
      LIMIT 10
    `).all();

    // Mode Closed Loop
    const mode = this.getSettings().closed_loop_mode || 'auto';

    return {
      total_incidents: totalIncidents,
      total_attackers_blocked: totalAttackersBlocked,
      current_defense_level: latestIncident ? latestIncident.mitigation_level : 0,
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
  authenticateAdmin(username, password) {
    if (!username || !password) return null;
    const user = db.prepare('SELECT * FROM admin_users WHERE username = ?').get(username);
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

  createAdminSession(username) {
    const token = crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    const expiresAt = now + (24 * 3600 * 1000); // 24 Hours

    db.prepare(`
      INSERT INTO admin_sessions (token, username, created_at, expires_at)
      VALUES (?, ?, ?, ?)
    `).run(token, username, now, expiresAt);

    // Update last_login on admin_users
    db.prepare('UPDATE admin_users SET last_login = ? WHERE username = ?').run(now, username);

    // Clean expired sessions
    db.prepare('DELETE FROM admin_sessions WHERE expires_at < ?').run(now);

    return {
      token,
      expires_at: expiresAt
    };
  },

  verifyAdminSession(token) {
    if (!token) return null;
    const now = Date.now();

    const session = db.prepare(`
      SELECT s.token, s.username, s.expires_at, u.full_name, u.role
      FROM admin_sessions s
      JOIN admin_users u ON s.username = u.username
      WHERE s.token = ? AND s.expires_at > ?
    `).get(token, now);

    return session || null;
  },

  deleteAdminSession(token) {
    if (!token) return;
    db.prepare('DELETE FROM admin_sessions WHERE token = ?').run(token);
  },

  changeAdminPassword(username, oldPassword, newPassword) {
    const user = db.prepare('SELECT * FROM admin_users WHERE username = ?').get(username);
    if (!user) return { success: false, error: 'User tidak ditemukan' };

    const isValid = verifyPassword(oldPassword, user.salt, user.password_hash);
    if (!isValid) return { success: false, error: 'Password lama salah' };

    const newSalt = crypto.randomBytes(16).toString('hex');
    const newHash = hashPassword(newPassword, newSalt);

    db.prepare(`
      UPDATE admin_users 
      SET password_hash = ?, salt = ? 
      WHERE username = ?
    `).run(newHash, newSalt, username);

    return { success: true };
  }
};

module.exports = DB;
