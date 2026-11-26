// Netdata Integration Service
// Communicates with Netdata Agent on Target (http://localhost:19999)

const DB = require('../db');

class NetdataService {
  constructor() {
    this.defaultHost = 'http://localhost:19999';
    this.timeoutMs = 3500;
  }

  getHost() {
    const settings = DB.getSettings();
    return settings.netdata_host || this.defaultHost;
  }

  async fetchWithTimeout(endpoint, timeout = this.timeoutMs) {
    const host = this.getHost();
    const url = `${host}${endpoint}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
      const res = await fetch(url, { signal: controller.signal });
      clearTimeout(timer);
      if (!res.ok) {
        throw new Error(`HTTP Error ${res.status} from Netdata`);
      }
      return await res.json();
    } catch (err) {
      clearTimeout(timer);
      throw err;
    }
  }

  // Get Host System info (Linux Mint, Cores, RAM, Netdata version)
  async getHostInfo() {
    try {
      const data = await this.fetchWithTimeout('/api/v1/info');
      return {
        online: true,
        hostname: data.hostname || 'zaa-VirtualBox',
        os_name: data.os_name || 'Linux Mint',
        os_version: data.os_version || '22.3',
        kernel: data.kernel_version || 'Linux x86_64',
        cores_total: parseInt(data.cores_total) || 1,
        ram_total_gb: Math.round(((parseInt(data.ram_total) || 3681464320) / (1024 ** 3)) * 10) / 10,
        disk_space_gb: Math.round(((parseInt(data.total_disk_space) || 34359738368) / (1024 ** 3)) * 10) / 10,
        version: data.version || 'v2.13.0',
        alarms_normal: data.alarms?.normal || 0,
        alarms_warning: data.alarms?.warning || 0,
        alarms_critical: data.alarms?.critical || 0
      };
    } catch (err) {
      return {
        online: false,
        error: err.message,
        hostname: 'zaa-VirtualBox (Offline/Unreachable)',
        os_name: 'Linux Mint',
        os_version: '22.3',
        cores_total: 1,
        ram_total_gb: 3.7,
        disk_space_gb: 32.0,
        version: 'Netdata v2.13'
      };
    }
  }

  // Get live CPU, RAM, Network, and Load metrics
  async getLiveTelemetry() {
    try {
      const [cpuData, ramData, netData, alarmsData] = await Promise.allSettled([
        this.fetchWithTimeout('/api/v1/data?chart=system.cpu&after=-5&points=1'),
        this.fetchWithTimeout('/api/v1/data?chart=system.ram&after=-5&points=1'),
        this.fetchWithTimeout('/api/v1/data?chart=system.net&after=-5&points=1'),
        this.fetchWithTimeout('/api/v1/alarms?active')
      ]);

      let cpu = { total: 0, user: 0, system: 0, softirq: 0 };
      if (cpuData.status === 'fulfilled' && cpuData.value.data?.[0]) {
        const labels = cpuData.value.labels;
        const vals = cpuData.value.data[0];
        const valMap = {};
        labels.forEach((l, i) => valMap[l] = vals[i] || 0);

        const user = Math.round((valMap.user || 0) * 10) / 10;
        const system = Math.round((valMap.system || 0) * 10) / 10;
        const softirq = Math.round((valMap.softirq || 0) * 10) / 10;
        const total = Math.min(100, Math.round((user + system + softirq) * 10) / 10);
        cpu = { total, user, system, softirq };
      }

      let ram = { percent: 0, used_gb: 0, total_gb: 3.7, free_gb: 0 };
      if (ramData.status === 'fulfilled' && ramData.value.data?.[0]) {
        const labels = ramData.value.labels;
        const vals = ramData.value.data[0];
        const valMap = {};
        labels.forEach((l, i) => valMap[l] = vals[i] || 0);

        const usedMb = valMap.used || 1200;
        const freeMb = valMap.free || 1500;
        const cachedMb = valMap.cached || 800;
        const buffersMb = valMap.buffers || 200;
        const totalMb = usedMb + freeMb + cachedMb + buffersMb;

        const usedGb = Math.round(((usedMb + cachedMb) / 1024) * 10) / 10;
        const totalGb = Math.round((totalMb / 1024) * 10) / 10;
        const percent = Math.min(100, Math.round(((usedMb + cachedMb) / totalMb) * 1000) / 10);
        ram = { percent, used_gb: usedGb, total_gb: totalGb, free_gb: Math.round((freeMb / 1024) * 10) / 10 };
      }

      let net = { rx_kbps: 0, tx_kbps: 0 };
      if (netData.status === 'fulfilled' && netData.value.data?.[0]) {
        const labels = netData.value.labels;
        const vals = netData.value.data[0];
        const valMap = {};
        labels.forEach((l, i) => valMap[l] = vals[i] || 0);
        net = {
          rx_kbps: Math.abs(Math.round((valMap.InOctets || valMap.received || 0) * 10) / 10),
          tx_kbps: Math.abs(Math.round((valMap.OutOctets || valMap.sent || 0) * 10) / 10)
        };
      }

      const activeAlarms = [];
      if (alarmsData.status === 'fulfilled' && alarmsData.value.alarms) {
        for (const [alarmKey, a] of Object.entries(alarmsData.value.alarms)) {
          activeAlarms.push({
            id: alarmKey,
            name: a.name,
            status: a.status,
            info: a.info,
            value: a.value_string || a.value,
            units: a.units,
            last_status_change: a.last_status_change
          });
        }
      }

      return {
        online: true,
        timestamp: Date.now(),
        cpu,
        ram,
        net,
        active_alarms: activeAlarms
      };
    } catch (err) {
      // Fallback
      return {
        online: false,
        timestamp: Date.now(),
        cpu: { total: 12.5, user: 6.2, system: 4.8, softirq: 1.5 },
        ram: { percent: 45.2, used_gb: 1.7, total_gb: 3.7, free_gb: 2.0 },
        net: { rx_kbps: 42.1, tx_kbps: 18.4 },
        active_alarms: []
      };
    }
  }

  // Get historical time series for charts (e.g. after=-900 for 15 minutes, points=60)
  async getChartHistory(chartName = 'system.cpu', afterSeconds = -900, points = 60) {
    try {
      const endpoint = `/api/v1/data?chart=${encodeURIComponent(chartName)}&after=${afterSeconds}&points=${points}`;
      const data = await this.fetchWithTimeout(endpoint);
      
      const labels = [];
      const series = {};

      if (data.labels && data.data) {
        // First column is usually timestamp
        const dimNames = data.labels.slice(1);
        dimNames.forEach(dim => series[dim] = []);

        // Netdata returns newest first, reverse for chronological chart
        const rows = [...data.data].reverse();
        for (const row of rows) {
          const t = new Date(row[0] * 1000);
          labels.push(`${String(t.getHours()).padStart(2, '0')}:${String(t.getMinutes()).padStart(2, '0')}:${String(t.getSeconds()).padStart(2, '0')}`);
          dimNames.forEach((dim, i) => {
            const val = row[i + 1];
            series[dim].push(val !== null && val !== undefined ? Math.round(val * 10) / 10 : 0);
          });
        }
      }

      return {
        success: true,
        chart: chartName,
        after: afterSeconds,
        points: points,
        labels,
        series
      };
    } catch (err) {
      // Provide simulated fallback timeline if Netdata is unreachable
      const pointsCount = Math.min(Math.abs(points), 60);
      const labels = [];
      const series = { user: [], system: [], softirq: [] };
      const now = Date.now();

      for (let i = pointsCount - 1; i >= 0; i--) {
        const t = new Date(now - (i * 15 * 1000));
        labels.push(`${String(t.getHours()).padStart(2, '0')}:${String(t.getMinutes()).padStart(2, '0')}:${String(t.getSeconds()).padStart(2, '0')}`);
        series.user.push(Math.round((5 + Math.random() * 8) * 10) / 10);
        series.system.push(Math.round((3 + Math.random() * 5) * 10) / 10);
        series.softirq.push(Math.round((1 + Math.random() * 2) * 10) / 10);
      }

      return {
        success: false,
        error: err.message,
        chart: chartName,
        after: afterSeconds,
        labels,
        series
      };
    }
  }

  // Check active DDoS alarms specifically for Closed-Loop triggers
  async checkDdosAlarms() {
    try {
      const data = await this.fetchWithTimeout('/api/v1/alarms?active', 2000);
      const triggered = [];

      if (data && data.alarms) {
        for (const [key, alarm] of Object.entries(data.alarms)) {
          if (alarm.status === 'CRITICAL' || alarm.status === 'WARNING') {
            const name = (alarm.name || key).toLowerCase();
            const keyLower = (key || '').toLowerCase();

            // Ignore non-network / non-security system alarms
            if (name.includes('disk') || name.includes('clock') || name.includes('timex') || name.includes('swap') || name.includes('entropy')) {
              continue;
            }

            let level = 0;
            let type = '';

            // 1. Layer 7: HTTP Request Flood & Web CPU Spike
            if (name.includes('l7') || name.includes('http') || name.includes('nginx') || (name.includes('cpu') && (name.includes('flood') || alarm.status === 'CRITICAL'))) {
              level = 3;
              type = 'Layer 7 HTTP Request Flood';
            }
            // 2. Layer 4: TCP SYN, Accept Queue Overflow, Socket Exhaustion
            else if (name.includes('l4') || name.includes('syn') || name.includes('accept_queue') || name.includes('syn_queue') || name.includes('tcp_conn') || name.includes('tcpsock') || keyLower.includes('ip.tcp') || keyLower.includes('tcp_listen')) {
              level = 2;
              type = 'Layer 4 TCP SYN / Connection Flood';
            }
            // 3. Layer 3: ICMP & Packet Rate Spike
            else if (name.includes('l3') || name.includes('icmp') || keyLower.includes('ipv4.icmp') || (name.includes('packet') && !name.includes('drop'))) {
              level = 1;
              type = 'Layer 3 ICMP / Inbound Packet Flood';
            }

            // Only push if matched an actual DDoS attack vector
            if (level > 0) {
              triggered.push({
                key,
                name: alarm.name || key,
                level,
                type,
                status: alarm.status,
                info: alarm.info,
                value: alarm.value_string || alarm.value
              });
            }
          }
        }
      }

      // Sort triggered alarms by severity (CRITICAL first, then highest level)
      triggered.sort((a, b) => {
        if (a.status === 'CRITICAL' && b.status !== 'CRITICAL') return -1;
        if (b.status === 'CRITICAL' && a.status !== 'CRITICAL') return 1;
        return b.level - a.level;
      });

      return triggered;
    } catch (err) {
      return [];
    }
  }
}

module.exports = new NetdataService();
