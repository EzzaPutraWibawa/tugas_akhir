const DB = require('../db');

// Cache to prevent alert spamming (cooldown 5 minutes per server per event)
const alertCooldowns = new Map();
const COOLDOWN_MS = 5 * 60 * 1000;

const Notifier = {
  async sendAlert({ serverId, serverName, eventType, message, level = 'warning' }) {
    const key = `${serverId}_${eventType}`;
    const now = Date.now();
    const lastSent = alertCooldowns.get(key) || 0;

    // Recovery alerts bypass cooldown
    if (eventType !== 'recovered' && (now - lastSent < COOLDOWN_MS)) {
      return { skipped: true, reason: 'Cooldown active' };
    }
    alertCooldowns.set(key, now);

    const settings = await DB.getSettings();
    const results = { telegram: false, discord: false };

    // Format emoji & title based on level & eventType
    let icon = '⚠️';
    let title = 'SERVER ALERT';
    if (eventType === 'offline') {
      icon = '🚨';
      title = 'SERVER DOWN / OFFLINE';
    } else if (eventType === 'recovered') {
      icon = '✅';
      title = 'SERVER RECOVERED';
    } else if (eventType === 'high_cpu') {
      icon = '🔥';
      title = 'HIGH CPU USAGE';
    } else if (eventType === 'high_ram') {
      icon = '💾';
      title = 'HIGH MEMORY USAGE';
    }

    const timestampStr = new Date().toLocaleString('id-ID', { timeZoneName: 'short' });

    // 1. Send to Telegram if configured
    if (settings.telegram_bot_token && settings.telegram_chat_id) {
      try {
        const dashboardUrl = process.env.PUBLIC_DASHBOARD_URL || 'http://localhost:3000';
        const tgText = `${icon} *${title}*\n\n` +
          `🖥️ *Server*: \`${serverName}\`\n` +
          `📌 *Event*: ${eventType.toUpperCase()}\n` +
          `📝 *Detail*: ${message}\n` +
          `⏰ *Waktu*: ${timestampStr}\n` +
          `🌐 *Monitoring*: [ServerPulse Dashboard](${dashboardUrl})`;

        const res = await fetch(`https://api.telegram.org/bot${settings.telegram_bot_token}/sendMessage`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            chat_id: settings.telegram_chat_id,
            text: tgText,
            parse_mode: 'Markdown'
          }),
          signal: AbortSignal.timeout(5000)
        });
        const data = await res.json();
        results.telegram = data.ok === true;
      } catch (err) {
        console.error('Failed to send Telegram alert:', err.message);
      }
    }

    // 2. Send to Discord if configured
    if (settings.discord_webhook_url) {
      try {
        let embedColor = 0xffa500; // orange
        if (eventType === 'offline') embedColor = 0xff0000; // red
        if (eventType === 'recovered') embedColor = 0x00ff00; // green

        const discordBody = {
          username: "ServerPulse Monitor",
          avatar_url: "https://img.icons8.com/fluency/96/server.png",
          embeds: [
            {
              title: `${icon} ${title}: ${serverName}`,
              description: message,
              color: embedColor,
              fields: [
                { name: "Server", value: serverName, inline: true },
                { name: "Event", value: eventType, inline: true },
                { name: "Timestamp", value: timestampStr, inline: false }
              ],
              footer: { text: "ServerPulse Real-Time Observability" }
            }
          ]
        };

        const res = await fetch(settings.discord_webhook_url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(discordBody),
          signal: AbortSignal.timeout(5000)
        });
        results.discord = res.ok;
      } catch (err) {
        console.error('Failed to send Discord alert:', err.message);
      }
    }

    return results;
  },

  async testNotification(params = {}) {
    const settings = await DB.getSettings();
    const token = params.telegram_bot_token || settings.telegram_bot_token;
    const chatId = params.telegram_chat_id || settings.telegram_chat_id;
    const discordUrl = params.discord_webhook_url || settings.discord_webhook_url;

    const results = { telegram: false, discord: false, errors: [] };

    if (token && chatId) {
      try {
        const res = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            chat_id: chatId,
            text: `🔔 *ServerPulse Test Alert*\n\nKoneksi bot Telegram monitoring berhasil dikonfigurasi!\nWaktu: ${new Date().toISOString()}`,
            parse_mode: 'Markdown'
          }),
          signal: AbortSignal.timeout(5000)
        });
        const data = await res.json();
        if (data.ok) results.telegram = true;
        else results.errors.push(`Telegram: ${data.description}`);
      } catch (err) {
        results.errors.push(`Telegram Error: ${err.message}`);
      }
    }

    if (discordUrl) {
      try {
        const res = await fetch(discordUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            content: "🔔 **ServerPulse Test Alert**: Koneksi Webhook Discord monitoring berhasil dikonfigurasi!"
          }),
          signal: AbortSignal.timeout(5000)
        });
        if (res.ok) results.discord = true;
        else results.errors.push(`Discord HTTP Status: ${res.status}`);
      } catch (err) {
        results.errors.push(`Discord Error: ${err.message}`);
      }
    }

    return results;
  }
};

module.exports = Notifier;
