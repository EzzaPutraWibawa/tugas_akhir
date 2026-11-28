/**
 * Tailscale Mesh Ingress Bridge for Multi-Device DDoS Evaluation
 * Binds Tailscale interface port 80 and bridges TCP streams directly into WSL 2 Nginx (127.0.0.1:80).
 * Zero external dependencies (uses Node.js native 'net' and 'child_process').
 */

const net = require('net');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

let tailscaleIp = null;
let bridgeServer = null;
let isBridgeActive = false;

function detectTailscaleIp() {
  // Method 1: Check Tailscale CLI
  try {
    const cliOutput = execSync('"C:\\Program Files\\Tailscale\\tailscale.exe" ip -4', { timeout: 3000, encoding: 'utf-8' }).trim();
    if (cliOutput && cliOutput.startsWith('100.')) {
      return cliOutput.split('\n')[0].trim();
    }
  } catch (e) {
    // CLI check fallback
  }

  // Method 2: Check PowerShell Get-NetIPAddress
  try {
    const psOutput = execSync('powershell.exe -NoProfile -Command "(Get-NetIPAddress -InterfaceAlias *Tailscale* -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress"', { timeout: 3000, encoding: 'utf-8' }).trim();
    if (psOutput && psOutput.startsWith('100.')) {
      return psOutput.split('\r\n')[0].trim();
    }
  } catch (e) {
    // PowerShell check fallback
  }

  return null;
}

function startBridge(targetPort = 80, localPort = 80) {
  tailscaleIp = detectTailscaleIp();
  if (!tailscaleIp) {
    console.log('[Tailscale Bridge] Interface Tailscale tidak terdeteksi. Berjalan dalam mode Localhost.');
    return { active: false, ip: null };
  }

  try {
    bridgeServer = net.createServer((clientSocket) => {
      const rawRemote = clientSocket.remoteAddress || '';
      const remoteIp = rawRemote.replace(/^.*:/, '');
      
      const targetSocket = net.connect({ host: '127.0.0.1', port: localPort }, () => {
        clientSocket.pipe(targetSocket);
        targetSocket.pipe(clientSocket);
      });

      targetSocket.on('error', (err) => {
        clientSocket.destroy();
      });

      clientSocket.on('error', (err) => {
        targetSocket.destroy();
      });
    });

    bridgeServer.on('error', (err) => {
      console.warn(`[Tailscale Bridge] Gagal mengikat port ${targetPort} di ${tailscaleIp}: ${err.message}`);
      isBridgeActive = false;
    });

    bridgeServer.listen(targetPort, tailscaleIp, () => {
      isBridgeActive = true;
      console.log(`🌐 [Tailscale Mesh] Ingress Bridge AKTIF di ${tailscaleIp}:${targetPort} -> WSL 127.0.0.1:${localPort}`);
      
      // Save target IP to ai_attacker_swarm directory for friends' scripts
      try {
        const swarmDir = path.resolve(__dirname, '..', '..', 'ai_attacker_swarm');
        if (fs.existsSync(swarmDir)) {
          fs.writeFileSync(path.join(swarmDir, 'tailscale_target.txt'), tailscaleIp, 'utf-8');
        }
      } catch (err) {
        // Non-critical write
      }
    });

    return { active: true, ip: tailscaleIp, port: targetPort };
  } catch (error) {
    console.warn(`[Tailscale Bridge] Inisialisasi bridge gagal: ${error.message}`);
    return { active: false, ip: tailscaleIp, error: error.message };
  }
}

function getStatus() {
  if (!tailscaleIp) {
    tailscaleIp = detectTailscaleIp();
  }
  return {
    installed: !!tailscaleIp,
    active: isBridgeActive,
    ip: tailscaleIp || null,
    target_bridge: isBridgeActive ? `${tailscaleIp}:80 -> 127.0.0.1:80` : null,
    dashboard_url: tailscaleIp ? `http://${tailscaleIp}:3000` : null,
    target_url: tailscaleIp ? `http://${tailscaleIp}:80` : null
  };
}

function stopBridge() {
  if (bridgeServer) {
    try {
      bridgeServer.close();
    } catch (e) {}
    bridgeServer = null;
    isBridgeActive = false;
  }
}

process.on('exit', () => {
  stopBridge();
});

module.exports = {
  detectTailscaleIp,
  startBridge,
  stopBridge,
  getStatus
};
