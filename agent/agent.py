#!/usr/bin/env python3
"""
ServerPulse Lightweight Monitoring Agent
Compatible with Python 3.7+ (Linux, Windows, macOS)
"""

import sys
import os
import time
import argparse
import platform
import json

try:
    import psutil
except ImportError:
    print("[WARNING] 'psutil' is not installed. Installing psutil is recommended for accurate metrics:")
    print("         pip install psutil requests")
    print("         Running in minimal fallback mode...")
    psutil = None

try:
    import urllib.request
    import urllib.error
except ImportError:
    pass


class ServerPulseAgent:
    def __init__(self, server_url, token, interval=3):
        self.server_url = server_url.rstrip('/')
        self.token = token
        self.interval = interval
        self.last_net_io = None
        self.last_net_time = None

    def get_system_info(self):
        info = {
            "platform": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "arch": platform.machine(),
            "hostname": platform.node(),
            "python_version": platform.python_version()
        }
        if psutil:
            info["cpus"] = psutil.cpu_count(logical=True)
            info["boot_time"] = int(psutil.boot_time())
        return info

    def collect_metrics(self):
        now = time.time()
        cpu_percent = 0.0
        mem_percent = 0.0
        mem_used_gb = 0.0
        mem_total_gb = 0.0
        disk_percent = 0.0
        net_rx_kb = 0.0
        net_tx_kb = 0.0
        top_processes = []

        if psutil:
            # CPU
            cpu_percent = round(psutil.cpu_percent(interval=None), 1)

            # RAM
            mem = psutil.virtual_memory()
            mem_percent = round(mem.percent, 1)
            mem_used_gb = round(mem.used / (1024 ** 3), 2)
            mem_total_gb = round(mem.total / (1024 ** 3), 2)

            # Disk
            try:
                root_path = 'C:\\' if platform.system() == 'Windows' else '/'
                disk = psutil.disk_usage(root_path)
                disk_percent = round(disk.percent, 1)
            except Exception:
                disk_percent = 0.0

            # Network I/O KB/s
            net = psutil.net_io_counters()
            if self.last_net_io and self.last_net_time:
                time_delta = max(0.1, now - self.last_net_time)
                rx_bytes_delta = net.bytes_recv - self.last_net_io.bytes_recv
                tx_bytes_delta = net.bytes_sent - self.last_net_io.bytes_sent
                net_rx_kb = round(max(0, rx_bytes_delta / 1024 / time_delta), 1)
                net_tx_kb = round(max(0, tx_bytes_delta / 1024 / time_delta), 1)

            self.last_net_io = net
            self.last_net_time = now

            # Top 5 processes by CPU
            try:
                procs = []
                for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        p_info = p.info
                        if p_info['name'] and p_info['cpu_percent'] is not None:
                            procs.append({
                                "pid": p_info['pid'],
                                "name": p_info['name'],
                                "cpu_percent": round(p_info['cpu_percent'], 1),
                                "memory_percent": round(p_info['memory_percent'] or 0, 1)
                            })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                procs.sort(key=lambda x: (x['cpu_percent'], x['memory_percent']), reverse=True)
                top_processes = procs[:5]
            except Exception:
                top_processes = []
        else:
            # Fallback estimation if psutil is missing
            cpu_percent = 5.0
            mem_percent = 25.0
            mem_used_gb = 2.0
            mem_total_gb = 8.0
            disk_percent = 30.0

        return {
            "timestamp": int(now * 1000),
            "cpu_percent": cpu_percent,
            "memory_percent": mem_percent,
            "memory_used_gb": mem_used_gb,
            "memory_total_gb": mem_total_gb,
            "disk_percent": disk_percent,
            "net_rx_kb": net_rx_kb,
            "net_tx_kb": net_tx_kb,
            "top_processes": top_processes,
            "os_info": self.get_system_info()
        }

    def send_metrics(self, payload):
        target_endpoint = f"{self.server_url}/api/metrics"
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            target_endpoint,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "ServerPulse-Agent/1.0"
            },
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception as e:
            raise e

    def run(self):
        print(f"==================================================")
        print(f"  ServerPulse Monitoring Agent Active")
        print(f"  Target Hub : {self.server_url}")
        print(f"  Host       : {platform.node()} ({platform.system()})")
        print(f"  Interval   : {self.interval}s")
        print(f"==================================================")

        # Initial CPU reading to calibrate psutil interval
        if psutil:
            psutil.cpu_percent(interval=0.5)

        consecutive_failures = 0
        while True:
            try:
                metrics = self.collect_metrics()
                status_code = self.send_metrics(metrics)
                if status_code == 200:
                    consecutive_failures = 0
                    print(f"[{time.strftime('%H:%M:%S')}] Telemetri terkirim | CPU: {metrics['cpu_percent']}% | RAM: {metrics['memory_percent']}% | Disk: {metrics['disk_percent']}% (200 OK)")
                elif status_code == 401:
                    print(f"[ERROR] Token autentikasi ditolak (401 Unauthorized). Periksa Server Token Anda.")
                    time.sleep(10)
                else:
                    print(f"[WARN] Server merespon status {status_code}")
            except Exception as e:
                consecutive_failures += 1
                print(f"[{time.strftime('%H:%M:%S')}] Gagal terhubung ke hub: {e} (Percobaan gagal #{consecutive_failures})")

            time.sleep(self.interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ServerPulse Monitoring Agent")
    parser.add_argument("--server", default=os.getenv("SERVER_URL", "http://localhost:3000"), help="Monitoring Hub URL")
    parser.add_argument("--token", default=os.getenv("SERVER_TOKEN", ""), help="Secret server token")
    parser.add_argument("--interval", type=int, default=3, help="Polling interval in seconds")

    args = parser.parse_args()

    if not args.token:
        print("[ERROR] Token wajib disertakan. Jalankan: python agent.py --token <TOKEN_DARI_DASHBOARD>")
        sys.exit(1)

    agent = ServerPulseAgent(args.server, args.token, args.interval)
    agent.run()
