# ServerPulse - Real-time Server Monitoring Platform 🚀

**ServerPulse** adalah platform pemantauan server dan observabilitas mandiri (*self-hosted*) yang modern, ringan, dan responsif. Dirancang untuk memudahkan sysadmin dan developer memantau kesehatan server, beban resource, ketersediaan (uptime SLA), dan insiden secara terpusat tanpa biaya berlangganan.

---

## 🌟 Fitur Utama

1. **Dashboard Fleet Terpusat**:
   - Status visual real-time (*Online*, *Degraded*, *Offline*).
   - Rata-rata utilisasi CPU & Memori RAM global.
   - Pencarian instan dan filter berdasarkan status, tipe agen, atau tag.
2. **Dua Mode Pemantauan (Hybrid Monitoring)**:
   - **Agent Telemetri (Mendalam)**: Mengumpulkan data CPU core %, RAM used/free, Disk partition space, Network I/O (KB/s), dan Top 5 proses yang berjalan secara real-time via WebSocket.
   - **Probe Uptime (Tanpa Agen)**: Memeriksa ketersediaan layanan web (HTTP status code) dan port TCP (SSH 22, DB 3306/5432, dll.) dengan pengukuran latensi milidetik (*ms*).
3. **Grafik Historis & Live Telemetri (Chart.js)**:
   - Grafik garis real-time CPU & RAM utilization.
   - Trafik jaringan *Inbound* dan *Outbound*.
   - Status bar 30-Day Uptime SLA per server.
4. **Sistem Notifikasi & Alert Otomatis**:
   - Terintegrasi dengan **Telegram Bot** dan **Discord Webhook**.
   - Alarm otomatis jika server down, tidak mengirim heartbeat, atau beban CPU/RAM melebihi ambang batas (*threshold*).
   - Pemberitahuan otomatis ketika server telah pulih (*recovered*).
5. **Pemasangan Agen 1-Baris (*One-Liner Install*)**:
   - Script instalasi otomatis untuk Linux dan script Python portabel untuk Windows / macOS.

---

## 🛠️ Persyaratan Sistem

- **Node.js**: Versi 20+ atau 24+ (Sudah terpasang di sistem).
- **Python**: Versi 3.7+ (Untuk menjalankan script agent di server target).

---

## 🚀 Panduan Memulai Cepat

### 1. Menjalankan Website Monitoring (Server & Dashboard)

Buka terminal di folder proyek:

```bash
cd C:\Users\Zaa\server-monitoring-app
npm start
```

Setelah server aktif, buka browser Anda di:
👉 **[http://localhost:3000](http://localhost:3000)**

*Catatan: Saat pertama kali dijalankan, ServerPulse otomatis menambahkan Host Lokal Anda ke dashboard dengan data CPU & RAM real-time.*

---

### 2. Menjalankan Pengujian Otomatis

Untuk memastikan seluruh API, database SQLite, dan ingestion telemetri berfungsi 100%:

```bash
npm test
```

---

### 3. Memasang Agen di Server Lain

#### Opsi A: Linux (Instalasi Otomatis 1-Baris)
Klik tombol **Tambah Server** di dashboard, pilih **Agent Telemetri**, lalu salin perintah:
```bash
curl -sSL "http://<IP_MONITORING>:3000/install.sh?token=<SERVER_TOKEN>" | bash
```

#### Opsi B: Windows / Manual Python
Di server yang ingin dipantau, pasang dependensi `psutil` lalu jalankan agent:
```bash
pip install psutil requests
python agent.py --server http://<IP_MONITORING>:3000 --token <SERVER_TOKEN>
```

---

### 4. Mengatur Notifikasi Telegram & Discord

1. Buka tab **Alert & Notifikasi** di dashboard web.
2. Masukkan **Telegram Bot Token** dan **Chat ID**, atau **Discord Webhook URL**.
3. Klik tombol **Kirim Pesan Tes Notifikasi** untuk memverifikasi koneksi.
4. Klik **Simpan Pengaturan**.

---

## 📁 Struktur Direktori

```text
server-monitoring-app/
├── server.js              # Entrypoint Express, WebSocket, & API Routes
├── db.js                  # Database SQLite (node:sqlite)
├── test.js                # Automated verification test suite
├── package.json           # Dependensi Node.js
├── README.md              # Dokumentasi lengkap
├── services/
│   ├── notifier.js        # Dispatcher notifikasi Telegram & Discord
│   └── prober.js          # Background health-check & heartbeat worker
├── agent/
│   ├── agent.py           # Script agen Python cross-platform
│   └── requirements.txt   # Dependensi agent (psutil, requests)
└── public/
    ├── index.html         # Tampilan Dashboard antarmuka modern
    ├── style.css          # Styling & animasi glassmorphism
    └── app.js             # Client WebSocket & Chart.js live rendering
```
