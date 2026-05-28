# ReconPro

ReconPro adalah toolkit reconnaissance + security posture scanning untuk **enumerasi aset**, **port scanning**, **web metadata probe**, **DNS & email security**, serta **risk summary** dalam bentuk **report HTML/JSON**.

> Bukan exploit tool. Gunakan hanya pada sistem/domain yang kamu miliki atau punya izin tertulis.

---

## Fitur Utama

- **Asset discovery**
  - Resolve domain → IP (IPv4/IPv6)
  - Menggabungkan host dari hasil subdomain resolve + DNS-derived hosts (NS/MX/SOA/CNAME)
- **DNS & Email Security**
  - A/AAAA/CNAME/NS/MX/TXT/SOA
  - SPF + DMARC (ringkas & terbaca)
  - MTA-STS / TLS-RPT (jika ada)
- **Subdomain Enumeration (hybrid)**
  - Sumber: `crtsh`, `certspotter`, (opsional) `virustotal`, `securitytrails`
  - Mode brute ringan `--sub-brute`
  - Resolve subdomain → IP
- **Port Scan (TCP connect)**
  - Preset `top` atau custom `80,443,8080` / `1-1024`
  - Telemetri: attempted / timeout / errors, supaya hasil “kosong” tidak misleading
- **Service Fingerprint (opsional)**
  - Banner ringan + TLS handshake/cert summary (untuk port terbuka)
- **Web Recon**
  - Status code, title, server header, security headers audit, cookie audit
  - WAF/CDN detection heuristik
  - Crawl internal (same-host) + deteksi endpoint/params/login/admin
  - Sitemap seeds dari `robots.txt`/`sitemap.xml`
  - Quick checks WordPress + admin panel
  - `--web-from-ports` untuk scan `:8080/:8443` otomatis jika port terbuka
- **Report**
  - Export HTML tema dark “hacker” (scanlines + neon sweep)
  - Export JSON (data lengkap)
  - Export disanitasi: mengurangi risiko token/cookie bocor di report

---

## Instalasi

### 1) Clone
```bash
git clone https://github.com/floryid/ReconPro.git
cd ReconPro
```

### 2) Buat venv (disarankan)
Windows PowerShell:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3) Install dependencies
```bash
pip install -r requirements.txt
```

---

## Quick Start

### Help
```bash
python app.py -h
```

### Scan cepat (DNS + TOP ports)
```bash
python app.py example.com --ports top
```

### Recon standar (direkomendasikan untuk baseline)
```bash
python app.py example.com --full --export html
```

### Deep preset (lebih agresif & lebih lama)
```bash
python app.py example.com --deep --export html
```

---

## Contoh Pemakaian (Lengkap)

### Web scan dari port terbuka (mis. 8080/8443)
```bash
python app.py example.com --full --web --web-from-ports --export html
```

### Crawl + sitemap seeds (endpoint discovery)
```bash
python app.py example.com --web --crawl --sitemap --export html
```

### Subdomain enum + resolve
```bash
python app.py example.com --subdomains --sub-brute --sub-resolve 200 --export html
```

### Port custom + service fingerprint
```bash
python app.py example.com --ports 80,443,8080,3389 --service-probe --export html
```

### Export JSON ke path custom
```bash
python app.py example.com --full --export json --export-path results/example.json
```

---

## Output & File Penting

- `report.html` / `report.json` (atau sesuai `--export-path`)
- `cache.sqlite` (cache untuk mempercepat & mengurangi request berulang)
- `scan_log.txt` (log run)

Repo sudah menyertakan `.gitignore` untuk mencegah file hasil scan/cache/log ikut ter-commit.

---

## Environment Variable (Opsional)

### API Key untuk sumber subdomain tambahan
- `VT_API_KEY` → VirusTotal (opsional)
- `SECURITYTRAILS_API_KEY` → SecurityTrails (opsional)

### UI terminal (warna/animasi)
- `RECONSCANPRO_NO_COLOR=1` → matikan warna
- `RECONSCANPRO_NO_ANIM=1` → matikan animasi
- `RECONSCANPRO_FORCE_COLOR=1` → paksa warna (jika terminal tidak terdeteksi TTY)
- `RECONSCANPRO_FORCE_ANIM=1` → paksa animasi
- `RECONSCANPRO_TQDM=1` → paksa progress bar tqdm (jika kamu prefer tqdm)

---

## Catatan Keamanan & Anti-Exposure

- Jangan commit token/cookie/api-key ke GitHub (gunakan environment variable).
- Jika menjalankan authenticated scan (`--cookie`/`--header`), ReconScanPro berusaha men-sanitasi report agar data sensitif tidak “kebawa” ke output.
- Jangan jalankan mode agresif (`--deep`, `--dir-checks`, crawl besar) tanpa izin—risiko memicu rate limit/WAF dan berpotensi dianggap hostile traffic.
- Jika scan dilakukan dari jaringan yang banyak timeout, port scan bisa “tidak konklusif”; lihat bagian telemetri di report.

---

## Struktur Project (Ringkas)

- `app.py` → entrypoint
- `main.py` → orchestrator + CLI + pipeline scan + terminal UI
- `core/` → DNS, port scanner, http client, crawler, sitemap, subdomain sources, service probe
- `analyzers/` → risk scoring, security headers, cookie audit, WP/panel checks, email security
- `utils/` → reporter (HTML/JSON + sanitization), logging

---

## Disclaimer

Tool ini disediakan untuk keperluan audit internal, hardening, dan pembelajaran keamanan. Penggunaan tanpa izin adalah tanggung jawab pengguna.
