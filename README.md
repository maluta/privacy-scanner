# Privacy Scanner — WiFi Surveillance Device Detector

Scans WiFi networks to detect hidden cameras and surveillance devices in rental accommodations (Airbnb, Booking, VRBO, etc.).

**Cross-platform**: Linux, macOS, and Windows.

## Quick Start

### Prerequisites

- **nmap** (mandatory): `brew install nmap` (macOS) / `sudo apt install nmap` (Debian) / [nmap.org](https://nmap.org/download) (Windows)
- **Python 3.10+**
- **uv** (recommended): `brew install uv` or see [docs.astral.sh/uv](https://docs.astral.sh/uv/getting-started/installation/)

### Run with uv (recommended)

```bash
uv sync
sudo uv run python scripts/scan.py
```

### Run with pip

```bash
pip install -r requirements.txt
sudo python3 scripts/scan.py
```

### Linux-only (Bash, no Python deps needed)

```bash
sudo bash scripts/scan.sh
```

## Usage

```bash
# Full scan (Portuguese report by default)
sudo uv run python scripts/scan.py

# English or Spanish report
sudo uv run python scripts/scan.py --lang en
sudo uv run python scripts/scan.py --lang es

# Quick mode (skip service discovery & deep inspection)
sudo uv run python scripts/scan.py --quick

# Specify WiFi interface or subnet
sudo uv run python scripts/scan.py --interface wlan0
sudo uv run python scripts/scan.py --subnet 192.168.1.0/24

# Show help
uv run python scripts/scan.py --help
```

### Windows (Admin PowerShell)

```powershell
uv sync
python scripts\scan.py
python scripts\scan.py --quick --lang en
```

## What It Scans

**7-Phase Pipeline:**

1. **Host Discovery** — Find all devices via ARP scan + nmap ping scan
2. **OUI Analysis** — Identify manufacturers from MAC addresses, flag camera brands
3. **Port Scan** — Check 20 camera-specific ports (RTSP, HTTP, vendor-proprietary)
4. **Service Discovery** — mDNS/Bonjour, UPnP/SSDP, ONVIF WS-Discovery
5. **Deep Inspection** — HTTP banner grabbing, RTSP verification, keyword analysis
6. **Risk Classification** — Correlate all evidence into risk levels
7. **Report** — Terminal output + HTML report

## Risk Levels

| Level | Meaning | Example |
|-------|---------|---------|
| 🔴 CRITICAL | Confirmed camera/streaming | Hikvision device with RTSP port open |
| 🟠 HIGH | Strong camera indicators | Wyze MAC address detected |
| 🟡 MODERATE | Suspicious/unidentified | Unknown device with HTTP server |
| 🟢 LOW | Probably safe | ESP32 device without camera ports |
| 🔵 INFO | Known safe | iPhone, laptop, printer |

## Output

- **Terminal**: Color-coded real-time output with risk-classified device list
- **HTML Report**: `./privacy-scan-results/privacy-scan-YYYYMMDD-HHMMSS.html`
  - Dark security-themed UI with animated scanning elements
  - Interactive device cards (click to expand, copy IP/MAC)
  - Live language switcher (PT / EN / ES) — no reload needed
  - Print-friendly mode (Ctrl+P)
  - Fully self-contained — works offline, no external dependencies
- **Raw Data**: `./privacy-scan-results/raw-data-YYYYMMDD-HHMMSS/`

## Limitations

This tool scans WiFi-connected devices only. It **cannot** detect:

- Cameras on a separate VLAN or wired-only network
- Cellular-connected cameras (4G/LTE)
- Cameras that are powered off
- Devices using MAC address randomization
- Local-storage cameras not connected to any network
- Audio-only recording devices (bugs)

**Always complement with a physical inspection.**

## Rental Platform Policies

Major short-term rental platforms prohibit indoor surveillance cameras:

- **[Airbnb](https://www.airbnb.com/help/article/3061)** — All indoor cameras prohibited, even if off. Hidden cameras always banned. Outdoor cameras must be disclosed.
- **[Booking.com](https://partner.booking.com/en-us/help/legal-security/security/requirements-and-regulations-surveillance-devices)** — Cameras allowed only in common/public areas, must be visible and disclosed. Prohibited where guests expect privacy.
- **[Vrbo](https://www.vrbo.com/tlp/trust-and-safety/use-of-surveillance-policy)** — Indoor cameras prohibited. Outdoor cameras allowed only for security at access points, must be disclosed.

## If You Find a Camera

1. Do NOT disconnect or tamper with it
2. Photograph the device and its location
3. Save the scan report as evidence
4. Contact Airbnb: App → Your Trips → Get Help → Report a safety concern
5. Airbnb Emergency: +1-855-424-7262
6. Leave if you feel unsafe
7. Consider contacting local law enforcement

## As a Claude Code Skill

Install by copying this directory to your Claude Code skills path. The skill triggers on phrases like "scan for cameras", "hidden camera", "privacy scan", "surveillance scan", etc.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

This tool is for **defensive security purposes only** — helping guests detect unauthorized surveillance in rental properties. Use responsibly and in accordance with local laws.
