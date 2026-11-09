# Analyzer2

A cross-platform **Network & System Misconfiguration Scanner** that detects security issues and compares your configuration against **CIS Benchmarks** and **NIST Guidelines**.

## Features

- **Network Configuration Checks** — Subnet mask, gateway, DNS, MTU, DHCP, NTP, wireless security
- **System Configuration Checks** — SSH config, firewall status, file permissions, antivirus, user accounts, system logs
- **Best-Practice Comparison** — Validates 10 categories against CIS/NIST standards with risk-level scoring
- **Auto-Detection** — Detects OS (Windows/macOS/Linux) and network type (Public/Private/Enterprise)
- **PDF Reports** — Generates professional scan reports with executive summary
- **Multiple Interfaces** — Desktop GUI (Tkinter), CLI, and REST API (FastAPI)
- **Optional Database** — MongoDB integration for persisting scan history

## Quick Start

### Prerequisites

- Python 3.9+
- `pip install -r requirements.txt`

### Run the GUI

```bash
python main.py
```

### Run a CLI Scan

```bash
python main.py --cli
```

### Start the API Server

```bash
python main.py --api
```

## Usage

### CLI Options

```
python main.py [options]

Options:
  --cli           Run scan in CLI mode (no GUI)
  --api           Start the FastAPI server
  --no-report     Skip PDF report generation (CLI only)
  --report-dir    Directory to save reports (default: reports/)
```

### API Endpoints

| Method | Endpoint          | Description                  |
|--------|-------------------|------------------------------|
| GET    | `/`               | Health check                 |
| POST   | `/scan/start`     | Start a background scan      |
| GET    | `/scan/latest`    | Get the latest scan results  |
| GET    | `/scans/history`  | Fetch scan history from DB   |

### Database (Optional)

MongoDB is optional. To enable scan persistence:

1. Copy `.env.example` to `.env`
2. Set `ANALYZER_MONGODB_URI` to your MongoDB connection string
3. The scanner will automatically persist results

## Project Structure

```
Analyzer2/
├── main.py                 # Entry point (GUI / CLI / API)
├── gui.py                  # Tkinter desktop interface
├── api.py                  # FastAPI REST backend
├── scanner/
│   ├── __init__.py
│   ├── config.py           # Configuration & utility functions
│   ├── database.py         # MongoDB integration (optional)
│   ├── network_checks.py   # Network configuration checks
│   ├── system_checks.py    # System configuration checks
│   ├── misconfig_scanner.py # CIS/NIST best-practice comparison
│   ├── scan_runner.py      # Orchestrates all checks + report
│   └── report_generator.py # PDF report generation
├── reports/                # Generated PDF reports
├── fonts/                  # DejaVu Sans fonts
├── requirements.txt
├── .env.example
└── .gitignore
```

## Security Checks

### Network Checks
| Check | Description |
|-------|-------------|
| Subnet Mask | Validates against expected subnet mask |
| Gateway | Verifies default gateway configuration |
| DNS | Checks for secure DNS server usage |
| MTU | Validates MTU size settings |
| DHCP | Verifies DHCP is configured |
| NTP | Checks time synchronization setup |
| Wireless | Validates wireless security (WPA/WPA2) |

### System Checks
| Check | Description |
|-------|-------------|
| SSH | Checks for default port, password auth, root login |
| Firewall | Verifies firewall is active |
| File Permissions | Checks critical file permission levels |
| Antivirus | Detects endpoint protection software |
| User Accounts | Lists user accounts for review |
| System Logs | Reviews recent authentication logs |

### CIS/NIST Best-Practice Comparison
Compares 10 configuration areas against industry standards:
- Unsecured Open Ports
- Weak DNS Configuration
- Unrestricted Network Access
- Weak DHCP Lease Time
- Default Route Configuration
- NTP Configuration
- Default Credentials
- Exposed SMB Shares
- Firewall Status
- IPv6 Security

## Tech Stack

- **Python 3.9+**
- **fpdf2** — PDF report generation
- **Tkinter** — Desktop GUI
- **FastAPI + Uvicorn** — REST API
- **PyMongo** — MongoDB driver (optional)

## License

MIT
