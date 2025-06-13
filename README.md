# ??? Suricata IDS + CSF Firewall Auto-Block System

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/ubuntu-22.04%20%7C%2024.04-orange.svg" alt="Ubuntu">
</p>

A complete solution for automatic intrusion detection and blocking using Suricata IDS and ConfigServer Security & Firewall (CSF).

Developed by **Paolo Caparrelli** at **[GOLINE SA](https://www.goline.ch)**

## ?? Features

- ? Real-time intrusion detection with Suricata IDS
- ? Automatic IP blocking based on alert severity
- ? AbuseIPDB integration via [CSFToAbuseIPDB](https://github.com/paolokappa/CSFToAbuseIPDB)
- ? Automatic Suricata rules updates
- ? Detailed monitoring and reporting
- ? Automatic log rotation with logrotate
- ? Cron-based automation (runs every minute)
- ? Zero configuration passwords - fully secure

## ?? Table of Contents

1. [Requirements](#requirements)
2. [Quick Start](#quick-start)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Usage](#usage)
6. [Monitoring](#monitoring)
7. [Troubleshooting](#troubleshooting)
8. [Contributing](#contributing)
9. [License](#license)

## ?? Requirements

- Ubuntu 22.04 or 24.04
- ConfigServer Security & Firewall (CSF) installed
- Python 3.x
- jq (JSON processor)
- Root access

### Optional (for AbuseIPDB integration)
- [CSFToAbuseIPDB](https://github.com/paolokappa/CSFToAbuseIPDB) installed
- AbuseIPDB API key

## ?? Quick Start

    # Clone the repository
    git clone https://github.com/goline-sa/suricata-csf-autoblock.git
    cd suricata-csf-autoblock

    # Run the installer
    sudo ./install.sh

## ?? Installation

See [INSTALL.md](docs/INSTALL.md) for detailed installation instructions.

## ?? Configuration

The system comes pre-configured with sensible defaults. Main configuration files:

- **Suricata config**: /etc/suricata/suricata.yaml
- **Blocking severity**: Edit MIN_SEVERITY in scripts/suricata-csf-block-simple.sh (default: 2)
- **Network interface**: Update in Suricata config

### Severity Levels
- 1 = HIGH (always block)
- 2 = MEDIUM (default threshold)
- 3 = LOW (usually false positives)

### AbuseIPDB Integration (Optional)

To enable AbuseIPDB reporting:

1. Install [CSFToAbuseIPDB](https://github.com/paolokappa/CSFToAbuseIPDB)
2. Configure your API key in CSF
3. The auto-block script will automatically use it if available

## ?? Usage

### Monitor alerts in real-time

    suricata-monitor

### Check last hour's activity

    suricata-monitor -H 1

### View blocked IPs

    grep "BLOCKED:" /var/log/suricata-csf-block.log | tail -20

### Manual operations

    # Force rule update
    /usr/local/bin/suricata-auto-update.sh

    # Run block script manually
    /usr/local/bin/suricata-csf-block-simple.sh

    # Check CSF blocks
    csf -d

## ?? Monitoring

The system includes a comprehensive monitoring tool that shows:
- Alert statistics and trends
- Top attacking IPs with their status (BLOCKED/ACTIVE/WHITELISTED)
- Attack signatures and categories
- Timeline of attacks
- CSF integration status

## ?? File Locations

- **Logs**: /var/log/suricata/eve.json
- **Block log**: /var/log/suricata-csf-block.log
- **Update log**: /var/log/suricata-auto-update.log
- **Processed IPs**: /var/lib/suricata/processed_ips.txt

## ??? Troubleshooting

See [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for common issues and solutions.

## ?? Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## ?? Related Projects

- [CSFToAbuseIPDB](https://github.com/paolokappa/CSFToAbuseIPDB) - CSF to AbuseIPDB integration

## ?? License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ?? Authors

- **Paolo Caparrelli** - *Initial work* - [GOLINE SA](https://www.goline.ch)

---

<p align="center">
  Made with ?? by <a href="https://www.goline.ch">GOLINE SA</a>
</p>
