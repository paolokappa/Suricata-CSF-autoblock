# ??? Suricata IDS + CSF Firewall Auto-Block System

![Version](https://img.shields.io/badge/version-2.1.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Ubuntu](https://img.shields.io/badge/ubuntu-22.04%20%7C%2024.04-orange.svg)
![Suricata](https://img.shields.io/badge/suricata-7.x-red.svg)
![Python](https://img.shields.io/badge/python-3.x-yellow.svg)


A complete solution for automatic intrusion detection and blocking using Suricata IDS and ConfigServer Security & Firewall (CSF).

Developed by **Paolo Caparrelli** at **GOLINE SA**

## 🎉 What's New in Version 2.1.0 (June 2025)

### 🌍 **Geolocation Intelligence**
- Real-time IP geolocation with country and city information
- Intelligent caching system to minimize API requests
- Geographic distribution analysis of attacks
- Support for multiple geolocation providers (ip-api.com, ipinfo.io)

### 📊 **Advanced Analytics & Anomaly Detection**
- Historical statistics tracking (30-day retention)
- Automatic anomaly detection (alerts when traffic exceeds 2x average)
- Trend analysis with 24-hour and 7-day comparisons
- Recurring attacker identification
- New attack type detection

### 🎯 **Enhanced IP Management**
- **Server IP Detection**: Automatically identifies all server IPs (IPv4/IPv6)
- **Trusted IP Support**: Define admin/monitoring IPs that won't be blocked
- **Smart IP Status**: BLOCKED, ACTIVE, WHITELISTED, TRUSTED, SERVER
- **IPv6 Optimization**: Proper compression and normalization

### 📈 **Detailed Threat Intelligence**
- **Enhanced Signature Descriptions**: Human-readable attack explanations
- **ModSecurity Rule Mapping**: Specific descriptions for 50+ ModSecurity rules
- **Port Service Database**: Detailed service identification for 100+ ports
- **CSF Block Reason Analysis**: Clear explanations for why IPs were blocked

### 📱 **Professional Monitoring Dashboard**
- **Attack Timeline**: Hourly visualization of attack patterns
- **Severity Distribution**: Visual breakdown of HIGH/MEDIUM/LOW threats
- **Auto-block Effectiveness**: Real-time blocking success metrics
- **Multi-source Integration**: Combines Suricata alerts, CSF blocks, and system logs

## 🚀 Features

### Core Features
- 🔥 Real-time intrusion detection with Suricata IDS
- 🛡️ Automatic IP blocking based on alert severity
- 📊 AbuseIPDB integration via CSFToAbuseIPDB
- ⚡ Automatic Suricata rules updates
- ⚙️ Automatic log rotation with logrotate
- 🔧 Cron-based automation (runs every minute)
- 🔒 Zero configuration passwords - fully secure

### New Advanced Features
- 🌍 **Geolocation Analysis**: Track attack origins by country/city
- 📈 **Historical Analytics**: 30-day statistics with anomaly detection
- 🎯 **Smart IP Classification**: Server, Trusted, Whitelisted, Active, Blocked
- 📊 **Professional Reports**: Colored output with graphs and trends
- 🛡️ **Multi-log Analysis**: Combines Suricata, CSF, and system logs
- 🔍 **Debug Mode**: Comprehensive system diagnostics
- 💾 **Intelligent Caching**: Reduces external API calls
- 🌐 **Full IPv6 Support**: Complete IPv6 handling and formatting

## 📋 Table of Contents

1. [Requirements](#-requirements)
2. [Quick Start](#-quick-start)
3. [Installation](#-installation)
4. [Configuration](#-configuration)
5. [Usage](#-usage)
6. [Advanced Monitoring](#-advanced-monitoring)
7. [Troubleshooting](#-troubleshooting)
8. [API Reference](#-api-reference)
9. [Contributing](#-contributing)
10. [License](#-license)

## 💻 Requirements

- Ubuntu 22.04 or 24.04
- ConfigServer Security & Firewall (CSF) installed
- Python 3.x with optional modules:
  - `netifaces` (for better network interface detection)
  - `urllib` (for geolocation, included in standard library)
- jq (JSON processor)
- Root access

**Optional (for enhanced features)**
- CSFToAbuseIPDB installed for threat intelligence
- Internet connection for geolocation services
- 100MB+ disk space for cache and historical data

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/paolokappa/Suricata-CSF-autoblock.git
cd suricata-csf-autoblock

# Run the installer
sudo ./install.sh

# View the enhanced monitoring dashboard
sudo suricata-monitor
```

## 📦 Installation

See [INSTALL.md](docs/INSTALL.md) for detailed installation instructions.

### Post-Installation Configuration

1. **Configure Trusted IPs** (optional):
   Edit `/usr/local/bin/suricata-monitor` and update the `TRUSTED_IPS` list:
   ```python
   TRUSTED_IPS = [
       "YOUR_ADMIN_IP",      # Your office/home IP
       "MONITORING_SERVER",  # Your monitoring service
   ]
   ```

2. **Enable Geolocation** (enabled by default):
   The system automatically uses free geolocation services. No API key required!

## ⚙️ Configuration

The system comes pre-configured with sensible defaults. Main configuration files:

- **Suricata config**: `/etc/suricata/suricata.yaml`
- **Blocking severity**: Edit `MIN_SEVERITY` in `scripts/suricata-csf-block-simple.sh` (default: 2)
- **Network interface**: Update in Suricata config
- **Trusted IPs**: Edit `TRUSTED_IPS` in `/usr/local/bin/suricata-monitor`

### Severity Levels

- **1** = HIGH (always block) - Critical threats
- **2** = MEDIUM (default threshold) - Suspicious activity
- **3** = LOW (usually false positives) - Minor alerts

## 🎯 Usage

### ⚡ Verify the System is Running

```bash
# Check if blocking is active (runs every minute via cron)
grep suricata /etc/crontab

# Check recent blocks
tail -f /var/log/suricata-csf-block.log

# NOTE: There is NO systemd service for blocking! It uses cron.
```

### 📊 Enhanced Monitoring Dashboard

```bash
# Standard monitoring with all features
sudo suricata-monitor

# Monitor last 12 hours
sudo suricata-monitor -H 12

# Disable geolocation (faster, no internet required)
sudo suricata-monitor --no-geo

# Show all blocked IPs (not just recent)
sudo suricata-monitor --show-all-blocked

# Debug mode - check log files and configuration
sudo suricata-monitor --debug

# Clear all caches
sudo suricata-monitor --clear-cache

# Disable colored output
sudo suricata-monitor --no-color
```

### Manual Operations

```bash
# Test the blocking script manually
/usr/local/bin/suricata-csf-block-simple.sh

# Update Suricata rules
systemctl start suricata-auto-update.service
```

## 📊 Advanced Monitoring

### Dashboard Overview

The enhanced monitoring dashboard shows:

```
================================================================================
                  SURICATA IDS MONITORING REPORT
              Last 24 hours - 2025-06-18 10:30
================================================================================

[GENERAL STATISTICS]
|- Total alerts: 1,234
|- Unique IPs detected: 45
|- Attack types: 12
`- Average alerts/hour: 51.4

WARNING: SEVERITY DISTRIBUTION
|- HIGH      [!]  [  234] ############                                     18.9%
|- MEDIUM    [*]  [  567] ############################                     45.9%
|- LOW       [-]  [  433] ######################                           35.1%

[TOP 10 ATTACKING IPs]
#   IP Address                               Country      Alerts     Status       Severity
1   192.0.2.1                               CN/Beijing   234        [X] BLOCKED   High:10, Med:224
2   2001:db8::1                             RU/Moscow    189        [!] ACTIVE    High:189
3   10.0.0.5                                LAN          156        [S] SERVER    Low:156
...
```

### Key Features Explained

#### 🌍 **Geolocation Intelligence**
- Shows country code and city for each attacking IP
- Caches results to minimize API calls
- Falls back between multiple providers for reliability

#### 📈 **Historical Analysis**
```
[HISTORICAL ANALYSIS & ANOMALY DETECTION]
|- 24h trend: Alerts ↑ 45 | IPs ↑ 12
|- 🚨 ANOMALY: Alert volume 3.2x higher than 7-day average
|- New attack types: SSH brute force, SQL injection
|- Recurring attackers (seen before): 5 IPs
|- Attack origins: China (45), Russia (23), USA (12)
```

#### 🎯 **Smart IP Classification**
- **[S] SERVER**: Your server's own IPs (never blocked)
- **[T] TRUSTED**: Admin/monitoring IPs (never blocked)
- **[OK] WHITELISTED**: IPs in CSF whitelist
- **[X] BLOCKED**: Successfully blocked by CSF
- **[!] ACTIVE**: Currently attacking, not yet blocked
- **[?] UNKNOWN**: Cannot determine status

#### 📊 **CSF Integration Metrics**
```
[CSF INTEGRATION STATUS]
|- IPs blocked today: 23
|- IPs blocked in last 24 hours: 45
|- Auto-block effectiveness: 45/89 threats blocked (50.6%)
|- Top blocking countries: CN (23), RU (12), US (8)
```

## 🔧 Troubleshooting

### ⚠️ Important: No systemd service for blocking!

The blocking functionality runs via **cron**, NOT systemd. There is NO `suricata-csf-block.service`.

If you see errors about `suricata-csf-block.service`:
```bash
# This is WRONG - this service doesn't exist!
systemctl status suricata-csf-block.service  # ❌ NO!

# Check cron instead - this is correct!
grep suricata /etc/crontab  # ✅ YES!
```

To fix if you have the wrong setup:
```bash
cd ~/suricata-csf-autoblock
sudo ./fix-installation.sh
```

### Enhanced Diagnostics

1. **Run debug mode first**:
   ```bash
   sudo suricata-monitor --debug
   ```
   This shows:
   - All log file locations and sizes
   - Recent block entries
   - Server IP addresses
   - Configuration status

2. **Common Issues**:

   **Geolocation not working?**
   - Check internet connection
   - Try `--no-geo` flag
   - Clear cache: `sudo suricata-monitor --clear-cache`

   **Wrong IP classification?**
   - Update TRUSTED_IPS in the script
   - Check CSF whitelist: `cat /etc/csf/csf.allow`
   - Verify server IPs in debug mode

   **Missing historical data?**
   - First run creates baseline
   - Data builds over 30 days
   - Check cache directory: `/var/cache/suricata-monitor/`

## 📚 API Reference

### Geolocation Services

The system automatically uses these free services:
1. **ip-api.com**: 45 requests/minute (primary)
2. **ipinfo.io**: 50k requests/month (fallback)

No API keys required!

### Cache Files

- **Geolocation**: `/var/cache/suricata-monitor/geo-cache.pkl`
- **Statistics**: `/var/cache/suricata-monitor/stats-history.json`
- **Position tracking**: `/var/lib/suricata/eve_position_simple`

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Maintain backward compatibility
- Add descriptions for new signatures/rules
- Update documentation for new features
- Test with both IPv4 and IPv6

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Suricata IDS team for the excellent intrusion detection system
- ConfigServer for CSF firewall
- AbuseIPDB for threat intelligence integration
- ip-api.com and ipinfo.io for geolocation services

## 📞 Support

For issues and questions:
- Open an issue on GitHub
- Contact: Paolo Caparrelli at GOLINE SA

---

**Made with ❤️ by [GOLINE SA](https://www.goline.ch)**

## 🚀 Choose Your Edition

### 🌐 Standard Edition
For regular servers that need robust intrusion detection and blocking.

### 🚀 Speedtest Server Edition  
Optimized for Ookla Speedtest servers handling high-volume HTTP traffic.
- 🎯 Ignores legitimate speedtest traffic on ports 80, 443, 8080, 5060
- ⏰ Uses 24-hour temporary blocks instead of permanent
- 🛡️ Focuses on real security threats only

➡️ **[Speedtest Server Documentation](docs/SPEEDTEST-SERVER.md)**
