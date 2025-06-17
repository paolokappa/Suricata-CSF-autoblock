# 🛡️ Suricata IDS + CSF Firewall Auto-Block System

A complete solution for automatic intrusion detection and blocking using Suricata IDS and ConfigServer Security & Firewall (CSF).

Developed by **Paolo Caparrelli** at **GOLINE SA**


## &#x1F3AF; Choose Your Edition

### &#x1F310; Standard Edition
For regular servers that need robust intrusion detection and blocking.

### &#x1F680; Speedtest Server Edition  
Optimized for Ookla Speedtest servers handling high-volume HTTP traffic.
- &#x1F3AF; Ignores legitimate speedtest traffic on ports 80, 443, 8080, 5060
- &#x23F0; Uses 24-hour temporary blocks instead of permanent
- &#x1F6E1;&#xFE0F; Focuses on real security threats only

&#x27A1;&#xFE0F; **[Speedtest Server Documentation](docs/SPEEDTEST-SERVER.md)**


## 🚀 Features

- 🔥 Real-time intrusion detection with Suricata IDS
- 🛡️ Automatic IP blocking based on alert severity
- 📊 AbuseIPDB integration via CSFToAbuseIPDB
- ⚡ Automatic Suricata rules updates
- 📋 Detailed monitoring and reporting
- ⚙️ Automatic log rotation with logrotate
- 🔧 Cron-based automation (runs every minute)
- 🔒 Zero configuration passwords - fully secure

## 📋 Table of Contents

1. [Requirements](#-requirements)
2. [Quick Start](#-quick-start)
3. [Installation](#-installation)
4. [Configuration](#-configuration)
5. [Usage](#-usage)
6. [Monitoring](#-monitoring)
7. [Troubleshooting](#-troubleshooting)
8. [Contributing](#-contributing)
9. [License](#-license)

## 💻 Requirements

- Ubuntu 22.04 or 24.04
- ConfigServer Security & Firewall (CSF) installed
- Python 3.x
- jq (JSON processor)
- Root access

**Optional (for AbuseIPDB integration)**
- CSFToAbuseIPDB installed
- AbuseIPDB API key

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/paolokappa/Suricata-CSF-autoblock.git
cd suricata-csf-autoblock

# Run the installer
sudo ./install.sh
```

## 📦 Installation

See [INSTALL.md](docs/INSTALL.md) for detailed installation instructions.

## ⚙️ Configuration

The system comes pre-configured with sensible defaults. Main configuration files:

- **Suricata config**: `/etc/suricata/suricata.yaml`
- **Blocking severity**: Edit `MIN_SEVERITY` in `scripts/suricata-csf-block-simple.sh` (default: 2)
- **Network interface**: Update in Suricata config

### Severity Levels

- **1** = HIGH (always block)
- **2** = MEDIUM (default threshold)
- **3** = LOW (usually false positives)

### AbuseIPDB Integration (Optional)

If you have CSFToAbuseIPDB installed:
1. Configure your API key in CSFToAbuseIPDB
2. The integration will work automatically

## 🎯 Usage

### Manual Blocking Script

```bash
# Test the blocking script manually
/usr/local/bin/suricata-csf-block-simple.sh
```

### Monitor Suricata Events

```bash
# Real-time monitoring with formatted output
/usr/local/bin/suricata-monitor
```

### Update Suricata Rules

```bash
# Manual update
systemctl start suricata-auto-update.service

# Check timer status
systemctl status suricata-auto-update.timer

### &#x1F4CA; Enhanced Monitoring (v2.0+)

The new monitoring script shows:
- &#x1F4C8; Real-time attack statistics
- &#x1F30D; Proper IPv6 address formatting
- &#x1F3AF; CSF status for each IP (WHITELISTED/BLOCKED/ACTIVE)
- &#x1F4CA; Attack categorization and severity distribution
- &#x23F1;&#xFE0F; Hourly attack timeline
```

## 📊 Monitoring

### Check Service Status

```bash
# Suricata status
systemctl status suricata

# Check if blocking is working
tail -f /var/log/suricata/csf-blocking.log

# View Suricata alerts
tail -f /var/log/suricata/fast.log
```

### Verify Cron Job

```bash
# Check if cron job is installed
crontab -l | grep suricata-csf-block
```

### CSF Blocked IPs

```bash
# View temporarily blocked IPs
csf -t

# View permanently blocked IPs
csf -g [IP_ADDRESS]
```

## 🔧 Troubleshooting

See [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for common issues and solutions.

### Quick Checks

1. **Suricata not starting?**
   ```bash
   suricata -T -c /etc/suricata/suricata.yaml
   ```

2. **No alerts generated?**
   ```bash
   # Test with a known bad pattern
   curl http://testmynids.org/uid/index.html
   ```

3. **IPs not being blocked?**
   - Check `/var/log/suricata/csf-blocking.log`
   - Verify CSF is running: `systemctl status csf`
   - Check MIN_SEVERITY setting

4. **Whitelisted IPs still generating alerts?**
   - This is normal - Suricata still detects and logs them
   - The blocking script will skip them (check for WHITELISTED in logs)
   - They won't be blocked in CSF or reported to AbuseIPDB

5. **Script not processing new logs after rotation?**
   - Check if position file exists: `ls -la /var/lib/suricata/eve_position_simple`
   - Position file is automatically reset during log rotation
   - Manual reset: `rm -f /var/lib/suricata/eve_position_simple`

4. **Whitelisted IPs still generating alerts?**
   - This is normal - Suricata still detects and logs them
   - The blocking script will skip them (check for WHITELISTED in logs)
   - They won't be blocked in CSF or reported to AbuseIPDB

5. **Script not processing new logs after rotation?**
   - Check if position file exists: `ls -la /var/lib/suricata/eve_position_simple`
   - Position file is automatically reset during log rotation
   - Manual reset: `rm -f /var/lib/suricata/eve_position_simple`

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Suricata IDS team for the excellent intrusion detection system
- ConfigServer for CSF firewall
- AbuseIPDB for threat intelligence integration

## 📞 Support

For issues and questions:
- Open an issue on GitHub
- Contact: Paolo Caparrelli at GOLINE SA

---

**Made with ❤️ by [GOLINE SA](https://www.goline.ch)**

---


---

## &#x1F680; Speedtest Server Edition

For Ookla Speedtest servers, use the specialized version that handles high-volume HTTP traffic intelligently.

### Quick Install for Speedtest Servers:
```bash
# Use the speedtest-optimized script
cp scripts/suricata-csf-block-speedtest.sh /usr/local/bin/
ln -sf /usr/local/bin/suricata-csf-block-speedtest.sh /usr/local/bin/suricata-csf-block-simple.sh

# Install enhanced monitor
cp scripts/suricata-monitor-enhanced.py /usr/local/bin/suricata-monitor
chmod +x /usr/local/bin/suricata-monitor
```

See [Speedtest Documentation](docs/SPEEDTEST-SERVER.md) for full details.

---

## &#x1F680; Speedtest Server Edition

For Ookla Speedtest servers, use the specialized version that handles high-volume HTTP traffic intelligently.

### &#x1F4E6; Quick Install for Speedtest Servers:
```bash
# Use the speedtest-optimized script
cp scripts/suricata-csf-block-speedtest.sh /usr/local/bin/
ln -sf /usr/local/bin/suricata-csf-block-speedtest.sh /usr/local/bin/suricata-csf-block-simple.sh

# Install enhanced monitor
cp scripts/suricata-monitor-enhanced.py /usr/local/bin/suricata-monitor
chmod +x /usr/local/bin/suricata-monitor
```

### &#x1F195; New in v2.0
- &#x1F30D; Full IPv6 support with proper address formatting
- &#x1F4CA; Enhanced monitoring with `--debug` and `--show-all-blocked` options
- &#x1F3AF; Intelligent scoring system for gradual threat detection
- &#x23F0; Temporary 24h blocks instead of permanent for speedtest servers
- &#x1F6E1;&#xFE0F; Focus on real threats, ignore legitimate speedtest traffic

See [Speedtest Documentation](docs/SPEEDTEST-SERVER.md) for full details.
