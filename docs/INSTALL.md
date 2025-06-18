# Installation Guide

## Prerequisites

- Ubuntu 22.04 or 24.04
- Root access
- ConfigServer Security & Firewall (CSF) installed and configured
- At least 1GB free disk space

## Quick Installation

```bash
# Clone the repository
git clone https://github.com/paolokappa/Suricata-CSF-autoblock.git
cd suricata-csf-autoblock

# Run the installer
sudo ./install.sh
```

## Manual Installation

### 1. Install Dependencies

```bash
# Update system
apt-get update

# Install required packages
apt-get install -y software-properties-common jq python3 python3-pip ipcalc

# Install optional Python modules
pip3 install netifaces  # Optional, for better network detection
```

### 2. Install Suricata

```bash
# Add Suricata repository
add-apt-repository -y ppa:oisf/suricata-stable
apt-get update

# Install Suricata
apt-get install -y suricata
```

### 3. Configure Suricata

Edit `/etc/suricata/suricata.yaml`:

```yaml
# Set your network interface
af-packet:
  - interface: eth0  # Change to your interface

# Set your network
vars:
  address-groups:
    HOME_NET: "[192.168.1.0/24,10.0.0.0/8]"  # Your network
```

### 4. Install Scripts

```bash
# Choose your version:
# For standard servers:
cp scripts/suricata-csf-block-simple.sh /usr/local/bin/

# For Speedtest servers:
cp scripts/suricata-csf-block-speedtest.sh /usr/local/bin/
ln -sf /usr/local/bin/suricata-csf-block-speedtest.sh /usr/local/bin/suricata-csf-block-simple.sh

# Install other scripts
cp scripts/suricata-auto-update.sh /usr/local/bin/
cp scripts/suricata-monitor.py /usr/local/bin/suricata-monitor

# Make executable
chmod +x /usr/local/bin/suricata-*
```

### 5. Setup Systemd Services

```bash
# Copy service files
cp systemd/*.service systemd/*.timer /etc/systemd/system/

# Reload systemd
systemctl daemon-reload

# Enable services
systemctl enable suricata
systemctl enable suricata-auto-update.timer

# Start services
systemctl start suricata
systemctl start suricata-auto-update.timer
```

### 6. Setup Cron Jobs

Add to `/etc/crontab`:

```bash
# Suricata auto-block and logrotate
*/30 * * * * root /usr/sbin/logrotate /etc/logrotate.d/suricata >/dev/null 2>&1
* * * * * root /usr/local/bin/suricata-csf-block-simple.sh >/dev/null 2>&1
```

### 7. Setup Log Rotation

```bash
cp logrotate/suricata /etc/logrotate.d/
```

### 8. Create Required Directories

```bash
mkdir -p /var/lib/suricata
mkdir -p /var/cache/suricata-monitor
touch /var/log/suricata-csf-block.log
```

## Post-Installation

### 1. Update Suricata Rules

```bash
suricata-update
```

### 2. Configure Trusted IPs (Optional)

Edit `/usr/local/bin/suricata-monitor` and add your admin IPs:

```python
TRUSTED_IPS = [
    "YOUR_ADMIN_IP",
    "MONITORING_SERVER_IP",
]
```

### 3. Test the System

```bash
# Check Suricata is running
systemctl status suricata

# Test blocking script
/usr/local/bin/suricata-csf-block-simple.sh

# View monitoring dashboard
sudo suricata-monitor
```

## Choosing Your Edition

### Standard Edition
- Use `suricata-csf-block-simple.sh`
- Blocks all attacks based on severity
- Permanent blocks

### Speedtest Server Edition
- Use `suricata-csf-block-speedtest.sh`
- Ignores legitimate speedtest traffic
- 24-hour temporary blocks
- Recommended for Ookla Speedtest servers

## Verification

Run the verification script:

```bash
./check-installation.sh
```

This will verify all components are properly installed and configured.
