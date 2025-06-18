#!/bin/bash

# Suricata + CSF Auto-Block System Installer
# By Paolo Caparrelli - GOLINE SA
# Version 2.1.0

set -e

echo "======================================"
echo "Suricata + CSF Auto-Block Installer"
echo "Version 2.1.0"
echo "By GOLINE SA"
echo "======================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

# Check Ubuntu version
if ! grep -E "22.04|24.04" /etc/lsb-release > /dev/null; then
    echo "This script requires Ubuntu 22.04 or 24.04"
    exit 1
fi

# Check if CSF is installed
if ! command -v csf &> /dev/null; then
    echo "CSF (ConfigServer Security & Firewall) is required but not installed."
    echo "Please install CSF first: https://configserver.com/cp/csf.html"
    exit 1
fi

echo "[*] Installing dependencies..."
apt-get update
apt-get install -y software-properties-common jq python3 python3-pip ipcalc

# Install optional Python modules for enhanced features
echo "[*] Installing optional Python modules..."
pip3 install netifaces || echo "Warning: netifaces installation failed (optional)"

echo "[*] Installing Suricata..."
add-apt-repository -y ppa:oisf/suricata-stable
apt-get update
apt-get install -y suricata

echo "[*] Installing scripts..."
# Copy the enhanced monitor script
if [ -f "scripts/suricata-monitor.py" ]; then
    cp scripts/suricata-monitor.py /usr/local/bin/suricata-monitor
else
    cp scripts/suricata-monitor /usr/local/bin/
fi

cp scripts/suricata-csf-block-simple.sh /usr/local/bin/
cp scripts/suricata-auto-update.sh /usr/local/bin/
chmod +x /usr/local/bin/suricata-*

echo "[*] Installing systemd services for auto-update..."
cp systemd/*.service systemd/*.timer /etc/systemd/system/
systemctl daemon-reload

echo "[*] Installing logrotate configuration..."
cp logrotate/suricata /etc/logrotate.d/

echo "[*] Creating directories..."
mkdir -p /var/lib/suricata
mkdir -p /var/cache/suricata-monitor
touch /var/log/suricata-csf-block.log
touch /var/log/suricata-auto-update.log

# Set proper permissions for cache directory
chmod 755 /var/cache/suricata-monitor

echo "[*] Configuring crontab..."
if ! grep -q "suricata-csf-block" /etc/crontab; then
    echo "" >> /etc/crontab
    echo "# Suricata auto-block and logrotate" >> /etc/crontab
    echo "*/30 * * * * root /usr/sbin/logrotate /etc/logrotate.d/suricata >/dev/null 2>&1" >> /etc/crontab
    echo "* * * * * root /usr/local/bin/suricata-csf-block-simple.sh >/dev/null 2>&1" >> /etc/crontab
fi

echo "[*] Updating Suricata rules..."
suricata-update

echo "[*] Enabling services..."
systemctl enable suricata
systemctl enable suricata-auto-update.timer
systemctl start suricata
systemctl start suricata-auto-update.timer

echo ""
echo "======================================"
echo "Installation complete!"
echo "======================================"
echo ""
echo "✨ NEW FEATURES in v2.1.0:"
echo "  - 🌍 Geolocation intelligence for attacking IPs"
echo "  - 📊 Historical analytics with anomaly detection"
echo "  - 🎯 Smart IP classification (Server/Trusted/Active/Blocked)"
echo "  - 📈 Professional monitoring dashboard with colors"
echo ""
echo "Next steps:"
echo "1. Edit /etc/suricata/suricata.yaml and set your network interface"
echo "2. (Optional) Edit /usr/local/bin/suricata-monitor to add TRUSTED_IPS"
echo "3. Restart Suricata: systemctl restart suricata"
echo "4. Run 'sudo suricata-monitor' to view the enhanced dashboard"
echo ""
echo "Quick commands:"
echo "  sudo suricata-monitor              # Full dashboard"
echo "  sudo suricata-monitor --debug      # Debug mode"
echo "  sudo suricata-monitor --no-geo     # Without geolocation"
echo "  sudo suricata-monitor -H 12        # Last 12 hours"
echo ""
echo "Configuration notes:"
echo "- Blocking threshold: severity <= 2 (edit MIN_SEVERITY in suricata-csf-block-simple.sh)"
echo "- Cron runs every minute to check for new alerts"
echo "- Logs rotate when they reach 100MB"
echo "- Cache stored in /var/cache/suricata-monitor/"
echo ""
echo "For more information, see the README.md"
