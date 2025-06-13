#!/bin/bash

# Suricata + CSF Auto-Block System Installer
# By Paolo Caparrelli - GOLINE SA

set -e

echo "======================================"
echo "Suricata + CSF Auto-Block Installer"
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
apt-get install -y software-properties-common jq python3 ipcalc

echo "[*] Installing Suricata..."
add-apt-repository -y ppa:oisf/suricata-stable
apt-get update
apt-get install -y suricata

echo "[*] Installing scripts..."
cp scripts/suricata-csf-block-simple.sh /usr/local/bin/
cp scripts/suricata-auto-update.sh /usr/local/bin/
cp scripts/suricata-monitor /usr/local/bin/
chmod +x /usr/local/bin/suricata-*

echo "[*] Installing systemd services for auto-update..."
cp systemd/*.service systemd/*.timer /etc/systemd/system/
systemctl daemon-reload

echo "[*] Installing logrotate configuration..."
cp logrotate/suricata /etc/logrotate.d/

echo "[*] Creating directories..."
mkdir -p /var/lib/suricata
touch /var/log/suricata-csf-block.log
touch /var/log/suricata-auto-update.log

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
echo "Next steps:"
echo "1. Edit /etc/suricata/suricata.yaml and set your network interface"
echo "2. Restart Suricata: systemctl restart suricata"
echo "3. Run 'suricata-monitor' to view alerts"
echo ""
echo "Configuration notes:"
echo "- Blocking threshold: severity <= 2 (edit MIN_SEVERITY in suricata-csf-block-simple.sh)"
echo "- Cron runs every minute to check for new alerts"
echo "- Logs rotate when they reach 100MB"
echo ""
echo "For more information, see the README.md"
