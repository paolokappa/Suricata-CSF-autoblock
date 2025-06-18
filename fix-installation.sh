#!/bin/bash

# Fix installation script for Suricata-CSF
# By Paolo Caparrelli - GOLINE SA

set -e

echo "======================================"
echo "Fixing Suricata-CSF Installation"
echo "======================================"

# 1. Ensure cron jobs are in system crontab
echo "[*] Checking cron jobs..."
if ! grep -q "suricata-csf-block" /etc/crontab; then
    echo "[*] Adding cron jobs to /etc/crontab..."
    echo "" >> /etc/crontab
    echo "# Suricata auto-block and logrotate" >> /etc/crontab
    echo "*/30 * * * * root /usr/sbin/logrotate /etc/logrotate.d/suricata >/dev/null 2>&1" >> /etc/crontab
    echo "* * * * * root /usr/local/bin/suricata-csf-block-simple.sh >/dev/null 2>&1" >> /etc/crontab
    echo "[OK] Cron jobs added"
else
    echo "[OK] Cron jobs already present"
fi

# 2. Fix any malformed cron entries
echo "[*] Fixing cron format..."
sed -i 's/\*\s*\*\s*\*\s*\*\*/\* \* \* \*/g' /etc/crontab
echo "[OK] Cron format fixed"

# 3. Ensure cron service is running
if ! systemctl is-active --quiet cron; then
    echo "[*] Starting cron service..."
    systemctl start cron
    systemctl enable cron
    echo "[OK] Cron service started"
else
    echo "[OK] Cron service is running"
fi

# 4. Create necessary directories
echo "[*] Creating directories..."
mkdir -p /var/lib/suricata
mkdir -p /var/cache/suricata-monitor
chmod 755 /var/cache/suricata-monitor
echo "[OK] Directories created"

# 5. Create log files if missing
echo "[*] Creating log files..."
touch /var/log/suricata-csf-block.log
touch /var/log/suricata-auto-update.log
chmod 644 /var/log/suricata-csf-block.log
chmod 644 /var/log/suricata-auto-update.log
echo "[OK] Log files created"

# 6. Fix script permissions
echo "[*] Setting script permissions..."
for script in suricata-csf-block-simple.sh suricata-auto-update.sh suricata-monitor; do
    if [ -f "/usr/local/bin/$script" ]; then
        chmod +x "/usr/local/bin/$script"
        echo "[OK] Fixed permissions for $script"
    fi
done

# 7. Ensure Suricata is running
if ! systemctl is-active --quiet suricata; then
    echo "[*] Starting Suricata..."
    systemctl start suricata
    systemctl enable suricata
    echo "[OK] Suricata started"
else
    echo "[OK] Suricata is running"
fi

# 8. Ensure CSF is running
if ! systemctl is-active --quiet csf; then
    echo "[*] Starting CSF..."
    systemctl start csf
    systemctl enable csf
    echo "[OK] CSF started"
else
    echo "[OK] CSF is running"
fi

# 9. Test the blocking script
echo "[*] Testing blocking script..."
if [ -x /usr/local/bin/suricata-csf-block-simple.sh ]; then
    timeout 5 /usr/local/bin/suricata-csf-block-simple.sh >/dev/null 2>&1 || true
    echo "[OK] Blocking script test completed"
else
    echo "[WARN] Blocking script not found or not executable"
fi

echo ""
echo "======================================"
echo "Installation fixed!"
echo "======================================"
echo ""
echo "Current status:"
echo "- Cron jobs: $(grep -c 'suricata-csf-block' /etc/crontab 2>/dev/null || echo 0) entries in /etc/crontab"
echo "- Suricata: $(systemctl is-active suricata)"
echo "- CSF: $(systemctl is-active csf)"
echo "- Cron service: $(systemctl is-active cron)"
echo "- Auto-update timer: $(systemctl is-active suricata-auto-update.timer)"
echo ""
echo "The blocking script will run every minute via cron."
echo ""
echo "Check the logs:"
echo "  tail -f /var/log/suricata-csf-block.log"
echo ""
echo "Monitor alerts:"
echo "  sudo suricata-monitor"
echo ""
