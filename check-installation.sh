#!/bin/bash

# Script per verificare l'installazione di Suricata-CSF
# By Paolo Caparrelli - GOLINE SA

echo "======================================"
echo "Verifica installazione Suricata-CSF"
echo "======================================"
echo ""

# Colori
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Funzione per check
check_ok() {
    echo -e "${GREEN}[OK]${NC} $1"
}

check_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

check_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo "1. Verifica servizi systemd:"
echo "----------------------------"

# Check suricata service
if systemctl is-active --quiet suricata; then
    check_ok "Suricata service is running"
else
    check_fail "Suricata service is not running"
fi

# Check auto-update timer
if systemctl is-active --quiet suricata-auto-update.timer; then
    check_ok "Auto-update timer is active"
else
    check_fail "Auto-update timer is not active"
fi

echo ""
echo "2. Verifica cron jobs:"
echo "----------------------"

# Check system crontab
if grep -q "suricata-csf-block" /etc/crontab; then
    check_ok "Cron job found in /etc/crontab"
    grep "suricata-csf-block" /etc/crontab | sed 's/^/  /'
else
    check_fail "Cron job NOT found in /etc/crontab"
fi

echo ""
echo "3. Verifica script e file:"
echo "--------------------------"

# Check scripts
for script in suricata-csf-block-simple.sh suricata-auto-update.sh suricata-monitor; do
    if [ -x "/usr/local/bin/$script" ]; then
        check_ok "Script $script exists and is executable"
    else
        check_fail "Script $script missing or not executable"
    fi
done

# Check log files
for logfile in /var/log/suricata-csf-block.log /var/log/suricata/eve.json; do
    if [ -f "$logfile" ]; then
        size=$(du -h "$logfile" | cut -f1)
        check_ok "Log file $logfile exists (size: $size)"
    else
        check_fail "Log file $logfile missing"
    fi
done

# Check directories
for dir in /var/lib/suricata /var/cache/suricata-monitor; do
    if [ -d "$dir" ]; then
        check_ok "Directory $dir exists"
    else
        check_fail "Directory $dir missing"
    fi
done

echo ""
echo "4. Test blocking script:"
echo "------------------------"

# Test run the blocking script
echo "Running blocking script test..."
if timeout 5 /usr/local/bin/suricata-csf-block-simple.sh 2>&1 | head -n 5; then
    check_ok "Blocking script runs successfully"
else
    check_fail "Blocking script failed to run"
fi

echo ""
echo "5. Recent activity:"
echo "-------------------"

# Show recent blocks
if [ -f /var/log/suricata-csf-block.log ]; then
    recent_blocks=$(grep "BLOCKED" /var/log/suricata-csf-block.log 2>/dev/null | tail -5)
    if [ -n "$recent_blocks" ]; then
        echo "Recent blocks:"
        echo "$recent_blocks" | sed 's/^/  /'
    else
        echo "No recent blocks found"
    fi
fi

# Show suricata alerts count
if [ -f /var/log/suricata/eve.json ]; then
    alert_count=$(grep '"event_type":"alert"' /var/log/suricata/eve.json | wc -l)
    echo "Total alerts in current log: $alert_count"
fi

echo ""
echo "======================================"
echo "Summary:"
echo "======================================"

# Check if CSF is running
if ! systemctl is-active --quiet csf; then
    echo ""
    check_fail "CSF is not running! Start it with: systemctl start csf"
fi

# Check if cron is running
if ! systemctl is-active --quiet cron; then
    echo ""
    check_fail "Cron is not running! Start it with: systemctl start cron"
fi

echo ""
echo "To monitor the system:"
echo "  sudo suricata-monitor"
echo ""
echo "To check if blocking is working:"
echo "  tail -f /var/log/suricata-csf-block.log"
echo ""
