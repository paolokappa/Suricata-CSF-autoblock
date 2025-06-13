# Troubleshooting Guide

## Common Issues

### 1. Suricata not starting

**Problem**: systemctl status suricata shows failed state

**Solution**:

    # Check configuration
    suricata -T -c /etc/suricata/suricata.yaml

    # Check logs
    journalctl -u suricata -n 50

### 2. No alerts being generated

**Problem**: suricata-monitor shows no alerts

**Solution**:
- Verify correct network interface in config
- Check if traffic is reaching the interface
- Ensure Suricata rules are updated: suricata-update

### 3. IPs not being blocked

**Problem**: Alerts show but IPs are not blocked

**Solution**:
- Check script logs: tail -50 /var/log/suricata-csf-block.log
- Verify CSF is running: csf -v
- Check severity setting in script (default MIN_SEVERITY=2)

### 4. Log file too large

**Problem**: /var/log/suricata/eve.json is very large

**Solution**:

    # Force logrotate
    logrotate -f /etc/logrotate.d/suricata

    # Check logrotate configuration
    cat /etc/logrotate.d/suricata

### 5. Monitor shows wrong IP status

**Problem**: Blocked IPs show as "ACTIVE"

**Solution**:
- Check CSF status: csf -g IP_ADDRESS
- Restart monitor after changes

## Debug Commands

    # Test block script manually
    /usr/local/bin/suricata-csf-block-simple.sh

    # Run script in debug mode
    bash -x /usr/local/bin/suricata-csf-block-simple.sh

    # Check cron execution
    grep suricata /var/log/syslog | tail -20

    # Reset file position to reprocess
    rm -f /var/lib/suricata/eve_position_simple

## Log Files

- Suricata alerts: /var/log/suricata/eve.json
- Block script log: /var/log/suricata-csf-block.log
- Update log: /var/log/suricata-auto-update.log
- System log: /var/log/syslog
