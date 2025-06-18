# Troubleshooting Guide

## Common Issues and Solutions

### 1. Suricata Not Starting

**Symptoms:**
- `systemctl status suricata` shows failed state
- No alerts being generated

**Solutions:**

```bash
# Test configuration
suricata -T -c /etc/suricata/suricata.yaml

# Check logs
journalctl -u suricata -n 50

# Common fixes:
# 1. Wrong interface in config
# Edit /etc/suricata/suricata.yaml and set correct interface

# 2. Permission issues
chown -R suricata:suricata /var/log/suricata
chmod 755 /var/log/suricata
```

### 2. No Alerts Being Generated

**Symptoms:**
- Suricata running but no alerts in logs
- `/var/log/suricata/eve.json` empty or not growing

**Solutions:**

```bash
# Test with known bad traffic
curl http://testmynids.org/uid/index.html

# Check if interface is correct
ip link show
# Update interface in /etc/suricata/suricata.yaml

# Check if rules are loaded
suricata-update list-sources
suricata-update
systemctl restart suricata
```

### 3. IPs Not Being Blocked

**Symptoms:**
- Alerts showing in logs but IPs not blocked
- No entries in `/var/log/suricata-csf-block.log`

**Solutions:**

```bash
# Check if cron job exists
grep suricata /etc/crontab

# If missing, add it:
echo "* * * * * root /usr/local/bin/suricata-csf-block-simple.sh >/dev/null 2>&1" >> /etc/crontab

# Check if CSF is running
systemctl status csf
csf -v

# Test blocking script manually
/usr/local/bin/suricata-csf-block-simple.sh

# Check for errors in log
tail -f /var/log/suricata-csf-block.log
```

### 4. Wrong Service Error

**Error:**
```
Unit suricata-csf-block.service not found
```

**Solution:**
This service doesn't exist! The blocking uses cron, not systemd.

```bash
# Remove failed service state
systemctl reset-failed suricata-csf-block.service

# Verify cron is set up correctly
grep suricata /etc/crontab
```

### 5. Legitimate Traffic Being Blocked

**Symptoms:**
- Speedtest servers blocking legitimate tests
- Admin IPs being blocked

**Solutions:**

```bash
# For Speedtest servers, use the speedtest version:
ln -sf /usr/local/bin/suricata-csf-block-speedtest.sh /usr/local/bin/suricata-csf-block-simple.sh

# Whitelist important IPs
csf -a YOUR_IP "Admin IP - Do not block"

# Add to trusted IPs in monitor
# Edit /usr/local/bin/suricata-monitor
```

### 6. High CPU Usage

**Symptoms:**
- Script consuming too much CPU
- System slow during processing

**Solutions:**

```bash
# Check log size
ls -lh /var/log/suricata/eve.json

# If too large, rotate it
logrotate -f /etc/logrotate.d/suricata

# Adjust processing frequency
# Edit /etc/crontab and change from every minute to every 5 minutes:
# */5 * * * * root /usr/local/bin/suricata-csf-block-simple.sh
```

### 7. Position File Issues

**Symptoms:**
- Script not processing new entries after log rotation
- Same alerts processed multiple times

**Solutions:**

```bash
# Reset position file
rm -f /var/lib/suricata/eve_position_simple

# The script will start fresh on next run
```

### 8. Geolocation Not Working

**Symptoms:**
- Monitor shows "N/A" for all countries
- Timeout errors in monitor

**Solutions:**

```bash
# Run monitor without geolocation
sudo suricata-monitor --no-geo

# Clear geo cache
sudo suricata-monitor --clear-cache

# Check internet connectivity
ping -c 1 ip-api.com
```

### 9. Memory Issues

**Symptoms:**
- Out of memory errors
- Script killed by system

**Solutions:**

```bash
# Check available memory
free -h

# Reduce processed IPs cache
# Edit the script and change:
# tail -500 to tail -100

# Increase system swap if needed
```

### 10. CSF Integration Issues

**Symptoms:**
- CSF commands failing
- "command not found" errors

**Solutions:**

```bash
# Verify CSF installation
which csf
csf -v

# Reinstall CSF if needed
cd /usr/src
wget https://download.configserver.com/csf.tgz
tar -xzf csf.tgz
cd csf
sh install.sh
```

## Debug Mode

For comprehensive diagnostics:

```bash
# Run installation check
./check-installation.sh

# Run monitor in debug mode
sudo suricata-monitor --debug

# Check all logs
tail -f /var/log/suricata/*.log /var/log/suricata-csf-block.log
```

## Getting Help

1. Check the logs first:
   - `/var/log/suricata/suricata.log`
   - `/var/log/suricata-csf-block.log`
   - `journalctl -u suricata`

2. Run debug scripts:
   - `./check-installation.sh`
   - `suricata-monitor --debug`

3. Open an issue on GitHub with:
   - Error messages
   - Output of debug scripts
   - Your configuration
