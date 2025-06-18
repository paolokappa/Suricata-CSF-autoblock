# Speedtest Server Edition

Special configuration for Ookla Speedtest servers that handle high-volume HTTP traffic.

## Why Speedtest Edition?

Speedtest servers receive thousands of legitimate HTTP requests on ports 80, 443, 8080, and 5060. The standard edition would block many legitimate users running speed tests, causing:

- False positive blocks
- Degraded speedtest performance
- Angry users unable to test their connection

## Key Differences

| Feature | Standard Edition | Speedtest Edition |
|---------|-----------------|-------------------|
| HTTP traffic on speedtest ports | Blocks suspicious | Ignores completely |
| Block duration | Permanent | 24 hours |
| Speedtest ports excluded | None | 80, 443, 8080, 5060 |
| Focus | All threats | Real threats only |

## Installation

### 1. Use the Speedtest Script

```bash
# Copy speedtest version
cp scripts/suricata-csf-block-speedtest.sh /usr/local/bin/

# Create symlink (replaces standard version)
ln -sf /usr/local/bin/suricata-csf-block-speedtest.sh /usr/local/bin/suricata-csf-block-simple.sh
chmod +x /usr/local/bin/suricata-csf-block-speedtest.sh
```

### 2. Configure Excluded Ports

Edit `/usr/local/bin/suricata-csf-block-speedtest.sh` if you need to adjust ports:

```bash
# Default speedtest ports
SPEEDTEST_PORTS="8080|5060|80|443"

# Add more if needed
SPEEDTEST_PORTS="8080|5060|80|443|8443|9000"
```

### 3. Verify Installation

```bash
# Check script is correct version
grep SPEEDTEST_PORTS /usr/local/bin/suricata-csf-block-simple.sh
# Should show: SPEEDTEST_PORTS="8080|5060|80|443"

# Test run
/usr/local/bin/suricata-csf-block-simple.sh
```

## How It Works

### Traffic Filtering

The script ignores HTTP-related alerts on speedtest ports:

```bash
# Ignored signatures on speedtest ports:
- LOCAL HTTP GET request
- LOCAL HTTP POST request  
- LOCAL HTTP request port 80
- HTTP Protocol violation

# Still blocked on speedtest ports:
- SQL injection attempts
- Command injection
- Exploit attempts
- Malware signatures
```

### Temporary Blocks

Instead of permanent blocks, uses 24-hour temporary blocks:

```bash
# Standard edition:
csf -d $IP "Reason"  # Permanent block

# Speedtest edition:
csf -td $IP 86400 "Reason"  # 24-hour block
```

This allows legitimate users who triggered false positives to retry after 24 hours.

## Monitoring

### Check Blocked IPs

```bash
# View temporary blocks
csf -t | grep Suricata

# Count daily blocks
grep "BLOCKED (24h)" /var/log/suricata-csf-block.log | grep "$(date +%Y-%m-%d)" | wc -l
```

### Analyze Ignored Traffic

```bash
# See what's being ignored
grep "port 8080\|port 80\|port 443\|port 5060" /var/log/suricata/eve.json | \
  jq -r '.alert.signature' | sort | uniq -c | sort -rn | head -20
```

## Best Practices

### 1. Whitelist Known Good IPs

```bash
# Whitelist Ookla servers
csf -a 151.101.2.219 "Ookla server"
csf -a 198.41.0.4 "Ookla root server"

# Whitelist monitoring services
csf -a YOUR_MONITORING_IP "Monitoring service"
```

### 2. Regular Cleanup

```bash
# Add to crontab for daily cleanup of old blocks
0 3 * * * root csf -tr
```

### 3. Monitor Performance

```bash
# Check blocking rate
tail -f /var/log/suricata-csf-block.log | grep -E "(BLOCKED|Ignoring)"

# Ensure legitimate traffic flows
netstat -an | grep -E ":(80|443|8080|5060)" | grep ESTABLISHED | wc -l
```

## Switching Between Editions

### To Speedtest Edition:

```bash
ln -sf /usr/local/bin/suricata-csf-block-speedtest.sh /usr/local/bin/suricata-csf-block-simple.sh
```

### To Standard Edition:

```bash
rm /usr/local/bin/suricata-csf-block-simple.sh
cp scripts/suricata-csf-block-simple.sh /usr/local/bin/
chmod +x /usr/local/bin/suricata-csf-block-simple.sh
```

## Troubleshooting

### Too Many Blocks

If still blocking legitimate users:

1. Increase severity threshold:
   ```bash
   # Edit script and change:
   if [ "$severity" -le 2 ]; then
   # To:
   if [ "$severity" -le 1 ]; then
   ```

2. Add more port exclusions:
   ```bash
   SPEEDTEST_PORTS="8080|5060|80|443|8443|3000"
   ```

### Not Blocking Real Threats

If missing real attacks:

1. Check ignored patterns:
   ```bash
   grep "Ignoring" /var/log/suricata-csf-block.log | tail -50
   ```

2. Ensure severity 1 alerts are never ignored

## FAQ

**Q: Why 24-hour blocks instead of permanent?**
A: Speedtest users are often on dynamic IPs. A permanent block could affect different users later.

**Q: Can I customize which ports are excluded?**
A: Yes, edit the `SPEEDTEST_PORTS` variable in the script.

**Q: Will this miss real attacks?**
A: No, it only ignores generic HTTP alerts on speedtest ports. Real attacks (SQL injection, exploits, etc.) are still blocked.

**Q: How do I know it's working?**
A: Check logs for "Ignoring speedtest traffic" messages and verify speedtests complete successfully.
