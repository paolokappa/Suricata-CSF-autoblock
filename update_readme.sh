#!/bin/bash

# Backup
cp README.md README.md.backup

# Aggiungi features
sed -i '/ðŸ"' Zero configuration passwords/a\- ðŸ"' Whitelist protection - Never blocks or reports whitelisted IPs to AbuseIPDB\n- ðŸ"„ Proper log rotation handling with position tracking' README.md

# Aggiungi Whitelist Management section
sed -i '/## ðŸŽ¯ Usage/i\
### ðŸ"' Whitelist Management\n\
The system automatically respects CSF whitelist (csf.allow) entries:\n\
\n\
- Whitelisted IPs are **never** blocked\n\
- Whitelisted IPs are **never** reported to AbuseIPDB\n\
- Supports both individual IPs and CIDR subnets (including IPv6)\n\
\n\
To whitelist an IP or subnet:\n\
```bash\n\
# Add to permanent whitelist\n\
csf -a 192.168.1.0/24 "Local network"\n\
csf -a 2a02:4460:1:1::/64 "DMZ GOLINE"\n\
\n\
# Check if an IP is whitelisted\n\
csf -g IP_ADDRESS\n\
```\n\
\n\
Whitelisted IPs will appear in logs as:\n\
```\n\
[2025-06-14 XX:XX:XX] WHITELISTED: IP_ADDRESS - Skipping (in csf.allow)\n\
```\n' README.md

# Aggiungi Log Files section
sed -i '/### AbuseIPDB Integration/i\
### Log Files\n\
\n\
- **Suricata alerts**: `/var/log/suricata/eve.json` (JSON format)\n\
- **Blocking log**: `/var/log/suricata-csf-block.log`\n\
- **Position tracking**: `/var/lib/suricata/eve_position_simple`\n\
- **Log rotation**: Automatic at 100MB, keeps 7 compressed copies\n' README.md

# Aggiungi troubleshooting items
sed -i '/## ðŸ¤ Contributing/i\
4. **Whitelisted IPs still generating alerts?**\n\
   - This is normal - Suricata still detects and logs them\n\
   - The blocking script will skip them (check for WHITELISTED in logs)\n\
   - They won'"'"'t be blocked in CSF or reported to AbuseIPDB\n\
\n\
5. **Script not processing new logs after rotation?**\n\
   - Check if position file exists: `ls -la /var/lib/suricata/eve_position_simple`\n\
   - Position file is automatically reset during log rotation\n\
   - Manual reset: `rm -f /var/lib/suricata/eve_position_simple`\n' README.md

echo "README.md updated successfully!"
