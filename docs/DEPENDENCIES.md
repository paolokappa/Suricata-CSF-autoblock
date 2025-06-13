# Dependencies

## Required Dependencies

- **Suricata IDS**: The core intrusion detection system
- **CSF (ConfigServer Security & Firewall)**: For firewall management
- **Python 3.x**: For the monitoring script
- **jq**: For JSON parsing in bash scripts
- **ipcalc**: For IP subnet calculations

## Optional Dependencies

### CSFToAbuseIPDB

For AbuseIPDB integration, install: https://github.com/paolokappa/CSFToAbuseIPDB

This project provides the integration between CSF and AbuseIPDB, allowing automatic reporting of blocked IPs to the AbuseIPDB threat intelligence platform.

Features provided by CSFToAbuseIPDB:
- Automatic IP reputation reporting
- Configurable categories and confidence scores
- Detailed logging
- Rate limiting to avoid API limits

## System Requirements

- Ubuntu 22.04 or 24.04
- Minimum 1GB RAM
- Network interface with promiscuous mode support
- Root access for installation and operation
