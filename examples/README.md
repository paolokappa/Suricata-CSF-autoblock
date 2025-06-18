# Example Files

This directory contains example configurations and templates for the Suricata-CSF Auto-Block system.

## Files

- **csf.allow.example** - Example whitelist configuration for CSF
- **trusted-ips-example.py** - Example trusted IPs configuration for the monitor
- **crontab.example** - Example crontab entries for automation
- **suricata-custom.yaml.example** - Example Suricata configuration

## Usage

1. Copy the example files to their proper locations
2. Modify them according to your environment
3. Never commit actual configuration files with real IPs or sensitive data

## Quick Start

```bash
# Copy CSF whitelist example
sudo cp csf.allow.example /etc/csf/csf.allow

# Copy crontab entries
cat crontab.example | sudo tee -a /etc/crontab

# Copy Suricata config
sudo cp suricata-custom.yaml.example /etc/suricata/suricata-custom.yaml
```
