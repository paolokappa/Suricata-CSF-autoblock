# Systemd Services

This directory contains systemd service files for the Suricata-CSF integration.

## Files

- `suricata-auto-update.service` - Service for updating Suricata rules
- `suricata-auto-update.timer` - Timer that triggers daily rule updates at 01:00

## Important Note

There is **NO** `suricata-csf-block.service`. The blocking functionality runs via cron, not systemd.

## Installation

```bash
sudo cp *.service *.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable suricata-auto-update.timer
sudo systemctl start suricata-auto-update.timer
```

## Check Status

```bash
systemctl status suricata-auto-update.timer
systemctl list-timers --all | grep suricata
```

## Manual Rule Update

```bash
sudo systemctl start suricata-auto-update.service
```
