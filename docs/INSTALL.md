# Installation Guide

## Prerequisites

Before installing, ensure you have:

1. **Ubuntu 22.04 or 24.04** server
2. **CSF (ConfigServer Security & Firewall)** installed and configured
3. **Root access** to the server
4. **Network interface** name (usually eth0)

## Installation Steps

### 1. Install CSF (if not already installed)

    cd /usr/src
    wget https://download.configserver.com/csf.tgz
    tar -xzf csf.tgz
    cd csf
    sh install.sh

### 2. Install CSFToAbuseIPDB (Optional - for AbuseIPDB integration)

    git clone https://github.com/paolokappa/CSFToAbuseIPDB.git
    cd CSFToAbuseIPDB
    # Follow the installation instructions in the CSFToAbuseIPDB README

### 3. Clone this repository

    git clone https://github.com/goline-sa/suricata-csf-autoblock.git
    cd suricata-csf-autoblock

### 4. Run the installer

    sudo ./install.sh

### 5. Configure network interface

Edit /etc/suricata/suricata.yaml and update the interface:

    af-packet:
      - interface: eth0  # Change this to your interface

### 6. Restart Suricata

    systemctl restart suricata

### 7. Configure AbuseIPDB (Optional)

If you installed CSFToAbuseIPDB, edit /etc/csf/csf.conf and add your AbuseIPDB API key:

    ABUSEIPDB_KEY = "your_api_key_here"

## Verification

Run these commands to verify the installation:

    # Check Suricata status
    systemctl status suricata

    # Check auto-update timer
    systemctl status suricata-auto-update.timer

    # Run the monitor
    suricata-monitor

    # Check logs
    tail -f /var/log/suricata-csf-block.log

    # If using AbuseIPDB, check its log
    tail -f /var/log/csf_abuseipdb.log
