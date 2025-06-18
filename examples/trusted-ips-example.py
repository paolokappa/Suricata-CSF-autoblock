# Example configuration for trusted IPs in suricata-monitor
# Copy this section to /usr/local/bin/suricata-monitor and modify with your IPs

# List of trusted IPs that should never be blocked
# These IPs will show as [T] TRUSTED in the monitor
TRUSTED_IPS = [
    # Admin workstations
    "192.168.1.10",         # Office admin PC
    "192.168.1.11",         # Home office VPN
    "203.0.113.5",          # CEO home IP
    
    # Monitoring services  
    "198.51.100.22",        # Uptime monitoring service
    "203.0.113.99",         # External monitoring probe
    
    # IPv6 examples
    "2001:db8:1234::1",     # IPv6 admin
    "2001:db8:cafe::42",    # IPv6 monitoring
    
    # Partner services
    "10.0.0.5",             # Internal monitoring server
    "172.16.0.100",         # Backup server
]

# Note: These IPs will:
# - Never be blocked by the auto-block script
# - Show as TRUSTED in monitoring reports  
# - Still generate alerts (for awareness) but won't be acted upon
# - Be highlighted separately in the monitoring dashboard
