#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Suricata Monitor - Analyze and display statistics from Suricata logs
Enhanced version with detailed CSF blocking information and improved descriptions
"""

import json
import sys
import os
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import argparse
import subprocess
import socket
import ipaddress
import re
import pickle
from pathlib import Path

# Try to import urllib, use simple fallback if not available
try:
    import urllib.request
    import urllib.error
except ImportError:
    urllib = None

# Colors for output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

# Mappatura delle signature con descrizioni più parlanti
SIGNATURE_DESCRIPTIONS = {
    "LOCAL HTTP GET request": "Suspicious HTTP GET request - Possible scanning or unauthorized access attempt",
    "LOCAL Port scan detected": "Port scan detected - Attempt to identify vulnerable services",
    "LOCAL HTTP request port 80": "Anomalous HTTP traffic on port 80 - Possible web exploit attempt",
    "LOCAL SSH brute force": "SSH brute force attack - Attempt to guess login credentials",
    "SURICATA Applayer Detect protocol only one direction": "Protocol detected only one direction - Possible abnormal connection",
    "LOCAL FTP connection attempt": "FTP connection attempt - Possible search for vulnerable FTP servers",
    "SURICATA Applayer Mismatch protocol both directions": "Protocol mismatch - Possible evasion or attack attempt",
    "SURICATA STREAM excessive retransmissions": "Excessive retransmissions - Possible DoS attack or network issue",
    "LOCAL FTP USER command": "FTP USER command detected - Possible FTP access attempt",
    "ET SCAN Suspicious inbound to": "Suspicious inbound traffic - Possible scanning or reconnaissance",
    "ET POLICY": "Policy violation - Behavior not compliant with security rules",
    "ET MALWARE": "Malware detected - Possible infection or malware spreading attempt",
    "ET TROJAN": "Trojan detected - System potentially compromised",
    "ET EXPLOIT": "Exploit attempt - Exploitation of known vulnerability",
}

# Mappatura dei motivi di blocco con descrizioni migliorate
BLOCK_REASON_DESCRIPTIONS = {
    "mod_security": "ModSecurity block - Suspicious or malformed web activity detected",
    "mod_security (3600s)": "ModSecurity temporary block (1 hour) - Suspicious web activity",
    "Score threshold reached": "Score threshold reached - Too many suspicious activities accumulated",
    "Suspicious HTTP activity pattern detected": "Suspicious HTTP activity pattern - Abnormal behavior detected",
    "Excessive HTTP requests - possible bot/scanner": "Excessive HTTP requests - Probable bot or automated scanner",
    "WordPress login attempt blocked": "WordPress login attempt blocked - Possible brute force attack",
    "SSH brute force": "SSH brute force attack - Multiple failed login attempts",
    "Port scan": "Port scan - Attempt to map server services",
    "Security block": "Generic security block - Suspicious activity detected",
    "In CSF deny list": "In CSF deny list - IP previously identified as malicious",
}

# Mappatura specifica per ModSecurity rule IDs
MODSECURITY_RULE_DESCRIPTIONS = {
    # OWASP ModSecurity Core Rule Set (CRS) common rules
    "91003": "Path traversal attempt - Trying to access files outside web root",
    "91004": "Remote file inclusion (RFI) attempt - Trying to include external malicious files",
    "91005": "Local file inclusion (LFI) attempt - Trying to access local system files",
    "91010": "HTTP header injection - Attempting to inject malicious headers",
    "91011": "GET/HEAD request with body - Abnormal request structure",
    "91012": "POST request missing Content-Length - Malformed POST request",
    
    # WordPress specific rules
    "92010": "WordPress login brute force - Multiple failed login attempts",
    "92011": "WordPress xmlrpc.php attack - Attempting to exploit XML-RPC interface",
    "92012": "WordPress admin access attempt - Unauthorized admin panel access",
    
    # SQL Injection rules
    "95001": "SQL injection attempt - Trying to manipulate database queries",
    "95002": "SQL injection (cookie) - SQL injection via cookie values",
    "95003": "SQL injection (user-agent) - SQL injection via User-Agent header",
    
    # XSS rules
    "96001": "Cross-site scripting (XSS) attempt - Trying to inject malicious scripts",
    "96002": "XSS in request body - Script injection in POST data",
    "96003": "XSS in headers - Script injection in HTTP headers",
    
    # Command injection rules
    "93001": "Unix command injection - Attempting to execute system commands",
    "93002": "Windows command injection - Attempting to execute Windows commands",
    
    # Scanner detection rules
    "99001": "Security scanner detected - Automated vulnerability scanning tool",
    "99002": "Web crawler abuse - Aggressive bot ignoring robots.txt",
    "99003": "Suspicious user agent - Known malicious tool or bot",
    
    # File upload rules
    "97001": "Malicious file upload attempt - Trying to upload executable files",
    "97002": "PHP code injection in upload - Attempting to upload PHP backdoor",
    
    # Generic attack rules
    "98001": "Multiple attack patterns detected - Combined attack attempt",
    "98002": "Anomaly score threshold exceeded - Too many suspicious indicators",
}

# Mappatura estesa dei servizi per porte
PORT_SERVICES = {
    20: "FTP-DATA (FTP data transfer)",
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell - Remote access)",
    23: "TELNET (Insecure remote access)",
    25: "SMTP (Email sending)",
    53: "DNS (Domain name resolution)",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP (Trivial File Transfer)",
    80: "HTTP (Unencrypted web traffic)",
    110: "POP3 (Email retrieval)",
    111: "RPC (Remote Procedure Call)",
    119: "NNTP (Network News)",
    123: "NTP (Network Time Protocol)",
    135: "RPC/DCE (Windows RPC)",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session (SMB)",
    143: "IMAP (Email access)",
    161: "SNMP (Network monitoring)",
    162: "SNMP Trap",
    389: "LDAP (Directory Service)",
    443: "HTTPS (Encrypted web traffic)",
    445: "SMB/CIFS (Windows file sharing)",
    465: "SMTPS (Secure SMTP)",
    514: "Syslog",
    587: "SMTP Submission",
    636: "LDAPS (Secure LDAP)",
    873: "RSYNC (File synchronization)",
    993: "IMAPS (Secure IMAP)",
    995: "POP3S (Secure POP3)",
    1080: "SOCKS Proxy",
    1194: "OpenVPN",
    1433: "MS SQL Server",
    1434: "MS SQL Monitor",
    1521: "Oracle Database",
    1723: "PPTP VPN",
    2049: "NFS (Network File System)",
    2082: "cPanel",
    2083: "cPanel SSL",
    2086: "WHM (Web Host Manager)",
    2087: "WHM SSL",
    2095: "Webmail",
    2096: "Webmail SSL",
    3128: "Squid Proxy",
    3306: "MySQL/MariaDB Database",
    3389: "RDP (Windows Remote Desktop)",
    4443: "HTTPS alternative",
    5060: "SIP (VoIP unencrypted)",
    5061: "SIPS (VoIP encrypted)",
    5432: "PostgreSQL Database",
    5900: "VNC (Virtual Network Computing)",
    6379: "Redis (Cache/Database)",
    6660: "IRC", 
    6661: "IRC",
    6662: "IRC",
    6663: "IRC",
    6664: "IRC",
    6665: "IRC",
    6666: "IRC",
    6667: "IRC",
    6668: "IRC",
    6669: "IRC",
    7000: "Cassandra",
    8000: "HTTP alternative",
    8008: "HTTP alternative",
    8080: "HTTP-Alt (Proxy/Web development)",
    8081: "HTTP alternative",
    8086: "InfluxDB",
    8087: "Riak",
    8088: "HTTP alternative",
    8443: "HTTPS-Alt (Alternative SSL)",
    8888: "HTTP alternative",
    9000: "PHP-FPM",
    9001: "Tor",
    9090: "Openfire/Websocket",
    9092: "Kafka",
    9200: "Elasticsearch",
    9300: "Elasticsearch Cluster",
    9418: "Git",
    10000: "Webmin",
    11211: "Memcached",
    11371: "PGP/GPG Keyserver",
    22022: "SSH alternative",
    25565: "Minecraft",
    27017: "MongoDB Database",
    27018: "MongoDB Shard",
    27019: "MongoDB Config Server",
    33060: "MySQL X Protocol",
}

# Cache globale per IP del server
_server_ips_cache = None

# Cache per geolocalizzazione
_geo_cache = {}
_geo_cache_file = '/var/cache/suricata-monitor/geo-cache.pkl'

# File per statistiche storiche
_stats_history_file = '/var/cache/suricata-monitor/stats-history.json'

# Crea directory cache se non esiste
try:
    os.makedirs('/var/cache/suricata-monitor', exist_ok=True)
except:
    # Fallback to /tmp if /var/cache is not writable
    _geo_cache_file = '/tmp/suricata-monitor-geo.pkl'
    _stats_history_file = '/tmp/suricata-monitor-stats.json'

# Lista di IP fidati (amministratori, monitoring, etc.)
# Modifica questa lista con gli IP dei tuoi amministratori
TRUSTED_IPS = [
    "2a02:4460:1:2::15",  # Admin PC
    "185.54.81.5",        # Server
]

def load_geo_cache():
    """Load geolocation cache from disk"""
    global _geo_cache
    try:
        if os.path.exists(_geo_cache_file):
            with open(_geo_cache_file, 'rb') as f:
                _geo_cache = pickle.load(f)
    except:
        _geo_cache = {}
    return _geo_cache

def save_geo_cache():
    """Save geolocation cache to disk"""
    try:
        os.makedirs(os.path.dirname(_geo_cache_file), exist_ok=True)
        with open(_geo_cache_file, 'wb') as f:
            pickle.dump(_geo_cache, f)
    except:
        pass

def get_ip_geolocation(ip, disable_geo=False):
    """Get geolocation for an IP address"""
    # If geo is disabled, return placeholder
    if disable_geo:
        return {"country": "N/A", "city": "N/A", "country_code": "--"}
    
    # Check cache first
    if ip in _geo_cache:
        return _geo_cache[ip]
    
    # Skip private/local IPs
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            _geo_cache[ip] = {"country": "Local", "city": "Private Network", "country_code": "LAN"}
            return _geo_cache[ip]
    except:
        pass
    
    # Try multiple geolocation services
    geo_info = {"country": "Unknown", "city": "Unknown", "country_code": "??"}
    
    # If urllib is not available, return unknown
    if not urllib:
        _geo_cache[ip] = geo_info
        return geo_info
    
    try:
        # Try ip-api.com (free, no key required, but limited to 45 requests per minute)
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,regionName"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=2) as response:
            data = json.loads(response.read().decode())
            if data.get('status') == 'success':
                geo_info = {
                    "country": data.get('country', 'Unknown'),
                    "city": data.get('city', 'Unknown'),
                    "region": data.get('regionName', ''),
                    "country_code": data.get('countryCode', '??')
                }
    except Exception:
        # Fallback to ipinfo.io (limited to 50k requests per month)
        try:
            url = f"https://ipinfo.io/{ip}/json"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=2) as response:
                data = json.loads(response.read().decode())
                geo_info = {
                    "country": data.get('country', 'Unknown'),
                    "city": data.get('city', 'Unknown'),
                    "region": data.get('region', ''),
                    "country_code": data.get('country', '??')
                }
        except Exception:
            pass
    
    _geo_cache[ip] = geo_info
    save_geo_cache()
    return geo_info

def load_stats_history():
    """Load historical statistics"""
    try:
        if os.path.exists(_stats_history_file):
            with open(_stats_history_file, 'r') as f:
                return json.load(f)
    except:
        pass
    return {}

def save_stats_history(stats):
    """Save statistics for historical comparison"""
    try:
        history = load_stats_history()
        today = datetime.now().strftime('%Y-%m-%d')
        
        # Keep only last 30 days
        cutoff_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        history = {k: v for k, v in history.items() if k >= cutoff_date}
        
        # Save today's stats
        history[today] = stats
        
        os.makedirs(os.path.dirname(_stats_history_file), exist_ok=True)
        with open(_stats_history_file, 'w') as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        print(f"{Colors.WARNING}Warning: Could not save statistics history: {e}{Colors.END}")

def compare_with_history(current_stats, history):
    """Compare current statistics with historical data"""
    comparison = {
        'trend': {},
        'anomalies': [],
        'new_attack_types': [],
        'recurring_ips': []
    }
    
    if not history:
        return comparison
    
    # Get yesterday's stats
    yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    yesterday_stats = history.get(yesterday, {})
    
    # Calculate 7-day average
    week_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
    week_stats = [v for k, v in history.items() if k >= week_ago and k < datetime.now().strftime('%Y-%m-%d')]
    
    if week_stats:
        avg_alerts = sum(s.get('total_alerts', 0) for s in week_stats) / len(week_stats)
        avg_ips = sum(s.get('unique_ips', 0) for s in week_stats) / len(week_stats)
        
        # Calculate trends
        if yesterday_stats:
            comparison['trend']['alerts'] = current_stats['total_alerts'] - yesterday_stats.get('total_alerts', 0)
            comparison['trend']['ips'] = current_stats['unique_ips'] - yesterday_stats.get('unique_ips', 0)
        
        # Detect anomalies (>200% of average)
        if current_stats['total_alerts'] > avg_alerts * 2:
            comparison['anomalies'].append(f"Alert volume {current_stats['total_alerts']/avg_alerts:.1f}x higher than 7-day average")
        
        if current_stats['unique_ips'] > avg_ips * 2:
            comparison['anomalies'].append(f"Attacking IPs {current_stats['unique_ips']/avg_ips:.1f}x higher than 7-day average")
    
    # Find new attack types
    if yesterday_stats and 'attack_types' in yesterday_stats:
        yesterday_types = set(yesterday_stats['attack_types'])
        current_types = set(current_stats.get('attack_types', []))
        new_types = current_types - yesterday_types
        comparison['new_attack_types'] = list(new_types)
    
    # Find recurring IPs from past week
    all_ips = set()
    for stats in week_stats:
        if 'top_ips' in stats:
            all_ips.update(stats['top_ips'])
    
    if 'top_ips' in current_stats:
        comparison['recurring_ips'] = [ip for ip in current_stats['top_ips'] if ip in all_ips]
    
    return comparison

def format_number(num):
    """Format numbers with thousand separators"""
    return f"{num:,}"

def compress_ipv6(ip):
    """Compress IPv6 address for display"""
    if ':' in ip:
        try:
            return str(ipaddress.ip_address(ip).compressed)
        except:
            return ip
    return ip

def normalize_ip(ip):
    """Normalize IP address for comparison"""
    try:
        return str(ipaddress.ip_address(ip))
    except:
        return ip

def get_server_ips():
    """Get all server IP addresses (IPv4 and IPv6)"""
    global _server_ips_cache
    
    if _server_ips_cache is not None:
        return _server_ips_cache
    
    server_ips = set()
    
    try:
        # Get all network interfaces
        import netifaces
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            # IPv4
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    if 'addr' in addr:
                        server_ips.add(normalize_ip(addr['addr']))
            # IPv6
            if netifaces.AF_INET6 in addrs:
                for addr in addrs[netifaces.AF_INET6]:
                    if 'addr' in addr:
                        # Remove interface suffix from IPv6 (e.g., %eth0)
                        ipv6 = addr['addr'].split('%')[0]
                        server_ips.add(normalize_ip(ipv6))
    except ImportError:
        # Fallback method if netifaces is not available
        try:
            # Get hostname IPs
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None):
                server_ips.add(normalize_ip(info[4][0]))
            
            # Try to get IPs from ip command
            result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if 'inet' in line:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            ip = parts[1].split('/')[0]
                            server_ips.add(normalize_ip(ip))
        except:
            pass
    
    # Add localhost IPs
    server_ips.add('127.0.0.1')
    server_ips.add('::1')
    
    _server_ips_cache = server_ips
    return server_ips

def is_server_ip(ip):
    """Check if IP belongs to the server"""
    try:
        normalized_ip = normalize_ip(ip)
        server_ips = get_server_ips()
        
        # Direct check
        if normalized_ip in server_ips:
            return True
        
        # Check if it's in the same /64 subnet for IPv6 (common for server IPs)
        if ':' in normalized_ip:
            ip_obj = ipaddress.ip_address(normalized_ip)
            for server_ip in server_ips:
                if ':' in server_ip:
                    try:
                        server_obj = ipaddress.ip_address(server_ip)
                        # Check if in same /64
                        if ip_obj.packed[:8] == server_obj.packed[:8]:
                            return True
                    except:
                        continue
        
        return False
    except:
        return False

def get_signature_description(signature):
    """Get a more descriptive explanation for a signature"""
    # Prima controlla se c'è una descrizione esatta
    if signature in SIGNATURE_DESCRIPTIONS:
        return SIGNATURE_DESCRIPTIONS[signature]
    
    # Poi controlla per pattern parziali
    for pattern, description in SIGNATURE_DESCRIPTIONS.items():
        if pattern in signature:
            return description
    
    # Analizza la signature per categorie comuni
    sig_lower = signature.lower()
    
    if 'scan' in sig_lower or 'scanner' in sig_lower:
        return f"{signature} - Scanning or reconnaissance activity"
    elif 'brute' in sig_lower or 'bruteforce' in sig_lower:
        return f"{signature} - Brute force attack attempt"
    elif 'malware' in sig_lower or 'virus' in sig_lower:
        return f"{signature} - Possible malware activity"
    elif 'trojan' in sig_lower:
        return f"{signature} - Possible trojan detected"
    elif 'exploit' in sig_lower:
        return f"{signature} - Exploit attempt"
    elif 'dos' in sig_lower or 'ddos' in sig_lower:
        return f"{signature} - Possible Denial of Service attack"
    elif 'sql' in sig_lower and 'injection' in sig_lower:
        return f"{signature} - SQL injection attempt"
    elif 'xss' in sig_lower:
        return f"{signature} - Cross-Site Scripting attempt"
    elif 'bot' in sig_lower:
        return f"{signature} - Suspicious bot activity"
    else:
        return signature

def get_block_reason_description(reason):
    """Get a more descriptive explanation for block reasons"""
    # Prima controlla descrizioni esatte
    if reason in BLOCK_REASON_DESCRIPTIONS:
        return BLOCK_REASON_DESCRIPTIONS[reason]
    
    # Controlla se è una regola ModSecurity con ID
    modsec_match = re.search(r'ModSecurity rule (\d+)', reason)
    if modsec_match:
        rule_id = modsec_match.group(1)
        if rule_id in MODSECURITY_RULE_DESCRIPTIONS:
            base_desc = MODSECURITY_RULE_DESCRIPTIONS[rule_id]
            # Preserva informazioni sulla durata se presenti
            if '(' in reason and ')' in reason:
                duration_part = reason[reason.rfind('('):reason.rfind(')')+1]
                return f"ModSecurity: {base_desc} {duration_part}"
            return f"ModSecurity: {base_desc}"
    
    # Poi controlla per pattern
    for pattern, description in BLOCK_REASON_DESCRIPTIONS.items():
        if pattern in reason:
            return description
    
    # Se contiene informazioni sulla durata, preservale
    duration_match = re.search(r'\((\d+)s\)', reason)
    if duration_match:
        duration = int(duration_match.group(1))
        if duration == 3600:
            duration_str = "1 hour"
        elif duration == 86400:
            duration_str = "24 hours"
        elif duration < 3600:
            duration_str = f"{duration} seconds"
        elif duration < 86400:
            duration_str = f"{duration//3600} hours"
        else:
            duration_str = f"{duration//86400} days"
        
        base_reason = reason.replace(duration_match.group(0), '').strip()
        return f"{get_block_reason_description(base_reason)} - Block duration: {duration_str}"
    
    return reason

def check_ip_in_whitelist(ip, whitelist_cache={}):
    """Check if IP is whitelisted (with caching)"""
    if ip in whitelist_cache:
        return whitelist_cache[ip]
    
    try:
        if not os.path.exists('/etc/csf/csf.allow'):
            return False
            
        with open('/etc/csf/csf.allow', 'r') as f:
            whitelist_content = f.read()
            
        for line in whitelist_content.splitlines():
            # Skip comments and empty lines
            if not line.strip() or line.strip().startswith('#'):
                continue
                
            # Extract IP/subnet from line
            entry = line.split('#')[0].strip()
            if not entry:
                continue
            
            # Normalize the entry IP
            try:
                if '/' in entry:
                    # It's a subnet
                    network = ipaddress.ip_network(entry, strict=False)
                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj in network:
                        whitelist_cache[ip] = True
                        return True
                else:
                    # Direct IP comparison
                    if normalize_ip(entry) == normalize_ip(ip):
                        whitelist_cache[ip] = True
                        return True
            except:
                continue
                
    except Exception:
        pass
    
    whitelist_cache[ip] = False
    return False

def check_ip_status(ip):
    """Check if IP is whitelisted, blocked, server IP, trusted, or active"""
    # First check if it's server IP
    if is_server_ip(ip):
        return "SERVER"
    
    # Check if it's a trusted IP
    if ip in TRUSTED_IPS:
        return "TRUSTED"
    
    # Then check whitelist
    if check_ip_in_whitelist(ip):
        return "WHITELISTED"
    
    # Then check if blocked in CSF
    try:
        result = subprocess.run(['sudo', 'csf', '-g', ip], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and ("DROP" in result.stdout or "csf.deny:" in result.stdout):
            return "BLOCKED"
        return "ACTIVE"
    except:
        return "UNKNOWN"

def get_blocked_ips_from_csf_deny(hours=24):
    """Get blocked IPs directly from csf.deny with timestamps"""
    blocked_ips = []
    
    try:
        # Try to get recent blocks from csf.deny
        denied_ips = set()
        
        # First, get list of denied IPs from csf.deny
        if os.path.exists('/etc/csf/csf.deny'):
            with open('/etc/csf/csf.deny', 'r') as f:
                for line in f:
                    if not line.strip() or line.strip().startswith('#'):
                        continue
                    # Extract IP
                    parts = line.split('#')
                    if parts:
                        ip = parts[0].strip()
                        if ip:
                            try:
                                ip = normalize_ip(ip)
                                # Skip server IPs, whitelisted IPs, and trusted IPs
                                if is_server_ip(ip) or check_ip_in_whitelist(ip) or ip in TRUSTED_IPS:
                                    continue
                                    
                                # Extract comment/reason if available
                                reason_text = parts[1].strip() if len(parts) > 1 else 'In permanent block list'
                                
                                # Check if it's a ModSecurity rule reference in the comment
                                modsec_id_match = re.search(r'id:(\d+)', reason_text)
                                if modsec_id_match:
                                    rule_id = modsec_id_match.group(1)
                                    if rule_id in MODSECURITY_RULE_DESCRIPTIONS:
                                        reason = f"ModSecurity: {MODSECURITY_RULE_DESCRIPTIONS[rule_id]}"
                                    else:
                                        reason = get_block_reason_description(reason_text)
                                else:
                                    reason = get_block_reason_description(reason_text)
                                
                                blocked_ips.append({
                                    'ip': ip,
                                    'time': datetime.now(),  # We don't have exact time from csf.deny
                                    'reason': reason
                                })
                            except:
                                continue
    except Exception:
        pass
    
    return blocked_ips

def check_system_logs_for_blocks(hours=24):
    """Check system logs for CSF blocks"""
    blocked_ips = []
    time_threshold = datetime.now() - timedelta(hours=hours)
    
    # Check multiple possible log locations
    log_files = [
        '/var/log/lfd.log',
        '/var/log/messages',
        '/var/log/syslog'
    ]
    
    for log_file in log_files:
        if os.path.exists(log_file):
            try:
                # Use subprocess to handle large files and grep for efficiency
                result = subprocess.run(
                    ['grep', '-E', '(Blocked in csf|blocked|BLOCKED|deny)', log_file],
                    capture_output=True, text=True, timeout=10
                )
                
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        # Skip removal lines
                        if 'block removed' in line.lower():
                            continue
                            
                        # Parse LFD format: "triggered by IP_ADDRESS"
                        triggered_match = re.search(r'triggered by\s+(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+:[0-9a-fA-F:]+)', line)
                        if triggered_match:
                            try:
                                ip = normalize_ip(triggered_match.group(1))
                                
                                # Skip server IPs, whitelisted IPs, and trusted IPs
                                if is_server_ip(ip) or check_ip_in_whitelist(ip) or ip in TRUSTED_IPS:
                                    continue
                                
                                # Parse date - try multiple formats
                                # Format 1: "Jun 17 09:43:51"
                                date_match = re.match(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
                                # Format 2: "2025-06-17T10:32:40"
                                if not date_match:
                                    date_match = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
                                    if date_match:
                                        log_time = datetime.strptime(date_match.group(1).split('.')[0], '%Y-%m-%dT%H:%M:%S')
                                    else:
                                        continue
                                else:
                                    # Add current year for syslog format
                                    date_str = f"{datetime.now().year} {date_match.group(1)}"
                                    log_time = datetime.strptime(date_str, '%Y %b %d %H:%M:%S')
                                    
                                    # Handle year boundary
                                    if log_time > datetime.now():
                                        log_time = log_time.replace(year=log_time.year - 1)
                                
                                if log_time >= time_threshold:
                                    # Extract reason
                                    reason = "Security block"
                                    if 'mod_security' in line:
                                        id_match = re.search(r'\(id:(\d+)\)', line)
                                        if id_match:
                                            rule_id = id_match.group(1)
                                            # Check if we have a specific description for this rule
                                            if rule_id in MODSECURITY_RULE_DESCRIPTIONS:
                                                reason = f"ModSecurity: {MODSECURITY_RULE_DESCRIPTIONS[rule_id]}"
                                            elif rule_id == "92010":
                                                reason = "WordPress login attempt blocked [1 hour block]"
                                            else:
                                                reason = f"ModSecurity rule {rule_id} triggered - Suspicious web activity"
                                        else:
                                            reason = "ModSecurity - Abnormal web activity detected"
                                    elif 'SSH' in line or 'sshd' in line:
                                        reason = "SSH brute force attack - Multiple login attempts"
                                    elif 'port scan' in line.lower():
                                        reason = "Port scan - Searching for vulnerable services"
                                    
                                    # Extract block duration if available
                                    duration_match = re.search(r'for (\d+) secs', line)
                                    if duration_match:
                                        duration = int(duration_match.group(1))
                                        if duration == 3600:
                                            reason += " (1 hour block)"
                                        elif duration == 86400:
                                            reason += " (24 hour block)"
                                        else:
                                            reason += f" ({duration}s block)"
                                    
                                    blocked_ips.append({
                                        'ip': ip,
                                        'time': log_time,
                                        'reason': reason
                                    })
                            except Exception as e:
                                continue
            except:
                continue
                
    return blocked_ips

def get_blocked_ips_from_log(log_file='/var/log/suricata-csf-block.log', hours=24):
    """Extract blocked IPs from CSF block log"""
    blocked_ips = []
    time_threshold = datetime.now() - timedelta(hours=hours)
    
    # Try primary log file first
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    # Format 1: [2025-06-17 17:24:02] BLOCKED: 2.40.201.116 - LOCAL Port scan detected
                    if 'BLOCKED:' in line:
                        try:
                            # Extract date from brackets
                            date_match = re.search(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]', line)
                            if date_match:
                                log_time = datetime.strptime(date_match.group(1), '%Y-%m-%d %H:%M:%S')
                            else:
                                continue
                                
                            if log_time < time_threshold:
                                continue
                            
                            # Extract IP after "BLOCKED: "
                            ip_match = re.search(r'BLOCKED:\s*(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+:[0-9a-fA-F:]+)', line)
                            if ip_match:
                                ip = normalize_ip(ip_match.group(1))
                                
                                # Skip server IPs, whitelisted IPs, and trusted IPs
                                if is_server_ip(ip) or check_ip_in_whitelist(ip) or ip in TRUSTED_IPS:
                                    continue
                                
                                # Extract reason after dash
                                reason_match = re.search(r'BLOCKED:\s*[^\s]+\s*-\s*(.+?)(?:\s*\(|$)', line)
                                if reason_match:
                                    reason = get_signature_description(reason_match.group(1).strip())
                                    # Add severity if present
                                    sev_match = re.search(r'\(Severity:\s*(\d+)\)', line)
                                    if sev_match:
                                        sev_level = int(sev_match.group(1))
                                        if sev_level == 1:
                                            reason += " (Severity: HIGH)"
                                        elif sev_level == 2:
                                            reason += " (Severity: MEDIUM)"
                                        else:
                                            reason += " (Severity: LOW)"
                                else:
                                    reason = "Automatic Suricata block - Suspicious activity"
                                
                                blocked_ips.append({
                                    'ip': ip,
                                    'time': log_time,
                                    'reason': reason
                                })
                        except Exception as e:
                            continue
                            
        except Exception as e:
            pass
    
    # If no blocks found in primary log, check system logs
    system_blocks = check_system_logs_for_blocks(hours)
    blocked_ips.extend(system_blocks)
    
    # If still no blocks found, check csf.deny (but without timestamps)
    if not blocked_ips and hours >= 24:  # Only check deny list for 24h+ queries
        denied_blocks = get_blocked_ips_from_csf_deny(hours)
        blocked_ips.extend(denied_blocks)
    
    # Remove duplicates based on IP, keeping the most recent entry
    ip_dict = {}
    for block in blocked_ips:
        ip = block['ip']
        if ip not in ip_dict or block['time'] > ip_dict[ip]['time']:
            ip_dict[ip] = block
    
    return list(ip_dict.values())

def parse_suricata_log(log_file="/var/log/suricata/eve.json", hours=24):
    """Read and parse Suricata log efficiently"""
    alerts = []
    stats = {
        'total_events': 0,
        'total_alerts': 0,
        'total_flows': 0
    }
    
    time_threshold = datetime.now() - timedelta(hours=hours)
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    stats['total_events'] += 1
                    
                    # Quick event type check
                    event_type = event.get('event_type')
                    if event_type != 'alert':
                        if event_type == 'flow':
                            stats['total_flows'] += 1
                        continue
                    
                    # Parse timestamp efficiently
                    timestamp_str = event['timestamp'].split('+')[0]
                    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%f')
                    if timestamp < time_threshold:
                        continue
                    
                    stats['total_alerts'] += 1
                    alert_data = event.get('alert', {})
                    
                    alerts.append({
                        'timestamp': timestamp,
                        'src_ip': normalize_ip(event.get('src_ip', 'unknown')),
                        'dest_ip': event.get('dest_ip', 'unknown'),
                        'dest_port': event.get('dest_port', 0),
                        'proto': event.get('proto', 'unknown'),
                        'severity': alert_data.get('severity', 3),
                        'signature': alert_data.get('signature', 'unknown'),
                        'category': alert_data.get('category', 'unknown'),
                        'signature_id': alert_data.get('signature_id', 0)
                    })
                    
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue
                    
    except FileNotFoundError:
        print(f"{Colors.FAIL}Error: File {log_file} not found{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.FAIL}Error reading log file: {e}{Colors.END}")
        sys.exit(1)
    
    return alerts, stats

def analyze_alerts(alerts):
    """Analyze alerts and generate statistics"""
    analysis = {
        'src_ips': Counter(),
        'signatures': Counter(),
        'categories': Counter(),
        'severities': Counter(),
        'dest_ports': Counter(),
        'protocols': Counter(),
        'timeline': defaultdict(int),
        'severity_by_ip': defaultdict(lambda: defaultdict(int))
    }
    
    for alert in alerts:
        analysis['src_ips'][alert['src_ip']] += 1
        analysis['signatures'][alert['signature']] += 1
        analysis['categories'][alert['category']] += 1
        analysis['severities'][alert['severity']] += 1
        analysis['dest_ports'][alert['dest_port']] += 1
        analysis['protocols'][alert['proto']] += 1
        
        # Timeline by hour
        hour = alert['timestamp'].strftime('%H:00')
        analysis['timeline'][hour] += 1
        
        # Severity by IP
        analysis['severity_by_ip'][alert['src_ip']][alert['severity']] += 1
    
    return analysis

def print_report(analysis, stats, hours, alerts, args=None):
    """Print formatted report"""
    
    # Header
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*80}")
    print(f"                  SURICATA IDS MONITORING REPORT")
    print(f"              Last {hours} hours - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*80}{Colors.END}\n")
    
    # General statistics
    print(f"{Colors.CYAN}[GENERAL STATISTICS]{Colors.END}")
    print(f"|- Total alerts: {Colors.BOLD}{format_number(len(alerts))}{Colors.END}")
    print(f"|- Unique IPs detected: {Colors.BOLD}{len(analysis['src_ips'])}{Colors.END}")
    print(f"|- Attack types: {Colors.BOLD}{len(analysis['signatures'])}{Colors.END}")
    print(f"`- Average alerts/hour: {Colors.BOLD}{len(alerts)/hours:.1f}{Colors.END}\n")
    
    # Severity Distribution
    print(f"{Colors.WARNING}WARNING: SEVERITY DISTRIBUTION{Colors.END}")
    severity_names = {
        1: "HIGH     [!]", 
        2: "MEDIUM   [*]", 
        3: "LOW      [-]"
    }
    total_alerts = sum(analysis['severities'].values())
    if total_alerts > 0:
        for sev in sorted(analysis['severities'].keys()):
            count = analysis['severities'][sev]
            percent = (count / total_alerts) * 100
            bar_length = int(percent / 2)
            bar = '#' * bar_length
            print(f"|- {severity_names.get(sev, f'Level {sev}'):14} [{count:5}] {bar:<48} {percent:5.1f}%")
    print()
    
    # Top 10 Attacking IPs
    print(f"{Colors.FAIL}[TOP 10 ATTACKING IPs]{Colors.END}")
    
    # Determine if geo is disabled
    disable_geo = args and hasattr(args, 'no_geo') and args.no_geo
    
    # Print header with or without Country column
    if not disable_geo:
        print(f"{'#':<3} {'IP Address':<40} {'Country':<12} {'Alerts':<10} {'Status':<12} {'Severity'}")
        print("-" * 105)
    else:
        print(f"{'#':<3} {'IP Address':<40} {'Alerts':<10} {'Status':<12} {'Severity details'}")
        print("-" * 90)
    
    # Load geo cache at start if not disabled
    if not disable_geo:
        load_geo_cache()
    
    for i, (ip, count) in enumerate(analysis['src_ips'].most_common(10), 1):
        status = check_ip_status(ip)
        
        # Get geolocation
        geo = get_ip_geolocation(ip, disable_geo)
        country = f"{geo['country_code']}/{geo['city'][:8]}" if geo['city'] != 'Unknown' and geo['city'] != 'N/A' else geo['country_code']
        
        # Color and symbol based on status
        if status == "SERVER":
            status_color = Colors.CYAN
            status_icon = "[S]"
            status_text = "SERVER IP"
        elif status == "TRUSTED":
            status_color = Colors.BLUE
            status_icon = "[T]"
            status_text = "TRUSTED"
        elif status == "WHITELISTED":
            status_color = Colors.GREEN
            status_icon = "[OK]"
            status_text = "WHITELISTED"
        elif status == "BLOCKED":
            status_color = Colors.FAIL
            status_icon = "[X]"
            status_text = "BLOCKED"
        elif status == "ACTIVE":
            status_color = Colors.WARNING
            status_icon = "[!]"
            status_text = "ACTIVE"
        else:
            status_color = Colors.END
            status_icon = "[?]"
            status_text = "UNKNOWN"
        
        # Compress IPv6 for display
        display_ip = compress_ipv6(ip)
        
        # Severity breakdown for this IP
        sev_breakdown = []
        for sev in sorted(analysis['severity_by_ip'][ip].keys()):
            sev_count = analysis['severity_by_ip'][ip][sev]
            sev_name = {1: "High", 2: "Med", 3: "Low"}.get(sev, f"L{sev}")
            sev_breakdown.append(f"{sev_name}:{sev_count}")
        
        if not disable_geo:
            print(f"{i:<3} {display_ip:<40} {country:<12} {count:<10} {status_color}{status_icon} {status_text:<7}{Colors.END} {', '.join(sev_breakdown)}")
        else:
            print(f"{i:<3} {display_ip:<40} {count:<10} {status_color}{status_icon} {status_text:<7}{Colors.END} {', '.join(sev_breakdown)}")
    
    # Save geo cache after use if not disabled
    if not disable_geo:
        save_geo_cache()
    print()
    
    # Top Attack Types
    print(f"{Colors.BLUE}[TOP 10 ATTACK TYPES]{Colors.END}")
    print(f"{'Detections':<12} {'Description'}")
    print("-" * 100)
    
    for sig, count in analysis['signatures'].most_common(10):
        # Get enhanced description
        sig_display = get_signature_description(sig)
        # Truncate if too long
        if len(sig_display) > 85:
            sig_display = sig_display[:82] + "..."
        print(f"{count:<12} {sig_display}")
    print()
    
    # Top Target Ports
    print(f"{Colors.GREEN}[MOST ATTACKED PORTS]{Colors.END}")
    print(f"{'Port':<8} {'Attacks':<10} {'Service/Description'}")
    print("-" * 60)
    
    for port, count in analysis['dest_ports'].most_common(10):
        service = PORT_SERVICES.get(port, f"Unknown service (port {port})")
        print(f"{port:<8} {count:<10} {service}")
    print()
    
    # Timeline
    if len(analysis['timeline']) > 0:
        print(f"{Colors.CYAN}[ALERT TIMELINE (by hour)]{Colors.END}")
        max_count = max(analysis['timeline'].values()) if analysis['timeline'] else 1
        
        # Get current hour and previous 23 hours
        current_hour = datetime.now().hour
        hours_list = []
        for i in range(23, -1, -1):
            hour = (current_hour - i) % 24
            hours_list.append(f"{hour:02d}:00")
        
        for hour in hours_list:
            count = analysis['timeline'].get(hour, 0)
            bar_length = int((count / max_count) * 40) if max_count > 0 else 0
            bar = '#' * bar_length
            # Add indicator for hours with many alerts
            indicator = " <!>" if count > (len(alerts) / 24 * 2) else ""
            print(f"{hour} [{count:4}] {bar}{indicator}")
    print()
    
    # Get blocked IPs for use in multiple sections
    blocked_ips = get_blocked_ips_from_log(hours=hours)
    
    # CSF Integration Status with blocked IPs
    print(f"{Colors.BOLD}[CSF INTEGRATION STATUS (ConfigServer Security & Firewall)]{Colors.END}")
    
    # Count blocked today from the parsed results
    today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    blocked_today = len([b for b in blocked_ips if b['time'] >= today_start])
    
    # Calculate effectiveness
    total_malicious_attempts = len([a for a in alerts if check_ip_status(a['src_ip']) not in ['SERVER', 'TRUSTED', 'WHITELISTED']])
    blocked_count = len(blocked_ips)
    
    # Show both formats for compatibility
    print(f"|- IPs blocked today: {Colors.BOLD}{blocked_today}{Colors.END}")
    print(f"|- IPs blocked in last {hours} hours: {Colors.BOLD}{len(blocked_ips)}{Colors.END}")
    
    # Add effectiveness metric
    if total_malicious_attempts > 0:
        effectiveness = (blocked_count / (blocked_count + total_malicious_attempts)) * 100
        print(f"|- Auto-block effectiveness: {Colors.BOLD}{blocked_count}/{blocked_count + total_malicious_attempts} potential threats blocked ({effectiveness:.1f}%){Colors.END}")
    
    # Geographic distribution of blocked IPs
    if blocked_ips and not disable_geo:
        blocked_countries = Counter()
        for blocked in blocked_ips:
            geo = get_ip_geolocation(blocked['ip'], disable_geo)
            blocked_countries[geo['country_code']] += 1
        
        top_countries = blocked_countries.most_common(5)
        if top_countries:
            print(f"|- Top blocking countries: {', '.join([f'{cc} ({cnt})' for cc, cnt in top_countries])}")
    
    if blocked_ips:
        print(f"\n{Colors.FAIL}[RECENTLY BLOCKED IPs]{Colors.END}")
        if not disable_geo:
            print(f"{'Time':<20} {'IP Address':<40} {'Country':<10} {'Block reason'}")
            print("-" * 140)
        else:
            print(f"{'Time':<20} {'IP Address':<40} {'Block reason'}")
            print("-" * 130)
        
        # Sort by time (most recent first)
        for blocked in sorted(blocked_ips, key=lambda x: x['time'], reverse=True)[:15]:
            time_str = blocked['time'].strftime('%Y-%m-%d %H:%M')
            ip_display = compress_ipv6(blocked['ip'])
            reason = blocked['reason']
            
            if not disable_geo:
                geo = get_ip_geolocation(blocked['ip'], disable_geo)
                country = geo['country_code']
                # Truncate reason if too long, but keep it readable
                if len(reason) > 58:
                    reason = reason[:55] + "..."
                print(f"{time_str:<20} {ip_display:<40} {country:<10} {reason}")
            else:
                # Truncate reason if too long, but keep it readable
                if len(reason) > 68:
                    reason = reason[:65] + "..."
                print(f"{time_str:<20} {ip_display:<40} {reason}")
    else:
        # Show current deny list if no recent blocks in log
        print(f"\n{Colors.WARNING}Note: No recent blocks found in logs.{Colors.END}")
        
        # Try to show some info from csf.deny
        if os.path.exists('/etc/csf/csf.deny'):
            try:
                denied_count = 0
                recent_denies = []
                with open('/etc/csf/csf.deny', 'r') as f:
                    for line in f:
                        if line.strip() and not line.strip().startswith('#'):
                            denied_count += 1
                            # Try to extract IP and comment
                            parts = line.split('#', 1)
                            if parts:
                                ip = parts[0].strip()
                                comment = parts[1].strip() if len(parts) > 1 else ""
                                if ip and not is_server_ip(ip) and not check_ip_in_whitelist(ip) and ip not in TRUSTED_IPS:
                                    recent_denies.append((ip, comment))
                
                if denied_count > 0:
                    print(f"Total IPs in CSF block list: {Colors.BOLD}{denied_count}{Colors.END}")
                    if recent_denies and args and args.show_all_blocked:
                        print(f"\n{Colors.FAIL}[IPs IN CSF DENY LIST]{Colors.END}")
                        print(f"{'IP Address':<40} {'Comment'}")
                        print("-" * 80)
                        for ip, comment in recent_denies[:20]:
                            try:
                                ip_display = compress_ipv6(normalize_ip(ip))
                            except:
                                ip_display = ip
                            print(f"{ip_display:<40} {comment[:39]}")
                    else:
                        print("Run with --show-all-blocked to see all blocked IPs")
            except:
                pass
    
    # Check if timer is active
    try:
        result = subprocess.run(['systemctl', 'is-active', 'cron'],
                              capture_output=True, text=True)
        timer_status = "Active [OK]" if result.stdout.strip() == "active" else "Inactive [X]"
        print(f"\n`- Auto-block cron status: {timer_status}")
    except:
        pass
    
    # Check for whitelisted IPs with high alert counts
    print(f"\n{Colors.WARNING}[WHITELISTED IPs WITH ALERTS]{Colors.END}")
    whitelisted_with_alerts = []
    for ip, count in analysis['src_ips'].most_common():
        if check_ip_in_whitelist(ip) and count > 5 and not is_server_ip(ip) and ip not in TRUSTED_IPS:
            whitelisted_with_alerts.append((ip, count))
    
    if whitelisted_with_alerts:
        print(f"{'IP Address':<40} {'Alerts':<10} {'Notes'}")
        print("-" * 70)
        for ip, count in whitelisted_with_alerts[:5]:
            note = "<!> Verify if whitelisting is still valid" if count > 50 else ""
            print(f"{compress_ipv6(ip):<40} {count:<10} {note}")
    else:
        print("[OK] No whitelisted IPs with significant alerts")
    
    # Check for trusted IPs with alerts
    trusted_with_alerts = []
    for ip, count in analysis['src_ips'].most_common():
        if ip in TRUSTED_IPS:
            trusted_with_alerts.append((ip, count))
    
    if trusted_with_alerts:
        print(f"\n{Colors.BLUE}[TRUSTED IPs WITH ALERTS]{Colors.END}")
        print(f"{'IP Address':<40} {'Alerts':<10} {'Notes'}")
        print("-" * 70)
        for ip, count in trusted_with_alerts[:5]:
            # Find dominant signature for this IP
            ip_signatures = Counter()
            for alert in alerts:
                if alert['src_ip'] == ip:
                    ip_signatures[alert['signature']] += 1
            if ip_signatures:
                top_sig = ip_signatures.most_common(1)[0][0]
                note = get_signature_description(top_sig).split(' - ')[1] if ' - ' in get_signature_description(top_sig) else ""
                if len(note) > 40:
                    note = note[:37] + "..."
            else:
                note = ""
            print(f"{compress_ipv6(ip):<40} {count:<10} {note}")
    
    # Check for server IPs with alerts
    server_ips_with_alerts = []
    for ip, count in analysis['src_ips'].most_common():
        if is_server_ip(ip):
            server_ips_with_alerts.append((ip, count))
    
    if server_ips_with_alerts:
        print(f"\n{Colors.CYAN}[SERVER IPs WITH ALERTS]{Colors.END}")
        print(f"{'IP Address':<40} {'Alerts':<10} {'Notes'}")
        print("-" * 70)
        for ip, count in server_ips_with_alerts[:5]:
            note = "Internal traffic - Usually normal" if count < 10 else "High internal activity"
            print(f"{compress_ipv6(ip):<40} {count:<10} {note}")
    
    # Footer with recommendations
    print(f"\n{Colors.CYAN}[RECOMMENDATIONS]{Colors.END}")
    
    # Count trusted IPs for recommendations
    trusted_with_alerts = [(ip, count) for ip, count in analysis['src_ips'].items() if ip in TRUSTED_IPS]
    
    high_severity_count = analysis['severities'].get(1, 0)
    if high_severity_count > 10:
        print(f"[!] Detected {high_severity_count} high severity alerts - Immediate verification required")
    
    active_attackers = sum(1 for ip in analysis['src_ips'] 
                          if check_ip_status(ip) == "ACTIVE" 
                          and not is_server_ip(ip) 
                          and not check_ip_in_whitelist(ip)
                          and ip not in TRUSTED_IPS)
    if active_attackers > 0:
        print(f"[!] {active_attackers} attacking IPs still active - Consider manual blocking")
    
    if len(whitelisted_with_alerts) > 0:
        print(f"[*] {len(whitelisted_with_alerts)} whitelisted IPs with suspicious activity - Review whitelist")
    
    if len(trusted_with_alerts) > 0:
        total_trusted_alerts = sum(count for ip, count in trusted_with_alerts)
        if total_trusted_alerts > 10:
            print(f"[*] {len(trusted_with_alerts)} trusted IPs with {total_trusted_alerts} alerts - Review Suricata rules or add to HOME_NET")
    
    # More detailed analysis for server IPs
    if len(server_ips_with_alerts) > 0:
        total_server_alerts = sum(count for ip, count in server_ips_with_alerts)
        if total_server_alerts < 10:
            print(f"[i] {len(server_ips_with_alerts)} server IPs detected in alerts - Normal internal traffic")
        elif total_server_alerts < 50:
            print(f"[*] {len(server_ips_with_alerts)} server IPs with {total_server_alerts} alerts - Monitor for anomalies")
        else:
            print(f"[!] {len(server_ips_with_alerts)} server IPs with {total_server_alerts} alerts - Review Suricata rules for false positives")
            # Check dominant signature for server IPs
            server_signatures = Counter()
            for alert in alerts:
                if is_server_ip(alert['src_ip']):
                    server_signatures[alert['signature']] += 1
            if server_signatures:
                top_sig, count = server_signatures.most_common(1)[0]
                if count > total_server_alerts * 0.5:  # If one signature is >50% of server alerts
                    print(f"    +- Dominant: '{get_signature_description(top_sig)}' ({count} alerts)")
                    print(f"    +- Consider adding exception in Suricata for local traffic")
    
    # Historical comparison and anomaly detection
    print(f"\n{Colors.HEADER}[HISTORICAL ANALYSIS & ANOMALY DETECTION]{Colors.END}")
    
    # Prepare stats for saving
    current_stats = {
        'total_alerts': len(alerts),
        'unique_ips': len(analysis['src_ips']),
        'attack_types': list(analysis['signatures'].keys()),
        'top_ips': [ip for ip, _ in analysis['src_ips'].most_common(20)],
        'high_severity': analysis['severities'].get(1, 0),
        'blocked_count': len(blocked_ips)
    }
    
    # Load history and compare
    history = load_stats_history()
    comparison = compare_with_history(current_stats, history)
    
    # Show trends
    if comparison['trend']:
        print(f"|- 24h trend: ", end="")
        trend_parts = []
        if 'alerts' in comparison['trend']:
            diff = comparison['trend']['alerts']
            symbol = "?" if diff > 0 else "?" if diff < 0 else "?"
            color = Colors.FAIL if diff > 10 else Colors.WARNING if diff > 0 else Colors.GREEN
            trend_parts.append(f"{color}Alerts {symbol} {abs(diff)}{Colors.END}")
        if 'ips' in comparison['trend']:
            diff = comparison['trend']['ips']
            symbol = "?" if diff > 0 else "?" if diff < 0 else "?"
            color = Colors.FAIL if diff > 5 else Colors.WARNING if diff > 0 else Colors.GREEN
            trend_parts.append(f"{color}IPs {symbol} {abs(diff)}{Colors.END}")
        print(" | ".join(trend_parts))
    
    # Show anomalies
    if comparison['anomalies']:
        for anomaly in comparison['anomalies']:
            print(f"|- {Colors.FAIL}? ANOMALY: {anomaly}{Colors.END}")
    else:
            print(f"|- {Colors.GREEN}[OK] No anomalies detected{Colors.END}")
    
    # New attack types
    if comparison['new_attack_types']:
        print(f"|- {Colors.WARNING}New attack types: {', '.join(comparison['new_attack_types'][:3])}{Colors.END}")
    
    # Recurring attackers
    if comparison['recurring_ips']:
        recurring_active = [ip for ip in comparison['recurring_ips'] if check_ip_status(ip) == "ACTIVE"]
        if recurring_active:
            print(f"|- {Colors.FAIL}Recurring attackers (seen before): {len(recurring_active)} IPs{Colors.END}")
    
    # Geographic insights
    if analysis['src_ips'] and not disable_geo:
        countries = Counter()
        for ip in analysis['src_ips']:
            if not is_server_ip(ip) and ip not in TRUSTED_IPS:
                geo = get_ip_geolocation(ip, disable_geo)
                if geo['country_code'] != 'LAN' and geo['country_code'] != '--':
                    countries[geo['country']] += 1
        
        if countries:
            top_countries = countries.most_common(3)
            print(f"|- Attack origins: {', '.join([f'{c} ({n})' for c, n in top_countries])}")
    
    # Save current stats for future comparison
    save_stats_history(current_stats)
    
    print(f"\n{Colors.GREEN}Report generated successfully [OK]{Colors.END}")

def main():
    parser = argparse.ArgumentParser(
        description='Suricata IDS Monitoring Tool - Advanced security log analysis',
        epilog='Example: %(prog)s -H 12 --show-all-blocked'
    )
    parser.add_argument('-H', '--hours', type=int, default=24,
                      help='Number of hours to analyze (default: 24)')
    parser.add_argument('-f', '--file', default='/var/log/suricata/eve.json',
                      help='Path to Suricata eve.json log file')
    parser.add_argument('--no-color', action='store_true',
                      help='Disable colored output')
    parser.add_argument('--show-all-blocked', action='store_true',
                      help='Show all blocked IPs (not just recent)')
    parser.add_argument('--debug', action='store_true',
                      help='Show debug information about log files')
    parser.add_argument('--no-geo', action='store_true',
                      help='Disable geolocation lookups')
    parser.add_argument('--clear-cache', action='store_true',
                      help='Clear geolocation and statistics cache')
    
    args = parser.parse_args()
    
    if args.no_color:
        for attr in dir(Colors):
            if not attr.startswith('__'):
                setattr(Colors, attr, '')
    
    # Clear cache if requested
    if args.clear_cache:
        try:
            if os.path.exists(_geo_cache_file):
                os.remove(_geo_cache_file)
                print(f"{Colors.GREEN}[OK] Geolocation cache cleared{Colors.END}")
            if os.path.exists(_stats_history_file):
                os.remove(_stats_history_file)
                print(f"{Colors.GREEN}[OK] Statistics history cleared{Colors.END}")
        except Exception as e:
            print(f"{Colors.FAIL}[ERROR] Could not clear cache: {e}{Colors.END}")
        return
    
    # Debug mode
    if args.debug:
        print(f"{Colors.CYAN}=== DEBUG MODE ==={Colors.END}")
        log_files = [
            '/var/log/suricata-csf-block.log',
            '/var/log/lfd.log', 
            '/var/log/messages',
            '/var/log/syslog',
            '/etc/csf/csf.deny',
            '/etc/csf/csf.allow'
        ]
        
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    size = os.path.getsize(log_file)
                    mtime = datetime.fromtimestamp(os.path.getmtime(log_file))
                    print(f"[OK] {log_file} - {format_number(size)} bytes - Modified: {mtime.strftime('%Y-%m-%d %H:%M')}")
                    
                    # Show sample of block-related entries
                    if 'csf' in log_file or 'suricata' in log_file:
                        with open(log_file, 'r') as f:
                            lines = f.readlines()
                            block_lines = [l for l in lines[-100:] if 'block' in l.lower() or 'deny' in l.lower()]
                            if block_lines:
                                print(f"  Found: {len(block_lines)} block-related entries in last 100 lines")
                except Exception as e:
                    print(f"[X] {log_file} - Error: {e}")
            else:
                print(f"[X] {log_file} - Not found")
        
        # Show server IPs
        print(f"\n{Colors.CYAN}Server IP addresses:{Colors.END}")
        for ip in sorted(get_server_ips()):
            print(f"  - {ip}")
        
        print(f"{Colors.CYAN}=================={Colors.END}\n")
    
    # Parse logs
    print(f"{Colors.BLUE}[*] Analyzing Suricata logs...{Colors.END}")
    alerts, stats = parse_suricata_log(args.file, args.hours)
    
    if not alerts:
        print(f"{Colors.WARNING}[!] No alerts found in the last {args.hours} hours{Colors.END}")
        # Still show blocked IPs even if no alerts
        blocked_ips = get_blocked_ips_from_log(hours=args.hours)
        if blocked_ips:
            print(f"\n{Colors.FAIL}IPs blocked in last {args.hours} hours: {len(blocked_ips)}{Colors.END}")
            for blocked in sorted(blocked_ips, key=lambda x: x['time'], reverse=True)[:10]:
                time_str = blocked['time'].strftime('%Y-%m-%d %H:%M')
                ip_display = compress_ipv6(blocked['ip'])
                print(f"  {time_str} - {ip_display} ({blocked['reason']})")
        sys.exit(0)
    
    # Analyze
    analysis = analyze_alerts(alerts)
    
    # Print report
    print_report(analysis, stats, args.hours, alerts, args)

if __name__ == "__main__":
    main()
