#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Suricata Monitor - Analyze and display statistics from Suricata logs
Enhanced version with detailed CSF blocking information
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
    """Check if IP is whitelisted, blocked, or active"""
    # First check whitelist
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
                                # Extract comment/reason if available
                                reason = parts[1].strip() if len(parts) > 1 else 'In CSF deny list'
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
                                            reason = f"mod_security (id:{id_match.group(1)})"
                                        else:
                                            reason = "mod_security"
                                    elif 'SSH' in line or 'sshd' in line:
                                        reason = "SSH brute force"
                                    elif 'port scan' in line.lower():
                                        reason = "Port scan"
                                    
                                    # Extract block duration if available
                                    duration_match = re.search(r'for (\d+) secs', line)
                                    if duration_match:
                                        reason += f" ({duration_match.group(1)}s)"
                                    
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
                                
                                # Extract reason after dash
                                reason_match = re.search(r'BLOCKED:\s*[^\s]+\s*-\s*(.+?)(?:\s*\(|$)', line)
                                if reason_match:
                                    reason = reason_match.group(1).strip()
                                    # Add severity if present
                                    sev_match = re.search(r'\(Severity:\s*(\d+)\)', line)
                                    if sev_match:
                                        reason += f" (Severity: {sev_match.group(1)})"
                                else:
                                    reason = "Suricata block"
                                
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
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*55}")
    print(f"           SURICATA IDS MONITORING REPORT")
    print(f"         Last {hours} hours - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*55}{Colors.END}\n")
    
    # General statistics
    print(f"{Colors.CYAN}GENERAL STATISTICS{Colors.END}")
    print(f"|- Total Alerts: {Colors.BOLD}{format_number(len(alerts))}{Colors.END}")
    print(f"|- Unique IPs: {Colors.BOLD}{len(analysis['src_ips'])}{Colors.END}")
    print(f"|- Unique Signatures: {Colors.BOLD}{len(analysis['signatures'])}{Colors.END}")
    print(f"|- Alert Rate: {Colors.BOLD}{len(alerts)/hours:.1f} alerts/hour{Colors.END}\n")
    
    # Severity Distribution
    print(f"{Colors.WARNING}SEVERITY DISTRIBUTION{Colors.END}")
    severity_names = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}
    total_alerts = sum(analysis['severities'].values())
    if total_alerts > 0:
        for sev in sorted(analysis['severities'].keys()):
            count = analysis['severities'][sev]
            percent = (count / total_alerts) * 100
            bar_length = int(percent / 2)
            bar = '#' * bar_length
            print(f"|- {severity_names.get(sev, f'Level {sev}'):8} [{count:5}] {bar:<48} {percent:5.1f}%")
    print()
    
    # Top 10 Attacking IPs
    print(f"{Colors.FAIL}TOP 10 ATTACKING IPs{Colors.END}")
    print(f"{'Rank':<5} {'IP Address':<40} {'Alerts':<8} {'Status':<12} {'Severities'}")
    print("-" * 85)
    
    for i, (ip, count) in enumerate(analysis['src_ips'].most_common(10), 1):
        status = check_ip_status(ip)
        
        # Color based on status
        if status == "WHITELISTED":
            status_color = Colors.GREEN
        elif status == "BLOCKED":
            status_color = Colors.FAIL
        elif status == "ACTIVE":
            status_color = Colors.WARNING
        else:
            status_color = Colors.END
        
        # Compress IPv6 for display
        display_ip = compress_ipv6(ip)
        
        # Severity breakdown for this IP
        sev_breakdown = []
        for sev in sorted(analysis['severity_by_ip'][ip].keys()):
            sev_count = analysis['severity_by_ip'][ip][sev]
            sev_breakdown.append(f"S{sev}:{sev_count}")
        
        print(f"{i:<5} {display_ip:<40} {count:<8} {status_color}{status:<12}{Colors.END} {', '.join(sev_breakdown)}")
    print()
    
    # Top Attack Types
    print(f"{Colors.BLUE}TOP 10 ATTACK SIGNATURES{Colors.END}")
    print(f"{'Count':<8} {'Signature'}")
    print("-" * 70)
    
    for sig, count in analysis['signatures'].most_common(10):
        # Truncate long signatures
        sig_display = sig[:60] + "..." if len(sig) > 60 else sig
        print(f"{count:<8} {sig_display}")
    print()
    
    # Top Target Ports
    print(f"{Colors.GREEN}TOP TARGET PORTS{Colors.END}")
    print(f"{'Port':<8} {'Count':<8} {'Service'}")
    print("-" * 40)
    
    port_names = {
        22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL",
        21: "FTP", 25: "SMTP", 110: "POP3", 143: "IMAP",
        3389: "RDP", 8080: "HTTP-Alt", 53: "DNS", 8443: "HTTPS-Alt",
        5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"
    }
    
    for port, count in analysis['dest_ports'].most_common(10):
        service = port_names.get(port, "Unknown")
        print(f"{port:<8} {count:<8} {service}")
    print()
    
    # Timeline
    if len(analysis['timeline']) > 0:
        print(f"{Colors.CYAN}ALERT TIMELINE (by hour){Colors.END}")
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
            print(f"{hour} [{count:3}] {bar}")
    print()
    
    # CSF Integration Status with blocked IPs
    print(f"{Colors.BOLD}CSF INTEGRATION STATUS{Colors.END}")
    
    # Get blocked IPs with improved parsing
    blocked_ips = get_blocked_ips_from_log(hours=hours)
    
    # Count blocked today from the parsed results
    today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    blocked_today = len([b for b in blocked_ips if b['time'] >= today_start])
    
    # Show both formats for compatibility
    print(f"|- IPs blocked today: {Colors.BOLD}{blocked_today}{Colors.END}")
    print(f"|- IPs blocked in last {hours} hours: {Colors.BOLD}{len(blocked_ips)}{Colors.END}")
    
    if blocked_ips:
        print(f"\n{Colors.FAIL}RECENTLY BLOCKED IPs{Colors.END}")
        print(f"{'Time':<20} {'IP Address':<40} {'Reason'}")
        print("-" * 80)
        
        # Sort by time (most recent first)
        for blocked in sorted(blocked_ips, key=lambda x: x['time'], reverse=True)[:15]:
            time_str = blocked['time'].strftime('%Y-%m-%d %H:%M')
            ip_display = compress_ipv6(blocked['ip'])
            print(f"{time_str:<20} {ip_display:<40} {blocked['reason']}")
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
                                if ip:
                                    recent_denies.append((ip, comment))
                
                if denied_count > 0:
                    print(f"Total IPs in CSF deny list: {Colors.BOLD}{denied_count}{Colors.END}")
                    if recent_denies and args and args.show_all_blocked:
                        print(f"\n{Colors.FAIL}IPs IN CSF DENY LIST{Colors.END}")
                        print(f"{'IP Address':<40} {'Comment'}")
                        print("-" * 80)
                        for ip, comment in recent_denies[:20]:
                            try:
                                ip_display = compress_ipv6(normalize_ip(ip))
                            except:
                                ip_display = ip
                            print(f"{ip_display:<40} {comment[:39]}")
                    else:
                        print("Run with --show-all-blocked to see deny list entries")
            except:
                pass
    
    # Check if timer is active
    try:
        result = subprocess.run(['systemctl', 'is-active', 'cron'],
                              capture_output=True, text=True)
        timer_status = "Active" if result.stdout.strip() == "active" else "Inactive"
        timer_color = Colors.GREEN if "Active" in timer_status else Colors.FAIL
        print(f"\n|- Auto-block cron: {timer_color}{timer_status}{Colors.END}")
    except:
        pass
    
    # Check for whitelisted IPs with high alert counts
    print(f"\n{Colors.WARNING}WHITELISTED IPs WITH ALERTS{Colors.END}")
    whitelisted_with_alerts = []
    for ip, count in analysis['src_ips'].most_common():
        if check_ip_in_whitelist(ip) and count > 5:
            whitelisted_with_alerts.append((ip, count))
    
    if whitelisted_with_alerts:
        print(f"{'IP Address':<40} {'Alerts'}")
        print("-" * 50)
        for ip, count in whitelisted_with_alerts[:5]:
            print(f"{compress_ipv6(ip):<40} {count}")
    else:
        print("No whitelisted IPs with significant alerts")

def main():
    parser = argparse.ArgumentParser(description='Suricata IDS Monitoring Tool')
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
    
    args = parser.parse_args()
    
    if args.no_color:
        for attr in dir(Colors):
            if not attr.startswith('__'):
                setattr(Colors, attr, '')
    
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
                    print(f"? {log_file} - {size} bytes - Modified: {mtime}")
                    
                    # Show sample of block-related entries
                    if 'csf' in log_file or 'suricata' in log_file:
                        with open(log_file, 'r') as f:
                            lines = f.readlines()
                            block_lines = [l for l in lines[-100:] if 'block' in l.lower() or 'deny' in l.lower()]
                            if block_lines:
                                print(f"  Sample entries: {len(block_lines)} block-related in last 100 lines")
                except Exception as e:
                    print(f"? {log_file} - Error: {e}")
            else:
                print(f"? {log_file} - Not found")
        print(f"{Colors.CYAN}=================={Colors.END}\n")
    
    # Parse logs
    print(f"{Colors.BLUE}Analyzing Suricata logs...{Colors.END}")
    alerts, stats = parse_suricata_log(args.file, args.hours)
    
    if not alerts:
        print(f"{Colors.WARNING}No alerts found in the last {args.hours} hours{Colors.END}")
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
