#!/bin/bash

LOG_FILE="/var/log/suricata/eve.json"
POSITION_FILE="/var/lib/suricata/eve_position_simple"
LOG_OUTPUT="/var/log/suricata-csf-block.log"
PROCESSED_IPS="/var/lib/suricata/processed_ips.txt"
STATS_FILE="/var/lib/suricata/hourly_stats"
ABUSEIPDB_SCRIPT="/var/lib/csf/abuseipdb_block.sh"

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_OUTPUT"
}

# Create files if not exist
[ ! -f "$PROCESSED_IPS" ] && touch "$PROCESSED_IPS"
[ ! -f "$STATS_FILE" ] && echo "0" > "$STATS_FILE"

# Get last position
if [ -f "$POSITION_FILE" ]; then
    last_pos=$(cat "$POSITION_FILE")
else
    last_pos=0
fi

# Get current size
current_size=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)

# Process new lines
if [ "$current_size" -gt "$last_pos" ]; then
    log_message "Processing from $last_pos to $current_size"
    
    # Use temp file to count blocks
    temp_blocked="/tmp/blocked_$$"
    echo "0" > "$temp_blocked"
    
    # Extract only alerts with severity <= 2 and unique IPs
    tail -c +$((last_pos + 1)) "$LOG_FILE" | \
    grep '"event_type":"alert"' | \
    jq -r 'select(.alert.severity <= 2) | "\(.src_ip)|\(.alert.severity)|\(.alert.signature)|\(.alert.category)|\(.dest_port)|\(.proto)"' | \
    while IFS='|' read -r ip severity signature category dest_port proto; do
        if [ -n "$ip" ]; then
            # Check if already processed
            if ! grep -q "^${ip}$" "$PROCESSED_IPS"; then
                log_message "Checking IP: $ip (severity: $severity)"
                
                # Check if already blocked in CSF
                if csf -g "$ip" 2>/dev/null | grep -q "No matches"; then
                    if csf -d "$ip" "Suricata: $signature (Severity: $severity)" >/dev/null 2>&1; then
                        log_message "BLOCKED: $ip - $signature (Severity: $severity)"
                        echo "$ip" >> "$PROCESSED_IPS"
                        count=$(cat "$temp_blocked")
                        echo $((count + 1)) > "$temp_blocked"
                        
                        # Report to AbuseIPDB if script exists
                        if [ -f "$ABUSEIPDB_SCRIPT" ] && [ -x "$ABUSEIPDB_SCRIPT" ]; then
                            comment="Suricata IDS Alert: $signature | Category: $category | Severity: $severity | Port: $dest_port | Protocol: $proto"
                            log_message "Reporting to AbuseIPDB: $ip"
                            "$ABUSEIPDB_SCRIPT" "$ip" "$dest_port" "in" "" "" "$comment" "Alert: $signature" "SURICATA" >/dev/null 2>&1
                        fi
                    else
                        log_message "ERROR: Failed to block $ip"
                    fi
                else
                    log_message "Already blocked: $ip"
                    echo "$ip" >> "$PROCESSED_IPS"
                fi
            fi
        fi
    done
    
    # Get blocked count
    blocked_count=$(cat "$temp_blocked")
    rm -f "$temp_blocked"
    
    # Save position
    echo "$current_size" > "$POSITION_FILE"
    
    # Log if there was activity
    if [ "$blocked_count" -gt 0 ]; then
        log_message "Check completed - Blocked: $blocked_count new IPs"
    fi
    
    # Clean old processed IPs (keep last 1000)
    if [ $(wc -l < "$PROCESSED_IPS" 2>/dev/null || echo 0) -gt 1000 ]; then
        tail -1000 "$PROCESSED_IPS" > "$PROCESSED_IPS.tmp"
        mv "$PROCESSED_IPS.tmp" "$PROCESSED_IPS"
    fi
fi

# Hourly statistics
current_hour=$(date +%Y%m%d%H)
last_hour=$(cat "$STATS_FILE" 2>/dev/null || echo "0")

if [ "$current_hour" != "$last_hour" ]; then
    total_blocked=$(grep -c "BLOCKED:" "$LOG_OUTPUT" 2>/dev/null || echo 0)
    total_processed=$(wc -l < "$PROCESSED_IPS" 2>/dev/null || echo 0)
    log_message "HOURLY STATS - Processed IPs: $total_processed, Total blocked all time: $total_blocked"
    echo "$current_hour" > "$STATS_FILE"
fi
