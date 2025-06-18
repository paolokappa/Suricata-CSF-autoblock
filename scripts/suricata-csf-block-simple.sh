#!/bin/bash
# Suricata CSF Auto-Block Script - Standard Version
# Automatically blocks IPs based on Suricata alert severity

LOG_FILE="/var/log/suricata/eve.json"
POSITION_FILE="/var/lib/suricata/eve_position_simple"
LOG_OUTPUT="/var/log/suricata-csf-block.log"
PROCESSED_IPS="/var/lib/suricata/processed_ips.txt"

# Minimum severity to block (1=high, 2=medium, 3=low)
MIN_SEVERITY=2

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_OUTPUT"
}

is_whitelisted() {
    local ip="$1"
    if csf -g "$ip" 2>/dev/null | grep -q "csf.allow"; then
        return 0
    fi
    return 1
}

# Create processed IPs file if it doesn't exist
[ ! -f "$PROCESSED_IPS" ] && touch "$PROCESSED_IPS"

# Get last position
last_pos=$(cat "$POSITION_FILE" 2>/dev/null || echo 0)
current_size=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)

# Process new entries
if [ "$current_size" -gt "$last_pos" ]; then
    log_message "Processing from $last_pos to $current_size"
    
    blocked_count=0
    
    # Read new log entries
    tail -c +$((last_pos + 1)) "$LOG_FILE" | \
    grep '"event_type":"alert"' | \
    jq -r '"\(.src_ip)|\(.alert.severity)|\(.alert.signature)"' | \
    while IFS='|' read -r ip severity signature; do
        if [ -n "$ip" ] && [ "$ip" != "null" ]; then
            # Skip if already processed
            if grep -q "^${ip}$" "$PROCESSED_IPS"; then
                continue
            fi
            
            # Skip if whitelisted
            if is_whitelisted "$ip"; then
                log_message "WHITELISTED: $ip - $signature"
                echo "$ip" >> "$PROCESSED_IPS"
                continue
            fi
            
            # Block if severity meets threshold
            if [ "$severity" -le "$MIN_SEVERITY" ]; then
                # Check if not already blocked
                if csf -g "$ip" 2>/dev/null | grep -q "No matches"; then
                    # Block permanently
                    if csf -d "$ip" "Suricata: $signature (Severity: $severity)" >/dev/null 2>&1; then
                        log_message "BLOCKED: $ip - $signature (Severity: $severity)"
                        echo "$ip" >> "$PROCESSED_IPS"
                        ((blocked_count++))
                        
                        # Report to AbuseIPDB if available
                        if command -v csf-report-abuser >/dev/null 2>&1; then
                            csf-report-abuser "$ip" "Suricata: $signature" >/dev/null 2>&1 &
                        fi
                    fi
                fi
            fi
        fi
    done
    
    # Update position
    echo "$current_size" > "$POSITION_FILE"
    
    if [ "$blocked_count" -gt 0 ]; then
        log_message "Blocked $blocked_count IPs"
    fi
fi

# Cleanup old processed IPs (keep last 500)
if [ $(wc -l < "$PROCESSED_IPS" 2>/dev/null || echo 0) -gt 1000 ]; then
    tail -500 "$PROCESSED_IPS" > "$PROCESSED_IPS.tmp"
    mv "$PROCESSED_IPS.tmp" "$PROCESSED_IPS"
fi
