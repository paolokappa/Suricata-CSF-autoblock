#!/bin/bash

LOG_FILE="/var/log/suricata/eve.json"
POSITION_FILE="/var/lib/suricata/eve_position_simple"
LOG_OUTPUT="/var/log/suricata-csf-block.log"
PROCESSED_IPS="/var/lib/suricata/processed_ips.txt"

# Porte speedtest da escludere
SPEEDTEST_PORTS="8080|5060|80|443"

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

# Pattern da bloccare SEMPRE
should_block() {
    local signature="$1"
    local severity="$2"
    local dest_port="$3"
    
    # Blocca sempre severity 1 e 2
    if [ "$severity" -le 2 ]; then
        return 0
    fi
    
    # Per severity 3, blocca solo pattern pericolosi
    if echo "$signature" | grep -q -E -i "(SQL injection|XSS|Command injection|Directory traversal|exploit|backdoor|trojan|shellcode)"; then
        return 0
    fi
    
    # Ignora tutto il traffico HTTP normale sulle porte speedtest
    if echo "$dest_port" | grep -q -E "^($SPEEDTEST_PORTS)$"; then
        if echo "$signature" | grep -q -E "LOCAL HTTP|HTTP request"; then
            return 1  # Non bloccare
        fi
    fi
    
    return 1  # Default: non bloccare
}

[ ! -f "$PROCESSED_IPS" ] && touch "$PROCESSED_IPS"

last_pos=$(cat "$POSITION_FILE" 2>/dev/null || echo 0)
current_size=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)

if [ "$current_size" -gt "$last_pos" ]; then
    log_message "Processing from $last_pos to $current_size"
    
    blocked_count=0
    
    tail -c +$((last_pos + 1)) "$LOG_FILE" | \
    grep '"event_type":"alert"' | \
    jq -r '"\(.src_ip)|\(.alert.severity)|\(.alert.signature)|\(.dest_port)"' | \
    while IFS='|' read -r ip severity signature dest_port; do
        if [ -n "$ip" ] && [ "$ip" != "null" ]; then
            # Skip se già processato
            if grep -q "^${ip}$" "$PROCESSED_IPS"; then
                continue
            fi
            
            # Skip se whitelisted
            if is_whitelisted "$ip"; then
                log_message "WHITELISTED: $ip - $signature"
                echo "$ip" >> "$PROCESSED_IPS"
                continue
            fi
            
            # Verifica se deve essere bloccato
            if should_block "$signature" "$severity" "$dest_port"; then
                if csf -g "$ip" 2>/dev/null | grep -q "No matches"; then
                    if csf -td "$ip" 86400 "Suricata: $signature" >/dev/null 2>&1; then
                        log_message "BLOCKED (24h): $ip - $signature"
                        echo "$ip" >> "$PROCESSED_IPS"
                        ((blocked_count++))
                    fi
                fi
            fi
        fi
    done
    
    echo "$current_size" > "$POSITION_FILE"
    
    if [ "$blocked_count" -gt 0 ]; then
        log_message "Blocked $blocked_count IPs"
    fi
fi

# Cleanup vecchi IP processati
if [ $(wc -l < "$PROCESSED_IPS" 2>/dev/null || echo 0) -gt 1000 ]; then
    tail -500 "$PROCESSED_IPS" > "$PROCESSED_IPS.tmp"
    mv "$PROCESSED_IPS.tmp" "$PROCESSED_IPS"
fi
