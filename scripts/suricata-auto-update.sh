#!/bin/bash
# Aggiornamento automatico intelligente per Suricata con rilevamento versione
# Versione ottimizzata per web server con filtri mirati

LOG_FILE="/var/log/suricata-auto-update.log"
LOCK_FILE="/var/run/suricata-auto-update.lock"
RULES_DIR="/etc/suricata/rules"
TEMP_DIR="/tmp/suricata-update-$$"
UPDATED=0

# Evita esecuzioni multiple
if [ -f "$LOCK_FILE" ]; then
    exit 0
fi
touch "$LOCK_FILE"
trap "rm -f $LOCK_FILE" EXIT

# Funzione di log
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

log "===== Inizio aggiornamento automatico ====="

# Rileva versione Suricata automaticamente
SURICATA_VERSION=$(/usr/bin/suricata -V 2>&1 | grep -oP "version \K[0-9]+\.[0-9]+\.[0-9]+" | head -1)
if [ -z "$SURICATA_VERSION" ]; then
    log "ERRORE: Impossibile rilevare versione Suricata"
    exit 1
fi
log "Versione Suricata rilevata: $SURICATA_VERSION"

# Salva versione per confronto futuro
VERSION_FILE="/var/lib/suricata/current-version"
mkdir -p /var/lib/suricata
if [ -f "$VERSION_FILE" ]; then
    OLD_VERSION=$(cat "$VERSION_FILE")
    if [ "$OLD_VERSION" != "$SURICATA_VERSION" ]; then
        log "ATTENZIONE: Versione Suricata cambiata da $OLD_VERSION a $SURICATA_VERSION"
        # Reset delle regole ET in caso di cambio versione
        rm -f "$RULES_DIR/et-auto-updates.rules"
    fi
fi
echo "$SURICATA_VERSION" > "$VERSION_FILE"

# Costruisci URL base per la versione corrente
BASE_URL="https://rules.emergingthreats.net/open/suricata-${SURICATA_VERSION}/rules"

# Test se l'URL esiste
if ! wget -q --spider "${BASE_URL}/emerging-web_server.rules"; then
    # Prova con versione major.minor (senza patch)
    MAJOR_VERSION=$(echo "$SURICATA_VERSION" | cut -d. -f1-2)
    BASE_URL="https://rules.emergingthreats.net/open/suricata-${MAJOR_VERSION}/rules"
    
    if ! wget -q --spider "${BASE_URL}/emerging-web_server.rules"; then
        # Prova con "suricata" generico
        BASE_URL="https://rules.emergingthreats.net/open/suricata/rules"
        
        if ! wget -q --spider "${BASE_URL}/emerging-web_server.rules"; then
            log "ERRORE: Impossibile trovare regole per Suricata $SURICATA_VERSION"
            exit 1
        fi
    fi
fi
log "URL regole: $BASE_URL"

# Crea directory temporanea
mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"

# Lista delle regole ET da scaricare (solo quelle rilevanti per web server)
RULE_FILES=(
    "emerging-web_server.rules"
    "emerging-web_specific_apps.rules"
    "emerging-exploit.rules"
    "emerging-current_events.rules"
    "emerging-sql.rules"
)

# Scarica le regole
log "Scaricamento regole ET..."
DOWNLOAD_SUCCESS=0
for rule_file in "${RULE_FILES[@]}"; do
    if wget -q -T 30 "${BASE_URL}/${rule_file}" -O "$rule_file"; then
        ((DOWNLOAD_SUCCESS++))
    else
        log "Avviso: impossibile scaricare $rule_file"
    fi
done

if [ "$DOWNLOAD_SUCCESS" -eq 0 ]; then
    log "ERRORE: Nessuna regola scaricata con successo"
    exit 1
fi
log "Scaricate $DOWNLOAD_SUCCESS file di regole"

# Estrai solo regole rilevanti per i tuoi servizi
log "Estrazione regole rilevanti..."
> "$RULES_DIR/et-auto-updates.rules.tmp"

# Pattern MOLTO specifici per i tuoi servizi
SERVICES_PATTERN="(WordPress|PHP|Apache|MySQL|MariaDB|FTP|SSH|Webmin)"

# Estrai regole che sono SPECIFICAMENTE per i tuoi servizi
# 1. WordPress exploits
grep -h "WordPress" emerging-*.rules 2>/dev/null | \
    grep -E "(EXPLOIT|WEB_SPECIFIC_APPS|backdoor|RCE|injection)" | \
    grep -v -E "(INFO|GAMES|CHAT)" >> "$RULES_DIR/et-auto-updates.rules.tmp"

# 2. PHP exploits e webshells
grep -h -E "(PHP|php)" emerging-*.rules 2>/dev/null | \
    grep -E "(EXPLOIT|WEB_SERVER|RCE|injection|eval\(|base64_decode|webshell|backdoor)" | \
    grep -v -E "(INFO|USER_AGENTS|CHAT)" >> "$RULES_DIR/et-auto-updates.rules.tmp"

# 3. Apache exploits
grep -h "Apache" emerging-*.rules 2>/dev/null | \
    grep -E "(EXPLOIT|WEB_SERVER|CVE|vulnerability)" | \
    grep -v "INFO" >> "$RULES_DIR/et-auto-updates.rules.tmp"

# 4. MySQL/MariaDB exploits
grep -h -E "(MySQL|MariaDB|mysql)" emerging-*.rules 2>/dev/null | \
    grep -E "(EXPLOIT|injection|CVE)" | \
    grep -v "INFO" >> "$RULES_DIR/et-auto-updates.rules.tmp"

# 5. SSH brute force (ma non info generiche)
grep -h "SSH" emerging-*.rules 2>/dev/null | \
    grep -E "(brute|EXPLOIT|CVE)" | \
    grep -v -E "(INFO|SCAN)" | head -20 >> "$RULES_DIR/et-auto-updates.rules.tmp"

# 6. Webmin exploits
grep -h -i "webmin" emerging-*.rules 2>/dev/null | \
    grep -E "(EXPLOIT|CVE)" >> "$RULES_DIR/et-auto-updates.rules.tmp"

# 7. Web shells comuni (non malware generico)
grep -h -E "(c99|r57|WSO|b374k|Mini.?Shell|web.?shell|China.?Chopper)" emerging-*.rules 2>/dev/null | \
    grep -E "(WEB_SERVER|WEB_SPECIFIC_APPS|EXPLOIT)" | \
    grep -v "INFO" >> "$RULES_DIR/et-auto-updates.rules.tmp"

# 8. SQL injection generiche
grep -h -E "SQL.*[Ii]njection" emerging-*.rules 2>/dev/null | \
    grep -E "(WEB_SERVER|WEB_SPECIFIC_APPS)" | \
    grep -v "INFO" | head -50 >> "$RULES_DIR/et-auto-updates.rules.tmp"

# 9. CVE critici recenti SOLO per servizi web
grep -h -E "CVE-202[4-9]-[0-9]{4,5}" emerging-*.rules 2>/dev/null | \
    grep -E "$SERVICES_PATTERN" | \
    grep -E "(EXPLOIT|ATTACK|Critical)" | \
    grep -v "INFO" >> "$RULES_DIR/et-auto-updates.rules.tmp"

# 10. Log4j e simili (vulnerabilità critiche recenti)
grep -h -E "(log4j|Log4Shell|Spring4Shell|ProxyShell)" emerging-*.rules 2>/dev/null | \
    grep -v "INFO" >> "$RULES_DIR/et-auto-updates.rules.tmp"

# Rimuovi duplicati e linee vuote
sort -u "$RULES_DIR/et-auto-updates.rules.tmp" | grep -v '^$' > "$RULES_DIR/et-auto-updates.rules.new"

# Confronta con le regole esistenti
if [ -f "$RULES_DIR/et-auto-updates.rules" ]; then
    NEW_RULES=$(comm -23 <(sort "$RULES_DIR/et-auto-updates.rules.new") <(sort "$RULES_DIR/et-auto-updates.rules") | wc -l)
    REMOVED_RULES=$(comm -13 <(sort "$RULES_DIR/et-auto-updates.rules.new") <(sort "$RULES_DIR/et-auto-updates.rules") | wc -l)
else
    NEW_RULES=$(wc -l < "$RULES_DIR/et-auto-updates.rules.new")
    REMOVED_RULES=0
fi

if [ "$NEW_RULES" -gt 0 ] || [ "$REMOVED_RULES" -gt 0 ]; then
    log "Modifiche rilevate: +$NEW_RULES nuove, -$REMOVED_RULES rimosse"
    
    # Backup
    if [ -f "$RULES_DIR/et-auto-updates.rules" ]; then
        cp "$RULES_DIR/et-auto-updates.rules" "$RULES_DIR/et-auto-updates.rules.bak"
    fi
    
    # Applica nuove regole
    mv "$RULES_DIR/et-auto-updates.rules.new" "$RULES_DIR/et-auto-updates.rules"
    
    # Test configurazione
    if /usr/bin/suricata -T -c /etc/suricata/suricata.yaml &>/dev/null; then
        log "Test configurazione OK"
        
        # Ricarica Suricata
        if systemctl reload-or-restart suricata; then
            log "Suricata ricaricato con successo"
            UPDATED=1
            
            # Log delle modifiche (prime 5 di ogni tipo)
            if [ "$NEW_RULES" -gt 0 ]; then
                log "Esempio nuove regole aggiunte:"
                comm -23 <(sort "$RULES_DIR/et-auto-updates.rules") <(sort "$RULES_DIR/et-auto-updates.rules.bak" 2>/dev/null || echo) | \
                    head -5 | sed 's/^/  /' >> "$LOG_FILE"
            fi
        else
            log "ERRORE: Ricarica Suricata fallita"
            # Ripristina backup
            [ -f "$RULES_DIR/et-auto-updates.rules.bak" ] && mv "$RULES_DIR/et-auto-updates.rules.bak" "$RULES_DIR/et-auto-updates.rules"
        fi
    else
        log "ERRORE: Test configurazione fallito"
        # Ripristina backup
        [ -f "$RULES_DIR/et-auto-updates.rules.bak" ] && mv "$RULES_DIR/et-auto-updates.rules.bak" "$RULES_DIR/et-auto-updates.rules"
    fi
else
    log "Nessuna modifica alle regole"
    rm -f "$RULES_DIR/et-auto-updates.rules.new"
fi

# Cleanup
rm -rf "$TEMP_DIR"

# Report finale
TOTAL_RULES=$(grep -c "^alert" "$RULES_DIR/et-auto-updates.rules" 2>/dev/null || echo 0)
log "Regole ET automatiche totali: $TOTAL_RULES"

# Statistiche per tipo
if [ -f "$RULES_DIR/et-auto-updates.rules" ]; then
    log "Distribuzione regole:"
    log "  - WordPress: $(grep -c "WordPress" "$RULES_DIR/et-auto-updates.rules")"
    log "  - PHP: $(grep -c -i "PHP" "$RULES_DIR/et-auto-updates.rules")"
    log "  - Apache: $(grep -c "Apache" "$RULES_DIR/et-auto-updates.rules")"
    log "  - MySQL: $(grep -c -i "MySQL" "$RULES_DIR/et-auto-updates.rules")"
    log "  - SQL Injection: $(grep -c -i "SQL.*injection" "$RULES_DIR/et-auto-updates.rules")"
    log "  - Web Shell: $(grep -c -i "shell" "$RULES_DIR/et-auto-updates.rules")"
fi

# Statistiche sistema
if [ "$UPDATED" -eq 1 ]; then
    log "Statistiche sistema:"
    log "  - Versione Suricata: $SURICATA_VERSION"
    log "  - Regole totali caricate: $(grep -c "^alert" "$RULES_DIR"/*.rules)"
    MEM_KB=$(ps aux | grep "[S]uricata-Main" | awk '{print $6}')
    [ -n "$MEM_KB" ] && log "  - Memoria Suricata: $(($MEM_KB/1024)) MB"
fi

log "===== Fine aggiornamento ====="

# Notifica significativa (più di 20 nuove regole o cambio versione)
if [ "$UPDATED" -eq 1 ] && ([ "$NEW_RULES" -gt 20 ] || [ "$OLD_VERSION" != "$SURICATA_VERSION" ]); then
    MSG="Suricata update: "
    [ "$OLD_VERSION" != "$SURICATA_VERSION" ] && MSG+="nuova versione $SURICATA_VERSION, "
    MSG+="$NEW_RULES nuove regole, totale $TOTAL_RULES"
    echo "$MSG" | logger -t suricata-update -p user.notice
fi

exit 0
