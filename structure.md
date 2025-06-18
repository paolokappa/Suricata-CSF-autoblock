suricata-csf-autoblock/
├── README.md                          # Documentazione principale (aggiornata v2.1.0)
├── CHANGELOG.md                       # Changelog dettagliato
├── LICENSE                            # MIT License
├── install.sh                         # Script di installazione principale
├── check-installation.sh              # Script verifica installazione
├── fix-installation.sh                # Script correzione problemi comuni
│
├── scripts/                           # Script principali
│   ├── suricata-csf-block-simple.sh   # Versione standard del blocker
│   ├── suricata-csf-block-speedtest.sh # Versione per Speedtest Server
│   ├── suricata-auto-update.sh        # Aggiornamento automatico regole
│   ├── suricata-monitor.py            # Monitor avanzato con geolocalizzazione
│   └── suricata-backup-rules.sh       # Backup regole (opzionale)
│
├── systemd/                           # Servizi systemd
│   ├── suricata-auto-update.service   # Servizio aggiornamento
│   ├── suricata-auto-update.timer     # Timer giornaliero
│   └── README.md                      # Spiegazione servizi
│
├── logrotate/                         # Configurazione logrotate
│   └── suricata                       # Config rotazione log
│
├── docs/                              # Documentazione aggiuntiva
│   ├── INSTALL.md                     # Guida installazione dettagliata
│   ├── TROUBLESHOOTING.md             # Risoluzione problemi
│   ├── SPEEDTEST-SERVER.md            # Guida per Speedtest Server
│   └── trusted-ips-example.py         # Esempio configurazione IP fidati
│
└── examples/                          # File di esempio
    ├── csf.allow.example              # Esempio whitelist CSF
    └── suricata-rules.example         # Esempio regole custom
