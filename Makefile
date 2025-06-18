# Makefile for Suricata-CSF Auto-Block

.PHONY: install check clean update help

help:
	@echo "Suricata-CSF Auto-Block - Available commands:"
	@echo "  make install    - Install the system"
	@echo "  make check      - Check installation status"
	@echo "  make update     - Update Suricata rules"
	@echo "  make clean      - Clean log files"
	@echo "  make monitor    - Run the monitoring dashboard"

install:
	@echo "Installing Suricata-CSF Auto-Block..."
	@sudo ./install.sh

check:
	@echo "Checking installation..."
	@./check-installation.sh

update:
	@echo "Updating Suricata rules..."
	@sudo systemctl start suricata-auto-update.service

clean:
	@echo "Cleaning old logs..."
	@sudo find /var/log/suricata -name "*.log.*" -mtime +7 -delete
	@echo "Cleaned old log files"

monitor:
	@sudo suricata-monitor
