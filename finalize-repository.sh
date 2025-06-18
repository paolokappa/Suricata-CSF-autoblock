#!/bin/bash
# Final touches for Suricata-CSF repository

echo "======================================"
echo "Finalizing Repository - v2.1.0"
echo "======================================"
echo ""

# 1. Clean up temporary files
echo "[*] Cleaning up temporary files..."
rm -f cleanup-commands.txt analyze-and-cleanup.sh cleanup-repository.sh 2>/dev/null
echo "  ? Removed temporary scripts"

# 2. Add README files to directories
echo ""
echo "[*] Adding README files to directories..."

# README for examples directory
cat > examples/README.md << 'EOF'
# Example Files

This directory contains example configurations and templates for the Suricata-CSF Auto-Block system.

## Files

- **csf.allow.example** - Example whitelist configuration for CSF
- **trusted-ips-example.py** - Example trusted IPs configuration for the monitor
- **crontab.example** - Example crontab entries for automation
- **suricata-custom.yaml.example** - Example Suricata configuration

## Usage

1. Copy the example files to their proper locations
2. Modify them according to your environment
3. Never commit actual configuration files with real IPs or sensitive data

## Quick Start

```bash
# Copy CSF whitelist example
sudo cp csf.allow.example /etc/csf/csf.allow

# Copy crontab entries
cat crontab.example | sudo tee -a /etc/crontab

# Copy Suricata config
sudo cp suricata-custom.yaml.example /etc/suricata/suricata-custom.yaml
```
EOF
echo "  ? Created examples/README.md"

# README for systemd directory (already exists, update it)
cat > systemd/README.md << 'EOF'
# Systemd Services

This directory contains systemd service files for the Suricata-CSF integration.

## Files

- `suricata-auto-update.service` - Service for updating Suricata rules
- `suricata-auto-update.timer` - Timer that triggers daily rule updates at 01:00

## Important Note

There is **NO** `suricata-csf-block.service`. The blocking functionality runs via cron, not systemd.

## Installation

```bash
sudo cp *.service *.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable suricata-auto-update.timer
sudo systemctl start suricata-auto-update.timer
```

## Check Status

```bash
systemctl status suricata-auto-update.timer
systemctl list-timers --all | grep suricata
```

## Manual Rule Update

```bash
sudo systemctl start suricata-auto-update.service
```
EOF
echo "  ? Updated systemd/README.md"

# 3. Create CONTRIBUTING.md
echo ""
echo "[*] Creating CONTRIBUTING.md..."
cat > CONTRIBUTING.md << 'EOF'
# Contributing to Suricata-CSF Auto-Block

Thank you for your interest in contributing to this project!

## How to Contribute

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Commit your changes** (`git commit -m 'Add amazing feature'`)
4. **Push to the branch** (`git push origin feature/amazing-feature`)
5. **Open a Pull Request**

## Guidelines

### Code Style
- Use 4 spaces for indentation in Python
- Use 2 spaces for indentation in Bash scripts
- Add comments for complex logic
- Keep functions small and focused

### Commit Messages
- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less

### Testing
- Test your changes on Ubuntu 22.04 and/or 24.04
- Ensure Suricata doesn't generate errors with your changes
- Test both standard and speedtest editions if modifying blockers

### Documentation
- Update README.md if adding new features
- Update CHANGELOG.md for significant changes
- Add comments to your code
- Update help text in scripts

## Reporting Issues

- Use GitHub Issues
- Include your OS version
- Include Suricata version (`suricata --version`)
- Include relevant log snippets
- Describe steps to reproduce

## Feature Requests

- Open an issue with "Feature Request" in the title
- Describe the use case
- Explain why it would be useful for others

## Questions?

Open an issue with "Question" in the title.
EOF
echo "  ? Created CONTRIBUTING.md"

# 4. Create a simple Makefile for common tasks
echo ""
echo "[*] Creating Makefile..."
cat > Makefile << 'EOF'
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
EOF
echo "  ? Created Makefile"

# 5. Update README with badges and latest info
echo ""
echo "[*] Adding badges to README..."
# Create a temporary file with the badge header
cat > README_badges.tmp << 'EOF'
# ??? Suricata IDS + CSF Firewall Auto-Block System

![Version](https://img.shields.io/badge/version-2.1.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Ubuntu](https://img.shields.io/badge/ubuntu-22.04%20%7C%2024.04-orange.svg)
![Suricata](https://img.shields.io/badge/suricata-7.x-red.svg)
![Python](https://img.shields.io/badge/python-3.x-yellow.svg)

EOF

# Combine with existing README (skip the first line)
tail -n +2 README.md >> README_badges.tmp
mv README_badges.tmp README.md
echo "  ? Added badges to README.md"

# 6. Create a VERSION file
echo "2.1.0" > VERSION
echo "  ? Created VERSION file"

# 7. Add check-installation.sh and fix-installation.sh if they don't exist
if [ ! -f "check-installation.sh" ]; then
    echo ""
    echo "[!] Note: check-installation.sh is missing"
    echo "    Copy from earlier in our conversation or create a new one"
fi

if [ ! -f "fix-installation.sh" ]; then
    echo "[!] Note: fix-installation.sh is missing"
    echo "    Copy from earlier in our conversation or create a new one"
fi

# 8. Create .gitattributes for better GitHub stats
cat > .gitattributes << 'EOF'
# Linguist overrides
*.py linguist-language=Python
*.sh linguist-language=Shell
docs/* linguist-documentation
examples/* linguist-documentation

# Line endings
*.sh text eol=lf
*.py text eol=lf
*.md text eol=lf
*.yaml text eol=lf
*.yml text eol=lf
EOF
echo "  ? Created .gitattributes"

# 9. Final summary
echo ""
echo "======================================"
echo "Repository Finalized!"
echo "======================================"
echo ""
echo "New files added:"
echo "  - examples/README.md"
echo "  - CONTRIBUTING.md"
echo "  - Makefile"
echo "  - VERSION"
echo "  - .gitattributes"
echo "  - Badges in README.md"
echo ""
echo "To commit these changes:"
echo "  git add ."
echo "  git commit -m 'docs: Add contributing guide, makefiles and final touches'"
echo "  git push origin main"
echo ""
echo "Your repository is now complete and professional! ??"
echo ""
echo "Quick commands:"
echo "  make help      - Show available commands"
echo "  make install   - Install the system"
echo "  make monitor   - Run monitoring dashboard"
