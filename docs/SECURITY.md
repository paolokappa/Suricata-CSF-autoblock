# Security Policy

## Security Features

This system is designed with security in mind:

- **No passwords stored**: All scripts and configurations contain no hardcoded passwords
- **Privilege separation**: Scripts run with minimum required privileges
- **Secure communication**: Integration with CSF for secure firewall management
- **Audit trail**: All actions are logged for security auditing

## Reporting Security Vulnerabilities

If you discover a security vulnerability, please:

1. **DO NOT** open a public issue
2. Email security concerns to: security@goline.ch
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a detailed response within 5 business days.

## Security Best Practices

When using this system:

1. **Regularly update** Suricata and system packages
2. **Monitor logs** for suspicious activity
3. **Review blocked IPs** periodically
4. **Keep CSF updated** and properly configured
5. **Restrict access** to configuration files
6. **Use strong passwords** for system accounts
7. **Enable firewall** rules for management access

## API Keys

If using AbuseIPDB integration:
- Store API keys in CSF configuration only
- Never commit API keys to version control
- Rotate keys periodically
- Use minimum required permissions
