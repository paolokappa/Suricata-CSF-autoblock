# Changelog

All notable changes to this project will be documented in this file.

## [2.1.0] - 2025-06-18

### 🎉 Major New Features

#### 🌍 Geolocation Intelligence
- Added real-time IP geolocation with country and city information
- Implemented intelligent caching system to minimize API requests  
- Added geographic distribution analysis of attacks
- Integrated multiple providers (ip-api.com as primary, ipinfo.io as fallback)
- Cache stored in `/var/cache/suricata-monitor/geo-cache.pkl`

#### 📊 Advanced Analytics & Anomaly Detection
- Added 30-day historical statistics tracking
- Implemented automatic anomaly detection (2x average threshold)
- Added trend analysis with 24-hour and 7-day comparisons
- Added recurring attacker identification
- New attack type detection and tracking

#### 🎯 Enhanced IP Management  
- Automatic server IP detection (all IPv4 and IPv6 addresses)
- Added trusted IP support for admins/monitoring that won't be blocked
- Implemented smart IP status classification: BLOCKED, ACTIVE, WHITELISTED, TRUSTED, SERVER
- Full IPv6 support with proper compression and normalization

#### 📈 Detailed Threat Intelligence
- Added human-readable descriptions for all Suricata signatures
- Mapped 50+ ModSecurity rules with specific descriptions
- Created comprehensive port service database (100+ services)
- Enhanced CSF block reason analysis with clear explanations

#### 📱 Professional Monitoring Dashboard
- Redesigned output with colored, formatted display
- Added hourly attack timeline visualization
- Added severity distribution with visual bars
- Added CSF integration effectiveness metrics
- Multi-source log analysis (Suricata + CSF + system logs)

### 🚀 New Command Line Options
- `--no-geo`: Disable geolocation lookups for offline use
- `--debug`: Comprehensive system diagnostics mode
- `--show-all-blocked`: Display all blocked IPs from CSF deny list
- `--clear-cache`: Clear geolocation and statistics cache
- `--no-color`: Disable colored output for log compatibility

### 🛠️ Technical Improvements
- Optimized log parsing performance
- Added fallback for systems without netifaces module
- Improved IPv6 handling throughout the codebase
- Better error handling and recovery
- Reduced external API dependencies

### 🐛 Bug Fixes
- Fixed IPv6 address parsing and display
- Fixed log rotation position file handling
- Improved CSF deny list parsing
- Better handling of malformed log entries
- Fixed timezone issues in log parsing

### 📚 Documentation
- Completely rewritten README with all new features
- Added detailed feature descriptions
- Updated troubleshooting guide
- Added API reference section

## [2.0.0] - 2025-06-17
- Added speedtest server support
- Enhanced monitoring with IPv6
- Fixed various bugs

## [1.0.0] - 2025-06-01
- Initial release
- Basic Suricata + CSF integration
- Automatic blocking functionality
- Simple monitoring script
