# 🔒 Linux System Hardening Tool

**Enterprise-Grade Security Hardening and Compliance Tool for Linux Systems**

Automate security hardening, compliance checks, and system auditing with both CLI and Web interfaces.

---

## 📋 Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
  - [CLI Mode](#cli-mode)
  - [Web GUI Mode](#web-gui-mode)
- [Security Topics](#security-topics)
- [File Structure](#file-structure)
- [Configuration](#configuration)
- [Advanced Usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)
- [Security Best Practices](#security-best-practices)
- [Contributing](#contributing)
- [License](#license)

---

## ✨ Features

### Core Capabilities
- ✅ **Automated Security Scanning** - Detect misconfigurations and vulnerabilities
- ✅ **One-Click Hardening** - Apply security fixes automatically
- ✅ **Backup & Rollback** - Safely revert changes if needed
- ✅ **Comprehensive Reporting** - Generate detailed audit reports
- ✅ **Database Tracking** - Track all changes in SQLite database
- ✅ **Dual Interface** - CLI for automation, Web GUI for management

### Web GUI Features
- 📊 **Interactive Dashboard** - Visual security status overview
- 🔍 **Real-Time Scanning** - Live scan progress and results
- 🔧 **One-Click Fixes** - Apply hardening with a single click
- 🌐 **Remote Control** - Manage remote systems via SSH
- 📈 **Visual Reports** - Charts and graphs for security metrics
- ⏮️ **Easy Rollback** - Undo changes through web interface
- 👥 **Multi-User Support** - Secure authentication system

### CLI Features
- ⚡ **Fast Automation** - Perfect for scripts and cron jobs
- 📝 **Detailed Logging** - Comprehensive output files
- 🔄 **Batch Operations** - Scan/fix multiple topics at once
- 💻 **Interactive Menu** - User-friendly command interface
- 🎯 **Targeted Actions** - Focus on specific security areas

---

## 🚀 Quick Start

### Installation (One Command)

```bash
# Download and extract the tool, then:
cd linux_hardening_tool
sudo python3 install.py
```

The installer will:
1. Detect your preferred mode (CLI/Web/Both)
2. Set up all directories and files
3. Install Python dependencies
4. Initialize the database
5. Create launcher scripts

### Running the Tool

#### CLI Mode
```bash
sudo ./hardening-cli
```

#### Web GUI Mode
```bash
sudo ./hardening-web
# Access at: http://localhost:5000
# Login: admin / changeme123
```

---

## 📦 Installation

### Prerequisites

- **Operating System:** Linux (Ubuntu/Debian/RHEL/CentOS)
- **Python:** 3.6 or higher
- **Privileges:** Root access required for fixes
- **Disk Space:** ~100MB for installation and logs

### Step-by-Step Installation

1. **Extract the tool:**
   ```bash
   tar -xzf linux_hardening_tool.tar.gz
   cd linux_hardening_tool
   ```

2. **Run the installer:**
   ```bash
   sudo python3 install.py
   ```

3. **Choose installation mode:**
   - Option 1: CLI only (lightweight)
   - Option 2: Web GUI only
   - Option 3: Both CLI + Web GUI (recommended)

4. **Verify installation:**
   ```bash
   ls -la
   # Should see: hardening-cli, hardening-web, hardening.db
   ```

### Manual Installation

If you prefer manual setup:

```bash
# Create directories
mkdir -p hardening_scripts templates output backups reports remote_logs

# Move files
mv *.sh hardening_scripts/
mv *.html templates/

# Install Python packages
pip3 install Flask werkzeug paramiko

# Initialize database
python3 -c "import sqlite3; conn = sqlite3.connect('hardening.db'); conn.close()"

# Set permissions
chmod +x hardening_scripts/*.sh
chmod +x *.py
```

---

## 📖 Usage

### CLI Mode

#### Interactive Menu

```bash
sudo ./hardening-cli
```

**Menu Options:**
- `scan` - Scan security topics
- `fix` - Apply hardening fixes
- `rollback` - Revert changes
- `report` - Generate audit report
- `status` - View current status
- `all` - Scan all topics at once
- `exit` - Exit the tool

#### Command Line Mode

```bash
# Scan all topics
sudo ./hardening-cli scan-all

# Generate report
sudo ./hardening-cli report

# Check status
sudo ./hardening-cli status

# Scan specific topic
sudo ./hardening-cli scan filesystem

# Fix specific topic
sudo ./hardening-cli fix network
```

#### Example Workflow

```bash
# 1. Initial scan
sudo ./hardening-cli
> scan
> 1    # Select Filesystem

# 2. Review results
cat output/Filesystem_scan_*.txt

# 3. Apply fixes
sudo ./hardening-cli
> fix
> 1    # Apply Filesystem fixes

# 4. Verify changes
sudo ./hardening-cli
> scan
> 1    # Rescan to confirm

# 5. Generate report
sudo ./hardening-cli
> report
```

---

### Web GUI Mode

#### Starting the Web Server

```bash
sudo ./hardening-web
```

**Access:** http://localhost:5000

**Default Credentials:**
- Username: `admin`
- Password: `changeme123`

⚠️ **CRITICAL:** Change the default password immediately in `.env` file!

#### Dashboard Features

**Main Dashboard:**
- Security status overview
- Topic-by-topic progress
- Quick action buttons
- Real-time statistics

**Available Actions:**
1. **Scan** - Check security compliance
2. **Fix** - Apply hardening measures
3. **Rollback** - Undo changes
4. **View Results** - See detailed findings
5. **Export Report** - Download PDF/TXT report

#### Remote System Control

1. **Navigate to Remote Control** panel
2. **Enter SSH credentials:**
   - Hostname/IP address
   - SSH username
   - Private key path
3. **Connect** to remote system
4. **Execute** hardening operations remotely
5. **View logs** in real-time

#### Screenshots

![Dashboard](docs/dashboard.png)
![Remote Control](docs/remote.png)

---

## 🛡️ Security Topics

The tool covers **9 critical security areas:**

### 1. **Filesystem Security**
- File and directory permissions
- Mount options (noexec, nosuid, nodev)
- World-writable file checks
- Critical system file permissions (/etc/passwd, /etc/shadow)

### 2. **Network Security**
- IP forwarding configuration
- ICMP redirects
- Source routing
- TCP SYN cookies
- Reverse path filtering

### 3. **Host-Based Firewall**
- UFW configuration
- iptables rules
- Default deny policies
- Open port management
- Loopback traffic rules

### 4. **Services Hardening**
- Disable unnecessary services
- Secure running services
- Service configuration hardening
- Daemon security

### 5. **Access Control**
- PAM configuration
- sudo policies
- Login restrictions
- Session limits

### 6. **User Accounts**
- Password policies
- Account lockout
- Password aging
- Inactive account handling
- Root account security

### 7. **Logging & Auditing**
- Syslog configuration
- Audit daemon setup
- Log rotation
- Remote logging
- File integrity monitoring

### 8. **System Maintenance**
- Automatic updates
- Patch management
- Backup verification
- Cron job security

### 9. **Kernel Security**
- Kernel parameters (sysctl)
- Address space layout randomization (ASLR)
- Core dumps
- Kernel module restrictions

---

## 📂 File Structure

```
linux_hardening_tool/
│
├── install.py                    # Unified installer script
├── hardening-cli                 # CLI launcher
├── hardening-web                 # Web launcher
│
├── complete_unified_app.py       # Flask web application
├── hardening_controller.py       # Python controller
├── hardening.db                  # SQLite database
│
├── requirements.txt              # Python dependencies
├── .env                          # Environment configuration
├── README.md                     # This file
│
├── hardening_scripts/            # Shell hardening scripts
│   ├── filesystem_hardening.sh
│   ├── network_hardening.sh
│   ├── firewall.sh
│   ├── service_hardening.sh
│   ├── auth_hardening.sh
│   ├── user_accounts.sh
│   ├── logging_auditing.sh
│   ├── system_maintenance.sh
│   └── kernel_hardening.sh
│
├── templates/                    # HTML templates (web mode)
│   ├── dashboard.html
│   ├── login.html
│   ├── remote_control.html
│   ├── error.html
│   ├── 404.html
│   └── 500.html
│
├── output/                       # Scan results and logs
│   └── [timestamp]_scan.txt
│
├── backups/                      # Configuration backups
│   ├── filesystem/
│   ├── network/
│   └── [other topics]/
│
├── reports/                      # Generated audit reports
│   └── hardening_report_[timestamp].txt
│
└── remote_logs/                  # Remote operation logs
    └── [host]_[action]_[timestamp].log
```

---

## ⚙️ Configuration

### Environment Variables (.env)

```bash
# Flask Configuration
FLASK_SECRET_KEY=<random_hex_key>      # Auto-generated
FLASK_DEBUG=False                      # Set True for debugging
FLASK_HOST=0.0.0.0                     # Listen on all interfaces
FLASK_PORT=5000                        # Web server port

# Admin Credentials
ADMIN_USER=admin                       # Change this!
ADMIN_PASS=changeme123                 # Change this immediately!

# Database
DB_PATH=hardening.db                   # SQLite database location
```

### Changing Admin Password

**Method 1: Edit .env file**
```bash
nano .env
# Change: ADMIN_PASS=your_secure_password
```

**Method 2: Use environment variables**
```bash
export ADMIN_USER=myadmin
export ADMIN_PASS=MySecurePassword123!
sudo ./hardening-web
```

### Network Configuration

**Allow remote access:**
```bash
# Edit .env
FLASK_HOST=0.0.0.0  # Listen on all interfaces
FLASK_PORT=8080     # Custom port

# Update firewall
sudo ufw allow 8080/tcp
```

**Restrict to local only:**
```bash
# Edit .env
FLASK_HOST=127.0.0.1  # Localhost only
```

---

## 🔧 Advanced Usage

### Automation with Cron

```bash
# Daily security scan at 2 AM
0 2 * * * /path/to/hardening-cli scan-all >> /var/log/hardening_scan.log 2>&1

# Weekly report generation
0 3 * * 0 /path/to/hardening-cli report >> /var/log/hardening_report.log 2>&1

# Monthly full hardening
0 4 1 * * /path/to/hardening-cli fix-all >> /var/log/hardening_fix.log 2>&1
```

### Integration with CI/CD

```yaml
# GitLab CI example
security_scan:
  stage: test
  script:
    - sudo ./hardening-cli scan-all
    - sudo ./hardening-cli report
  artifacts:
    paths:
      - reports/
```

### API Usage (Web Mode)

```bash
# Get system status
curl -u admin:password http://localhost:5000/api/status

# Trigger scan
curl -u admin:password -X POST http://localhost:5000/scan/filesystem

# Get task status
curl -u admin:password http://localhost:5000/task_status/TASK_ID
```

### Custom Scripts

Add your own hardening scripts:

1. Create script: `my_custom_hardening.sh`
2. Place in: `hardening_scripts/`
3. Update `hardening_controller.py` topics dictionary:
   ```python
   "custom": {
       "name": "Custom Security",
       "description": "My custom checks",
       "script": "my_custom_hardening.sh",
       "severity": "medium"
   }
   ```

---

## 🐛 Troubleshooting

### Common Issues

#### "Permission denied" errors

**Problem:** Script can't modify system files

**Solution:**
```bash
# Ensure running as root
sudo ./hardening-cli
sudo ./hardening-web
```

#### "Module not found" errors

**Problem:** Python dependencies not installed

**Solution:**
```bash
pip3 install -r requirements.txt
# or
pip3 install Flask werkzeug paramiko
```

#### Web interface not accessible

**Problem:** Firewall blocking port 5000

**Solution:**
```bash
# Allow port through firewall
sudo ufw allow 5000/tcp

# Or use different port in .env
FLASK_PORT=8080
```

#### Remote features disabled

**Problem:** Paramiko not installed

**Solution:**
```bash
pip3 install paramiko
```

#### Database locked errors

**Problem:** Multiple instances running

**Solution:**
```bash
# Kill existing processes
pkill -f hardening_controller
pkill -f complete_unified_app

# Restart
sudo ./hardening-cli
```

#### Scripts not executable

**Problem:** Permission denied when running scripts

**Solution:**
```bash
chmod +x hardening_scripts/*.sh
chmod +x hardening-cli
chmod +x hardening-web
```

### Logs and Debugging

**Enable debug mode:**
```bash
# Edit .env
FLASK_DEBUG=True
```

**Check logs:**
```bash
# Scan logs
ls -lh output/

# View latest scan
cat output/*_scan_*.txt | tail -50

# Check database
sqlite3 hardening.db "SELECT * FROM audit_log ORDER BY id DESC LIMIT 10;"
```

**Reset everything:**
```bash
# Backup current database
cp hardening.db hardening.db.backup

# Reinstall
sudo python3 install.py
```

---

## 🔐 Security Best Practices

### Before Using in Production

1. **Test in Staging**
   - Run all scans in test environment first
   - Review proposed changes carefully
   - Test rollback procedures

2. **Backup Critical Files**
   ```bash
   tar -czf system_backup_$(date +%F).tar.gz /etc /var /home
   ```

3. **Change Default Credentials**
   ```bash
   nano .env
   # Set strong ADMIN_PASS
   ```

4. **Enable HTTPS (Production)**
   ```bash
   # Use reverse proxy (nginx/apache)
   # Or generate SSL certificates
   ```

5. **Restrict Access**
   ```bash
   # Firewall rules
   sudo ufw deny 5000/tcp
   sudo ufw allow from 192.168.1.0/24 to any port 5000
   ```

### Hardening the Tool Itself

```bash
# Secure file permissions
chmod 600 .env
chmod 600 hardening.db
chmod 700 backups/

# Run as non-root user (scan only)
sudo -u secaudit ./hardening-cli

# Use AppArmor/SELinux profiles
# Create dedicated service account
useradd -r -s /bin/false hardening_svc
```

### Audit Trail

All actions are logged:
```bash
# View audit log
sqlite3 hardening.db "SELECT * FROM audit_log;"

# Export audit log
sqlite3 hardening.db "SELECT * FROM audit_log;" > audit_trail.txt
```

---

## 📊 Database Schema

### Tables

**configurations**
- Stores all configuration changes
- Tracks original and current values
- Maintains rollback information

**scan_history**
- Records all scan operations
- Tracks pass/fail/warning counts
- Historical trend analysis

**audit_log**
- Complete audit trail
- User actions and timestamps
- Change tracking

### Querying the Database

```bash
# View all configurations
sqlite3 hardening.db "SELECT * FROM configurations;"

# View failed checks
sqlite3 hardening.db "SELECT * FROM configurations WHERE status='pending';"

# View recent scans
sqlite3 hardening.db "SELECT * FROM scan_history ORDER BY scan_date DESC LIMIT 5;"

# View audit trail
sqlite3 hardening.db "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 20;"
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/new-hardening-check
   ```
3. **Test thoroughly**
4. **Submit pull request**

### Adding New Security Checks

1. Create shell script in `hardening_scripts/`
2. Follow existing format (scan/fix/rollback modes)
3. Update `hardening_controller.py` topics dictionary
4. Test in isolated environment
5. Document in README

---

## 📄 License

**Enterprise Edition** - For authorized use only

This tool is designed for security professionals and system administrators. Use responsibly and only on systems you own or have permission to audit.

---

## 📞 Support

For issues, questions, or feature requests:
- Check troubleshooting section above
- Review logs in `output/` directory
- Check database: `sqlite3 hardening.db`
- Enable debug mode for detailed output

---

## ⚠️ Disclaimer

This tool modifies system configurations and should be used with caution. Always:
- Test in non-production environments first
- Review proposed changes before applying
- Maintain backups of critical systems
- Understand the impact of each hardening measure

The authors are not responsible for any damage or data loss resulting from the use of this tool.

---

## 🎯 Roadmap

**Planned Features:**
- [ ] Integration with vulnerability scanners
- [ ] Compliance frameworks (CIS, STIG, PCI-DSS)
- [ ] Container security hardening
- [ ] Cloud platform support (AWS, Azure, GCP)
- [ ] Automated remediation workflows
- [ ] Multi-tenancy support
- [ ] REST API for integrations
- [ ] Mobile app for monitoring

---

**Made with 🔒 for better Linux security**

**Version:** 4.0 Enterprise Edition  
**Last Updated:** 2024  
**Maintainer:** Security Team

---

*For the latest updates and documentation, visit the project repository.*
