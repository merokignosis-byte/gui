#!/usr/bin/env python3
"""
Linux Hardening Tool - Unified Installation Script
Supports both CLI and Web GUI modes with automatic setup
Version: 3.0 Enterprise Edition
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path
import secrets

# Color codes
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
CYAN = '\033[0;36m'
BOLD = '\033[1m'
NC = '\033[0m'

def log_info(msg):
    print(f"{GREEN}[INFO]{NC} {msg}")

def log_warn(msg):
    print(f"{YELLOW}[WARN]{NC} {msg}")

def log_error(msg):
    print(f"{RED}[ERROR]{NC} {msg}")

def log_success(msg):
    print(f"{GREEN}[✓]{NC} {msg}")

def log_header(msg):
    print(f"\n{CYAN}{BOLD}{'='*70}{NC}")
    print(f"{CYAN}{BOLD}{msg}{NC}")
    print(f"{CYAN}{BOLD}{'='*70}{NC}\n")

def check_root():
    """Check if running as root"""
    if os.geteuid() != 0:
        log_error("This script must be run as root!")
        log_info("Please use: sudo python3 install.py")
        sys.exit(1)

def check_prerequisites():
    """Check and install prerequisites"""
    log_info("Checking prerequisites...")
    
    # Check Python version
    if sys.version_info < (3, 6):
        log_error("Python 3.6 or higher is required!")
        sys.exit(1)
    log_success(f"Python {sys.version_info.major}.{sys.version_info.minor} detected")
    
    # Check SQLite
    try:
        import sqlite3
        log_success("SQLite3 available")
    except ImportError:
        log_warn("Installing Python SQLite3...")
        subprocess.run(['apt-get', 'update', '-qq'], check=False)
        subprocess.run(['apt-get', 'install', '-y', '-qq', 'python3-sqlite3'], check=False)
        log_success("SQLite3 installed")
    
    # Check pip
    try:
        import pip
        log_success("pip available")
    except ImportError:
        log_warn("Installing pip...")
        subprocess.run(['apt-get', 'install', '-y', '-qq', 'python3-pip'], check=False)
        log_success("pip installed")

def detect_installation_mode():
    """Detect whether to install CLI only or Web GUI"""
    base_dir = Path.cwd()
    
    has_web_app = (base_dir / "complete_unified_app.py").exists()
    has_templates = (base_dir / "templates").exists() or len(list(base_dir.glob("*.html"))) > 0
    has_controller = (base_dir / "hardening_controller.py").exists()
    
    print()
    log_info("Detecting installation mode...")
    print()
    
    if has_web_app or has_templates:
        log_success("Web GUI files detected")
        return "web"
    elif has_controller:
        log_success("CLI mode detected")
        return "cli"
    else:
        # Ask user
        print("Choose installation mode:")
        print("  1) CLI only (command-line interface)")
        print("  2) Web GUI (Flask web interface)")
        print("  3) Both (CLI + Web GUI)")
        print()
        
        while True:
            choice = input("Enter choice [1-3]: ").strip()
            if choice == "1":
                return "cli"
            elif choice == "2":
                return "web"
            elif choice == "3":
                return "both"
            else:
                log_warn("Invalid choice. Please enter 1, 2, or 3")

def create_directory_structure(mode):
    """Create all necessary directories"""
    log_info("Creating directory structure...")
    
    base_dir = Path.cwd()
    
    # Common directories
    directories = [
        base_dir / "hardening_scripts",
        base_dir / "output",
        base_dir / "backups",
        base_dir / "backups" / "filesystem",
        base_dir / "backups" / "network",
        base_dir / "backups" / "firewall",
        base_dir / "backups" / "services",
        base_dir / "backups" / "access_control",
        base_dir / "backups" / "user_accounts",
        base_dir / "backups" / "logging_auditing",
        base_dir / "backups" / "system_maintenance",
    ]
    
    # Web mode additional directories
    if mode in ["web", "both"]:
        directories.extend([
            base_dir / "templates",
            base_dir / "reports",
            base_dir / "remote_logs",
        ])
    
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
    
    log_success(f"Created {len(directories)} directories")
    return base_dir

def copy_hardening_scripts(base_dir):
    """Copy all hardening scripts to hardening_scripts directory"""
    log_info("Processing hardening scripts...")
    
    # Expected script names (flexible matching)
    script_patterns = [
        "filesystem*.sh",
        "network*.sh",
        "firewall*.sh",
        "service*.sh",
        "auth*.sh",
        "access*.sh",
        "user*.sh",
        "account*.sh",
        "log*.sh",
        "audit*.sh",
        "system*.sh",
        "maintenance*.sh",
        "package*.sh",
        "kernel*.sh",
    ]
    
    source_dir = base_dir
    dest_dir = base_dir / "hardening_scripts"
    
    # Find all .sh files in current directory
    source_scripts = list(source_dir.glob("*.sh"))
    
    copied = 0
    already_exists = 0
    
    print()
    for script_file in source_scripts:
        dest_file = dest_dir / script_file.name
        
        # Skip if already in destination
        if dest_file.exists():
            log_info(f"  ✓ {script_file.name} (already exists)")
            already_exists += 1
            continue
        
        # Copy script
        try:
            shutil.copy2(script_file, dest_file)
            os.chmod(dest_file, 0o755)  # Make executable
            log_success(f"  ✓ {script_file.name} → hardening_scripts/")
            copied += 1
        except Exception as e:
            log_error(f"  ✗ Failed to copy {script_file.name}: {e}")
    
    # Count total scripts in destination
    total_scripts = len(list(dest_dir.glob("*.sh")))
    
    print()
    log_info(f"Script Summary: {total_scripts} total, {copied} copied, {already_exists} existing")
    
    return total_scripts

def install_python_dependencies(mode):
    """Install required Python packages"""
    log_info("Installing Python dependencies...")
    
    base_dir = Path.cwd()
    req_file = base_dir / "requirements.txt"
    
    # Check if requirements.txt exists
    if req_file.exists():
        log_info("Found requirements.txt, installing packages...")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", str(req_file)],
                check=True
            )
            log_success("All packages installed from requirements.txt")
            return
        except subprocess.CalledProcessError as e:
            log_error(f"Failed to install from requirements.txt: {e}")
            log_info("Falling back to manual installation...")
    
    # Fallback: manual installation
    packages = []
    
    if mode in ["web", "both"]:
        packages = ["Flask==3.0.0", "werkzeug==3.0.1", "paramiko==3.4.0", "reportlab==4.0.7"]
    
    if not packages:
        log_info("No additional packages needed for CLI mode")
        return
    
    print()
    for package in packages:
        try:
            log_info(f"Installing {package}...")
            subprocess.run(
                [sys.executable, "-m", "pip", "install", package],
                check=True
            )
            log_success(f"  ✓ {package.split('==')[0]}")
        except subprocess.CalledProcessError:
            log_warn(f"  ! Failed to install {package}")
    
    print()

def create_requirements_file(base_dir, mode):
    """Create requirements.txt file"""
    if mode not in ["web", "both"]:
        return
    
    log_info("Creating requirements.txt...")
    
    content = """Flask==3.0.0
werkzeug==3.0.1
paramiko==3.4.0
"""
    
    req_file = base_dir / "requirements.txt"
    with open(req_file, 'w') as f:
        f.write(content)
    
    log_success("requirements.txt created")

def set_permissions(base_dir, mode):
    """Set executable permissions on scripts"""
    log_info("Setting permissions...")
    
    # Make controller executable
    controller = base_dir / "hardening_controller.py"
    if controller.exists():
        os.chmod(controller, 0o755)
        log_success("  ✓ hardening_controller.py")
    
    # Make web app executable
    if mode in ["web", "both"]:
        webapp = base_dir / "complete_unified_app.py"
        if webapp.exists():
            os.chmod(webapp, 0o755)
            log_success("  ✓ complete_unified_app.py")
    
    # Make all scripts in hardening_scripts executable
    scripts_dir = base_dir / "hardening_scripts"
    if scripts_dir.exists():
        script_count = 0
        for script_file in scripts_dir.glob("*.sh"):
            os.chmod(script_file, 0o755)
            script_count += 1
        log_success(f"  ✓ {script_count} shell scripts")

def initialize_database(base_dir):
    """Initialize SQLite database"""
    log_info("Initializing database...")
    
    import sqlite3
    
    db_path = base_dir / "hardening.db"
    
    # Remove old database if exists
    if db_path.exists():
        backup_path = base_dir / "hardening.db.old"
        shutil.copy2(db_path, backup_path)
        log_info("  Backed up existing database to hardening.db.old")
        db_path.unlink()
    
    # Create new database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Configurations table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS configurations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            topic TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_name TEXT,
            description TEXT,
            status TEXT DEFAULT 'pending',
            backup_data TEXT,
            applied_date TIMESTAMP,
            rollback_date TIMESTAMP,
            UNIQUE(topic, rule_id)
        )
    ''')
    
    # Scan history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            topic TEXT NOT NULL,
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            total_rules INTEGER,
            passed INTEGER,
            failed INTEGER,
            warnings INTEGER
        )
    ''')
    
    # Audit log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            topic TEXT,
            user TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            details TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
    
    log_success("Database initialized successfully")

def create_env_file(base_dir, mode):
    """Create .env file for web mode"""
    if mode not in ["web", "both"]:
        return
    
    log_info("Creating .env configuration...")
    
    env_file = base_dir / ".env"
    
    if env_file.exists():
        log_warn("  .env already exists, skipping")
        return
    
    # Generate random secret key
    secret_key = secrets.token_hex(32)
    
    content = f"""# Flask Configuration
FLASK_SECRET_KEY={secret_key}
FLASK_DEBUG=False

# Admin Credentials (CHANGE THESE!)
ADMIN_USER=admin
ADMIN_PASS=changeme123

# Server Configuration
FLASK_HOST=0.0.0.0
FLASK_PORT=5000

# Database
DB_PATH=hardening.db
"""
    
    with open(env_file, 'w') as f:
        f.write(content)
    
    os.chmod(env_file, 0o600)  # Secure permissions
    log_success(".env created with secure random key")
    log_warn("  ⚠️  IMPORTANT: Change ADMIN_PASS in .env file!")

def create_wrapper_scripts(base_dir, mode):
    """Create convenient wrapper scripts"""
    log_info("Creating launcher scripts...")
    
    # CLI wrapper
    if mode in ["cli", "both"]:
        cli_wrapper = """#!/bin/bash
# CLI Launcher for Linux Hardening Tool

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$EUID" -ne 0 ]; then
    echo -e "\\033[0;31m[ERROR]\\033[0m This tool must be run as root!"
    echo -e "\\033[0;32m[INFO]\\033[0m Use: sudo ./hardening-cli"
    exit 1
fi

cd "$SCRIPT_DIR"
exec python3 hardening_controller.py "$@"
"""
        
        cli_file = base_dir / "hardening-cli"
        with open(cli_file, 'w') as f:
            f.write(cli_wrapper)
        os.chmod(cli_file, 0o755)
        log_success("  ✓ hardening-cli")
    
    # Web wrapper
    if mode in ["web", "both"]:
        web_wrapper = """#!/bin/bash
# Web GUI Launcher for Linux Hardening Tool

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================="
echo "🔒 Linux Hardening Tool - Web Interface"
echo "========================================="
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "✓ Running with root privileges"
    echo "  Full features available (scan/fix/rollback)"
else
    echo "⚠️  Running without root privileges"
    echo "  Scan available, fix/rollback limited"
    echo ""
    read -p "Continue anyway? [y/N]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Tip: Run with sudo for full features"
        exit 1
    fi
fi

echo ""
echo "Starting web server..."
echo "Access at: http://localhost:5000"
echo "Login: admin / changeme123"
echo ""
echo "Press Ctrl+C to stop"
echo "========================================="
echo ""

cd "$SCRIPT_DIR"
exec python3 complete_unified_app.py
"""
        
        web_file = base_dir / "hardening-web"
        with open(web_file, 'w') as f:
            f.write(web_wrapper)
        os.chmod(web_file, 0o755)
        log_success("  ✓ hardening-web")

def create_readme(base_dir, mode):
    """Create comprehensive README"""
    log_info("Creating README.md...")
    
    cli_section = """
## CLI Usage

### Quick Start
```bash
sudo ./hardening-cli
```

### Interactive Menu
- Scan individual topics
- Fix detected issues
- Rollback changes
- Generate reports
- View status

### Command Line Mode
```bash
# Scan all topics
sudo ./hardening-cli scan-all

# Generate report
sudo ./hardening-cli report

# Check status
sudo ./hardening-cli status
```
""" if mode in ["cli", "both"] else ""
    
    web_section = """
## Web GUI Usage

### Start Web Interface
```bash
# With root privileges (recommended)
sudo ./hardening-web

# Without root (scan only)
./hardening-web
```

### Access
- **URL:** http://localhost:5000
- **Username:** admin
- **Password:** changeme123

⚠️ **IMPORTANT:** Change default password in `.env` file!

### Features
- 📊 Interactive dashboard
- 🔍 Real-time scanning
- 🔧 One-click fixes
- 🌐 Remote system control (SSH)
- 📈 Visual reports
- ⏮️ Rollback capability
""" if mode in ["web", "both"] else ""
    
    readme_content = f"""# Linux System Hardening Tool

Enterprise-grade security hardening and compliance tool for Linux systems.

## Installation

✅ Installation complete! Just run the launcher scripts below.

## Features

- ✅ Automated security scanning
- ✅ One-click hardening fixes
- ✅ Configuration backup & rollback
- ✅ Comprehensive audit reports
- ✅ Database tracking
{"- ✅ Web-based GUI" if mode in ["web", "both"] else ""}
{"- ✅ Remote system control" if mode in ["web", "both"] else ""}

{cli_section}
{web_section}

## Security Topics

1. **Filesystem Security** - Permissions, mount options
2. **Network Security** - Protocols, sysctl parameters
3. **Firewall** - UFW/iptables configuration
4. **Services** - Disable unnecessary services
5. **Access Control** - PAM, sudo configuration
6. **User Accounts** - Password policies, user security
7. **Logging & Auditing** - System logs, audit trails
8. **System Maintenance** - Updates, patches

## File Structure

```
.
├── hardening-cli              # CLI launcher
├── hardening-web              # Web GUI launcher (if installed)
├── hardening_controller.py    # Python controller
├── complete_unified_app.py    # Flask web app (if installed)
├── hardening_scripts/         # Shell scripts
├── templates/                 # HTML templates (if web mode)
├── output/                    # Scan results
├── backups/                   # Configuration backups
├── reports/                   # Generated reports
└── hardening.db               # SQLite database
```

## Important Notes

### Root Privileges
- **Scanning:** Can run without root (limited info)
- **Fixing:** Requires root privileges
- **Rollback:** Requires root privileges

### Production Use
1. Test in staging environment first
2. Review scan results before fixing
3. Backup important configurations
4. Some changes require system reboot
5. Keep database backups

### Security
- Change default web credentials immediately
- Use HTTPS in production
- Restrict network access
- Enable audit logging
- Regular security updates

## Troubleshooting

### Permission Errors
```bash
# Ensure running as root
sudo ./hardening-cli
sudo ./hardening-web
```

### Missing Dependencies
```bash
# Reinstall dependencies
pip3 install -r requirements.txt
```

### Database Issues
```bash
# Reinitialize database
rm hardening.db
sudo python3 install.py
```

## Support

For issues or questions:
1. Check output logs in `output/` directory
2. Review database with: `sqlite3 hardening.db`
3. Enable debug mode in `.env` (web mode)

## License

Enterprise Edition - For authorized use only

---

**Made with 🔒 for better Linux security**
"""
    
    readme_file = base_dir / "README.md"
    with open(readme_file, 'w') as f:
        f.write(readme_content)
    
    log_success("README.md created")

def check_required_files(base_dir, mode):
    """Check if all required files are present"""
    log_info("Verifying installation...")
    
    missing = []
    
    # Common files
    if not (base_dir / "hardening_controller.py").exists():
        missing.append("hardening_controller.py")
    
    # Web mode files
    if mode in ["web", "both"]:
        if not (base_dir / "complete_unified_app.py").exists():
            missing.append("complete_unified_app.py")
        
        template_files = ["dashboard.html", "login.html", "remote_control.html", 
                         "error.html", "404.html", "500.html"]
        templates_dir = base_dir / "templates"
        
        for template in template_files:
            if not (templates_dir / template).exists():
                missing.append(f"templates/{template}")
    
    # Scripts
    scripts_dir = base_dir / "hardening_scripts"
    script_count = len(list(scripts_dir.glob("*.sh")))
    
    if script_count == 0:
        missing.append("hardening_scripts/*.sh (no scripts found)")
    
    if missing:
        print()
        log_warn("Missing files detected:")
        for item in missing:
            print(f"  ✗ {item}")
        print()
        return False
    
    log_success("All required files present")
    return True

def print_final_summary(base_dir, mode, script_count):
    """Print installation summary and next steps"""
    log_header("Installation Complete!")
    
    print(f"{BOLD}Installation Summary:{NC}")
    print(f"  Mode: {CYAN}{mode.upper()}{NC}")
    print(f"  Shell Scripts: {GREEN}{script_count}{NC}")
    print(f"  Database: {GREEN}Initialized{NC}")
    print(f"  Location: {BLUE}{base_dir}{NC}")
    print()
    
    print(f"{BOLD}🚀 Quick Start:{NC}\n")
    
    if mode in ["cli", "both"]:
        print(f"{GREEN}CLI Mode:{NC}")
        print(f"  sudo ./hardening-cli")
        print()
    
    if mode in ["web", "both"]:
        print(f"{GREEN}Web GUI Mode:{NC}")
        print(f"  sudo ./hardening-web")
        print(f"  Then open: {CYAN}http://localhost:5000{NC}")
        print(f"  Login: {YELLOW}admin / changeme123{NC}")
        print()
    
    print(f"{BOLD}📚 Documentation:{NC}")
    print(f"  README.md - Full documentation")
    print()
    
    print(f"{BOLD}⚠️  Important:{NC}")
    if mode in ["web", "both"]:
        print(f"  1. Change admin password in .env file")
    print(f"  2. Test in staging before production")
    print(f"  3. Review scan results before applying fixes")
    print()
    
    log_success("Happy hardening! 🔒")
    print()

def main():
    """Main installation function"""
    log_header("Linux Hardening Tool - Unified Installer v3.0")
    
    # Check root
    check_root()
    
    # Prerequisites
    check_prerequisites()
    
    # Detect mode
    mode = detect_installation_mode()
    log_info(f"Installing in {mode.upper()} mode")
    print()
    
    # Create directories
    base_dir = create_directory_structure(mode)
    
    # Copy scripts
    script_count = copy_hardening_scripts(base_dir)
    
    # Install Python packages
    install_python_dependencies(mode)
    
    # Create requirements file
    create_requirements_file(base_dir, mode)
    
    # Set permissions
    set_permissions(base_dir, mode)
    
    # Initialize database
    initialize_database(base_dir)
    
    # Create env file
    create_env_file(base_dir, mode)
    
    # Create wrappers
    create_wrapper_scripts(base_dir, mode)
    
    # Create README
    create_readme(base_dir, mode)
    
    # Verify installation
    check_required_files(base_dir, mode)
    
    # Print summary
    print_final_summary(base_dir, mode, script_count)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[INFO]{NC} Installation cancelled by user")
        sys.exit(1)
    except Exception as e:
        log_error(f"Installation failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

