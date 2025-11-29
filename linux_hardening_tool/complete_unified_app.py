#!/usr/bin/env python3
"""
Linux System Hardening Tool - Complete Unified Web Interface
Supports: Local Hardening + Remote Control + Beautiful GUI
Version: 2.0 Enterprise Edition
"""

from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for, flash
import os
import hashlib
import json
import datetime
import secrets
import sqlite3
import subprocess
import threading
import time
from pathlib import Path
from werkzeug.utils import secure_filename
from functools import wraps

# Try to import paramiko for remote operations
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    print("[WARNING] paramiko not installed - remote features will be disabled")
    print("[INFO] Install with: pip install paramiko")

# Import the hardening controller
try:
    from hardening_controller import HardeningController
    hardening = HardeningController()
except Exception as e:
    print(f"[ERROR] Failed to initialize HardeningController: {e}")
    hardening = None

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload

# Configuration
BASE_DIR = Path(__file__).parent
SCRIPTS_FOLDER = BASE_DIR / "hardening_scripts"
REPORT_FOLDER = BASE_DIR / "reports"
OUTPUT_FOLDER = BASE_DIR / "output"
BACKUP_FOLDER = BASE_DIR / "backups"
REMOTE_LOGS_FOLDER = BASE_DIR / "remote_logs"
ALLOWED_EXTENSIONS = {'.json', '.txt', '.log', '.sh', '.py'}

# Create all directories
for folder in [REPORT_FOLDER, OUTPUT_FOLDER, BACKUP_FOLDER, REMOTE_LOGS_FOLDER]:
    folder.mkdir(exist_ok=True)

# Authentication credentials (CHANGE IN PRODUCTION!)
ADMIN_USER = os.getenv('ADMIN_USER', 'admin')
ADMIN_PASS = os.getenv('ADMIN_PASS', 'changeme123')

# Task tracking
task_status = {}
remote_sessions = {}

# ============================================================================
# Authentication & Security
# ============================================================================

def login_required(f):
    """Decorator for route protection"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def check_auth():
    """Check if user is authenticated"""
    return session.get('authenticated', False)

# ============================================================================
# Utility Functions
# ============================================================================

def parse_script_output(output_text):
    """Parse hardening script output into structured data"""
    rules = {}
    lines = output_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("Rule ID:"):
            rule_id = line.split("Rule ID:")[1].strip()
            status = "UNKNOWN"
            description = ""
            for j in range(1, 4):
                if i + j < len(lines):
                    next_line = lines[i + j].strip()
                    if next_line.startswith("[PASS]"):
                        status = "PASS"
                        description = next_line[6:].strip()
                        break
                    elif next_line.startswith("[FAIL]"):
                        status = "FAIL"
                        description = next_line[6:].strip()
                        break
                    elif next_line.startswith("[WARN]"):
                        status = "WARN"
                        description = next_line[6:].strip()
                        break
                    elif next_line.startswith("[INFO]"):
                        status = "INFO"
                        description = next_line[6:].strip()
                        break
            rules[rule_id] = {"status": status, "description": description}
        i += 1
    return rules

def get_latest_output_for_topic(topic_id):
    """Get latest output file for a topic"""
    try:
        if not hardening:
            return None
        topic_info = hardening.topics.get(topic_id)
        if not topic_info:
            return None
        
        topic_name = topic_info['name'].replace(' ', '_')
        matching_files = list(OUTPUT_FOLDER.glob(f"{topic_name}_scan_*.txt"))
        
        if not matching_files:
            return None
        
        latest_file = max(matching_files, key=lambda p: p.stat().st_mtime)
        return latest_file
    except Exception as e:
        print(f"[ERROR] Failed to get latest output: {e}")
        return None

def get_db_summary():
    """Get hardening status summary from database"""
    if not hardening:
        return {}
    
    try:
        conn = sqlite3.connect(hardening.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT topic, COUNT(*) as total,
                   SUM(CASE WHEN status = 'fixed' THEN 1 ELSE 0 END) as fixed
            FROM configurations
            GROUP BY topic
        ''')
        
        db_summary = {}
        for row in cursor.fetchall():
            db_summary[row[0]] = {"total": row[1], "fixed": row[2]}
        
        conn.close()
        return db_summary
    except Exception as e:
        print(f"[ERROR] Database query failed: {e}")
        return {}

# ============================================================================
# Authentication Routes
# ============================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page"""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        
        if username == ADMIN_USER and password == ADMIN_PASS:
            session['authenticated'] = True
            session['username'] = username
            session['login_time'] = datetime.datetime.now().isoformat()
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials!', 'error')
            return render_template("login.html", error="Invalid credentials")
    
    return render_template("login.html")

@app.route("/logout")
def logout():
    """Logout"""
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))

# ============================================================================
# Main Dashboard Routes
# ============================================================================

@app.route("/")
@login_required
def index():
    """Main dashboard - shows both local and remote options"""
    if not hardening:
        return render_template("error.html", 
                             error="Hardening controller not initialized",
                             message="Please check hardening_controller.py")
    
    topics = hardening.topics
    db_summary = get_db_summary()
    
    # Calculate overall stats
    total_checks = sum(v["total"] for v in db_summary.values())
    passed_checks = sum(v["fixed"] for v in db_summary.values())
    failed_checks = total_checks - passed_checks
    
    return render_template(
        "dashboard.html",
        topics=topics,
        db_summary=db_summary,
        total_checks=total_checks,
        passed_checks=passed_checks,
        failed_checks=failed_checks,
        username=session.get('username', 'Admin'),
        paramiko_available=PARAMIKO_AVAILABLE,
        is_root=(os.geteuid() == 0)
    )

# ============================================================================
# Local Hardening Routes
# ============================================================================

@app.route("/scan/<topic_id>")
@login_required
def scan_topic(topic_id):
    """Scan a specific topic locally"""
    if not hardening or topic_id not in hardening.topics:
        return jsonify({"error": "Invalid topic ID"}), 400
    
    task_id = f"local_scan_{topic_id}_{int(time.time())}"
    task_status[task_id] = {"status": "running", "progress": 0, "type": "local"}
    
    def run_scan():
        try:
            success = hardening.run_script(topic_id, 'scan')
            task_status[task_id] = {
                "status": "completed" if success else "failed",
                "progress": 100,
                "type": "local"
            }
        except Exception as e:
            task_status[task_id] = {
                "status": "error",
                "progress": 0,
                "error": str(e),
                "type": "local"
            }
    
    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        "task_id": task_id,
        "message": f"Scanning {hardening.topics[topic_id]['name']}...",
        "type": "local"
    })

@app.route("/fix/<topic_id>")
@login_required
def fix_topic(topic_id):
    """Fix issues in a specific topic locally"""
    if not hardening or topic_id not in hardening.topics:
        return jsonify({"error": "Invalid topic ID"}), 400
    
    if os.geteuid() != 0:
        return jsonify({
            "error": "Root privileges required",
            "message": "Please run: sudo python3 app.py"
        }), 403
    
    task_id = f"local_fix_{topic_id}_{int(time.time())}"
    task_status[task_id] = {"status": "running", "progress": 0, "type": "local"}
    
    def run_fix():
        try:
            success = hardening.run_script(topic_id, 'fix')
            task_status[task_id] = {
                "status": "completed" if success else "failed",
                "progress": 100,
                "type": "local"
            }
        except Exception as e:
            task_status[task_id] = {
                "status": "error",
                "progress": 0,
                "error": str(e),
                "type": "local"
            }
    
    thread = threading.Thread(target=run_fix)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        "task_id": task_id,
        "message": f"Fixing {hardening.topics[topic_id]['name']}...",
        "type": "local"
    })

@app.route("/rollback/<topic_id>")
@login_required
def rollback_topic(topic_id):
    """Rollback fixes for a specific topic locally"""
    if not hardening or topic_id not in hardening.topics:
        return jsonify({"error": "Invalid topic ID"}), 400
    
    if os.geteuid() != 0:
        return jsonify({"error": "Root privileges required"}), 403
    
    task_id = f"local_rollback_{topic_id}_{int(time.time())}"
    task_status[task_id] = {"status": "running", "progress": 0, "type": "local"}
    
    def run_rollback():
        try:
            success = hardening.rollback_topic(topic_id)
            task_status[task_id] = {
                "status": "completed" if success else "failed",
                "progress": 100,
                "type": "local"
            }
        except Exception as e:
            task_status[task_id] = {
                "status": "error",
                "progress": 0,
                "error": str(e),
                "type": "local"
            }
    
    thread = threading.Thread(target=run_rollback)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        "task_id": task_id,
        "message": f"Rolling back {hardening.topics[topic_id]['name']}...",
        "type": "local"
    })

@app.route("/scan_all")
@login_required
def scan_all():
    """Scan all topics locally"""
    if not hardening:
        return jsonify({"error": "Controller not initialized"}), 500
    
    task_id = f"local_scan_all_{int(time.time())}"
    task_status[task_id] = {"status": "running", "progress": 0, "type": "local"}
    
    def run_scan_all():
        try:
            total = len(hardening.topics)
            for idx, topic_id in enumerate(hardening.topics.keys()):
                hardening.run_script(topic_id, 'scan')
                task_status[task_id]["progress"] = int((idx + 1) / total * 100)
            
            task_status[task_id] = {
                "status": "completed",
                "progress": 100,
                "type": "local"
            }
        except Exception as e:
            task_status[task_id] = {
                "status": "error",
                "progress": 0,
                "error": str(e),
                "type": "local"
            }
    
    thread = threading.Thread(target=run_scan_all)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        "task_id": task_id,
        "message": "Scanning all topics...",
        "type": "local"
    })

# ============================================================================
# Remote Control Routes
# ============================================================================

@app.route("/remote")
@login_required
def remote_control():
    """Remote control panel"""
    if not PARAMIKO_AVAILABLE:
        flash('Paramiko library not installed. Install with: pip install paramiko', 'error')
    
    return render_template("remote_control.html", 
                         paramiko_available=PARAMIKO_AVAILABLE,
                         username=session.get('username'))

@app.route("/remote/connect", methods=["POST"])
@login_required
def remote_connect():
    """Connect to remote host"""
    if not PARAMIKO_AVAILABLE:
        return jsonify({"error": "Paramiko not installed"}), 400
    
    data = request.json
    host = data.get('host')
    username = data.get('username')
    key_path = data.get('key_path', '~/.ssh/id_ed25519')
    
    if not host or not username:
        return jsonify({"error": "Host and username required"}), 400
    
    session_id = f"remote_{host}_{int(time.time())}"
    
    def connect_ssh():
        try:
            key_path_expanded = os.path.expanduser(key_path)
            
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            private_key = paramiko.Ed25519Key.from_private_key_file(key_path_expanded)
            
            ssh_client.connect(
                hostname=host,
                username=username,
                pkey=private_key,
                timeout=10
            )
            
            remote_sessions[session_id] = {
                "client": ssh_client,
                "host": host,
                "username": username,
                "status": "connected"
            }
            
            task_status[session_id] = {
                "status": "completed",
                "message": f"Connected to {host}",
                "type": "remote"
            }
        except Exception as e:
            task_status[session_id] = {
                "status": "error",
                "error": str(e),
                "type": "remote"
            }
    
    task_status[session_id] = {"status": "running", "type": "remote"}
    
    thread = threading.Thread(target=connect_ssh)
    thread.daemon = True
    thread.start()
    
    return jsonify({"session_id": session_id})

@app.route("/remote/execute", methods=["POST"])
@login_required
def remote_execute():
    """Execute command on remote host"""
    if not PARAMIKO_AVAILABLE:
        return jsonify({"error": "Paramiko not installed"}), 400
    
    data = request.json
    session_id = data.get('session_id')
    action = data.get('action')
    topic_id = data.get('topic_id')
    
    if session_id not in remote_sessions:
        return jsonify({"error": "Session not found"}), 404
    
    task_id = f"remote_{action}_{topic_id}_{int(time.time())}"
    
    def execute_remote():
        try:
            ssh_client = remote_sessions[session_id]["client"]
            host = remote_sessions[session_id]["host"]
            
            # Ensure remote directory exists
            remote_dir = "/tmp/hardening_remote"
            ssh_client.exec_command(f"mkdir -p {remote_dir}")
            
            # Transfer controller and scripts (simplified for demo)
            command = f"cd {remote_dir} && sudo python3 hardening_controller.py {action}"
            
            stdin, stdout, stderr = ssh_client.exec_command(command, timeout=300)
            exit_code = stdout.channel.recv_exit_status()
            
            output = stdout.read().decode('utf-8')
            errors = stderr.read().decode('utf-8')
            
            # Save output
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = REMOTE_LOGS_FOLDER / f"{host}_{action}_{timestamp}.log"
            
            with open(log_file, 'w') as f:
                f.write(f"Host: {host}\n")
                f.write(f"Action: {action}\n")
                f.write(f"Exit Code: {exit_code}\n")
                f.write(f"{'='*70}\n\n")
                f.write(output)
                if errors:
                    f.write(f"\n\nErrors:\n{errors}")
            
            task_status[task_id] = {
                "status": "completed" if exit_code == 0 else "failed",
                "output": output,
                "errors": errors,
                "log_file": str(log_file.name),
                "type": "remote"
            }
        except Exception as e:
            task_status[task_id] = {
                "status": "error",
                "error": str(e),
                "type": "remote"
            }
    
    task_status[task_id] = {"status": "running", "type": "remote"}
    
    thread = threading.Thread(target=execute_remote)
    thread.daemon = True
    thread.start()
    
    return jsonify({"task_id": task_id})

@app.route("/remote/disconnect/<session_id>", methods=["POST"])
@login_required
def remote_disconnect(session_id):
    """Disconnect from remote host"""
    if session_id in remote_sessions:
        try:
            remote_sessions[session_id]["client"].close()
            del remote_sessions[session_id]
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    return jsonify({"error": "Session not found"}), 404

# ============================================================================
# Status & Monitoring Routes
# ============================================================================

@app.route("/task_status/<task_id>")
@login_required
def get_task_status(task_id):
    """Get status of background task"""
    status = task_status.get(task_id, {"status": "not_found"})
    return jsonify(status)

@app.route("/view_output/<topic_id>")
@login_required
def view_output(topic_id):
    """View latest output for a topic"""
    output_file = get_latest_output_for_topic(topic_id)
    
    if not output_file or not output_file.exists():
        return jsonify({"error": "No output found"}), 404
    
    try:
        with open(output_file, 'r') as f:
            content = f.read()
        
        rules = parse_script_output(content)
        
        return jsonify({
            "topic": hardening.topics[topic_id]['name'],
            "file": output_file.name,
            "rules": rules,
            "raw_output": content
        })
    except Exception as e:
        return jsonify({"error": f"Failed to read output: {str(e)}"}), 500

@app.route("/api/status")
@login_required
def api_status():
    """API endpoint for overall status"""
    db_summary = get_db_summary()
    
    results = []
    for topic_name, data in db_summary.items():
        results.append({
            "topic": topic_name,
            "total": data["total"],
            "fixed": data["fixed"],
            "percentage": round((data["fixed"] / data["total"] * 100) if data["total"] > 0 else 0, 1)
        })
    
    return jsonify({"status": results})

# ============================================================================
# Report & Export Routes
# ============================================================================

@app.route("/export_report")
@login_required
def export_report():
    """Export comprehensive report"""
    if not hardening:
        return jsonify({"error": "Controller not initialized"}), 500
    
    hardening.export_report()
    
    report_files = list(OUTPUT_FOLDER.glob("hardening_report_*.txt"))
    if report_files:
        latest_report = max(report_files, key=lambda p: p.stat().st_mtime)
        return send_file(latest_report, as_attachment=True)
    
    return jsonify({"error": "No report generated"}), 500

@app.route("/download/<path:filename>")
@login_required
def download_file(filename):
    """Secure file download"""
    safe_filename = secure_filename(filename)
    
    # Check in multiple directories
    for directory in [REPORT_FOLDER, OUTPUT_FOLDER, REMOTE_LOGS_FOLDER]:
        file_path = directory / safe_filename
        if file_path.exists() and file_path.suffix in ALLOWED_EXTENSIONS:
            return send_file(file_path, as_attachment=True)
    
    return jsonify({"error": "File not found"}), 404

# ============================================================================
# Context Processor
# ============================================================================

@app.context_processor
def inject_globals():
    """Make variables available to all templates"""
    return {
        'datetime': datetime,
        'paramiko_available': PARAMIKO_AVAILABLE,
        'is_root': os.geteuid() == 0
    }

# ============================================================================
# Error Handlers
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({"error": "Not found"}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    if request.path.startswith('/api/'):
        return jsonify({"error": "Internal server error"}), 500
    return render_template('500.html'), 500

# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    print("\n" + "="*70)
    print("🔒 Linux System Hardening Tool - Enterprise Edition")
    print("="*70)
    print("\n⚠️  SECURITY CHECKLIST:")
    print("  1. Change default credentials (ADMIN_USER/ADMIN_PASS)")
    print("  2. Use environment variables for secrets")
    print("  3. Enable HTTPS in production")
    print("  4. Restrict network access")
    print("  5. Keep audit logs")
    print("="*70)
    print("\n📊 Features Available:")
    print("  ✓ Local System Hardening")
    if PARAMIKO_AVAILABLE:
        print("  ✓ Remote Control (SSH)")
    else:
        print("  ✗ Remote Control (install paramiko)")
    print("  ✓ Real-time Monitoring")
    print("  ✓ Comprehensive Reporting")
    print("="*70)
    print("\n🚀 Starting Server...")
    
    if os.geteuid() == 0:
        print("  ✓ Running with root privileges")
    else:
        print("  ⚠  Not running as root - fix/rollback limited")
    
    print(f"  🌐 Access at: http://localhost:5000")
    print(f"  👤 Login: {ADMIN_USER} / {ADMIN_PASS}")
    print("="*70 + "\n")
    
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=debug_mode,
        threaded=True
    )
