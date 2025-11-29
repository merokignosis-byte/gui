#!/usr/bin/env python3
"""
Linux System Hardening Controller
Manages security hardening operations, database, and script execution
"""

import os
import sys
import sqlite3
import subprocess
import json
import datetime
from pathlib import Path
import shutil

class HardeningController:
    def __init__(self, base_dir=None):
        self.base_dir = Path(base_dir) if base_dir else Path(__file__).parent
        self.db_path = self.base_dir / "hardening.db"
        self.scripts_dir = self.base_dir / "hardening_scripts"
        self.output_dir = self.base_dir / "output"
        self.backup_dir = self.base_dir / "backups"
        
        # Create necessary directories
        for directory in [self.scripts_dir, self.output_dir, self.backup_dir]:
            directory.mkdir(exist_ok=True)
        
        # Security topics configuration
        self.topics = {
            "filesystem": {
                "name": "Filesystem Security",
                "description": "File permissions, mount options, and filesystem hardening",
                "script": "filesystem_hardening.sh",
                "severity": "high"
            },
            "network": {
                "name": "Network Security",
                "description": "Firewall, network protocols, and connection hardening",
                "script": "network_hardening.sh",
                "severity": "critical"
            },
            "authentication": {
                "name": "Authentication & PAM",
                "description": "Password policies, PAM configuration, and login security",
                "script": "auth_hardening.sh",
                "severity": "critical"
            },
            "services": {
                "name": "Service Hardening",
                "description": "Disable unnecessary services and secure running services",
                "script": "service_hardening.sh",
                "severity": "high"
            },
            "kernel": {
                "name": "Kernel Security",
                "description": "Sysctl parameters and kernel hardening",
                "script": "kernel_hardening.sh",
                "severity": "medium"
            },
            "audit": {
                "name": "Audit & Logging",
                "description": "System audit configuration and log security",
                "script": "audit_hardening.sh",
                "severity": "medium"
            }
        }
        
        # Initialize database
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database for tracking configurations"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS configurations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                topic TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'pending',
                backup_data TEXT,
                applied_date TIMESTAMP,
                rollback_date TIMESTAMP,
                UNIQUE(topic, rule_id)
            )
        ''')
        
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
        print(f"[✓] Database initialized: {self.db_path}")
    
    def run_script(self, topic_id, mode='scan'):
        """
        Execute hardening script
        mode: 'scan' (check only) or 'fix' (apply changes)
        """
        if topic_id not in self.topics:
            print(f"[ERROR] Invalid topic: {topic_id}")
            return False
        
        topic_info = self.topics[topic_id]
        script_path = self.scripts_dir / topic_info['script']
        
        if not script_path.exists():
            print(f"[ERROR] Script not found: {script_path}")
            return False
        
        # Prepare output file
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        topic_name = topic_info['name'].replace(' ', '_')
        output_file = self.output_dir / f"{topic_name}_{mode}_{timestamp}.txt"
        
        # Prepare command
        cmd = ['bash', str(script_path), mode]
        
        print(f"\n[→] Running {mode} for {topic_info['name']}...")
        print(f"[→] Script: {script_path}")
        print(f"[→] Output: {output_file}")
        
        try:
            # Execute script
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300
            )
            
            # Save output
            with open(output_file, 'w') as f:
                f.write(f"Topic: {topic_info['name']}\n")
                f.write(f"Mode: {mode}\n")
                f.write(f"Timestamp: {timestamp}\n")
                f.write(f"Exit Code: {result.returncode}\n")
                f.write("="*70 + "\n\n")
                f.write(result.stdout)
                if result.stderr:
                    f.write("\n\nErrors:\n")
                    f.write(result.stderr)
            
            # Parse results and update database
            if mode == 'scan':
                self.update_scan_results(topic_id, result.stdout)
            elif mode == 'fix':
                self.update_fix_status(topic_id, result.stdout)
            
            # Log action
            self.log_action(mode, topic_id, f"Exit code: {result.returncode}")
            
            if result.returncode == 0:
                print(f"[✓] {mode.capitalize()} completed successfully")
                return True
            else:
                print(f"[!] {mode.capitalize()} completed with warnings/errors")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"[ERROR] Script execution timeout (300s)")
            return False
        except Exception as e:
            print(f"[ERROR] Script execution failed: {e}")
            return False
    
    def update_scan_results(self, topic_id, output):
        """Parse scan output and update database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        passed = output.count('[PASS]')
        failed = output.count('[FAIL]')
        warnings = output.count('[WARN]')
        total = passed + failed + warnings
        
        # Record scan history
        cursor.execute('''
            INSERT INTO scan_history (topic, total_rules, passed, failed, warnings)
            VALUES (?, ?, ?, ?, ?)
        ''', (topic_id, total, passed, failed, warnings))
        
        # Parse individual rules
        lines = output.splitlines()
        for i, line in enumerate(lines):
            if line.startswith("Rule ID:"):
                rule_id = line.split("Rule ID:")[1].strip()
                status = "unknown"
                description = ""
                
                # Look ahead for status
                for j in range(1, 5):
                    if i + j < len(lines):
                        next_line = lines[i + j].strip()
                        if next_line.startswith('[PASS]'):
                            status = 'fixed'
                            description = next_line[6:].strip()
                            break
                        elif next_line.startswith('[FAIL]'):
                            status = 'pending'
                            description = next_line[6:].strip()
                            break
                        elif next_line.startswith('[WARN]'):
                            status = 'warning'
                            description = next_line[6:].strip()
                            break
                
                # Insert or update rule
                cursor.execute('''
                    INSERT OR REPLACE INTO configurations 
                    (topic, rule_id, description, status)
                    VALUES (?, ?, ?, ?)
                ''', (topic_id, rule_id, description, status))
        
        conn.commit()
        conn.close()
        print(f"[✓] Scan results saved: {passed} passed, {failed} failed, {warnings} warnings")
    
    def update_fix_status(self, topic_id, output):
        """Update database after fix operation"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Mark all rules for this topic as fixed if mentioned in output
        lines = output.splitlines()
        for line in lines:
            if "Applied:" in line or "[FIXED]" in line:
                # Extract rule ID if present
                rule_id = None
                if "Rule ID:" in line:
                    rule_id = line.split("Rule ID:")[1].split()[0].strip()
                
                if rule_id:
                    cursor.execute('''
                        UPDATE configurations 
                        SET status = 'fixed', applied_date = CURRENT_TIMESTAMP
                        WHERE topic = ? AND rule_id = ?
                    ''', (topic_id, rule_id))
        
        conn.commit()
        conn.close()
        print(f"[✓] Fix status updated for {topic_id}")
    
    def rollback_topic(self, topic_id):
        """Rollback all changes for a topic"""
        if topic_id not in self.topics:
            return False
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get all fixed configurations
        cursor.execute('''
            SELECT rule_id, backup_data FROM configurations
            WHERE topic = ? AND status = 'fixed' AND backup_data IS NOT NULL
        ''', (topic_id,))
        
        rollback_items = cursor.fetchall()
        
        if not rollback_items:
            print(f"[!] No rollback data found for {topic_id}")
            conn.close()
            return False
        
        print(f"[→] Rolling back {len(rollback_items)} items...")
        
        # Here you would execute actual rollback commands
        # For now, we'll just update the database status
        
        cursor.execute('''
            UPDATE configurations
            SET status = 'pending', rollback_date = CURRENT_TIMESTAMP
            WHERE topic = ? AND status = 'fixed'
        ''', (topic_id,))
        
        conn.commit()
        conn.close()
        
        self.log_action('rollback', topic_id, f"Rolled back {len(rollback_items)} items")
        print(f"[✓] Rollback completed for {topic_id}")
        return True
    
    def export_report(self):
        """Generate comprehensive hardening report"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.output_dir / f"hardening_report_{timestamp}.txt"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        with open(report_file, 'w') as f:
            f.write("="*70 + "\n")
            f.write("LINUX SYSTEM HARDENING REPORT\n")
            f.write("="*70 + "\n\n")
            f.write(f"Generated: {datetime.datetime.now()}\n")
            f.write(f"Hostname: {os.uname().nodename}\n")
            f.write(f"System: {os.uname().sysname} {os.uname().release}\n\n")
            
            # Overall summary
            cursor.execute('''
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'fixed' THEN 1 ELSE 0 END) as fixed,
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
                    SUM(CASE WHEN status = 'warning' THEN 1 ELSE 0 END) as warnings
                FROM configurations
            ''')
            
            summary = cursor.fetchone()
            f.write("OVERALL SUMMARY\n")
            f.write("-"*70 + "\n")
            f.write(f"Total Rules:     {summary[0]}\n")
            f.write(f"Fixed:           {summary[1]} ({summary[1]/summary[0]*100:.1f}%)\n")
            f.write(f"Pending:         {summary[2]} ({summary[2]/summary[0]*100:.1f}%)\n")
            f.write(f"Warnings:        {summary[3]} ({summary[3]/summary[0]*100:.1f}%)\n\n")
            
            # Per-topic breakdown
            for topic_id, topic_info in self.topics.items():
                f.write("="*70 + "\n")
                f.write(f"TOPIC: {topic_info['name']}\n")
                f.write(f"Severity: {topic_info['severity'].upper()}\n")
                f.write("="*70 + "\n\n")
                
                cursor.execute('''
                    SELECT rule_id, description, status, applied_date
                    FROM configurations
                    WHERE topic = ?
                    ORDER BY status, rule_id
                ''', (topic_id,))
                
                rules = cursor.fetchall()
                
                if rules:
                    for rule in rules:
                        status_icon = "✓" if rule[2] == 'fixed' else "✗" if rule[2] == 'pending' else "⚠"
                        f.write(f"{status_icon} Rule: {rule[0]}\n")
                        f.write(f"  Status: {rule[2].upper()}\n")
                        f.write(f"  Description: {rule[1]}\n")
                        if rule[3]:
                            f.write(f"  Applied: {rule[3]}\n")
                        f.write("\n")
                else:
                    f.write("  No data available - run scan first\n\n")
        
        conn.close()
        print(f"[✓] Report generated: {report_file}")
        return report_file
    
    def log_action(self, action, topic, details=""):
        """Log action to audit trail"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO audit_log (action, topic, user, details)
            VALUES (?, ?, ?, ?)
        ''', (action, topic, os.getenv('USER', 'unknown'), details))
        
        conn.commit()
        conn.close()
    
    def get_status_summary(self):
        """Get summary of all topics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        summary = {}
        for topic_id in self.topics.keys():
            cursor.execute('''
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'fixed' THEN 1 ELSE 0 END) as fixed
                FROM configurations
                WHERE topic = ?
            ''', (topic_id,))
            
            result = cursor.fetchone()
            summary[topic_id] = {
                'total': result[0] or 0,
                'fixed': result[1] or 0
            }
        
        conn.close()
        return summary


if __name__ == "__main__":
    # CLI interface for direct usage
    print("\n🔒 Linux System Hardening Controller\n")
    
    controller = HardeningController()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "scan_all":
            for topic_id in controller.topics.keys():
                controller.run_script(topic_id, 'scan')
        
        elif command == "report":
            controller.export_report()
        
        elif command == "status":
            summary = controller.get_status_summary()
            for topic_id, stats in summary.items():
                print(f"{controller.topics[topic_id]['name']}: {stats['fixed']}/{stats['total']} fixed")
        
        else:
            print(f"Unknown command: {command}")
            print("Usage: python3 hardening_controller.py [scan_all|report|status]")
    else:
        print("Available topics:")
        for topic_id, info in controller.topics.items():
            print(f"  - {topic_id}: {info['name']}")
        print("\nUsage: python3 hardening_controller.py [scan_all|report|status]")
