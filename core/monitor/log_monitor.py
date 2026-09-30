import os
import time
import threading
import logging
from typing import Dict, List, Any

logger = logging.getLogger("LogMonitor")

class LogMonitor:
    def __init__(self, config: Dict[str, Any]):
        self.config = config.get("log", {})
        self.watch_file = os.path.abspath(self.config.get("watch_file", "./logs/system_logs/auth.log"))
        self.interval = self.config.get("interval", 5.0)
        
        self.running = False
        self._thread = None
        self._generator_thread = None
        self.stats_lock = threading.Lock()
        
        # Log Metrics
        self.failed_login_count = 0
        self.total_scanned_lines = 0
        self.suspicious_entries = []
        
        self.simulated_attack_type = None
        self.last_position = 0

    def start(self):
        # Create directories and file if not present
        os.makedirs(os.path.dirname(self.watch_file), exist_ok=True)
        if not os.path.exists(self.watch_file):
            with open(self.watch_file, 'w') as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] System initialized. Log monitoring activated.\n")
        
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        
        # Start a thread to periodically generate realistic log traffic
        self._generator_thread = threading.Thread(target=self._generate_logs, daemon=True)
        self._generator_thread.start()
        
        logger.info(f"Log Monitor watching log file: {self.watch_file}")

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=2.0)
        if self._generator_thread:
            self._generator_thread.join(timeout=2.0)
        logger.info("Log Monitor stopped.")

    def _run(self):
        # Position at end of file initially
        if os.path.exists(self.watch_file):
            self.last_position = os.path.getsize(self.watch_file)
            
        while self.running:
            try:
                self._scan_new_lines()
            except Exception as e:
                logger.error(f"Error scanning logs: {e}")
            time.sleep(self.interval)

    def _scan_new_lines(self):
        if not os.path.exists(self.watch_file):
            return
            
        current_size = os.path.getsize(self.watch_file)
        if current_size < self.last_position:
            # File was rotated/cleared, reset position
            self.last_position = 0
            
        if current_size == self.last_position:
            return
            
        with open(self.watch_file, 'r', encoding='utf-8', errors='ignore') as f:
            f.seek(self.last_position)
            lines = f.readlines()
            self.last_position = f.tell()
            
        with self.stats_lock:
            self.total_scanned_lines += len(lines)
            for line in lines:
                line_str = line.strip()
                if not line_str:
                    continue
                    
                # Scan for keywords
                is_suspicious = False
                lower_line = line_str.lower()
                
                # Threat matching patterns
                if "failed login" in lower_line or "invalid user" in lower_line:
                    self.failed_login_count += 1
                    is_suspicious = True
                if "sql" in lower_line or "union select" in lower_line or "drop table" in lower_line:
                    is_suspicious = True
                if "unauthorized" in lower_line or "access denied" in lower_line:
                    is_suspicious = True
                    
                if is_suspicious:
                    self.suspicious_entries.insert(0, {
                        "timestamp": time.strftime("%H:%M:%S"),
                        "message": line_str
                    })
                    self.suspicious_entries = self.suspicious_entries[:30]

    def _generate_logs(self):
        """Periodically appends logs to simulate a running operating system."""
        users = ["admin", "root", "db_user", "guest", "developer"]
        ips = ["192.168.1.10", "10.0.0.12", "192.168.1.15", "185.220.101.4", "198.51.100.12"]
        
        while self.running:
            time.sleep(8.0)
            
            # Decide what kind of log to write
            now_str = time.strftime('%Y-%m-%d %H:%M:%S')
            
            with self.stats_lock:
                att_type = self.simulated_attack_type
                
            if att_type == "Brute Force":
                # Rapid failed logins
                with open(self.watch_file, 'a') as f:
                    for _ in range(5):
                        f.write(f"[{now_str}] sshd[1024]: Failed login attempt for invalid user admin from 185.220.101.4 port 54124\n")
                continue
            elif att_type == "SQL Injection":
                # SQL Injection logs
                with open(self.watch_file, 'a') as f:
                    f.write(f"[{now_str}] nginx: 198.51.100.12 - - \"GET /login?user=admin' UNION SELECT NULL,password-- HTTP/1.1\" 401\n")
                continue
            
            # Normal random log
            import random
            log_type = random.choice(["success", "info", "failed_login"])
            
            if log_type == "success":
                user = random.choice(users)
                ip = random.choice(ips)
                log_line = f"[{now_str}] auth: Connection accepted for user '{user}' from {ip}\n"
            elif log_type == "failed_login":
                user = random.choice(users)
                ip = random.choice(ips)
                log_line = f"[{now_str}] auth: Failed login attempt for user '{user}' from {ip}\n"
            else:
                log_line = f"[{now_str}] systemd: Periodic cleanup task executed successfully.\n"
                
            try:
                with open(self.watch_file, 'a') as f:
                    f.write(log_line)
            except Exception:
                pass

    def trigger_simulated_attack(self, attack_type: str):
        with self.stats_lock:
            self.simulated_attack_type = attack_type

    def get_features(self) -> Dict[str, Any]:
        """Extract features to pass to the AI detector model."""
        with self.stats_lock:
            failed_count = self.failed_login_count
            
            if self.simulated_attack_type == "Brute Force":
                failed_count += 35
                
            return {
                "failed_login_count": failed_count
            }

    def get_status(self) -> Dict[str, Any]:
        with self.stats_lock:
            return {
                "failed_login_count": self.failed_login_count,
                "total_scanned_lines": self.total_scanned_lines,
                "suspicious_entries": self.suspicious_entries
            }
