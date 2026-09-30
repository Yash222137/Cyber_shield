import time
import psutil
import threading
import logging
from typing import Dict, List, Any

logger = logging.getLogger("ProcessMonitor")

class ProcessMonitor:
    def __init__(self, config: Dict[str, Any]):
        self.config = config.get("process", {})
        self.interval = self.config.get("interval", 2.0)
        self.cpu_threshold = self.config.get("cpu_threshold", 80.0)
        self.ram_threshold = self.config.get("ram_threshold", 80.0)
        
        self.running = False
        self._thread = None
        self.stats_lock = threading.Lock()
        
        # In-memory stats
        self.system_cpu = 0.0
        self.system_ram = 0.0
        self.top_processes = []
        
        self.simulated_attack_type = None

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("Process Monitor started.")

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=2.0)
        logger.info("Process Monitor stopped.")

    def _run(self):
        # Initialize CPU percent calculation
        psutil.cpu_percent(interval=None)
        
        while self.running:
            try:
                self._update_stats()
            except Exception as e:
                logger.error(f"Error updating process stats: {e}")
            time.sleep(self.interval)

    def _update_stats(self):
        sys_cpu = psutil.cpu_percent(interval=None)
        sys_ram = psutil.virtual_memory().percent
        
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                info = proc.info
                # Some platforms might return None for values initially
                cpu_p = info['cpu_percent'] or 0.0
                mem_p = info['memory_percent'] or 0.0
                
                processes.append({
                    "pid": info['pid'],
                    "name": info['name'],
                    "cpu_percent": round(cpu_p, 1),
                    "memory_percent": round(mem_p, 1)
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # Sort by CPU usage descending
        processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        
        with self.stats_lock:
            self.system_cpu = sys_cpu
            self.system_ram = sys_ram
            self.top_processes = processes[:15] # Top 15 processes for the UI
            
            # Injection patterns for simulation
            if self.simulated_attack_type == "Ransomware":
                # Ransomware causes rapid disk read/writes and high CPU spike
                self.system_cpu = max(self.system_cpu, 92.5)
                self.top_processes.insert(0, {
                    "pid": 9999,
                    "name": "crypt_locker.exe",
                    "cpu_percent": 88.0,
                    "memory_percent": 12.4
                })
            elif self.simulated_attack_type == "Zero-day Exploit":
                # Exploit triggers suspicious system calls and RAM spike
                self.system_ram = max(self.system_ram, 95.0)
                self.top_processes.insert(0, {
                    "pid": 8888,
                    "name": "exploit_payload.exe",
                    "cpu_percent": 45.0,
                    "memory_percent": 35.2
                })

    def trigger_simulated_attack(self, attack_type: str):
        with self.stats_lock:
            self.simulated_attack_type = attack_type

    def get_features(self) -> Dict[str, Any]:
        """Extract features to pass to the Anomaly Detection Model."""
        with self.stats_lock:
            cpu = self.system_cpu
            ram = self.system_ram
            process_count = len(self.top_processes)
            high_cpu_procs = sum(1 for p in self.top_processes if p['cpu_percent'] > 50.0)
            
            return {
                "system_cpu": cpu,
                "system_ram": ram,
                "process_count": process_count,
                "high_cpu_procs": high_cpu_procs
            }

    def get_status(self) -> Dict[str, Any]:
        with self.stats_lock:
            return {
                "system_cpu": round(self.system_cpu, 1),
                "system_ram": round(self.system_ram, 1),
                "top_processes": self.top_processes
            }
