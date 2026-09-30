import time
import psutil
import threading
import logging
from typing import Dict, List, Any

# Optional import for packet analysis
try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("NetworkMonitor")

class NetworkMonitor:
    def __init__(self, config: Dict[str, Any]):
        self.config = config.get("network", {})
        self.interval = self.config.get("interval", 1.0)
        self.sniff_packets = self.config.get("sniff_packets", False) and SCAPY_AVAILABLE
        self.running = False
        self._thread = None
        self.stats_lock = threading.Lock()
        
        # In-memory traffic metrics
        self.connection_count = 0
        self.unique_ips = set()
        self.bytes_sent_rate = 0.0
        self.bytes_recv_rate = 0.0
        self.recent_connections = []
        
        self.last_io = psutil.net_io_counters()
        self.last_time = time.time()
        
        # Mock attack flag for dashboard simulation
        self.simulated_attack_type = None

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("Network Monitor started.")

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=2.0)
        logger.info("Network Monitor stopped.")

    def _run(self):
        while self.running:
            try:
                self._update_stats()
            except Exception as e:
                logger.error(f"Error updating network stats: {e}")
            time.sleep(self.interval)

    def _update_stats(self):
        now = time.time()
        duration = now - self.last_time
        if duration <= 0:
            duration = 1.0
            
        current_io = psutil.net_io_counters()
        connections = psutil.net_connections(kind='inet')
        
        sent_diff = current_io.bytes_sent - self.last_io.bytes_sent
        recv_diff = current_io.bytes_recv - self.last_io.bytes_recv
        
        with self.stats_lock:
            self.bytes_sent_rate = sent_diff / duration
            self.bytes_recv_rate = recv_diff / duration
            self.connection_count = len(connections)
            
            # Record unique remote IPs and recent connections info
            self.unique_ips.clear()
            self.recent_connections.clear()
            
            for conn in connections[:20]: # Keep last 20 for dashboard
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                
                if conn.raddr:
                    self.unique_ips.add(conn.raddr.ip)
                    
                self.recent_connections.append({
                    "fd": conn.fd,
                    "family": str(conn.family),
                    "type": "TCP" if conn.type == 1 else "UDP",
                    "local_address": laddr,
                    "remote_address": raddr,
                    "status": conn.status
                })
                
        self.last_io = current_io
        self.last_time = now

    def trigger_simulated_attack(self, attack_type: str):
        """Used to inject traffic features for demo/dashboard testing."""
        with self.stats_lock:
            self.simulated_attack_type = attack_type

    def get_features(self) -> Dict[str, Any]:
        """Extract features to pass to the AI detector model."""
        with self.stats_lock:
            # Generate feature vector based on current state (and inject simulation patterns if active)
            conn_count = self.connection_count
            unique_ip_count = len(self.unique_ips)
            bytes_sent = self.bytes_sent_rate
            bytes_recv = self.bytes_recv_rate
            
            # Injection patterns for demo validation
            if self.simulated_attack_type == "DDoS":
                conn_count += 800
                unique_ip_count += 350
                bytes_recv += 5000000.0  # 5MB/s traffic spike
            elif self.simulated_attack_type == "SQL Injection":
                # Simulated high connection count with low bytes
                conn_count += 5
                bytes_sent += 50000.0
            
            return {
                "connection_count": conn_count,
                "unique_ips": unique_ip_count,
                "bytes_sent_rate": bytes_sent,
                "bytes_recv_rate": bytes_recv,
                "simulated_attack": self.simulated_attack_type
            }

    def get_status(self) -> Dict[str, Any]:
        with self.stats_lock:
            return {
                "connection_count": self.connection_count,
                "unique_ip_count": len(self.unique_ips),
                "bytes_sent_rate": round(self.bytes_sent_rate, 2),
                "bytes_recv_rate": round(self.bytes_recv_rate, 2),
                "recent_connections": self.recent_connections
            }
