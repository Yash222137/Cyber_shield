import logging
import re
import time
from typing import Dict, List, Set, Any

logger = logging.getLogger("FirewallManager")


class FirewallManager:
    def __init__(self):
        logger.info("Firewall Manager initialized (Security Sandbox Mode). Rules modification is active in virtual space.")
        # Layer 1: Network Layer (IP Filtering)
        self.blocked_ips: Set[str] = set()
        
        # Layer 2: Transport/Port Layer (Port Filtering)
        self.blocked_ports: Set[int] = set()
        
        # Layer 3: Application Layer (Payload Inspector)
        self.payloads_scanned = 0
        self.violations_detected = 0
        self.sqli_pattern = re.compile(r"(\bUNION\b|\bSELECT\b|' OR '|--|/\*|\*/|\bDROP\b|\bINSERT\b)", re.IGNORECASE)
        self.xss_pattern = re.compile(r"(<script>|javascript:|onerror=|onload=|<img|<iframe)", re.IGNORECASE)
        self.path_traversal_pattern = re.compile(r"(\.\./|\.\.\\)", re.IGNORECASE)
        self.cmd_injection_pattern = re.compile(r"(;|&&|\||\$\(|\bsh\b|\bbash\b|\bcmd\b)", re.IGNORECASE)

        # Layer 4: System/Process Layer (Binding Guard)
        self.processes_verified = 0
        self.authorized_processes: Dict[int, List[str]] = {
            22: ["sshd", "systemd"],
            80: ["nginx", "httpd", "apache2", "python"],
            443: ["nginx", "httpd", "apache2", "python"],
            1433: ["sqlservr"],
            3306: ["mysqld"],
            5432: ["postgres"],
            8000: ["python", "uvicorn"]
        }

        # Layer 5: Behavioral Layer (Rate Limiter)
        self.ip_connections: Dict[str, List[float]] = {}
        self.rate_limit_violations = 0

    # Layer 1: Network Filter
    def block_ip(self, ip_address: str) -> bool:
        if ip_address not in self.blocked_ips:
            self.blocked_ips.add(ip_address)
            logger.warning(f"SIMULATED IP BLOCK: {ip_address} [Blocked by Safety Policy]")
            return True
        return False

    def unblock_ip(self, ip_address: str) -> bool:
        if ip_address in self.blocked_ips:
            self.blocked_ips.remove(ip_address)
            logger.info(f"SIMULATED IP UNBLOCK: {ip_address}")
            return True
        return False

    def is_ip_blocked(self, ip_address: str) -> bool:
        return ip_address in self.blocked_ips

    # Layer 2: Port Filter
    def block_port(self, port: int) -> bool:
        if port not in self.blocked_ports:
            self.blocked_ports.add(port)
            logger.warning(f"SIMULATED PORT BLOCK: {port} [Blocked by Safety Policy]")
            return True
        return False

    def unblock_port(self, port: int) -> bool:
        if port in self.blocked_ports:
            self.blocked_ports.remove(port)
            logger.info(f"SIMULATED PORT UNBLOCK: {port}")
            return True
        return False

    def is_port_blocked(self, port: int) -> bool:
        return port in self.blocked_ports

    # Layer 3: Application Payload Inspector
    def inspect_payload(self, payload: str, service: str = "web") -> Dict[str, Any]:
        self.payloads_scanned += 1
        if not payload:
            return {"clean": True, "detected_attack": None, "severity": 0}

        # Scan for SQL Injection
        if self.sqli_pattern.search(payload):
            self.violations_detected += 1
            return {"clean": False, "detected_attack": "SQL Injection", "severity": 85}

        # Scan for XSS
        if self.xss_pattern.search(payload):
            self.violations_detected += 1
            return {"clean": False, "detected_attack": "Cross-Site Scripting (XSS)", "severity": 75}

        # Scan for Path Traversal
        if self.path_traversal_pattern.search(payload):
            self.violations_detected += 1
            return {"clean": False, "detected_attack": "Path Traversal", "severity": 70}

        # Scan for Command Injection
        if self.cmd_injection_pattern.search(payload):
            self.violations_detected += 1
            return {"clean": False, "detected_attack": "Command Injection", "severity": 90}

        return {"clean": True, "detected_attack": None, "severity": 0}

    # Layer 4: System Process Binding Guard
    def verify_process(self, pid: int, process_name: str, port: int) -> bool:
        self.processes_verified += 1
        if port in self.authorized_processes:
            allowed = self.authorized_processes[port]
            if process_name.lower() not in allowed:
                self.violations_detected += 1
                logger.warning(f"UNAUTHORIZED PROCESS DETECTED: Process '{process_name}' (PID {pid}) attempted to bind to service port {port}.")
                return False
        return True

    # Layer 5: Behavioral Rate Limiter
    def track_traffic(self, ip: str, limit: int = 15, window_seconds: float = 5.0) -> bool:
        now = time.time()
        if ip not in self.ip_connections:
            self.ip_connections[ip] = []
        
        self.ip_connections[ip].append(now)
        
        # Filter connections outside window
        self.ip_connections[ip] = [t for t in self.ip_connections[ip] if now - t <= window_seconds]
        
        if len(self.ip_connections[ip]) > limit:
            self.rate_limit_violations += 1
            self.block_ip(ip)
            logger.warning(f"RATE LIMIT EXCEEDED: Source IP {ip} flooded requests. Triggering Layer 1 block.")
            return False
            
        return True

    def reset_rules(self) -> bool:
        self.blocked_ips.clear()
        self.blocked_ports.clear()
        self.ip_connections.clear()
        self.payloads_scanned = 0
        self.violations_detected = 0
        self.processes_verified = 0
        self.rate_limit_violations = 0
        logger.info("Firewall rules and metrics reset simulated.")
        return True

    def get_stats(self) -> Dict[str, Any]:
        return {
            "blocked_ips": list(self.blocked_ips),
            "blocked_ports": list(self.blocked_ports),
            "payloads_scanned": self.payloads_scanned,
            "violations_detected": self.violations_detected,
            "processes_verified": self.processes_verified,
            "rate_limit_violations": self.rate_limit_violations,
        }
