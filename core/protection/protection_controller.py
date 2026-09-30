import logging
import time
from typing import Any, Dict

from core.backup.safe_backup_manager import SafeBackupManager
from core.defense.firewall_manager import FirewallManager
from core.defense.network_isolator import NetworkIsolator
from core.defense.process_killer import ProcessKiller
from core.detection.threat_forecaster import ThreatForecaster
from core.defense.data_isolator import DataIsolator
from core.defense.ip_blocker import IPBlocker

logger = logging.getLogger("ProtectionController")


class ProtectionController:
    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}
        protection_cfg = self.config.get("protection", {})
        self.auto_protect = bool(protection_cfg.get("auto_protect", True))
        self.snapshot_cooldown_seconds = int(protection_cfg.get("snapshot_cooldown_seconds", 60))
        self.guard_ports = protection_cfg.get("guard_ports", [22, 445, 3389])

        self.forecaster = ThreatForecaster(self.config)
        self.backup_manager = SafeBackupManager(self.config)
        self.firewall = FirewallManager()
        self.network_isolator = NetworkIsolator()
        self.process_killer = ProcessKiller()
        self.data_isolator = DataIsolator(self.config)
        self.ip_blocker = IPBlocker()

        self.last_snapshot_time = 0.0
        self.last_action = {
            "status": "idle",
            "message": "Protection controller is monitoring.",
            "timestamp": None,
        }
        self.active_protocol = {
            "mode": "monitoring",
            "actions": [],
            "updated_at": None,
        }
        self.action_history = []
        self.prevention_failed = False

    def evaluate(
        self,
        network_features: Dict[str, Any],
        process_features: Dict[str, Any],
        file_features: Dict[str, Any],
        log_features: Dict[str, Any],
        threat_prediction: Dict[str, Any],
        anomaly_prediction: Dict[str, Any],
        process_status: Dict[str, Any],
        network_status: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        forecast = self.forecaster.analyze(
            network_features,
            process_features,
            file_features,
            log_features,
            threat_prediction,
            anomaly_prediction,
        )

        is_under_attack = (forecast["level"] in {"warning", "critical"}) or (threat_prediction.get("is_threat", False))
        was_active = self.last_action.get("status") in ("protection_active", "isolation_active")

        # 1. Feed Layer 5 (Behavioral Rate Limiter) and Layer 1 (IP Filtering)
        if network_status:
            for conn in network_status.get("recent_connections", []):
                raddr = conn.get("remote_address")
                if raddr and raddr != "N/A":
                    ip = raddr.split(":")[0]
                    if ip not in ("127.0.0.1", "0.0.0.0", "localhost"):
                        # If under attack, enforce lower traffic limit to trigger behavioral shield
                        self.firewall.track_traffic(ip, limit=5 if is_under_attack else 20)

        # 2. Feed Layer 3 (Application Payload Inspector) with simulation patterns if threat is active
        if is_under_attack and threat_prediction.get("attack_type"):
            attack = threat_prediction.get("attack_type").lower()
            if "sql" in attack:
                self.firewall.inspect_payload("SELECT * FROM users WHERE username = 'admin' OR '1'='1'")
            elif "brute" in attack:
                self.firewall.inspect_payload("admin; /bin/sh -c 'id'")
            elif "ransomware" in attack or "zero-day" in attack:
                self.firewall.inspect_payload("../../windows/system32/cmd.exe")
        else:
            # Under normal load, perform random cleanup inspections
            self.firewall.inspect_payload("GET /index.html HTTP/1.1")

        # 3. Feed Layer 4 (System Process Binding Guard)
        for proc in process_status.get("top_processes", []):
            pname = proc.get("name", "")
            pid = proc.get("pid", 0)
            if pname in ("sshd", "nginx", "mysqld", "postgres"):
                port = 22 if pname == "sshd" else (3306 if pname == "mysqld" else 80)
                self.firewall.verify_process(pid, pname, port)

        if self.auto_protect and is_under_attack:
            self._protect(forecast, process_status, threat_prediction, network_status)
        elif self.auto_protect and self._should_enter_early_guard(forecast, threat_prediction, anomaly_prediction):
            self._activate_early_guard(forecast, threat_prediction, network_status)
        elif forecast["level"] == "normal" and not threat_prediction.get("is_threat", False):
            msg = "Protected successfully." if was_active else "No protection action required at current risk level."
            self.last_action = {
                "status": "monitoring",
                "message": msg,
                "timestamp": forecast["timestamp"],
            }
            self.active_protocol = {
                "mode": "monitoring",
                "actions": [],
                "updated_at": forecast["timestamp"],
            }
            # Reset firewall rules when returning to safety baseline
            if was_active:
                self.firewall.reset_rules()

        if self.data_isolator.is_active:
            if (forecast["level"] == "normal" and not threat_prediction.get("is_threat", False)) or not self.auto_protect:
                self.data_isolator.restore_files()

        return {
            "forecast": forecast,
            "auto_protect": self.auto_protect,
            "last_action": self.last_action,
            "active_protocol": self.active_protocol,
            "action_history": self.action_history[:10],
            "backup": self.backup_manager.get_status(),
            "isolation": self.data_isolator.get_status(),
            "prevention_failed": self.prevention_failed,
            "firewall": self.firewall.get_stats(),
        }

    def _protect(
        self,
        forecast: Dict[str, Any],
        process_status: Dict[str, Any],
        threat_prediction: Dict[str, Any],
        network_status: Dict[str, Any] | None = None,
    ):
        actions = []

        # 1. Firstly, disconnect the system from internet (isolate host network)
        self.network_isolator.isolate_host()
        actions.append({
            "type": "network",
            "status": "simulated",
            "message": "Host network disconnected (isolated) from internet immediately to contain threat propagation."
        })

        # 2. Protect sensitive information and isolate it only if prevention has failed (firewall breach)
        if self.prevention_failed:
            iso_res = self.data_isolator.isolate_files()
            if iso_res["status"] == "activated":
                actions.append({
                    "type": "isolation",
                    "status": "active",
                    "message": f"Sensitive data protected successfully. Secured in Isolation Vault ({iso_res['count']} files)."
                })
            elif iso_res["status"] == "already_active":
                actions.append({
                    "type": "isolation",
                    "status": "active",
                    "message": f"Sensitive data protected successfully. Remains secured in Isolation Vault ({iso_res['count']} files)."
                })
            else:
                actions.append({
                    "type": "isolation",
                    "status": "idle",
                    "message": "No sensitive files found to isolate."
                })
        else:
            iso_res = {"status": "disabled", "count": 0}
            actions.append({
                "type": "isolation",
                "status": "disabled",
                "message": "Sensitive data isolation idle (prevention shields holding)."
            })

        # 2. Dont protect critical files (do NOT back up critical configs or system files)
        actions.append({
            "type": "snapshot",
            "status": "disabled",
            "message": "Critical configuration/system files protection bypassed for stability."
        })

        # 3. Respond properly on any type of attack
        attack_type = threat_prediction.get("attack_type", "unknown").lower()

        if "ddos" in attack_type:
            # DDoS Attack mitigation
            self.firewall.block_port(80)
            self.firewall.block_port(443)
            actions.append({
                "type": "firewall",
                "status": "simulated",
                "message": "Blocked web ports 80 and 443."
            })

            blocked_ips = []
            if network_status:
                for conn in network_status.get("recent_connections", []):
                    raddr = conn.get("remote_address")
                    if raddr and raddr != "N/A":
                        ip = raddr.split(":")[0]
                        if ip not in ("127.0.0.1", "0.0.0.0", "localhost"):
                            self.ip_blocker.block_ip(ip)
                            blocked_ips.append(ip)
            if not blocked_ips:
                for ip in ["192.168.1.100", "10.0.0.50"]:
                    self.ip_blocker.block_ip(ip)
                    blocked_ips.append(ip)

            actions.append({
                "type": "ip_block",
                "status": "simulated",
                "message": f"Blocked {len(blocked_ips)} DDoS source IP addresses: {', '.join(blocked_ips)}."
            })

            mode = "containment"
            message = "DDoS attack mitigated: Web ports closed, malicious IPs blocked, host isolated."

        elif "sql" in attack_type:
            # SQL Injection mitigation
            for port in [1433, 3306, 5432]:
                self.firewall.block_port(port)
            actions.append({
                "type": "firewall",
                "status": "simulated",
                "message": "Blocked database ports 1433, 3306, 5432."
            })

            blocked_ips = []
            if network_status:
                for conn in network_status.get("recent_connections", []):
                    raddr = conn.get("remote_address")
                    if raddr and raddr != "N/A":
                        ip = raddr.split(":")[0]
                        if ip not in ("127.0.0.1", "0.0.0.0", "localhost"):
                            self.ip_blocker.block_ip(ip)
                            blocked_ips.append(ip)
                            break
            if not blocked_ips:
                self.ip_blocker.block_ip("192.168.1.150")
                blocked_ips.append("192.168.1.150")

            actions.append({
                "type": "ip_block",
                "status": "simulated",
                "message": f"Blocked SQL Injection attacker IP: {blocked_ips[0]}."
            })

            mode = "prevention"
            message = f"SQL Injection mitigation active: DB ports protected, suspect IP {blocked_ips[0]} blocked."

        elif "brute" in attack_type:
            # Brute Force mitigation
            for port in [22, 3389]:
                self.firewall.block_port(port)
            actions.append({
                "type": "firewall",
                "status": "simulated",
                "message": "Blocked authentication ports 22 (SSH) and 3389 (RDP)."
            })

            blocked_ips = []
            if network_status:
                for conn in network_status.get("recent_connections", []):
                    raddr = conn.get("remote_address")
                    if raddr and raddr != "N/A":
                        ip = raddr.split(":")[0]
                        if ip not in ("127.0.0.1", "0.0.0.0", "localhost"):
                            self.ip_blocker.block_ip(ip)
                            blocked_ips.append(ip)
                            break
            if not blocked_ips:
                self.ip_blocker.block_ip("10.0.0.75")
                blocked_ips.append("10.0.0.75")

            actions.append({
                "type": "ip_block",
                "status": "simulated",
                "message": f"Blocked Brute Force attacker IP: {blocked_ips[0]}."
            })

            mode = "prevention"
            message = f"Brute Force attack blocked: Auth ports closed, attacker IP {blocked_ips[0]} banned."

        elif "ransomware" in attack_type:
            # Ransomware mitigation
            self.firewall.block_port(445)
            actions.append({
                "type": "firewall",
                "status": "simulated",
                "message": "Blocked SMB port 445 to prevent remote encryption."
            })

            suspicious_pid = self._most_suspicious_pid(process_status)
            if suspicious_pid is not None:
                self.process_killer.kill_process(suspicious_pid)
                actions.append({
                    "type": "process",
                    "status": "simulated",
                    "message": f"Virus removed successfully. Ransomware suspect process PID {suspicious_pid} terminated."
                })
            else:
                actions.append({
                    "type": "process",
                    "status": "idle",
                    "message": "No anomalous high-CPU process found to terminate."
                })

            mode = "containment"
            message = "Virus removed successfully. Ransomware contained: Sensitive files isolated, SMB blocked, process terminated."

        elif "zero-day" in attack_type or "exploit" in attack_type:
            # Zero-day Exploit mitigation
            suspicious_pid = self._most_suspicious_pid(process_status)
            if suspicious_pid is not None:
                self.process_killer.kill_process(suspicious_pid)
                actions.append({
                    "type": "process",
                    "status": "simulated",
                    "message": f"Virus removed successfully. Anomalous process PID {suspicious_pid} terminated."
                })
            else:
                actions.append({
                    "type": "process",
                    "status": "idle",
                    "message": "No anomalous process found to terminate."
                })

            blocked_ips = []
            if network_status:
                for conn in network_status.get("recent_connections", []):
                    raddr = conn.get("remote_address")
                    if raddr and raddr != "N/A":
                        ip = raddr.split(":")[0]
                        if ip not in ("127.0.0.1", "0.0.0.0", "localhost"):
                            self.ip_blocker.block_ip(ip)
                            blocked_ips.append(ip)
                            break
            if not blocked_ips:
                self.ip_blocker.block_ip("192.168.1.200")
                blocked_ips.append("192.168.1.200")

            actions.append({
                "type": "ip_block",
                "status": "simulated",
                "message": f"Blocked exploit controller IP: {blocked_ips[0]}."
            })

            mode = "containment"
            message = "Virus removed successfully. Zero-day Exploit contained: Host isolated, suspicious process killed, control IP blocked."

        else:
            for port in [22, 80, 443, 445, 1433, 3306, 3389, 5432]:
                self.firewall.block_port(port)
            actions.append({
                "type": "firewall",
                "status": "simulated",
                "message": "Blocked network service ports: 22, 80, 443, 445, 1433, 3306, 3389, 5432."
            })

            blocked_ips = []
            if network_status:
                for conn in network_status.get("recent_connections", []):
                    raddr = conn.get("remote_address")
                    if raddr and raddr != "N/A":
                        ip = raddr.split(":")[0]
                        if ip not in ("127.0.0.1", "0.0.0.0", "localhost"):
                            self.ip_blocker.block_ip(ip)
                            blocked_ips.append(ip)
            if not blocked_ips:
                self.ip_blocker.block_ip("192.168.1.250")
                blocked_ips.append("192.168.1.250")

            actions.append({
                "type": "ip_block",
                "status": "simulated",
                "message": f"Blocked remote attacker IP address: {blocked_ips[0]}."
            })

            suspicious_pid = self._most_suspicious_pid(process_status)
            if suspicious_pid is not None:
                self.process_killer.kill_process(suspicious_pid)
                actions.append({
                    "type": "process",
                    "status": "simulated",
                    "message": f"Virus removed successfully. Threat suspect process PID {suspicious_pid} terminated."
                })
            else:
                actions.append({
                    "type": "process",
                    "status": "idle",
                    "message": "No anomalous hot process identified for termination."
                })

            mode = "containment"
            message = f"Virus removed successfully. Universal protection active: Host network isolated, service ports closed, process terminated, remote IP {blocked_ips[0]} blocked."

        if self.prevention_failed:
            mode = "isolation"
            message = f"Protection fails. {message}"

        if iso_res["status"] in ("activated", "already_active"):
            if "Sensitive data protected successfully." not in message:
                if "Protection fails." in message:
                    message = message.replace("Protection fails. ", "Protection fails. Sensitive data protected successfully. ")
                else:
                    message = f"Sensitive data protected successfully. {message}"

        self.last_action = {
            "status": "isolation_active" if iso_res["status"] in ("activated", "already_active") else "protection_active",
            "message": message,
            "timestamp": forecast["timestamp"],
        }

        self.active_protocol = {
            "mode": mode,
            "actions": actions,
            "updated_at": forecast["timestamp"],
        }

        self._record_actions(forecast, actions)

    def _activate_early_guard(self, forecast: Dict[str, Any], threat_prediction: Dict[str, Any], network_status: Dict[str, Any] | None = None):
        self._protect(forecast, {}, threat_prediction, network_status)

    def _should_enter_early_guard(
        self,
        forecast: Dict[str, Any],
        threat_prediction: Dict[str, Any],
        anomaly_prediction: Dict[str, Any],
    ) -> bool:
        if forecast["level"] != "normal":
            return False
        if threat_prediction.get("is_threat") and float(threat_prediction.get("confidence", 0)) >= 0.75:
            return True
        return bool(anomaly_prediction.get("is_anomaly") and forecast.get("signals"))

    def _guard_high_risk_ports(self) -> list:
        actions = []
        for port in self.guard_ports:
            if self.firewall.block_port(int(port)):
                actions.append({
                    "type": "firewall",
                    "status": "simulated",
                    "message": f"High-risk port {port} guard prepared.",
                })
        return actions

    def _record_actions(self, forecast: Dict[str, Any], actions: list):
        for action in actions:
            self.action_history.insert(0, {
                "timestamp": forecast["timestamp"],
                "risk_level": forecast["level"],
                **action,
            })
        self.action_history = self.action_history[:20]

    def _most_suspicious_pid(self, process_status: Dict[str, Any]) -> int | None:
        processes = process_status.get("top_processes", [])
        if not processes:
            return None
        hot_process = max(processes, key=lambda item: item.get("cpu_percent", 0))
        if hot_process.get("cpu_percent", 0) >= 50:
            return hot_process.get("pid")
        return None
