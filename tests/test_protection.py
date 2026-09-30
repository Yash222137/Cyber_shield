import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.detection.threat_forecaster import ThreatForecaster
from streamlit_app import CentralOrchestrator



class TestProtection(unittest.TestCase):
    def test_forecaster_flags_ransomware_like_activity(self):
        forecaster = ThreatForecaster({
            "protection": {
                "warning_threshold": 55,
                "critical_threshold": 75,
            }
        })

        result = forecaster.analyze(
            network={"connection_count": 30, "unique_ips": 5},
            process={"system_cpu": 92, "system_ram": 84, "high_cpu_procs": 2},
            file={"file_modification_rate": 145},
            log={"failed_login_count": 0},
            threat={"is_threat": True, "attack_type": "Ransomware", "severity_score": 90},
            anomaly={"is_anomaly": True, "anomaly_score": 92},
        )

        self.assertEqual(result["level"], "critical")
        self.assertGreaterEqual(result["risk_score"], 75)
        self.assertIn("Rapid file modification", result["signals"])

    def test_orchestrator_ransomware_simulation_creates_snapshot(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            watch_dir = root / "watch"
            backup_dir = root / "backup"
            watch_dir.mkdir()
            (watch_dir / "critical.txt").write_text("important", encoding="utf-8")
            settings_path = root / "settings.yaml"
            settings_path.write_text(
                f"""
monitors:
  network:
    interval: 1.0
    sniff_packets: false
  process:
    interval: 2.0
  file:
    watch_path: "{watch_dir.as_posix()}"
  log:
    watch_file: "{(root / 'auth.log').as_posix()}"
    interval: 5.0
detection:
  model_dir: "./ai_models/trained_models"
protection:
  auto_protect: true
  warning_threshold: 55
  critical_threshold: 75
  snapshot_cooldown_seconds: 60
backup:
  enabled: true
  local_destination: "{backup_dir.as_posix()}"
  critical_paths:
    - "{watch_dir.as_posix()}"
  critical_extensions:
    - ".txt"
server:
  host: "127.0.0.1"
  port: 8000
""",
                encoding="utf-8",
            )

            orchestrator = CentralOrchestrator(str(settings_path))
            orchestrator.authenticate_and_start_protection({"name": "Test User", "email": "test@outlook.com"})
            orchestrator.set_prevention_failure(True)
            orchestrator.trigger_simulation("Ransomware")
            telemetry = orchestrator.get_telemetry()

        self.assertEqual(telemetry["protection"]["forecast"]["level"], "critical")
        self.assertGreaterEqual(telemetry["protection"]["forecast"]["risk_score"], 75)
        self.assertEqual(telemetry["protection"]["backup"]["last_snapshot"]["file_count"], 0)
        self.assertEqual(telemetry["protection"]["isolation"]["is_active"], True)
        self.assertEqual(telemetry["protection"]["isolation"]["count"], 1)

    def test_simulation_seeds_snapshot_source_when_watch_dir_is_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            watch_dir = root / "watch"
            backup_dir = root / "backup"
            watch_dir.mkdir()
            settings_path = root / "settings.yaml"
            settings_path.write_text(
                f"""
monitors:
  network:
    interval: 1.0
    sniff_packets: false
  process:
    interval: 2.0
  file:
    watch_path: "{watch_dir.as_posix()}"
  log:
    watch_file: "{(root / 'auth.log').as_posix()}"
    interval: 5.0
detection:
  model_dir: "./ai_models/trained_models"
protection:
  auto_protect: true
  warning_threshold: 55
  critical_threshold: 75
  snapshot_cooldown_seconds: 60
backup:
  enabled: true
  local_destination: "{backup_dir.as_posix()}"
  critical_paths:
    - "{watch_dir.as_posix()}"
  critical_extensions:
    - ".txt"
server:
  host: "127.0.0.1"
  port: 8000
""",
                encoding="utf-8",
            )

            orchestrator = CentralOrchestrator(str(settings_path))
            orchestrator.authenticate_and_start_protection({"name": "Test User", "email": "test@outlook.com"})
            orchestrator.set_prevention_failure(True)
            orchestrator.trigger_simulation("Ransomware")
            telemetry = orchestrator.get_telemetry()

        self.assertEqual(telemetry["protection"]["backup"]["last_snapshot"]["file_count"], 0)
        self.assertEqual(telemetry["protection"]["isolation"]["is_active"], True)
        self.assertEqual(telemetry["protection"]["isolation"]["count"], 1)

    def test_upcoming_threat_arms_early_guard_before_warning_threshold(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            watch_dir = root / "watch"
            backup_dir = root / "backup"
            watch_dir.mkdir()
            settings_path = root / "settings.yaml"
            settings_path.write_text(
                f"""
monitors:
  network:
    interval: 1.0
    sniff_packets: false
  process:
    interval: 2.0
  file:
    watch_path: "{watch_dir.as_posix()}"
  log:
    watch_file: "{(root / 'auth.log').as_posix()}"
    interval: 5.0
detection:
  model_dir: "./ai_models/trained_models"
protection:
  auto_protect: true
  warning_threshold: 55
  critical_threshold: 75
  snapshot_cooldown_seconds: 60
  guard_ports:
    - 22
    - 445
backup:
  enabled: true
  local_destination: "{backup_dir.as_posix()}"
  critical_paths:
    - "{watch_dir.as_posix()}"
  critical_extensions:
    - ".txt"
server:
  host: "127.0.0.1"
  port: 8000
""",
                encoding="utf-8",
            )

            orchestrator = CentralOrchestrator(str(settings_path))
            orchestrator.authenticate_and_start_protection({"name": "Test User", "email": "test@outlook.com"})
            orchestrator.trigger_simulation("SQL Injection")
            telemetry = orchestrator.get_telemetry()

        protection = telemetry["protection"]
        self.assertEqual(protection["forecast"]["level"], "normal")
        self.assertEqual(protection["active_protocol"]["mode"], "prevention")
        self.assertEqual(protection["last_action"]["status"], "protection_active")
        self.assertTrue(any(action["type"] == "firewall" for action in protection["active_protocol"]["actions"]))

    def test_prevention_failure_isolates_sensitive_information(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            watch_dir = root / "watch"
            backup_dir = root / "backup"
            isolation_dir = root / "isolated"
            watch_dir.mkdir()
            
            # Create a critical file
            critical_file = watch_dir / "confidential.txt"
            critical_file.write_text("secret payload", encoding="utf-8")
            
            settings_path = root / "settings.yaml"
            settings_path.write_text(
                f"""
monitors:
  network:
    interval: 1.0
    sniff_packets: false
  process:
    interval: 2.0
  file:
    watch_path: "{watch_dir.as_posix()}"
  log:
    watch_file: "{(root / 'auth.log').as_posix()}"
    interval: 5.0
detection:
  model_dir: "./ai_models/trained_models"
protection:
  auto_protect: true
  warning_threshold: 55
  critical_threshold: 75
  snapshot_cooldown_seconds: 60
defense:
  isolation_directory: "{isolation_dir.as_posix()}"
backup:
  enabled: true
  local_destination: "{backup_dir.as_posix()}"
  critical_paths:
    - "{watch_dir.as_posix()}"
  critical_extensions:
    - ".txt"
server:
  host: "127.0.0.1"
  port: 8000
""",
                encoding="utf-8",
            )

            orchestrator = CentralOrchestrator(str(settings_path))
            orchestrator.authenticate_and_start_protection({"name": "Test User", "email": "test@outlook.com"})
            # 1. Enable prevention failure
            orchestrator.set_prevention_failure(True)
            # 2. Trigger simulation
            orchestrator.trigger_simulation("Ransomware")
            telemetry = orchestrator.get_telemetry()
            
            # File should be removed from watch directory
            self.assertFalse(critical_file.exists())
            
            # File should exist in isolation directory with .isolated suffix
            isolated_file = isolation_dir / "confidential.txt.isolated"
            self.assertTrue(isolated_file.exists())
            # Verify file is locked/encrypted and can be decrypted with secure key
            self.assertNotEqual(isolated_file.read_text(encoding="utf-8"), "secret payload")
            key_path = isolation_dir / ".vault_key"
            self.assertTrue(key_path.exists())
            from cryptography.fernet import Fernet
            fernet = Fernet(key_path.read_bytes())
            decrypted_payload = fernet.decrypt(isolated_file.read_bytes()).decode("utf-8")
            self.assertEqual(decrypted_payload, "secret payload")
            
            # Verify telemetry status
            self.assertEqual(telemetry["protection"]["isolation"]["is_active"], True)
            self.assertEqual(telemetry["protection"]["isolation"]["count"], 1)
            self.assertEqual(telemetry["protection"]["active_protocol"]["mode"], "isolation")
            
            # 3. Clear simulation (should restore)
            orchestrator.trigger_simulation("None")
            telemetry_after = orchestrator.get_telemetry()
            
            # File should be restored to watch directory
            self.assertTrue(critical_file.exists())
            self.assertFalse(isolated_file.exists())
            self.assertEqual(telemetry_after["protection"]["isolation"]["is_active"], False)

    def test_generic_attack_mitigation_isolates_and_protects(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            watch_dir = root / "watch"
            backup_dir = root / "backup"
            watch_dir.mkdir()
            (watch_dir / "critical.txt").write_text("critical core content", encoding="utf-8")
            settings_path = root / "settings.yaml"
            settings_path.write_text(
                f"""
monitors:
  network:
    interval: 1.0
    sniff_packets: false
  process:
    interval: 2.0
  file:
    watch_path: "{watch_dir.as_posix()}"
  log:
    watch_file: "{(root / 'auth.log').as_posix()}"
    interval: 5.0
detection:
  model_dir: "./ai_models/trained_models"
protection:
  auto_protect: true
  warning_threshold: 55
  critical_threshold: 75
  snapshot_cooldown_seconds: 60
backup:
  enabled: true
  local_destination: "{backup_dir.as_posix()}"
  critical_paths:
    - "{watch_dir.as_posix()}"
  critical_extensions:
    - ".txt"
server:
  host: "127.0.0.1"
  port: 8000
""",
                encoding="utf-8",
            )

            orchestrator = CentralOrchestrator(str(settings_path))
            orchestrator.authenticate_and_start_protection({"name": "Test User", "email": "test@outlook.com"})
            # Trigger custom/generic simulated attack not handled by specific clauses
            orchestrator.trigger_simulation("Malware Intrusion")
            telemetry = orchestrator.get_telemetry()

        protection = telemetry["protection"]
        self.assertEqual(protection["forecast"]["level"], "normal")
        self.assertEqual(protection["active_protocol"]["mode"], "containment")
        
        # Verify custom/generic actions are executed
        actions = protection["active_protocol"]["actions"]
        self.assertTrue(any(act["type"] == "network" and "isolated" in act["message"] for act in actions))
        self.assertTrue(any(act["type"] == "firewall" and "service ports" in act["message"] for act in actions))
        self.assertTrue(any(act["type"] == "ip_block" and "192.168.1.250" in act["message"] for act in actions))


    def test_authentication_flow_deactivate_activate(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            settings_path = root / "settings.yaml"
            settings_path.write_text(
                """
monitors:
  network: {interval: 1.0, sniff_packets: false}
  process: {interval: 2.0}
  file: {watch_path: "."}
  log: {watch_file: "./auth.log", interval: 5.0}
detection: {model_dir: "./ai_models/trained_models"}
protection: {auto_protect: true}
backup: {enabled: false}
server: {host: "127.0.0.1", port: 8000}
""",
                encoding="utf-8"
            )
            orchestrator = CentralOrchestrator(str(settings_path))
            
            # 1. Initially unauthenticated
            self.assertFalse(orchestrator.authenticated)
            telemetry = orchestrator.get_telemetry()
            self.assertFalse(telemetry["auth"]["authenticated"])
            self.assertEqual(telemetry["protection"]["active_protocol"]["mode"], "inactive")
            
            # 2. Authenticate
            orchestrator.authenticate_and_start_protection({"name": "Test User", "email": "test@outlook.com"})
            self.assertTrue(orchestrator.authenticated)
            
            telemetry = orchestrator.get_telemetry()
            self.assertTrue(telemetry["auth"]["authenticated"])
            self.assertEqual(telemetry["auth"]["user_profile"]["name"], "Test User")
            self.assertEqual(telemetry["protection"]["active_protocol"]["mode"], "monitoring")
            
            # 3. Log out
            orchestrator.logout()
            self.assertFalse(orchestrator.authenticated)
            telemetry = orchestrator.get_telemetry()
            self.assertFalse(telemetry["auth"]["authenticated"])
            self.assertEqual(telemetry["protection"]["active_protocol"]["mode"], "inactive")


if __name__ == "__main__":
    unittest.main()
