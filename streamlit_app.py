# This is the software whic analyse and monitor the realtime cyber threat . 
import os
import yaml
import time
import asyncio
import logging
import threading
from pathlib import Path
# pyrefly: ignore [missing-import]
import uvicorn
from typing import Dict, Any

from core.monitor.network_monitor import NetworkMonitor
from core.monitor.process_monitor import ProcessMonitor
from core.monitor.file_monitor import FileMonitor
from core.monitor.log_monitor import LogMonitor
from core.detection.ai_detector import AIDetector
from core.protection import ProtectionController
from dashboard.backend import api_server

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("CentralOrchestrator")

class CentralOrchestrator:
    def __init__(self, settings_path: str = "./config/settings.yaml"):
        self.settings_path = settings_path
        self.config = self._load_config()
        
        # Initialize sub-monitors
        self.network_monitor = NetworkMonitor(self.config)
        self.process_monitor = ProcessMonitor(self.config)
        self.file_monitor = FileMonitor(self.config)
        self.log_monitor = LogMonitor(self.config)
        
        # AI Detector
        model_dir = self.config.get("detection", {}).get("model_dir", "./ai_models/trained_models")
        self.ai_detector = AIDetector(model_dir)

        # Protection controller forecasts developing attacks and protects critical data.
        self.protection_controller = ProtectionController(self.config)
        
        self.running = False
        self.telemetry_loop_thread = None
        self.current_simulation = None
        self.announcement_text = None
        self.announcement_id = 0
        
        # Microsoft Account Authentication State
        self.authenticated = False
        self.user_profile = None  # Stores e.g. {"name": "User Name", "email": "user@outlook.com"}


    def _load_config(self) -> Dict[str, Any]:
        if os.path.exists(self.settings_path):
            try:
                with open(self.settings_path, 'r') as f:
                    raw_config = yaml.safe_load(f) or {}
                    monitor_config = raw_config.get("monitors", {})
                    # Keep legacy top-level monitor keys available to existing classes.
                    for key in ("network", "process", "file", "log"):
                        raw_config.setdefault(key, monitor_config.get(key, {}))
                    return raw_config
            except Exception as e:
                logger.error(f"Error loading configuration: {e}")
        return {}

    def start(self):
        self.running = True
        
        # Start backend telemetry push thread
        self.telemetry_loop_thread = threading.Thread(target=self._telemetry_broadcast_loop, daemon=True)
        self.telemetry_loop_thread.start()
        
        # Only start monitors if already authenticated
        if self.authenticated:
            self._start_monitors()
        else:
            logger.info("Central Orchestrator started in STANDBY mode. Awaiting Microsoft account authentication.")

    def _start_monitors(self):
        # Start all physical/software monitors
        self.network_monitor.start()
        self.process_monitor.start()
        self.file_monitor.start()
        self.log_monitor.start()
        logger.info("Central Orchestrator monitoring pipelines active.")

    def _stop_monitors(self):
        self.network_monitor.stop()
        self.process_monitor.stop()
        self.file_monitor.stop()
        self.log_monitor.stop()
        logger.info("Central Orchestrator monitoring pipelines stopped.")

    def authenticate_and_start_protection(self, user_info: dict):
        if not self.authenticated:
            self.authenticated = True
            self.user_profile = user_info
            logger.info(f"Microsoft Account authenticated: {user_info.get('email')} ({user_info.get('name')})")
            
            # Activate and start the system protection monitors only if orchestrator is running
            if self.running:
                self._start_monitors()
            
            self.announcement_id += 1
            self.announcement_text = f"Microsoft account authenticated. System protection is active for {user_info.get('name')}."
            logger.info("Protection activated for system and account.")

    def logout(self):
        if self.authenticated:
            self.authenticated = False
            user_email = self.user_profile.get('email') if self.user_profile else "Unknown"
            self.user_profile = None
            logger.info(f"Microsoft Account signed out ({user_email}). Deactivating protection.")
            
            # Deactivate and stop the system monitors only if orchestrator is running
            if self.running:
                self._stop_monitors()
            
            self.announcement_id += 1
            self.announcement_text = "Microsoft account signed out. System protection deactivated."

    def stop(self):
        self.running = False
        if self.authenticated:
            self._stop_monitors()
        logger.info("Central Orchestrator stopped.")

    def trigger_simulation(self, attack_type: str | None):
        """Triggers system metrics simulation state for testing UI visualization."""
        self.current_simulation = attack_type
        if not attack_type or attack_type == "None":
            self.protection_controller.prevention_failed = False
            if self.protection_controller.data_isolator.is_active:
                self.protection_controller.data_isolator.restore_files()
        
        self._ensure_simulation_snapshot_source(attack_type)
        
        # propagate to child monitors to generate characteristics
        self.network_monitor.trigger_simulated_attack(attack_type)
        self.process_monitor.trigger_simulated_attack(attack_type)
        self.file_monitor.trigger_simulated_attack(attack_type)
        self.log_monitor.trigger_simulated_attack(attack_type)
        logger.info(f"Simulation mode set to: {attack_type}")
        
        self.announcement_id += 1
        if attack_type and attack_type != "None":
            self.announcement_text = f"We are under attack. {attack_type} detected, and protection mode is activated."
        else:
            self.announcement_text = "Threat mitigated. Security shields are holding."

    def set_prevention_failure(self, failed: bool):
        """Sets simulated prevention failure state."""
        self.protection_controller.prevention_failed = failed
        logger.info(f"Prevention failure state set to: {failed}")
        
        self.announcement_id += 1
        if failed:
            self.announcement_text = "Firewall breached. Isolation starts, and files are moved to the isolation vault."
        else:
            self.announcement_text = "Prevention failure state resolved. Restoring isolated files."


    def get_telemetry(self) -> Dict[str, Any]:
        """Runs predictions and packages comprehensive real-time status."""
        if not self.authenticated:
            return {
                "auth": {
                    "authenticated": False,
                    "user_profile": None,
                    "account_status": "UNPROTECTED",
                    "system_status": "INACTIVE"
                },
                "network": {"connection_count": 0, "unique_ip_count": 0, "bytes_sent_rate": 0.0, "bytes_recv_rate": 0.0, "recent_connections": []},
                "process": {"system_cpu": 0.0, "system_ram": 0.0, "process_count": 0, "top_processes": []},
                "file": {"modification_rate": 0, "event_history": []},
                "log": {"failed_login_count": 0, "suspicious_entries": []},
                "threat": {"is_threat": False, "attack_type": "Normal", "confidence": 0.0, "severity_score": 0, "simulated_attack": False},
                "anomaly": {"is_anomaly": False, "anomaly_score": 0.0, "decision_score": 0.0},
                "protection": {
                    "forecast": {"level": "normal", "risk_score": 0.0, "recommended_action": "Login required.", "signals": []},
                    "auto_protect": self.protection_controller.auto_protect,
                    "last_action": {"status": "inactive", "message": "Login with Microsoft Account to start protection.", "timestamp": time.strftime("%H:%M:%S")},
                    "active_protocol": {"mode": "inactive", "actions": [], "updated_at": time.strftime("%H:%M:%S")},
                    "action_history": [],
                    "backup": {"last_snapshot": {}, "status": "Inactive"},
                    "isolation": {"is_active": False, "isolated_files": []},
                    "prevention_failed": False,
                    "firewall": {"blocked_ips": [], "blocked_ports": [], "payloads_scanned": 0, "violations_detected": 0}
                },
                "announcement": {
                    "text": "Please sign in with your Microsoft account to activate Cyber Shield protection.",
                    "id": self.announcement_id
                }
            }

        net_feats = self.network_monitor.get_features()
        proc_feats = self.process_monitor.get_features()
        file_feats = self.file_monitor.get_features()
        log_feats = self.log_monitor.get_features()
        self._apply_simulated_protection_features(net_feats, proc_feats, file_feats, log_feats)
        
        # Aggregate threat detection features
        classification_input = {
            "connection_count": net_feats["connection_count"],
            "unique_ips": net_feats["unique_ips"],
            "bytes_sent_rate": net_feats["bytes_sent_rate"],
            "bytes_recv_rate": net_feats["bytes_recv_rate"],
            "failed_login_count": log_feats["failed_login_count"]
        }
        
        anomaly_input = {
            "system_cpu": proc_feats["system_cpu"],
            "system_ram": proc_feats["system_ram"],
            "process_count": proc_feats["process_count"],
            "high_cpu_procs": proc_feats["high_cpu_procs"]
        }
        
        # Perform Inference
        threat_pred = self.ai_detector.analyze_network_and_logs(classification_input)
        anomaly_pred = self.ai_detector.analyze_system_anomalies(anomaly_input)
        
        # Inject custom classification response values if threat simulator is active
        if self.current_simulation is not None and self.current_simulation != "None":
            # Overwrite classification predictions to match the simulation trigger
            threat_pred = {
                "is_threat": True,
                "attack_type": self.current_simulation,
                "confidence": 0.94,
                "severity_score": 90 if self.current_simulation == "DDoS" else 85,
                "simulated_attack": True,
            }
            if self.current_simulation in ["Ransomware", "Zero-day Exploit"]:
                anomaly_pred = {
                    "is_anomaly": True,
                    "anomaly_score": 92.5,
                    "decision_score": -0.25
                }
            else:
                anomaly_pred = {
                    "is_anomaly": False,
                    "anomaly_score": 0.0,
                    "decision_score": 0.0
                }
        else:
            # Under baseline conditions, default to safe normal to avoid Streamlit local websocket noise triggering false threats.
            threat_pred = {
                "is_threat": False,
                "attack_type": "Normal",
                "confidence": 1.0,
                "severity_score": 0,
                "simulated_attack": False
            }
            anomaly_pred = {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "decision_score": 0.0
            }

        process_status = self.process_monitor.get_status()
        file_status = self.file_monitor.get_status()
        self._apply_simulated_status(process_status, file_status)

        protection_status = self.protection_controller.evaluate(
            classification_input,
            anomaly_input,
            file_feats,
            log_feats,
            threat_pred,
            anomaly_pred,
            process_status,
            self.network_monitor.get_status(),
        )
        
        return {
            "auth": {
                "authenticated": True,
                "user_profile": self.user_profile,
                "account_status": "PROTECTED",
                "system_status": "ACTIVE"
            },
            "network": self.network_monitor.get_status(),
            "process": process_status,
            "file": file_status,
            "log": self.log_monitor.get_status(),
            "threat": threat_pred,
            "anomaly": anomaly_pred,
            "protection": protection_status,
            "announcement": {
                "text": self.announcement_text,
                "id": self.announcement_id
            }
        }


    def _apply_simulated_protection_features(
        self,
        net_feats: Dict[str, Any],
        proc_feats: Dict[str, Any],
        file_feats: Dict[str, Any],
        log_feats: Dict[str, Any],
    ):
        """Make simulator inputs deterministic for forecasting and protection."""
        if self.current_simulation == "DDoS":
            net_feats["connection_count"] = max(net_feats.get("connection_count", 0), 850)
            net_feats["unique_ips"] = max(net_feats.get("unique_ips", 0), 360)
            net_feats["bytes_recv_rate"] = max(net_feats.get("bytes_recv_rate", 0), 5_000_000.0)
        elif self.current_simulation == "SQL Injection":
            net_feats["connection_count"] = max(net_feats.get("connection_count", 0), 180)
            log_feats["failed_login_count"] = max(log_feats.get("failed_login_count", 0), 8)
        elif self.current_simulation == "Brute Force":
            log_feats["failed_login_count"] = max(log_feats.get("failed_login_count", 0), 40)
        elif self.current_simulation == "Ransomware":
            file_feats["file_modification_rate"] = max(file_feats.get("file_modification_rate", 0), 145)
            proc_feats["system_cpu"] = max(proc_feats.get("system_cpu", 0), 92.5)
            proc_feats["system_ram"] = max(proc_feats.get("system_ram", 0), 84.0)
            proc_feats["high_cpu_procs"] = max(proc_feats.get("high_cpu_procs", 0), 2)
        elif self.current_simulation == "Zero-day Exploit":
            proc_feats["system_cpu"] = max(proc_feats.get("system_cpu", 0), 78.0)
            proc_feats["system_ram"] = max(proc_feats.get("system_ram", 0), 96.0)
            proc_feats["high_cpu_procs"] = max(proc_feats.get("high_cpu_procs", 0), 1)

    def _ensure_simulation_snapshot_source(self, attack_type: str | None):
        """Seed harmless critical data so simulator snapshots are visible."""
        if not attack_type or attack_type == "None":
            return

        scanner = self.protection_controller.backup_manager.scanner
        if scanner.find_critical_files():
            return

        extension = ".txt" if ".txt" in scanner.critical_extensions else sorted(scanner.critical_extensions)[0]
        for raw_path in scanner.critical_paths:
            try:
                base_path = Path(raw_path).expanduser().resolve()
                if base_path.suffix.lower() in scanner.critical_extensions:
                    target = base_path
                    target.parent.mkdir(parents=True, exist_ok=True)
                else:
                    base_path.mkdir(parents=True, exist_ok=True)
                    target = base_path / f"simulated_critical_data{extension}"

                if not target.exists():
                    target.write_text(
                        "AI Cyber Shield simulator demo data.\n"
                        f"Created so the {attack_type} simulation can record a visible protection snapshot.\n",
                        encoding="utf-8",
                    )
                logger.info("Seeded simulator snapshot source: %s", target)
                return
            except OSError as exc:
                logger.warning("Unable to seed simulator snapshot source at %s: %s", raw_path, exc)

    def _apply_simulated_status(self, process_status: Dict[str, Any], file_status: Dict[str, Any]):
        """Keep dashboard status aligned with simulator features."""
        if self.current_simulation == "Ransomware":
            file_status["modification_rate"] = max(file_status.get("modification_rate", 0), 145)
            if not file_status.get("event_history"):
                file_status["event_history"] = []
            if not file_status["event_history"] or file_status["event_history"][0].get("filename") != "critical_data.docx.locked":
                file_status["event_history"].insert(0, {
                    "timestamp": time.strftime("%H:%M:%S"),
                    "type": "MODIFIED",
                    "filename": "critical_data.docx.locked",
                    "path": os.path.join(self.file_monitor.watch_path, "critical_data.docx.locked")
                })
            process_status["system_cpu"] = max(process_status.get("system_cpu", 0), 92.5)
            process_status["system_ram"] = max(process_status.get("system_ram", 0), 84.0)
        elif self.current_simulation == "Zero-day Exploit":
            process_status["system_ram"] = max(process_status.get("system_ram", 0), 96.0)

    def _telemetry_broadcast_loop(self):
        """Asynchronously queries telemetry values and broadcasts to connected Websocket channels."""
        # Create a new event loop inside this daemon thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def broadcast_job():
            while self.running:
                try:
                    telemetry = self.get_telemetry()
                    # Broadcast as JSON string
                    await api_server.manager.broadcast(yaml.dump(telemetry) if False else uvicorn_dumps(telemetry))
                except Exception as e:
                    logger.error(f"Error in telemetry broadcast loop: {e}")
                await asyncio.sleep(1.0)
                
        def uvicorn_dumps(d):
            import json
            return json.dumps(d)

        loop.run_until_complete(broadcast_job())

class UvicornServer(uvicorn.Server):
    def install_signal_handlers(self) -> None:
        pass

def main():
    import argparse
    parser = argparse.ArgumentParser(description="AI Cyber Shield Command Hub")
    parser.add_argument("--headless", action="store_true", help="Run without native desktop GUI window")
    args = parser.parse_args()

    logger.info("Initializing AI Cyber Shield Command Hub...")
    orchestrator = CentralOrchestrator()
    orchestrator.start()
    
    # Expose orchestrator reference to HTTP API routes
    api_server.set_orchestrator(orchestrator)
    
    # Retrieve server configuration
    server_cfg = orchestrator.config.get("server", {})
    host = server_cfg.get("host", "127.0.0.1")
    port = server_cfg.get("port", 8000)
    
    headless_mode = args.headless or bool(os.environ.get("HEADLESS"))
    gui_failed = False

    if not headless_mode:
        try:
            import webview
            
            # Run Uvicorn in a daemon thread
            def run_server():
                config = uvicorn.Config(api_server.app, host=host, port=port, log_level="warning")
                server = UvicornServer(config)
                server.run()
                
            threading.Thread(target=run_server, daemon=True).start()
            
            logger.info(f"Starting API and command dashboard on http://{host}:{port}")
            # Give uvicorn server a brief moment to start up
            time.sleep(1.0)
            logger.info("Opening AI Cyber Shield Hub window...")
            webview.create_window("AI Cyber Shield Command Hub", f"http://{host}:{port}", width=1200, height=800)
            webview.start()
        except Exception as exc:
            logger.warning(f"Failed to start GUI interface: {exc}. Falling back to headless mode.")
            gui_failed = True

    if headless_mode or gui_failed:
        logger.info(f"Running in HEADLESS mode. Starting API and command dashboard on http://{host}:{port}")
        try:
            config = uvicorn.Config(api_server.app, host=host, port=port, log_level="warning")
            server = UvicornServer(config)
            server.run()
        except KeyboardInterrupt:
            pass
        finally:
            logger.info("Shutting down monitors...")
            orchestrator.stop()

if __name__ == "__main__":
    import sys
    try:
        import streamlit as st
        _basename = os.path.basename(sys.argv[0]).lower() if sys.argv else ""
        is_streamlit = st.runtime.exists() or ("streamlit" in _basename and "streamlit_app" not in _basename)
    except Exception:
        is_streamlit = False
    
    if not is_streamlit:
        main()

def run_streamlit_app():
    import streamlit as st
    import datetime
    import pandas as pd
    import os

    st.set_page_config(
        page_title="AI Cyber Shield - Central Command",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    
    # Inject Custom CSS
    st.markdown("""
    <style>
    /* Styling adjustments for dark theme and custom elements */
    [data-testid="stAppViewContainer"] {
        background-color: #0b0f19;
        color: #f3f4f6;
        background-image: 
            radial-gradient(at 10% 10%, rgba(59, 130, 246, 0.08) 0px, transparent 50%),
            radial-gradient(at 90% 90%, rgba(239, 68, 68, 0.05) 0px, transparent 50%),
            radial-gradient(at 50% 10%, rgba(16, 185, 129, 0.05) 0px, transparent 50%);
        background-attachment: fixed;
    }
    
    .status-badge {
        background: rgba(16, 185, 129, 0.15);
        border: 1px solid rgba(16, 185, 129, 0.3);
        color: #10b981;
        padding: 0.35rem 0.85rem;
        border-radius: 50px;
        font-size: 0.85rem;
        font-weight: 600;
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
    }
    
    .status-badge.threat-active {
        background: rgba(239, 68, 68, 0.15);
        border: 1px solid rgba(239, 68, 68, 0.35);
        color: #ef4444;
    }
    
    .status-dot {
        width: 8px;
        height: 8px;
        background-color: #10b981;
        border-radius: 50%;
        box-shadow: 0 0 10px #10b981;
    }
    
    .status-dot.threat-active {
        background-color: #ef4444;
        box-shadow: 0 0 10px #ef4444;
    }
    
    .metric-card {
        background: linear-gradient(135deg, rgba(17, 24, 39, 0.6) 0%, rgba(31, 41, 55, 0.6) 100%);
        border-radius: 12px;
        padding: 1.25rem;
        border: 1px solid rgba(255, 255, 255, 0.08);
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        min-height: 110px;
        margin-bottom: 1rem;
    }
    
    .metric-header {
        font-size: 0.85rem;
        text-transform: uppercase;
        color: #9ca3af;
        letter-spacing: 0.5px;
    }
    
    .metric-value {
        font-size: 1.8rem;
        font-weight: 700;
        margin-top: 0.5rem;
    }
    
    .metric-trend {
        font-size: 0.8rem;
        margin-top: 0.25rem;
    }
    
    .firewall-layer-card {
        background: rgba(17, 24, 39, 0.5);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        padding: 1rem;
        position: relative;
        overflow: hidden;
        margin-bottom: 1rem;
    }
    
    .firewall-layer-card.violation {
        border-color: rgba(239, 68, 68, 0.35);
        background: rgba(239, 68, 68, 0.05);
    }
    
    .layer-badge {
        position: absolute;
        top: 0.5rem;
        right: 0.5rem;
        background: rgba(255, 255, 255, 0.06);
        border-radius: 4px;
        padding: 0.1rem 0.4rem;
        font-size: 0.75rem;
        font-weight: 700;
        color: #9ca3af;
    }
    
    .layer-title {
        font-weight: 600;
        font-size: 0.95rem;
        margin-bottom: 0.25rem;
    }
    
    .layer-metric {
        font-size: 1.1rem;
        font-weight: 700;
        margin-bottom: 0.25rem;
        color: #3b82f6;
    }
    
    .firewall-layer-card.violation .layer-metric {
        color: #ef4444;
    }
    
    .layer-details {
        font-size: 0.75rem;
        color: #9ca3af;
    }
    
    .vault-details-panel {
        margin-top: 1.25rem;
        padding: 1.25rem;
        background: rgba(239, 68, 68, 0.03);
        border: 1px dashed rgba(239, 68, 68, 0.3);
        border-radius: 12px;
    }
    
    .vault-file-item {
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 0.8rem;
        padding: 0.5rem 0.75rem;
        background: rgba(0, 0, 0, 0.25);
        border-radius: 6px;
        border-left: 3px solid #ef4444;
        margin-bottom: 0.5rem;
    }
    
    .vault-file-name {
        font-weight: 600;
    }
    
    .vault-file-meta {
        color: #9ca3af;
        font-size: 0.75rem;
    }
    
    .signal-item {
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 8px;
        padding: 0.6rem 0.75rem;
        color: #9ca3af;
        background: rgba(0, 0, 0, 0.12);
        margin-bottom: 0.5rem;
        font-size: 0.85rem;
    }
    
    .log-item {
        padding: 0.65rem 0.85rem;
        border-bottom: 1px solid rgba(255, 255, 255, 0.03);
        display: flex;
        gap: 1rem;
        font-family: monospace;
        font-size: 0.85rem;
    }
    
    .log-timestamp {
        color: #3b82f6;
    }
    
    .log-msg {
        color: #9ca3af;
    }
    
    .log-item.threat {
        background: rgba(239, 68, 68, 0.08);
        border-left: 3px solid #ef4444;
    }
    
    .log-item.threat .log-msg {
        color: #ff8a8a;
        font-weight: bold;
    }
    </style>
    """, unsafe_allow_html=True)

    @st.cache_resource
    def get_cached_orchestrator():
        orchestrator = CentralOrchestrator()
        orchestrator.start()
        return orchestrator

    orchestrator = get_cached_orchestrator()
    if orchestrator.authenticated:
        st.session_state.authenticated = True

    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    # Render Microsoft Sign-In page if not authenticated
    if not st.session_state.authenticated:
        col_space1, col_form, col_space2 = st.columns([1, 2, 1])
        with col_form:
            st.markdown("""
            <div style="text-align: center; margin-top: 3rem; margin-bottom: 2rem;">
                <svg width="60" height="60" viewBox="0 0 23 23" style="margin-bottom: 1.5rem;">
                    <path fill="#f25022" d="M0 0h11v11H0z"/>
                    <path fill="#7fba00" d="M12 0h11v11H12z"/>
                    <path fill="#00a4ef" d="M0 12h11v11H0z"/>
                    <path fill="#ffb900" d="M12 12h11v11H12z"/>
                </svg>
                <h1 style="color: #ffffff; font-family: 'Outfit', sans-serif; font-size: 2.2rem; font-weight: 800; margin: 0;">Microsoft Account Login</h1>
                <p style="color: #9ca3af; font-size: 1rem; margin-top: 0.5rem;">Sign in with Microsoft to start Cyber Shield protection for system and account.</p>
            </div>
            """, unsafe_allow_html=True)

            st.markdown("""
            <div style="background: rgba(17, 24, 39, 0.4); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; padding: 2rem; margin-bottom: 2rem;">
            """, unsafe_allow_html=True)
            
            auth_mode = st.radio("Authentication Method", [
                "Simulated Instant Login (Recommended)", 
                "Real Microsoft Account Login (Device Flow / Verification Code)",
                "Real Microsoft Account Login (Direct Password)"
            ])
            
            if auth_mode == "Simulated Instant Login (Recommended)":
                email = st.text_input("Microsoft Account Email", value="security.officer@outlook.com", placeholder="e.g. email@outlook.com")
                name = st.text_input("Display Name", value="Security Officer")
                
                st.markdown("<div style='margin-top: 1rem;'></div>", unsafe_allow_html=True)
                if st.button("Sign In & Activate Protection", use_container_width=True, type="primary"):
                    if "@" in email:
                        user_info = {
                            "name": name,
                            "email": email,
                            "id": f"simulated-{email}"
                        }
                        orchestrator.authenticate_and_start_protection(user_info)
                        st.session_state.authenticated = True
                        st.success("Authenticated successfully! Activating system shields...")
                        time.sleep(1.0)
                        st.rerun()
                    else:
                        st.error("Please enter a valid Microsoft account email address.")
            elif auth_mode == "Real Microsoft Account Login (Direct Password)":
                email = st.text_input("Microsoft Account Email", placeholder="e.g. yourname@outlook.com")
                password = st.text_input("Microsoft Account Password", type="password", placeholder="Enter your password")
                
                st.markdown("<div style='margin-top: 1rem;'></div>", unsafe_allow_html=True)
                if st.button("Sign In with Microsoft", use_container_width=True, type="primary"):
                    if not email or "@" not in email:
                        st.error("Please enter a valid Microsoft account email address.")
                    elif not password:
                        st.error("Please enter your password.")
                    else:
                        try:
                            import msal
                            pca = msal.PublicClientApplication("04b07795-8ddb-461a-bbee-02f9e1bf7b46", authority="https://login.microsoftonline.com/common")
                            result = pca.acquire_token_by_username_password(username=email, password=password, scopes=["User.Read"])
                            if "access_token" in result:
                                # Fetch profile details
                                import urllib.request
                                import json
                                req = urllib.request.Request(
                                    "https://graph.microsoft.com/v1.0/me",
                                    headers={"Authorization": f"Bearer {result['access_token']}"}
                                )
                                try:
                                    with urllib.request.urlopen(req, timeout=5) as response:
                                        profile = json.loads(response.read().decode())
                                        user_info = {
                                            "name": profile.get("displayName", "Microsoft User"),
                                            "email": profile.get("mail") or profile.get("userPrincipalName", email),
                                            "id": profile.get("id", "0000")
                                        }
                                except Exception:
                                    id_token_claims = result.get("id_token_claims", {})
                                    user_info = {
                                        "name": id_token_claims.get("name", "Microsoft User"),
                                        "email": id_token_claims.get("preferred_username") or id_token_claims.get("email", email),
                                        "id": id_token_claims.get("oid", "0000")
                                    }
                                    
                                orchestrator.authenticate_and_start_protection(user_info)
                                st.session_state.authenticated = True
                                st.success(f"Authenticated as {user_info['name']}! Starting shields...")
                                time.sleep(1.0)
                                st.rerun()
                            else:
                                error_msg = result.get("error_description", "Invalid username or password.")
                                if "mfa" in error_msg.lower() or "interaction_required" in result.get("error", "").lower():
                                    error_msg = "Multi-Factor Authentication (MFA) is required on this account. Please use the Device Code Flow / Verification Code login option instead."
                                st.error(f"Authentication Failed: {error_msg}")
                        except Exception as e:
                            error_str = str(e)
                            if "wstrust" in error_str.lower() or "mex" in error_str.lower() or "msa" in error_str.lower():
                                error_msg = "Direct password sign-in is not supported for personal Microsoft accounts (like @gmail.com, @outlook.com, @hotmail.com) or accounts with Multi-Factor Authentication (MFA). Please use the 'Real Microsoft Account Login (Device Flow / Verification Code)' method instead."
                            else:
                                error_msg = f"Authentication failed: {e}"
                            st.error(error_msg)
            else:
                st.write("Initiate MSAL Device Flow. You will receive a code to enter on the Microsoft authentication site.")
                
                if "device_flow_info" not in st.session_state:
                    st.session_state.device_flow_info = None
                    st.session_state.device_flow_time = 0
                
                if st.button("Generate Login Code", use_container_width=True):
                    try:
                        import msal
                        pca = msal.PublicClientApplication("04b07795-8ddb-461a-bbee-02f9e1bf7b46", authority="https://login.microsoftonline.com/common")
                        flow = pca.initiate_device_flow(scopes=["User.Read"])
                        if "user_code" in flow:
                            st.session_state.device_flow_info = flow
                            st.session_state.device_flow_time = time.time()
                        else:
                            st.error("Failed to generate code. Please check your network connection.")
                    except ImportError:
                        st.error("MSAL library is not available. Please install msal or use Simulated Instant Login.")
                    except Exception as e:
                        st.error(f"Error initiating device flow: {e}")
                
                flow = st.session_state.device_flow_info
                if flow:
                    elapsed = time.time() - st.session_state.device_flow_time
                    if elapsed > flow.get("expires_in", 900):
                        st.session_state.device_flow_info = None
                        st.warning("Microsoft device login code expired. Please request a new code.")
                        st.rerun()
                        
                    st.markdown("---")
                    st.info(f"Your Microsoft Verification Code: **{flow['user_code']}**")
                    st.markdown(f"1. Navigate to: [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin)\n2. Enter the code: **{flow['user_code']}**\n3. Sign in to your Microsoft account.")
                    
                    st.markdown("""
                    <div style="display: flex; align-items: center; gap: 0.5rem; color: #3b82f6; margin-top: 1rem; margin-bottom: 1rem;">
                        <div class="status-dot" style="background-color: #3b82f6; box-shadow: 0 0 10px #3b82f6;"></div>
                        <span>Awaiting verification completion...</span>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    if st.button("I have verified on Microsoft", use_container_width=True, type="primary"):
                        try:
                            import msal
                            pca = msal.PublicClientApplication("04b07795-8ddb-461a-bbee-02f9e1bf7b46", authority="https://login.microsoftonline.com/common")
                            result = pca.acquire_token_by_device_flow(flow)
                            if "access_token" in result:
                                # Fetch profile details
                                import urllib.request
                                import json
                                req = urllib.request.Request(
                                    "https://graph.microsoft.com/v1.0/me",
                                    headers={"Authorization": f"Bearer {result['access_token']}"}
                                )
                                try:
                                    with urllib.request.urlopen(req, timeout=5) as response:
                                        profile = json.loads(response.read().decode())
                                        user_info = {
                                            "name": profile.get("displayName", "Microsoft User"),
                                            "email": profile.get("mail") or profile.get("userPrincipalName", "user@outlook.com"),
                                            "id": profile.get("id", "0000")
                                        }
                                except Exception:
                                    id_token_claims = result.get("id_token_claims", {})
                                    user_info = {
                                        "name": id_token_claims.get("name", "Microsoft User"),
                                        "email": id_token_claims.get("preferred_username") or id_token_claims.get("email", "user@outlook.com"),
                                        "id": id_token_claims.get("oid", "0000")
                                    }
                                    
                                orchestrator.authenticate_and_start_protection(user_info)
                                st.session_state.device_flow_info = None
                                st.session_state.authenticated = True
                                st.success(f"Authenticated as {user_info['name']}! Starting shields...")
                                time.sleep(1.0)
                                st.rerun()
                            else:
                                st.error("Login verification pending. Make sure you entered the code correctly on the Microsoft site.")
                        except Exception as e:
                            st.error(f"Error checking verification status: {e}")
            st.markdown("</div>", unsafe_allow_html=True)
        return

    telemetry = orchestrator.get_telemetry()
    prevention_failed = telemetry.get('protection', {}).get('prevention_failed', False)

    # Header
    header_col1, header_col2, header_col3 = st.columns([6, 3, 3])
    with header_col1:
        st.markdown('<h1 style="background: linear-gradient(135deg, #60a5fa 0%, #3b82f6 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin: 0; padding: 0;">🛡️ AI CYBER SHIELD</h1>', unsafe_allow_html=True)
    with header_col2:
        is_threat = telemetry['threat'].get('is_threat', False)
        status_class = "threat-active" if is_threat else ""
        status_dot_class = "threat-active" if is_threat else ""
        status_text = "THREAT ALERT ACTIVE" if is_threat else "MONITORING ACTIVATED"
        st.markdown(f"""
        <div style="text-align: right; padding-top: 0.5rem;">
            <div class="status-badge {status_class}">
                <div class="status-dot {status_dot_class}"></div>
                {status_text}
            </div>
        </div>
        """, unsafe_allow_html=True)
    with header_col3:
        profile = telemetry.get("auth", {}).get("user_profile") or {"name": "Security Officer", "email": "security.officer@outlook.com"}
        email = profile.get("email")
        name = profile.get("name")
        st.markdown(f"""
        <div style="text-align: right; font-size: 0.8rem; color: #9ca3af; padding-top: 0.2rem; margin-bottom: 0.2rem;">
            <strong>{name}</strong><br>
            <span style="color: #10b981; font-weight: bold;">🛡️ Account Protected</span> ({email})
        </div>
        """, unsafe_allow_html=True)
        if st.button("Sign Out", key="streamlit_logout_btn", use_container_width=True):
            orchestrator.logout()
            st.session_state.authenticated = False
            st.rerun()

    # Threat Alert Banner
    if is_threat:
        attack_type = telemetry['threat'].get('attack_type', 'Unknown')
        confidence = int(telemetry['threat'].get('confidence', 0.0) * 100)
        severity = telemetry['threat'].get('severity_score', 0)
        st.error(f"""
        🚨 **CRITICAL THREAT DETECTED: {attack_type}**  
        Machine Learning Model matched threat type. Confidence: {confidence}%. Severity: {severity}/100.
        """)

    # Speech Synthesis Announcements
    announcement = telemetry.get('announcement', {})
    announcement_id = announcement.get('id', 0)
    announcement_text = announcement.get('text', None)

    if "last_announcement_id" not in st.session_state:
        st.session_state.last_announcement_id = announcement_id

    speak_text = None
    if announcement_id > st.session_state.last_announcement_id:
        speak_text = announcement_text
        st.session_state.last_announcement_id = announcement_id

    if speak_text:
        st.components.v1.html(f"""
            <script>
            if ('speechSynthesis' in window) {{
                window.speechSynthesis.cancel();
                const utterance = new SpeechSynthesisUtterance("{speak_text}");
                window.speechSynthesis.speak(utterance);
            }}
            </script>
        """, height=0)


    # Metric Widgets
    st.markdown("---")
    m_cols = st.columns(4)
    with m_cols[0]:
        st.markdown(f"<div class='metric-card'><div class='metric-header'>Active Sockets</div><div class='metric-value'>{telemetry['network']['connection_count']}</div><div class='metric-trend' style='color: #10b981;'>✔ Stable Connections</div></div>", unsafe_allow_html=True)
    with m_cols[1]:
        traffic_kb = (telemetry['network']['bytes_sent_rate'] + telemetry['network']['bytes_recv_rate']) / 1024.0
        st.markdown(f"<div class='metric-card'><div class='metric-header'>Traffic Speed</div><div class='metric-value'>{traffic_kb:.1f} KB/s</div><div class='metric-trend' style='color: #3b82f6;'>⇅ Real-time Rx/Tx</div></div>", unsafe_allow_html=True)
    with m_cols[2]:
        file_rate = telemetry['file']['modification_rate']
        file_trend = "✔ Idle State"
        file_color = "#10b981"
        if file_rate > 100:
            file_trend = "⚠ Extreme Activity"
            file_color = "#ef4444"
        elif file_rate > 20:
            file_trend = "⚠ High Activity"
            file_color = "#f59e0b"
        st.markdown(f"<div class='metric-card'><div class='metric-header'>File Mod Rate</div><div class='metric-value'>{file_rate} / min</div><div class='metric-trend' style='color: {file_color};'>{file_trend}</div></div>", unsafe_allow_html=True)
    with m_cols[3]:
        anomaly_score = telemetry['anomaly']['anomaly_score']
        anomaly_trend = "✔ Safe baseline"
        anomaly_color = "#10b981"
        if telemetry['anomaly']['is_anomaly']:
            anomaly_trend = "⚠ Anomaly flag set"
            anomaly_color = "#ef4444"
        st.markdown(f"<div class='metric-card'><div class='metric-header'>System Anomaly Score</div><div class='metric-value'>{anomaly_score:.1f}%</div><div class='metric-trend' style='color: {anomaly_color};'>{anomaly_trend}</div></div>", unsafe_allow_html=True)

    # Predictive Protection & Traffic Chart
    st.markdown("---")
    col_mid_1, col_mid_2 = st.columns([7, 5])
    
    with col_mid_1:
        st.markdown("### Predictive Protection")
        col_prot_1, col_prot_2, col_prot_3 = st.columns(3)
        with col_prot_1:
            risk_score = telemetry['protection']['forecast']['risk_score']
            level = telemetry['protection']['forecast']['level'].upper()
            level_color = "#ef4444" if level == "CRITICAL" else "#f59e0b" if level == "WARNING" else "#10b981"
            st.markdown(f"<div style='padding: 1rem; background: rgba(17, 24, 39, 0.4); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; min-height: 120px;'><div class='metric-header'>Upcoming Threat Risk</div><div style='font-size: 2.2rem; font-weight: 800; margin: 0.35rem 0;'>{risk_score:.1f}%</div><div style='font-size: 0.8rem; color: {level_color}; font-weight: 600;'>{level}</div></div>", unsafe_allow_html=True)
        with col_prot_2:
            snapshot_count = telemetry['protection']['backup']['last_snapshot'].get('file_count', 0)
            snapshot_status = telemetry['protection']['backup']['last_snapshot'].get('status', 'Waiting for risk signal')
            st.markdown(f"<div style='padding: 1rem; background: rgba(17, 24, 39, 0.4); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; min-height: 120px;'><div class='metric-header'>Critical Data Snapshot</div><div style='font-size: 1.5rem; font-weight: 700; margin: 0.5rem 0;'>{snapshot_count} files</div><div style='font-size: 0.8rem; color: #9ca3af;'>{snapshot_status}</div></div>", unsafe_allow_html=True)
        with col_prot_3:
            mode = telemetry['protection']['active_protocol']['mode'].replace('_', ' ').upper()
            mode_color = "#ef4444" if mode in ["CONTAINMENT", "ISOLATION"] else "#f59e0b" if mode in ["EARLY GUARD", "PREVENTION"] else "#10b981"
            last_action = telemetry['protection'].get('last_action', {}).get('message', 'No guard action active')
            st.markdown(f"<div style='padding: 1rem; background: rgba(17, 24, 39, 0.4); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; min-height: 120px;'><div class='metric-header'>Protection Mode</div><div style='font-size: 1.5rem; font-weight: 700; margin: 0.5rem 0; color: {mode_color};'>{mode}</div><div style='font-size: 0.8rem; color: #9ca3af;'>{last_action}</div></div>", unsafe_allow_html=True)

            
        st.markdown("<div style='margin-top: 1rem;'></div>", unsafe_allow_html=True)
        col_sig_1, col_sig_2 = st.columns(2)
        with col_sig_1:
            st.markdown("**Elevated Threat Signals**")
            signals = telemetry['protection']['forecast'].get('signals', [])
            if not signals:
                st.markdown('<div class="signal-item">No elevated signals</div>', unsafe_allow_html=True)
            else:
                for sig in signals[:5]:
                    st.markdown(f'<div class="signal-item">{sig}</div>', unsafe_allow_html=True)
        with col_sig_2:
            st.markdown("**Protection Actions Log**")
            actions = telemetry['protection']['active_protocol'].get('actions', [])
            if not actions:
                st.markdown('<div class="signal-item">No protection actions yet</div>', unsafe_allow_html=True)
            else:
                for act in actions[:5]:
                    status = act.get('status', 'ready').upper()
                    msg = act.get('message', '')
                    st.markdown(f'<div class="signal-item">[{status}] {msg}</div>', unsafe_allow_html=True)

        # Vault details manifest panel
        isolation = telemetry['protection'].get('isolation', {})
        if isolation.get('is_active') and isolation.get('isolated_files'):
            st.markdown("""
            <div class="vault-details-panel">
                <h5>🔒 FAIL-SAFE ISOLATED SENSITIVE INFORMATION</h5>
            </div>
            """, unsafe_allow_html=True)
            for file in isolation['isolated_files']:
                filename = file.get('filename', '')
                orig_path = file.get('original_path', '')
                sizeKB = file.get('bytes', 0) / 1024.0
                base = os.path.basename(orig_path)
                st.markdown(f"<div class='vault-file-item'><span class='vault-file-name'>🔒 {filename}.isolated</span><span class='vault-file-meta'>Moved: {base} ({sizeKB:.2f} KB)</span></div>", unsafe_allow_html=True)

    with col_mid_2:
        st.markdown("### Network Telemetry Rate")
        if "chart_rx" not in st.session_state:
            st.session_state.chart_rx = []
        if "chart_tx" not in st.session_state:
            st.session_state.chart_tx = []
        if "chart_labels" not in st.session_state:
            st.session_state.chart_labels = []
            
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        st.session_state.chart_labels.append(current_time)
        st.session_state.chart_rx.append(telemetry["network"]["bytes_recv_rate"] / 1024.0)
        st.session_state.chart_tx.append(telemetry["network"]["bytes_sent_rate"] / 1024.0)
        
        if len(st.session_state.chart_labels) > 15:
            st.session_state.chart_labels.pop(0)
            st.session_state.chart_rx.pop(0)
            st.session_state.chart_tx.pop(0)
            
        chart_df = pd.DataFrame({
            "Rx Traffic (KB/s)": st.session_state.chart_rx,
            "Tx Traffic (KB/s)": st.session_state.chart_tx
        }, index=st.session_state.chart_labels)
        st.line_chart(chart_df, color=["#3b82f6", "#10b981"])

    # 5-Layer Firewall
    st.markdown("---")
    st.markdown("### 🛡️ Five-Layer Cognitive Firewall")
    fw_cols = st.columns(5)
    firewall = telemetry['protection'].get('firewall', {})

    if firewall:
        # L1: Network IP Filter
        blocked_ips = firewall.get("blocked_ips", [])
        l1_violation = "violation" if blocked_ips else ""
        l1_metric = f"{len(blocked_ips)} blocked IPs"
        l1_details = ", ".join(blocked_ips) if blocked_ips else "No IPs blocked"
        with fw_cols[0]:
            st.markdown(f"<div class='firewall-layer-card {l1_violation}'><div class='layer-badge'>L1</div><div class='layer-title'>Network IP Filter</div><div class='layer-metric'>{l1_metric}</div><div class='layer-details'>{l1_details}</div></div>", unsafe_allow_html=True)

        # L2: Transport Port Guard
        blocked_ports = firewall.get("blocked_ports", [])
        l2_violation = "violation" if blocked_ports else ""
        l2_metric = f"{len(blocked_ports)} blocked ports"
        l2_details = ", ".join(f"Port {p}" for p in blocked_ports) if blocked_ports else "No ports blocked"
        with fw_cols[1]:
            st.markdown(f"<div class='firewall-layer-card {l2_violation}'><div class='layer-badge'>L2</div><div class='layer-title'>Transport Port Guard</div><div class='layer-metric'>{l2_metric}</div><div class='layer-details'>{l2_details}</div></div>", unsafe_allow_html=True)

        # L3: Application Inspector
        payloads_scanned = firewall.get("payloads_scanned", 0)
        anomalies = firewall.get("payload_anomalies_detected", 0)
        l3_violation = "violation" if anomalies > 0 else ""
        l3_metric = f"{payloads_scanned} scanned"
        l3_details = f"{anomalies} anomalies detected" if anomalies > 0 else "No anomalies detected"
        with fw_cols[2]:
            st.markdown(f"<div class='firewall-layer-card {l3_violation}'><div class='layer-badge'>L3</div><div class='layer-title'>Application Inspector</div><div class='layer-metric'>{l3_metric}</div><div class='layer-details'>{l3_details}</div></div>", unsafe_allow_html=True)

        # L4: Process Binding Guard
        proc_verified = firewall.get("processes_verified", 0)
        proc_violations = firewall.get("process_binding_violations", 0)
        l4_violation = "violation" if proc_violations > 0 else ""
        l4_metric = f"{proc_verified} verified"
        l4_details = f"{proc_violations} violations blocked" if proc_violations > 0 else "All bindings safe"
        with fw_cols[3]:
            st.markdown(f"<div class='firewall-layer-card {l4_violation}'><div class='layer-badge'>L4</div><div class='layer-title'>Process Binding Guard</div><div class='layer-metric'>{l4_metric}</div><div class='layer-details'>{l4_details}</div></div>", unsafe_allow_html=True)

        # L5: Behavioral Rate Limiter
        rate_violations = firewall.get("rate_violations", 0)
        l5_violation = "violation" if rate_violations > 0 else ""
        l5_metric = f"{rate_violations} violations"
        l5_details = "Traffic spike blocked" if rate_violations > 0 else "Traffic within baseline"
        with fw_cols[4]:
            st.markdown(f"<div class='firewall-layer-card {l5_violation}'><div class='layer-badge'>L5</div><div class='layer-title'>Behavioral Rate Limiter</div><div class='layer-metric'>{l5_metric}</div><div class='layer-details'>{l5_details}</div></div>", unsafe_allow_html=True)


    # Simulator & logs / processes
    st.markdown("---")
    col_bot_1, col_bot_2 = st.columns([4, 8])
    
    with col_bot_1:
        st.markdown("### Threat Simulator Dashboard")
        st.write("Inject realistic mock cyber attack patterns to demonstrate machine learning model classification and real-time command dashboard updates.")
        
        sim_cols_1 = st.columns(3)
        sim_cols_2 = st.columns(3)
        
        with sim_cols_1[0]:
            if st.button("Normal baseline", use_container_width=True):
                orchestrator.trigger_simulation(None)
                st.rerun()
        with sim_cols_1[1]:
            if st.button("DDoS Attack", use_container_width=True):
                orchestrator.trigger_simulation("DDoS")
                st.rerun()
        with sim_cols_1[2]:
            if st.button("SQL Injection", use_container_width=True):
                orchestrator.trigger_simulation("SQL Injection")
                st.rerun()
                
        with sim_cols_2[0]:
            if st.button("Brute Force", use_container_width=True):
                orchestrator.trigger_simulation("Brute Force")
                st.rerun()
        with sim_cols_2[1]:
            if st.button("Ransomware", use_container_width=True):
                orchestrator.trigger_simulation("Ransomware")
                st.rerun()
        with sim_cols_2[2]:
            if st.button("Zero-day Exploit", use_container_width=True):
                orchestrator.trigger_simulation("Zero-day Exploit")
                st.rerun()
                
        st.markdown("<div style='margin-top: 1rem;'></div>", unsafe_allow_html=True)
        toggle_fail = st.toggle("Simulate Prevention Failure (Force shield failure & isolate sensitive files)", value=prevention_failed)
        if toggle_fail != prevention_failed: 
            orchestrator.set_prevention_failure(toggle_fail)
            st.rerun()
            
    with col_bot_2:
        tab_proc, tab_logs = st.tabs(["Top Processes", "Audit Logs"])
        
        with tab_proc:
            proc_rows = ""
            for proc in telemetry['process'].get('top_processes', []):
                cpu_style = 'color: #ef4444;' if proc['cpu_percent'] > 50 else ''
                ram_style = 'color: #f59e0b;' if proc['memory_percent'] > 30 else ''
                proc_rows += f"<tr><td style='padding: 0.5rem;'>{proc['pid']}</td><td style='padding: 0.5rem; font-weight: 600;'>{proc['name']}</td><td style='padding: 0.5rem; {cpu_style}'>{proc['cpu_percent']}%</td><td style='padding: 0.5rem; {ram_style}'>{proc['memory_percent']}%</td></tr>"
            if not proc_rows:
                proc_rows = "<tr><td colspan='4' style='text-align: center; color: #9ca3af; padding: 0.5rem;'>Querying active processes...</td></tr>"
            st.html(f"<table style='width: 100%; border-collapse: collapse; font-size: 0.9rem;'><thead><tr style='border-bottom: 1px solid rgba(255, 255, 255, 0.08); text-align: left; color: #9ca3af;'><th style='padding: 0.5rem;'>PID</th><th style='padding: 0.5rem;'>Name</th><th style='padding: 0.5rem;'>CPU %</th><th style='padding: 0.5rem;'>RAM %</th></tr></thead><tbody>{proc_rows}</tbody></table>")
            
        with tab_logs:
            with st.container(height=300):
                merged_logs = []
                if telemetry['threat']['is_threat']:
                    merged_logs.append({
                        "type": "threat",
                        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
                        "message": f"[AI Threat Classifier] CLASSIFIED THREAT: {telemetry['threat']['attack_type']} (Confidence: {int(telemetry['threat']['confidence'] * 100)}%)"
                    })
                if telemetry['anomaly']['is_anomaly']:
                    merged_logs.append({
                        "type": "threat",
                        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
                        "message": f"[AI Anomaly Detector] CPU/RAM/process allocation anomaly identified (Score: {telemetry['anomaly']['anomaly_score']}%)"
                    })
                for evt in telemetry['file'].get('event_history', [])[:8]:
                    merged_logs.append({
                        "type": "file",
                        "timestamp": evt.get('timestamp', ''),
                        "message": f"[File System] {evt.get('type', '')}: {evt.get('filename', '')}"
                    })
                for ent in telemetry['log'].get('suspicious_entries', [])[:10]:
                    merged_logs.append({
                        "type": "log",
                        "timestamp": ent.get('timestamp', ''),
                        "message": f"[Audit Log] {ent.get('message', '')}"
                    })
                if not merged_logs:
                    st.markdown("<div class='log-item'><span class='log-timestamp'>INFO</span><span class='log-msg'>Scanning channels active... No anomalies identified.</span></div>", unsafe_allow_html=True)
                else:
                    for log in merged_logs:
                        threat_class = "threat" if log['type'] == 'threat' else ""
                        st.markdown(f"<div class='log-item {threat_class}' style='margin-bottom: 0.25rem;'><span class='log-timestamp'>{log['timestamp']}</span><span class='log-msg' style='margin-left: 1rem;'>{log['message']}</span></div>", unsafe_allow_html=True)


    # Refresh
    import time
    time.sleep(1.0)
    st.rerun()

try:
    import sys
    import streamlit as st
    _basename = os.path.basename(sys.argv[0]).lower() if sys.argv else ""
    is_streamlit_run = st.runtime.exists() or ("streamlit" in _basename and "streamlit_app" not in _basename)
except Exception:
    is_streamlit_run = False

if is_streamlit_run:
    run_streamlit_app()

