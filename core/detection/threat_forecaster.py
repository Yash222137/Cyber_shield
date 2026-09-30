import time
from typing import Any, Dict, List


class ThreatForecaster:
    """Scores early-warning signals before a confirmed classifier hit."""

    def __init__(self, config: Dict[str, Any] | None = None):
        protection_cfg = (config or {}).get("protection", {})
        self.warning_threshold = float(protection_cfg.get("warning_threshold", 55))
        self.critical_threshold = float(protection_cfg.get("critical_threshold", 75))

    def analyze(
        self,
        network: Dict[str, Any],
        process: Dict[str, Any],
        file: Dict[str, Any],
        log: Dict[str, Any],
        threat: Dict[str, Any],
        anomaly: Dict[str, Any],
    ) -> Dict[str, Any]:
        score = 0.0
        signals: List[str] = []

        score += self._score_signal(file.get("file_modification_rate", 0), 20, 120, 30, "Rapid file modification", signals)
        score += self._score_signal(process.get("system_cpu", 0), 70, 95, 15, "High CPU pressure", signals)
        score += self._score_signal(process.get("system_ram", 0), 80, 96, 15, "High memory pressure", signals)
        score += self._score_signal(process.get("high_cpu_procs", 0), 1, 4, 10, "Multiple hot processes", signals)
        score += self._score_signal(network.get("connection_count", 0), 150, 800, 12, "Connection surge", signals)
        score += self._score_signal(network.get("unique_ips", 0), 60, 300, 10, "Unusual remote host spread", signals)
        score += self._score_signal(log.get("failed_login_count", 0), 5, 35, 10, "Repeated failed logins", signals)

        if threat.get("is_threat"):
            score += min(float(threat.get("severity_score", 60)) * 0.25, 25)
            signals.append(f"Classifier flagged {threat.get('attack_type', 'unknown threat')}")

        if anomaly.get("is_anomaly"):
            score += min(float(anomaly.get("anomaly_score", 60)) * 0.2, 20)
            signals.append("System anomaly detector is above baseline")

        score = round(min(score, 100.0), 1)
        level = "normal"
        if score >= self.critical_threshold:
            level = "critical"
        elif score >= self.warning_threshold:
            level = "warning"

        return {
            "risk_score": score,
            "level": level,
            "signals": signals,
            "recommended_action": self._recommended_action(level),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def _score_signal(
        self,
        value: float,
        warning: float,
        critical: float,
        weight: float,
        label: str,
        signals: List[str],
    ) -> float:
        value = float(value or 0)
        if value < warning:
            return 0.0
        signals.append(label)
        if value >= critical:
            return weight
        return ((value - warning) / (critical - warning)) * weight

    def _recommended_action(self, level: str) -> str:
        if level == "critical":
            return "Snapshot critical files and activate containment workflow."
        if level == "warning":
            return "Prepare critical data snapshot and continue close monitoring."
        return "Continue monitoring baseline."
