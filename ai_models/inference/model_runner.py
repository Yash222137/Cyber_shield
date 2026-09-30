# Model runner entrypoint for inference tasks
import os
import sys
from typing import Dict, Any

# Adjust paths to import core modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from core.detection.ai_detector import AIDetector

class ModelRunner:
    def __init__(self, model_dir: str = "./ai_models/trained_models"):
        self.detector = AIDetector(model_dir)

    def run_inference(self, connection_features: dict, system_features: dict) -> dict:
        threat_results = self.detector.analyze_network_and_logs(connection_features)
        anomaly_results = self.detector.analyze_system_anomalies(system_features)
        return {
            "threat": threat_results,
            "anomaly": anomaly_results
        }
