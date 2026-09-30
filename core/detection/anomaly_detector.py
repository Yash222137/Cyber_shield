# AI Anomaly Detector wrapper
import logging
from .ai_detector import AIDetector

logger = logging.getLogger("AnomalyDetector")

class AnomalyDetector:
    def __init__(self, model_dir: str = "./ai_models/trained_models"):
        self.detector = AIDetector(model_dir)

    def analyze(self, features: dict) -> dict:
        return self.detector.analyze_system_anomalies(features)
