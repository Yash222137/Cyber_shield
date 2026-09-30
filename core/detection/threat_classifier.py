# AI Threat Classifier wrapper
import logging
from .ai_detector import AIDetector

logger = logging.getLogger("ThreatClassifier")

class ThreatClassifier:
    def __init__(self, model_dir: str = "./ai_models/trained_models"):
        self.detector = AIDetector(model_dir)

    def classify(self, features: dict) -> dict:
        return self.detector.analyze_network_and_logs(features)
