import unittest
import os
import sys

# Adjust path to import core packages
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.detection.ai_detector import AIDetector

class TestDetection(unittest.TestCase):
    def setUp(self):
        self.detector = AIDetector("./ai_models/trained_models")

    def test_threat_classification_keys(self):
        # Sample normal features
        feats = {
            "connection_count": 10,
            "unique_ips": 2,
            "bytes_sent_rate": 5000.0,
            "bytes_recv_rate": 5000.0,
            "failed_login_count": 0
        }
        res = self.detector.analyze_network_and_logs(feats)
        self.assertIn("is_threat", res)
        self.assertIn("attack_type", res)
        self.assertIn("severity_score", res)

    def test_anomaly_detector_keys(self):
        # Sample normal features
        feats = {
            "system_cpu": 15.0,
            "system_ram": 45.0,
            "process_count": 60,
            "high_cpu_procs": 0
        }
        res = self.detector.analyze_system_anomalies(feats)
        self.assertIn("is_anomaly", res)
        self.assertIn("anomaly_score", res)

if __name__ == "__main__":
    unittest.main()
