import os
import pickle
import numpy as np
import logging
from typing import Dict, Any, Tuple

logger = logging.getLogger("AIDetector")

class AIDetector:
    def __init__(self, model_dir: str = "./ai_models/trained_models"):
        self.model_dir = model_dir
        self.threat_model_path = os.path.join(model_dir, "threat_detection_model.pkl")
        self.anomaly_model_path = os.path.join(model_dir, "anomaly_model.pkl")
        
        self.threat_model = None
        self.anomaly_model = None
        
        self.load_models()

    def load_models(self):
        try:
            if os.path.exists(self.threat_model_path):
                with open(self.threat_model_path, 'rb') as f:
                    self.threat_model = pickle.load(f)
                logger.info("Threat Detection model loaded successfully.")
            else:
                logger.warning(f"Threat Detection model file not found at {self.threat_model_path}. Train it first.")
        except Exception as e:
            logger.error(f"Error loading Threat Detection model: {e}")

        try:
            if os.path.exists(self.anomaly_model_path):
                with open(self.anomaly_model_path, 'rb') as f:
                    self.anomaly_model = pickle.load(f)
                logger.info("Anomaly Detection model loaded successfully.")
            else:
                logger.warning(f"Anomaly Detection model file not found at {self.anomaly_model_path}. Train it first.")
        except Exception as e:
            logger.error(f"Error loading Anomaly Detection model: {e}")

    def analyze_network_and_logs(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classifies threat type based on network metrics and log fail rates.
        Input: connection_count, unique_ips, bytes_sent_rate, bytes_recv_rate, failed_login_count
        """
        if not self.threat_model:
            return {"status": "error", "message": "Threat model not loaded"}
            
        # Feature order must match dataset_loader columns
        feat_vector = [
            features.get("connection_count", 0),
            features.get("unique_ips", 0),
            features.get("bytes_sent_rate", 0.0),
            features.get("bytes_recv_rate", 0.0),
            features.get("failed_login_count", 0)
        ]
        
        try:
            # Use pandas DataFrame to avoid scikit-learn warnings about feature names
            try:
                import pandas as pd
                df = pd.DataFrame([feat_vector], columns=[
                    "connection_count", "unique_ips", "bytes_sent_rate", "bytes_recv_rate", "failed_login_count"
                ])
                probs = self.threat_model.predict_proba(df)[0]
            except ImportError:
                # Predict probabilities
                probs = self.threat_model.predict_proba([feat_vector])[0]
            pred_class = int(np.argmax(probs))
            confidence = float(probs[pred_class])
            
            threat_map = {
                0: "Normal",
                1: "DDoS Attack",
                2: "SQL Injection",
                3: "Brute Force",
                4: "Ransomware",
                5: "Zero-day Exploit"
            }
            
            attack_type = threat_map.get(pred_class, "Unknown")
            is_threat = bool(pred_class != 0)
            
            # Map attack type to severity score
            severity_map = {
                "Normal": 0,
                "SQL Injection": 45,
                "Brute Force": 60,
                "Zero-day Exploit": 80,
                "DDoS Attack": 90,
                "Ransomware": 95
            }
            
            severity = severity_map.get(attack_type, 0) if is_threat else 0
            
            return {
                "is_threat": is_threat,
                "attack_type": attack_type,
                "confidence": round(confidence, 2),
                "severity_score": severity
            }
            
        except Exception as e:
            logger.error(f"Inference error in Threat Classifier: {e}")
            return {"is_threat": False, "attack_type": "Error", "severity_score": 0}

    def analyze_system_anomalies(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates system anomaly score using Isolation Forest.
        Input: system_cpu, system_ram, process_count, high_cpu_procs
        """
        if not self.anomaly_model:
            return {"status": "error", "message": "Anomaly model not loaded"}
            
        feat_vector = [
            features.get("system_cpu", 0.0),
            features.get("system_ram", 0.0),
            features.get("process_count", 0),
            features.get("high_cpu_procs", 0)
        ]
        
        try:
            # Use pandas DataFrame to avoid scikit-learn warnings about feature names
            try:
                import pandas as pd
                df = pd.DataFrame([feat_vector], columns=[
                    "system_cpu", "system_ram", "process_count", "high_cpu_procs"
                ])
                prediction = int(self.anomaly_model.predict(df)[0])
                decision_score = float(self.anomaly_model.decision_function(df)[0])
            except ImportError:
                # Isolation forest returns -1 for anomaly, 1 for normal
                prediction = int(self.anomaly_model.predict([feat_vector])[0])
                # Isolation forest anomaly score (lower is more anomalous)
                decision_score = float(self.anomaly_model.decision_function([feat_vector])[0])
            
            # Convert decision score to 0 - 100 anomaly metric
            # Normally decision_function returns negative values for outliers, positive for inliers
            anomaly_score = max(0.0, min(100.0, (0.5 - decision_score) * 100))
            is_anomaly = bool(prediction == -1)
            
            return {
                "is_anomaly": is_anomaly,
                "anomaly_score": round(anomaly_score, 1),
                "decision_score": round(decision_score, 3)
            }
            
        except Exception as e:
            logger.error(f"Inference error in Anomaly Detector: {e}")
            return {"is_anomaly": False, "anomaly_score": 0.0}
