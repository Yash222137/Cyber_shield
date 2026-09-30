import os
import pickle
import logging
from sklearn.ensemble import IsolationForest
from dataset_loader import DatasetLoader

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TrainAnomalyDetector")

def train_anomaly_detector():
    logger.info("Loading anomaly training dataset...")
    df = DatasetLoader.generate_anomaly_dataset(num_samples=1500)
    
    logger.info("Initializing Isolation Forest Model...")
    # contamination represents expected proportion of outliers (anomalies) in the training data
    model = IsolationForest(contamination=0.05, random_state=42)
    
    logger.info("Training anomaly detection model...")
    model.fit(df)
    
    # Save the model
    os.makedirs("./ai_models/trained_models", exist_ok=True)
    model_path = "./ai_models/trained_models/anomaly_model.pkl"
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
        
    logger.info(f"Anomaly detection model trained and saved to: {model_path}")

if __name__ == "__main__":
    train_anomaly_detector()
