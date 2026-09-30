import os
import pickle
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from dataset_loader import DatasetLoader

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TrainThreatDetector")

def train_threat_detector():
    logger.info("Loading threat training dataset...")
    X, y = DatasetLoader.generate_threat_dataset(num_samples=2000)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    logger.info("Initializing Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
    
    logger.info("Training threat detection model...")
    model.fit(X_train, y_train)
    
    # Evaluate
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    logger.info(f"Model accuracy on test set: {accuracy * 100:.2f}%")
    logger.info("Classification Report:")
    print(classification_report(y_test, predictions, target_names=[
        "Normal", "DDoS Attack", "SQL Injection", "Brute Force", "Ransomware", "Zero-day Exploit"
    ]))
    
    # Save the model
    os.makedirs("./ai_models/trained_models", exist_ok=True)
    model_path = "./ai_models/trained_models/threat_detection_model.pkl"
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
        
    logger.info(f"Threat detection model trained and saved to: {model_path}")

if __name__ == "__main__":
    train_threat_detector()
