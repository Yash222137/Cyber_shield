import numpy as np
import pandas as pd
from typing import Tuple

class DatasetLoader:
    @staticmethod
    def generate_threat_dataset(num_samples: int = 1000) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Generates a synthetic dataset for the Threat Classifier (Random Forest).
        Features: connection_count, unique_ips, bytes_sent_rate, bytes_recv_rate, failed_login_count
        Classes: 0: Normal, 1: DDoS Attack, 2: SQL Injection, 3: Brute Force, 4: Ransomware, 5: Zero-day Exploit
        """
        np.random.seed(42)
        data = []
        
        # 0: Normal (50% of data)
        for _ in range(num_samples // 2):
            conn = np.random.randint(5, 50)
            ips = np.random.randint(1, 10)
            sent = np.random.uniform(1000.0, 50000.0)
            recv = np.random.uniform(1000.0, 50000.0)
            failed = np.random.choice([0, 0, 0, 1], p=[0.7, 0.15, 0.1, 0.05])
            data.append([conn, ips, sent, recv, failed, 0])
            
        # 1: DDoS Attack (10% of data)
        for _ in range(num_samples // 10):
            conn = np.random.randint(500, 2000)
            ips = np.random.randint(200, 1000)
            sent = np.random.uniform(50000.0, 500000.0)
            recv = np.random.uniform(2000000.0, 10000000.0)
            failed = 0
            data.append([conn, ips, sent, recv, failed, 1])
            
        # 2: SQL Injection (10% of data)
        for _ in range(num_samples // 10):
            conn = np.random.randint(10, 40)
            ips = np.random.randint(1, 3)
            sent = np.random.uniform(10000.0, 60000.0)
            recv = np.random.uniform(10000.0, 60000.0)
            failed = np.random.choice([0, 1])
            data.append([conn, ips, sent, recv, failed, 2])
            
        # 3: Brute Force (10% of data)
        for _ in range(num_samples // 10):
            conn = np.random.randint(5, 20)
            ips = np.random.randint(1, 2)
            sent = np.random.uniform(5000.0, 15000.0)
            recv = np.random.uniform(5000.0, 15000.0)
            failed = np.random.randint(15, 80)
            data.append([conn, ips, sent, recv, failed, 3])
            
        # 4: Ransomware (10% of data)
        for _ in range(num_samples // 10):
            conn = np.random.randint(10, 60)
            ips = np.random.randint(1, 5)
            sent = np.random.uniform(10000.0, 100000.0)
            recv = np.random.uniform(10000.0, 100000.0)
            failed = 0
            data.append([conn, ips, sent, recv, failed, 4])
            
        # 5: Zero-day Exploit (10% of data)
        for _ in range(num_samples // 10):
            conn = np.random.randint(2, 10)
            ips = np.random.randint(1, 2)
            sent = np.random.uniform(80000.0, 300000.0)
            recv = np.random.uniform(5000.0, 20000.0)
            failed = 0
            data.append([conn, ips, sent, recv, failed, 5])

        columns = ["connection_count", "unique_ips", "bytes_sent_rate", "bytes_recv_rate", "failed_login_count", "label"]
        df = pd.DataFrame(data, columns=columns)
        
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        X = df.drop(columns=["label"])
        y = df["label"]
        return X, y

    @staticmethod
    def generate_anomaly_dataset(num_samples: int = 1000) -> pd.DataFrame:
        """
        Generates a synthetic dataset for the Anomaly Detector (Isolation Forest).
        """
        np.random.seed(42)
        data = []
        
        for _ in range(int(num_samples * 0.95)):
            cpu = np.random.uniform(2.0, 45.0)
            ram = np.random.uniform(20.0, 65.0)
            procs = np.random.randint(40, 110)
            high_cpu = np.random.choice([0, 1], p=[0.95, 0.05])
            data.append([cpu, ram, procs, high_cpu])
            
        for _ in range(int(num_samples * 0.05)):
            cpu = np.random.uniform(85.0, 100.0)
            ram = np.random.uniform(80.0, 99.0)
            procs = np.random.randint(120, 200)
            high_cpu = np.random.randint(2, 8)
            data.append([cpu, ram, procs, high_cpu])
            
        columns = ["system_cpu", "system_ram", "process_count", "high_cpu_procs"]
        df = pd.DataFrame(data, columns=columns)
        return df
