"""
ByteHunter Model Training Utility.
Trains RandomForest and LogisticRegression models on EMBER 2018 dataset shards.
Usage: python train_models.py [--quick-train | --full-train]
"""
import os
import json
import argparse
import time
import joblib
import numpy as np
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, roc_auc_score

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")
EMBER_DIR = r"D:\Malware_V2\datasets\ember2018"

def load_ember_subset(ember_dir, limit=5000):
    """Load stratified subset from EMBER shards."""
    X, y = [], []
    malicious_count = 0
    benign_count = 0
    target_per_class = limit // 2

    logger.info(f"Loading up to {limit} samples from {ember_dir}...")
    
    for shard in range(6):
        if len(y) >= limit:
            break
            
        shard_path = os.path.join(ember_dir, f"train_features_{shard}.jsonl")
        if not os.path.exists(shard_path):
            logger.warning(f"Shard {shard} not found at {shard_path}")
            continue
            
        with open(shard_path, "r") as f:
            for line in f:
                if len(y) >= limit:
                    break
                    
                data = json.loads(line)
                label = data.get("label", -1)
                
                if label == -1:
                    continue
                    
                # Stratification logic
                if label == 1 and malicious_count >= target_per_class:
                    continue
                if label == 0 and benign_count >= target_per_class:
                    continue
                
                # Extract vector (2381 features)
                # We need to be careful with nested structures.
                # A robust way is to use the specific indices or just flatten values recursively.
                def flatten_val(v):
                    if isinstance(v, list):
                        res = []
                        for item in v:
                            res.extend(flatten_val(item))
                        return res
                    elif isinstance(v, dict):
                        res = []
                        for key in sorted(v.keys()):
                            res.extend(flatten_val(v[key]))
                        return res
                    elif isinstance(v, (int, float)):
                        return [float(v)]
                    return []

                vec = []
                for key in ['histogram', 'byteentropy', 'strings', 'general', 
                            'header', 'section', 'imports', 'exports', 'datadirectories']:
                    val = data.get(key)
                    vec.extend(flatten_val(val))
                
                # Pad/Clip to 2381
                if len(vec) < 2381:
                    vec.extend([0.0] * (2381 - len(vec)))
                X.append(np.array(vec[:2381], dtype=np.float32))
                y.append(label)
                
                if label == 1: malicious_count += 1
                else: benign_count += 1

    return np.array(X, dtype=np.float32), np.array(y)

def train(quick=True):
    os.makedirs(MODELS_DIR, exist_ok=True)
    limit = 10000 if quick else 100000
    
    X, y = load_ember_subset(EMBER_DIR, limit=limit)
    if len(X) == 0:
        logger.error("No data loaded. Training aborted.")
        return

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # 1. Random Forest
    logger.info("Training Random Forest...")
    rf_start = time.time()
    rf = RandomForestClassifier(n_estimators=100, max_depth=15, n_jobs=-1, random_state=42)
    rf.fit(X_train, y_train)
    rf_dur = time.time() - rf_start
    
    rf_preds = rf.predict(X_test)
    rf_probs = rf.predict_proba(X_test)[:, 1]
    rf_acc = accuracy_score(y_test, rf_preds)
    rf_auc = roc_auc_score(y_test, rf_probs)
    
    logger.info(f"RF Trained in {rf_dur:.1f}s. Accuracy: {rf_acc:.4f}, AUC: {rf_auc:.4f}")
    joblib.dump(rf, os.path.join(MODELS_DIR, "random_forest.pkl"))
    
    # 2. Logistic Regression
    logger.info("Training Logistic Regression...")
    lr_start = time.time()
    lr_pipe = Pipeline([
        ('scaler', StandardScaler()),
        ('lr', LogisticRegression(max_iter=1000, random_state=42))
    ])
    lr_pipe.fit(X_train, y_train)
    lr_dur = time.time() - lr_start
    
    lr_preds = lr_pipe.predict(X_test)
    lr_probs = lr_pipe.predict_proba(X_test)[:, 1]
    lr_acc = accuracy_score(y_test, lr_preds)
    lr_auc = roc_auc_score(y_test, lr_probs)
    
    logger.info(f"LR Trained in {lr_dur:.1f}s. Accuracy: {lr_acc:.4f}, AUC: {lr_auc:.4f}")
    joblib.dump(lr_pipe, os.path.join(MODELS_DIR, "logistic_regression.pkl"))
    
    logger.info(f"Models saved to {MODELS_DIR}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--quick-train", action="store_true", default=True)
    group.add_argument("--full-train", action="store_true")
    args = parser.parse_args()
    
    is_quick = not args.full_train
    train(quick=is_quick)
