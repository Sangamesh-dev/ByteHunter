"""
Run this script once to generate model_training.ipynb.
Usage: python generate_notebook.py
"""
import json, os

def cell(cell_type, source, cell_id):
    base = {"cell_type": cell_type, "id": cell_id, "metadata": {}, "source": source}
    if cell_type == "code":
        base["outputs"] = []
        base["execution_count"] = None
    return base

md = lambda src, cid: cell("markdown", src, cid)
code = lambda src, cid: cell("code", src, cid)

cells = [

# ── Section 1 ─────────────────────────────────────────────────────────────────
md("""# ByteHunter — Model Training Notebook
**NCI Dublin MSc Artificial Intelligence — Data Analytics for AI**
**Methodology: CRISP-DM**

---
## Section 1 — Business Understanding

### Problem Statement
End users routinely receive files via email, downloads, and removable media. Determining whether a file is malicious before opening it requires expensive antivirus subscriptions or manual expert analysis. ByteHunter provides instant, AI-powered static malware analysis through a web browser.

### Research Questions
1. Can static PE features (imports, section entropy, headers) reliably distinguish malware from benign files?
2. Which features are most predictive of malicious behaviour?
3. Can a multi-class classifier identify the specific malware family from byte-level features?
4. How do LightGBM, XGBoost, Random Forest, and Logistic Regression compare on these tasks?

### Success Criteria
- Binary classifier AUC-ROC >= 0.99 on EMBER 2018 test set
- Multi-class classifier accuracy >= 95% on BIG-2015
- Inference time < 500ms per file in production
- SHAP explanations interpretable by non-expert users""", "s1"),

# ── Section 2 ─────────────────────────────────────────────────────────────────
md("""## Section 2 — Data Understanding

### EMBER 2018
- **Source**: Anderson & Roth (2018), arXiv:1804.04637
- **Size**: ~1,000,000 PE file feature vectors (600k train, 200k test)
- **Features**: 2381 static features per file (general, header, section, imports, exports, byte histogram, entropy histogram)
- **Labels**: 1 = malicious, 0 = benign, -1 = unlabeled (excluded from training)
- **Class balance**: ~50/50 malicious/benign in labeled set

### Microsoft BIG-2015
- **Source**: Kaggle Microsoft Malware Classification Challenge
- **Size**: 10,868 labeled samples across 9 malware families
- **Files**: `.bytes` (raw hex sequences) + `.asm` (disassembly)
- **Labels**: Ramnit, Lollipop, Kelihos_ver1, Vundo, Simda, Tracur, Kelihos_ver3, Obfuscator.ACY, Gatak""", "s2"),

code("""import os, json, math, warnings
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
warnings.filterwarnings('ignore')

EMBER_DIR = os.getenv('EMBER_DATASET_DIR', r'D:\\Malware_V2\\datasets\\ember2018')
BIG2015_DIR = os.getenv('BIG2015_DATASET_DIR', r'D:\\Malware_V2\\datasets\\Microsoft Malware Classification')

print('EMBER dir:', EMBER_DIR)
print('BIG-2015 dir:', BIG2015_DIR)""", "c_setup"),

code("""# BIG-2015 class distribution
labels_df = pd.read_csv(os.path.join(BIG2015_DIR, 'trainLabels.csv'))
class_names = ['Ramnit','Lollipop','Kelihos_ver1','Vundo','Simda','Tracur','Kelihos_ver3','Obfuscator.ACY','Gatak']
labels_df['ClassName'] = labels_df['Class'].apply(lambda x: class_names[x-1])
print(labels_df['ClassName'].value_counts())

fig, axes = plt.subplots(1, 2, figsize=(14, 5))
labels_df['ClassName'].value_counts().plot(kind='bar', ax=axes[0], color='#00ff88', edgecolor='black')
axes[0].set_title('BIG-2015 Class Distribution')
axes[0].tick_params(axis='x', rotation=45)

# EMBER label sample
ember_labels = []
with open(os.path.join(EMBER_DIR, 'train_features_0.jsonl')) as f:
    for i, line in enumerate(f):
        if i >= 5000: break
        ember_labels.append(json.loads(line).get('label', -1))

pd.Series(ember_labels).value_counts().sort_index().plot(kind='bar', ax=axes[1], color='#ff4444', edgecolor='black')
axes[1].set_title('EMBER Label Distribution (5k sample)')
axes[1].set_xlabel('Label (-1=unlabeled, 0=benign, 1=malicious)')
plt.tight_layout()
plt.savefig('class_distribution.png', dpi=100, bbox_inches='tight')
plt.show()""", "c_eda1"),

code("""# Entropy distribution: malicious vs benign
entropies_mal, entropies_ben = [], []
with open(os.path.join(EMBER_DIR, 'train_features_0.jsonl')) as f:
    for i, line in enumerate(f):
        if i >= 10000: break
        d = json.loads(line)
        label = d.get('label', -1)
        hist = d.get('histogram', [0]*256)
        if label == 1: entropies_mal.append(hist)
        elif label == 0: entropies_ben.append(hist)

def hist_entropy(h):
    h = np.array(h, dtype=float)
    h = h / (h.sum() + 1e-9)
    h = h[h > 0]
    return float(-np.sum(h * np.log2(h)))

ent_mal = [hist_entropy(h) for h in entropies_mal[:2000]]
ent_ben = [hist_entropy(h) for h in entropies_ben[:2000]]

plt.figure(figsize=(10, 4))
plt.hist(ent_ben, bins=50, alpha=0.6, color='#00ff88', label='Benign')
plt.hist(ent_mal, bins=50, alpha=0.6, color='#ff4444', label='Malicious')
plt.xlabel('File Entropy')
plt.ylabel('Count')
plt.title('Entropy Distribution: Malicious vs Benign (EMBER sample)')
plt.legend()
plt.savefig('entropy_distribution.png', dpi=100, bbox_inches='tight')
plt.show()""", "c_eda2"),

# ── Section 3 ─────────────────────────────────────────────────────────────────
md("""## Section 3 — Data Preparation""", "s3"),

code("""# EMBER: Load training shards, flatten feature vectors, exclude label=-1
def load_ember_features(ember_dir, max_per_shard=10000):
    X, y = [], []
    for shard in range(6):
        path = os.path.join(ember_dir, f'train_features_{shard}.jsonl')
        with open(path) as f:
            for i, line in enumerate(f):
                if max_per_shard and i >= max_per_shard:
                    break
                d = json.loads(line)
                label = d.get('label', -1)
                if label == -1:
                    continue
                vec = []
                for key in ['histogram','byteentropy','strings','general',
                            'header','section','imports','exports','datadirectories']:
                    val = d.get(key, {})
                    if isinstance(val, list): vec.extend(val)
                    elif isinstance(val, dict): vec.extend(list(val.values()))
                X.append(vec)
                y.append(label)
    return X, y

print('Loading EMBER features...')
X_ember_raw, y_ember = load_ember_features(EMBER_DIR, max_per_shard=10000)
print(f'Loaded {len(X_ember_raw)} samples')

max_len = max(len(v) for v in X_ember_raw)
X_ember = np.array([v + [0]*(max_len - len(v)) for v in X_ember_raw], dtype=np.float32)
y_ember = np.array(y_ember)
print(f'Feature vector length: {X_ember.shape[1]}')""", "c_prep1"),

code("""from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

X_train_e, X_test_e, y_train_e, y_test_e = train_test_split(
    X_ember, y_ember, test_size=0.2, random_state=42, stratify=y_ember
)
print(f'EMBER train: {X_train_e.shape}, test: {X_test_e.shape}')""", "c_prep2"),

code("""# BIG-2015: Extract byte histogram + entropy features from .bytes files
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import SMOTE

def load_bytes_features(bytes_path):
    try:
        with open(bytes_path, 'r', errors='ignore') as f:
            content = f.read()
        hex_vals = [int(t, 16) for t in content.split()
                    if len(t)==2 and t != '??' and all(c in '0123456789abcdefABCDEF' for c in t)]
        if not hex_vals:
            return None
        arr = np.array(hex_vals[:100000], dtype=np.uint8)
        counts = np.bincount(arr, minlength=256).astype(np.float32)
        hist = counts / max(counts.sum(), 1)
        probs = hist[hist > 0]
        entropy = float(-np.sum(probs * np.log2(probs)))
        return np.concatenate([hist, [entropy, math.log1p(len(hex_vals))]])
    except Exception:
        return None

X_big, y_big = [], []
for _, row in labels_df.iterrows():
    path = os.path.join(BIG2015_DIR, f"{row['Id']}.bytes")
    if not os.path.exists(path): continue
    feats = load_bytes_features(path)
    if feats is not None:
        X_big.append(feats)
        y_big.append(row['ClassName'])

X_big = np.array(X_big, dtype=np.float32)
le = LabelEncoder()
y_big_enc = le.fit_transform(y_big)
print(f'BIG-2015 loaded: {X_big.shape}')
print('Classes:', le.classes_)""", "c_prep3"),

code("""X_train_b, X_test_b, y_train_b, y_test_b = train_test_split(
    X_big, y_big_enc, test_size=0.2, random_state=42, stratify=y_big_enc
)
smote = SMOTE(random_state=42, k_neighbors=3)
X_train_b_sm, y_train_b_sm = smote.fit_resample(X_train_b, y_train_b)
print(f'After SMOTE — train: {X_train_b_sm.shape}')""", "c_prep4"),

# ── Section 4 ─────────────────────────────────────────────────────────────────
md("""## Section 4 — Modeling

Four models applied:
1. **LightGBM** — EMBER pre-trained model (no retraining, direct inference)
2. **XGBoost** — trained on BIG-2015 for malware type classification
3. **Random Forest** — trained on EMBER subset as comparison model
4. **Logistic Regression** — baseline model on EMBER subset""", "s4"),

code("""import lightgbm as lgb
import time

lgb_model = lgb.Booster(model_file=os.path.join(EMBER_DIR, 'ember_model_2018'))
print('LightGBM EMBER model loaded.')
print(f'Number of trees: {lgb_model.num_trees()}')

t0 = time.time()
lgb_probs = lgb_model.predict(X_test_e)
lgb_time = time.time() - t0
lgb_preds = (lgb_probs >= 0.5).astype(int)
print(f'LightGBM inference on {len(X_test_e)} samples: {lgb_time*1000:.1f}ms')""", "c_m1"),

code("""import xgboost as xgb
import joblib

xgb_model = xgb.XGBClassifier(
    n_estimators=300, max_depth=6, learning_rate=0.1,
    subsample=0.8, colsample_bytree=0.8,
    eval_metric='mlogloss', random_state=42, n_jobs=-1,
)
t0 = time.time()
xgb_model.fit(X_train_b_sm, y_train_b_sm,
              eval_set=[(X_test_b, y_test_b)], verbose=50)
xgb_train_time = time.time() - t0
print(f'XGBoost training time: {xgb_train_time:.1f}s')

t0 = time.time()
xgb_preds = xgb_model.predict(X_test_b)
xgb_infer_time = time.time() - t0

os.makedirs('../models', exist_ok=True)
joblib.dump(xgb_model, '../models/xgboost_type_classifier.pkl')
print('Saved: ../models/xgboost_type_classifier.pkl')""", "c_m2"),

code("""from sklearn.ensemble import RandomForestClassifier

rf_model = RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1, random_state=42)
t0 = time.time()
rf_model.fit(X_train_e, y_train_e)
rf_train_time = time.time() - t0

t0 = time.time()
rf_preds = rf_model.predict(X_test_e)
rf_probs = rf_model.predict_proba(X_test_e)[:, 1]
rf_infer_time = time.time() - t0
print(f'Random Forest — train: {rf_train_time:.1f}s, infer: {rf_infer_time*1000:.1f}ms')""", "c_m3"),

code("""from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

lr_pipeline = Pipeline([
    ('scaler', StandardScaler()),
    ('lr', LogisticRegression(max_iter=1000, C=1.0, random_state=42, n_jobs=-1))
])
t0 = time.time()
lr_pipeline.fit(X_train_e, y_train_e)
lr_train_time = time.time() - t0

t0 = time.time()
lr_preds = lr_pipeline.predict(X_test_e)
lr_probs = lr_pipeline.predict_proba(X_test_e)[:, 1]
lr_infer_time = time.time() - t0
print(f'Logistic Regression — train: {lr_train_time:.1f}s, infer: {lr_infer_time*1000:.1f}ms')""", "c_m4"),

# ── Section 5 ─────────────────────────────────────────────────────────────────
md("""## Section 5 — Evaluation

All metrics: Accuracy, F1 (macro + weighted), AUC-ROC, Cohen's Kappa, Precision, Recall, Specificity, Confusion Matrix.""", "s5"),

code("""from sklearn.metrics import (
    accuracy_score, f1_score, roc_auc_score, cohen_kappa_score,
    precision_score, recall_score, confusion_matrix, classification_report
)

def binary_metrics(name, y_true, y_pred, y_prob, train_t, infer_t):
    acc = accuracy_score(y_true, y_pred)
    f1_mac = f1_score(y_true, y_pred, average='macro')
    f1_wt = f1_score(y_true, y_pred, average='weighted')
    auc = roc_auc_score(y_true, y_prob)
    kappa = cohen_kappa_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred)
    rec = recall_score(y_true, y_pred)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    spec = tn / (tn + fp)
    print(f'\\n=== {name} ===')
    print(f'Accuracy:      {acc:.4f}')
    print(f'F1 (macro):    {f1_mac:.4f}')
    print(f'F1 (weighted): {f1_wt:.4f}')
    print(f'AUC-ROC:       {auc:.4f}')
    print(f"Cohen's Kappa: {kappa:.4f}")
    print(f'Precision:     {prec:.4f}')
    print(f'Recall:        {rec:.4f}')
    print(f'Specificity:   {spec:.4f}')
    print(f'Train time:    {train_t:.2f}s  |  Infer time: {infer_t*1000:.1f}ms')
    return dict(model=name, accuracy=acc, f1_macro=f1_mac, auc=auc, kappa=kappa)

results = []
results.append(binary_metrics('LightGBM (EMBER)', y_test_e, lgb_preds, lgb_probs, 0, lgb_time))
results.append(binary_metrics('Random Forest', y_test_e, rf_preds, rf_probs, rf_train_time, rf_infer_time))
results.append(binary_metrics('Logistic Regression', y_test_e, lr_preds, lr_probs, lr_train_time, lr_infer_time))""", "c_eval1"),

code("""# XGBoost multiclass evaluation
from sklearn.preprocessing import label_binarize

xgb_acc = accuracy_score(y_test_b, xgb_preds)
xgb_f1_mac = f1_score(y_test_b, xgb_preds, average='macro')
xgb_f1_wt = f1_score(y_test_b, xgb_preds, average='weighted')
xgb_kappa = cohen_kappa_score(y_test_b, xgb_preds)
xgb_prec = precision_score(y_test_b, xgb_preds, average='macro')
xgb_rec = recall_score(y_test_b, xgb_preds, average='macro')

xgb_proba = xgb_model.predict_proba(X_test_b)
y_test_bin = label_binarize(y_test_b, classes=list(range(9)))
xgb_auc = roc_auc_score(y_test_bin, xgb_proba, multi_class='ovr', average='macro')

print('=== XGBoost (BIG-2015) ===')
print(f'Accuracy:      {xgb_acc:.4f}')
print(f'F1 (macro):    {xgb_f1_mac:.4f}')
print(f'F1 (weighted): {xgb_f1_wt:.4f}')
print(f'AUC-ROC (OvR): {xgb_auc:.4f}')
print(f"Cohen's Kappa: {xgb_kappa:.4f}")
print(f'Precision:     {xgb_prec:.4f}')
print(f'Recall:        {xgb_rec:.4f}')
print()
print(classification_report(y_test_b, xgb_preds, target_names=le.classes_))""", "c_eval2"),

code("""# Confusion matrices
fig, axes = plt.subplots(1, 2, figsize=(16, 6))

cm_lgb = confusion_matrix(y_test_e, lgb_preds)
sns.heatmap(cm_lgb, annot=True, fmt='d', cmap='Reds', ax=axes[0],
            xticklabels=['Benign','Malicious'], yticklabels=['Benign','Malicious'])
axes[0].set_title('LightGBM Confusion Matrix')
axes[0].set_xlabel('Predicted')
axes[0].set_ylabel('Actual')

cm_xgb = confusion_matrix(y_test_b, xgb_preds)
sns.heatmap(cm_xgb, annot=True, fmt='d', cmap='Blues', ax=axes[1],
            xticklabels=le.classes_, yticklabels=le.classes_)
axes[1].set_title('XGBoost Confusion Matrix (BIG-2015)')
axes[1].tick_params(axis='x', rotation=45)

plt.tight_layout()
plt.savefig('confusion_matrices.png', dpi=100, bbox_inches='tight')
plt.show()""", "c_eval3"),

code("""# ROC curves — all binary models
from sklearn.metrics import roc_curve, auc as auc_score

fig, ax = plt.subplots(figsize=(8, 6))
for name, y_prob in [('LightGBM', lgb_probs), ('Random Forest', rf_probs), ('Logistic Regression', lr_probs)]:
    fpr, tpr, _ = roc_curve(y_test_e, y_prob)
    ax.plot(fpr, tpr, label=f'{name} (AUC={auc_score(fpr, tpr):.3f})')

ax.plot([0,1],[0,1],'k--', label='Random')
ax.set_xlabel('False Positive Rate')
ax.set_ylabel('True Positive Rate')
ax.set_title('ROC Curves — Binary Malware Detection')
ax.legend()
plt.savefig('roc_curves.png', dpi=100, bbox_inches='tight')
plt.show()""", "c_eval4"),

code("""# Cross-validation (5-fold)
from sklearn.model_selection import cross_val_score

print('Cross-validation (5-fold, AUC-ROC):')
for name, model in [('Random Forest', rf_model), ('Logistic Regression', lr_pipeline)]:
    cv = cross_val_score(model, X_ember, y_ember, cv=5, scoring='roc_auc', n_jobs=-1)
    print(f'  {name}: {cv.mean():.4f} +/- {cv.std():.4f}')""", "c_eval5"),

code("""# Summary comparison table
summary = pd.DataFrame([
    {'Model': 'LightGBM (EMBER 2018)', 'Task': 'Binary',
     'Accuracy': accuracy_score(y_test_e, lgb_preds),
     'F1 Macro': f1_score(y_test_e, lgb_preds, average='macro'),
     'AUC-ROC': roc_auc_score(y_test_e, lgb_probs),
     'Kappa': cohen_kappa_score(y_test_e, lgb_preds), 'Train Time': 'Pre-trained'},
    {'Model': 'XGBoost (BIG-2015)', 'Task': 'Multiclass',
     'Accuracy': xgb_acc, 'F1 Macro': xgb_f1_mac, 'AUC-ROC': xgb_auc,
     'Kappa': xgb_kappa, 'Train Time': f'{xgb_train_time:.1f}s'},
    {'Model': 'Random Forest', 'Task': 'Binary',
     'Accuracy': accuracy_score(y_test_e, rf_preds),
     'F1 Macro': f1_score(y_test_e, rf_preds, average='macro'),
     'AUC-ROC': roc_auc_score(y_test_e, rf_probs),
     'Kappa': cohen_kappa_score(y_test_e, rf_preds), 'Train Time': f'{rf_train_time:.1f}s'},
    {'Model': 'Logistic Regression', 'Task': 'Binary',
     'Accuracy': accuracy_score(y_test_e, lr_preds),
     'F1 Macro': f1_score(y_test_e, lr_preds, average='macro'),
     'AUC-ROC': roc_auc_score(y_test_e, lr_probs),
     'Kappa': cohen_kappa_score(y_test_e, lr_preds), 'Train Time': f'{lr_train_time:.1f}s'},
])
print(summary.round(4).to_string(index=False))""", "c_eval6"),

# ── Section 6 ─────────────────────────────────────────────────────────────────
md("""## Section 6 — Deployment Notes

### Model Serialization
- `ember_model_2018` — native LightGBM booster format, loaded via `lgb.Booster(model_file=...)`
- `xgboost_type_classifier.pkl` — XGBoost classifier serialized with `joblib.dump`
- `shap_explainer.pkl` — SHAP TreeExplainer serialized with `joblib.dump`

### FastAPI Inference Pipeline
1. File uploaded via `POST /api/analyze` (multipart/form-data)
2. Written to `tempfile.NamedTemporaryFile`, deleted after analysis
3. `extract_ember_features()` produces 2381-dim vector via lief PE parsing
4. `lgb_model.predict(vec)` returns threat score 0.0-1.0, multiplied by 100
5. If score > 50: byte histogram + entropy fed to `xgb_model.predict()` for malware family
6. `shap_explainer.shap_values(vec)` returns top 8 feature importances
7. Full JSON response returned in < 2 seconds

### SHAP Explainer — Save for Production""", "s6"),

code("""import shap

print('Building SHAP TreeExplainer...')
explainer = shap.TreeExplainer(lgb_model)
joblib.dump(explainer, '../models/shap_explainer.pkl')
print('Saved: ../models/shap_explainer.pkl')

# Example explanation on one test sample
shap_vals = explainer.shap_values(X_test_e[:1])[0]
top_idx = np.argsort(np.abs(shap_vals))[::-1][:10]
print('\\nTop 10 SHAP features for sample[0]:')
for i in top_idx:
    print(f'  Feature {i:4d}: SHAP = {shap_vals[i]:+.4f}')""", "c_shap"),

]

nb = {
    "nbformat": 4,
    "nbformat_minor": 5,
    "metadata": {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python", "version": "3.11.0"}
    },
    "cells": cells
}

out = os.path.join(os.path.dirname(__file__), "model_training.ipynb")
with open(out, "w", encoding="utf-8") as f:
    json.dump(nb, f, indent=1, ensure_ascii=False)

print(f"Generated: {out}")
