# ByteHunter 🔍

**ML-powered malware detection engine with explainable AI, behavior simulation, and PDF reporting.**

ByteHunter is a full-stack cybersecurity tool that analyzes PE (Windows executable) files using an ensemble of ML models — LightGBM trained on the EMBER 2018 dataset, XGBoost for malware type classification, and SHAP for explainability. It features a real-time React dashboard, scan history, behavioral API analysis, and downloadable PDF reports.

> Built as part of an MSc Artificial Intelligence portfolio project at National College of Ireland.

---

## Demo

![ByteHunter Dashboard](./docs/screenshots/dashboard.png)

---

## Features

- **Multi-model ensemble** — LightGBM (EMBER 2018), XGBoost (BIG-2015), Random Forest, and Logistic Regression
- **SHAP explainability** — shows which PE features drove the verdict (entropy, imports, entry point, etc.)
- **Behavior simulation** — detects suspicious Win32 API calls (code injection, persistence, anti-debug)
- **Batch scanning** — upload up to 5 files at once with per-file verdicts
- **Scan history** — SQLite-backed history with verdict and risk-level filtering
- **PDF reports** — downloadable forensic report per scan
- **SHA-256 caching** — avoids redundant analysis for previously scanned files
- **Docker Compose** — one command to spin up backend + frontend

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI, Python 3.11 |
| ML Models | LightGBM, XGBoost, Scikit-learn, SHAP |
| Feature Extraction | LIEF (PE parsing), EMBER 2018 feature set |
| Database | SQLite via aiosqlite |
| Report Generation | ReportLab |
| Frontend | React (Vite), Tailwind CSS |
| Containerization | Docker, Docker Compose |
| Scheduling | APScheduler (model hot-swap) |

---

## Project Structure

```
bytehunter/
├── backend/
│   ├── main.py                  # FastAPI app, endpoints
│   ├── analyzer.py              # Core analysis pipeline
│   ├── features/
│   │   ├── ember_features.py    # EMBER 2381-dim feature extractor
│   │   └── fallback_features.py # Fallback for non-PE files
│   ├── utils/
│   │   ├── db_manager.py        # SQLite async CRUD
│   │   ├── report_gen.py        # PDF generation (ReportLab)
│   │   ├── hash_utils.py        # SHA-256, MD5, SHA-1
│   │   ├── malware_labels.py    # Malware type label mappings
│   │   └── model_updater.py     # Hot-swap model scheduler
│   ├── models/                  # Trained model files (not committed)
│   ├── notebooks/               # Training notebook (model_training.ipynb)
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   └── components/
│   │       ├── UploadZone.jsx
│   │       ├── ThreatScoreGauge.jsx
│   │       ├── VerdictBanner.jsx
│   │       ├── ShapChart.jsx
│   │       ├── BehaviorSim.jsx
│   │       ├── ExplanationCard.jsx
│   │       ├── ScanHistory.jsx
│   │       └── ...
│   ├── vite.config.js
│   └── Dockerfile
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## Getting Started

### Prerequisites

- Docker + Docker Compose
- Python 3.11 (for local dev)
- Node.js 18+ (for frontend dev)
- EMBER 2018 model file (`ember_model_2018`) — see [Model Setup](#model-setup)

### 1. Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/bytehunter.git
cd bytehunter
```

### 2. Set up environment variables

```bash
cp .env.example .env
```

Edit `.env` as needed:

```env
CORS_ORIGINS=http://localhost:5173
MODELS_DIR=./backend/models
MAX_FILE_SIZE_MB=50
```

### 3. Model Setup

ByteHunter requires trained model files placed in `backend/models/`:

| File | Description |
|---|---|
| `ember_model_2018` | LightGBM model trained on EMBER 2018 |
| `xgboost_type_classifier.pkl` | XGBoost malware type classifier |
| `shap_explainer.pkl` | SHAP TreeExplainer for LightGBM |
| `random_forest.pkl` | Random Forest ensemble model |
| `logistic_regression.pkl` | Logistic Regression model |

To train the models yourself, run the notebook:

```bash
cd backend/notebooks
jupyter notebook model_training.ipynb
```

### 4. Run with Docker Compose

```bash
docker-compose up --build
```

- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API docs: http://localhost:8000/docs

### 5. Run locally (without Docker)

**Backend:**
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Model load status check |
| `POST` | `/api/analyze` | Analyze 1–5 PE files (multipart/form-data) |
| `GET` | `/api/history` | Retrieve scan history (filter by verdict/risk) |
| `GET` | `/api/history/{scan_id}` | Full details for a specific scan |
| `GET` | `/api/report/{scan_id}` | Download PDF forensic report |

### Example: Analyze a file

```bash
curl -X POST http://localhost:8000/api/analyze \
  -F "files=@suspicious.exe"
```

### Example Response

```json
{
  "filename": "suspicious.exe",
  "verdict": "MALICIOUS",
  "threat_score": 0.94,
  "risk_level": "HIGH",
  "malware_type": "Trojan",
  "sha256": "abc123...",
  "shap_features": [...],
  "behavior_indicators": [
    { "api": "CreateRemoteThread", "name": "Code Injection", "severity": "HIGH" }
  ],
  "scan_id": "uuid-here"
}
```

---

## ML Pipeline

```
PE File
   │
   ▼
LIEF Parser → EMBER 2381-dim feature vector
   │
   ├──► LightGBM → Threat Score (0.0 – 1.0)
   │
   ├──► XGBoost  → Malware Type (Trojan, Ransomware, Spyware...)
   │
   ├──► SHAP     → Top features driving the verdict
   │
   └──► Fallback → Entropy + string heuristics (non-PE files)
```

**Feature categories extracted:**
- General PE metadata (imports, exports, debug, TLS, relocations)
- PE header fields (machine type, section count, compile timestamp, image base)
- Section entropy (`.text`, `.data`, `.rsrc` and others)
- Byte histogram (256-dim)
- Byte-entropy histogram (16-dim sliding window)
- String features (URLs, registry keys, function names)

---

## Security Note

> **Do not upload real malware samples to any public-facing deployment of this tool.** ByteHunter is designed for research, education, and portfolio demonstration purposes. Always run in an isolated environment when analyzing potentially malicious files.

---

## Roadmap

- [ ] VirusTotal API integration for hash lookup
- [ ] YARA rule scanning
- [ ] Network traffic analysis (PCAP support)
- [ ] User authentication + multi-tenant scan history
- [ ] Deployment to cloud (Render + Vercel)

---

## License

MIT License — see [LICENSE](./LICENSE) for details.

---

## Author

**Sangamesh Girish Dandin**  
MSc Artificial Intelligence — National College of Ireland  
[LinkedIn](https://linkedin.com/in/YOUR_PROFILE) · [GitHub](https://github.com/YOUR_USERNAME)
