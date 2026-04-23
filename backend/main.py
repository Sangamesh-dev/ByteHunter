"""
ByteHunter — FastAPI backend entry point.
Loads models at startup, exposes /api/analyze and /api/health.
"""
import os
import sys
import logging
import tempfile
from contextlib import asynccontextmanager

import uuid
import joblib
import lightgbm as lgb
from typing import List, Optional
from fastapi import FastAPI, File, UploadFile, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

load_dotenv()

# Add backend root to path so relative imports work
sys.path.insert(0, os.path.dirname(__file__))

from analyzer import run_analysis
from utils.model_updater import start_scheduler
from utils.db_manager import DBManager, make_json_serializable
from utils.report_gen import generate_pdf_report
from utils.hash_utils import compute_hashes

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ── paths ─────────────────────────────────────────────────────────────────────
MODELS_DIR = os.getenv("MODELS_DIR", os.path.join(os.path.dirname(__file__), "models"))

# Allow individual overrides so you can point LightGBM at the dataset folder directly
LGB_MODEL_PATH = os.getenv(
    "LGB_MODEL_PATH",
    os.path.join(MODELS_DIR, "ember_model_2018")
)
XGB_MODEL_PATH = os.getenv(
    "XGB_MODEL_PATH",
    os.path.join(MODELS_DIR, "xgboost_type_classifier.pkl")
)
SHAP_EXPLAINER_PATH = os.getenv(
    "SHAP_EXPLAINER_PATH",
    os.path.join(MODELS_DIR, "shap_explainer.pkl")
)
RF_MODEL_PATH = os.path.join(MODELS_DIR, "random_forest.pkl")
LR_MODEL_PATH = os.path.join(MODELS_DIR, "logistic_regression.pkl")

MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE_MB", "50")) * 1024 * 1024  # bytes

# Shared app state (models live here)
app_state: dict = {
    "lgb_model": None,
    "xgb_model": None,
    "shap_explainer": None,
    "rf_model": None,
    "lr_model": None,
    "db": DBManager(),
}


# ── lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load LightGBM
    if os.path.exists(LGB_MODEL_PATH):
        try:
            app_state["lgb_model"] = lgb.Booster(model_file=LGB_MODEL_PATH)
            logger.info("LightGBM EMBER model loaded.")
        except Exception as e:
            logger.error(f"Failed to load LightGBM model: {e}")
    else:
        logger.warning(f"LightGBM model not found at {LGB_MODEL_PATH}")

    # Load XGBoost
    if os.path.exists(XGB_MODEL_PATH):
        try:
            app_state["xgb_model"] = joblib.load(XGB_MODEL_PATH)
            logger.info("XGBoost type classifier loaded.")
        except Exception as e:
            logger.error(f"Failed to load XGBoost model: {e}")
    else:
        logger.warning(f"XGBoost model not found at {XGB_MODEL_PATH}")

    # Load SHAP explainer
    if os.path.exists(SHAP_EXPLAINER_PATH):
        try:
            app_state["shap_explainer"] = joblib.load(SHAP_EXPLAINER_PATH)
            logger.info("SHAP explainer loaded.")
        except Exception as e:
            logger.error(f"Failed to load SHAP explainer: {e}")

    # Load Random Forest
    if os.path.exists(RF_MODEL_PATH):
        try:
            app_state["rf_model"] = joblib.load(RF_MODEL_PATH)
            logger.info("Random Forest model loaded.")
        except Exception as e:
            logger.error(f"Failed to load RF model: {e}")

    # Load Logistic Regression
    if os.path.exists(LR_MODEL_PATH):
        try:
            app_state["lr_model"] = joblib.load(LR_MODEL_PATH)
            logger.info("Logistic Regression model loaded.")
        except Exception as e:
            logger.error(f"Failed to load LR model: {e}")

    # Initialize DB
    await app_state["db"].init_db()

    # Start model hot-swap scheduler
    scheduler = start_scheduler(app_state)

    yield

    scheduler.shutdown(wait=False)
    logger.info("Scheduler stopped.")


# ── app ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="ByteHunter API", version="1.0.0", lifespan=lifespan)

ALLOWED_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── endpoints ─────────────────────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "models_loaded": {
            "lightgbm": app_state["lgb_model"] is not None,
            "xgboost": app_state["xgb_model"] is not None,
            "shap": app_state["shap_explainer"] is not None,
        },
    }


@app.post("/api/analyze")
async def analyze(files: List[UploadFile] = File(...)):
    """Analyze one or more files. Supports sequential batch processing (max 5)."""
    if len(files) > 5:
        raise HTTPException(status_code=400, detail="Batch limit exceeded (max 5 files).")

    results = []
    
    for file in files:
        file_bytes = await file.read()
        if not file_bytes:
            continue
            
        if len(file_bytes) > MAX_FILE_SIZE:
            results.append({
                "filename": file.filename,
                "error": f"File exceeds {MAX_FILE_SIZE // (1024*1024)} MB limit."
            })
            continue

        filename = file.filename or "unknown"
        hashes = compute_hashes(file_bytes)
        sha256 = hashes["sha256"]
        
        # 1. Check DB Cache
        cached_result = await app_state["db"].get_cached_result(sha256)
        if cached_result:
            logger.info(f"Cache hit for {filename} ({sha256})")
            results.append(cached_result)
            continue

        # 2. Run Analysis
        try:
            scan_id = str(uuid.uuid4())
            result = run_analysis(file_bytes, filename, app_state)
            result["scan_id"] = scan_id
            
            # 3. Save to DB
            await app_state["db"].save_scan_result(scan_id, filename, result)
            results.append(result)
            
        except Exception as e:
            logger.exception(f"Analysis failed for {filename}: {e}")
            results.append({
                "filename": filename,
                "error": "Analysis failed."
            })

    # Force JSON safe response
    results = make_json_serializable(results)
    return results


@app.get("/api/history")
async def get_history(
    verdict: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None)
):
    """Retrieve scan history with filters."""
    history = await app_state["db"].get_history(verdict, risk_level)
    return make_json_serializable(history)


@app.get("/api/history/{scan_id}")
async def get_scan_details(scan_id: str):
    """Retrieve full details for a past scan."""
    result = await app_state["db"].get_scan_by_id(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return make_json_serializable(result)


@app.get("/api/report/{scan_id}")
async def get_report(scan_id: str):
    """Generate and download PDF report for a scan."""
    result = await app_state["db"].get_scan_by_id(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found.")
    
    try:
        # Debug check as requested
        print("PDF RESULT:", result)
        pdf_bytes = generate_pdf_report(result)
        filename = f"ByteHunter_Report_{scan_id[:8]}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        logger.exception(f"Report generation failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate report.")
