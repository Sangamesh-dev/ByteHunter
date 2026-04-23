"""
APScheduler-based hot-swap model updater.
Checks /models/pending/ every 24 hours for new model files.
If found, replaces the active model in-memory without restarting.
"""
import os
import logging
import shutil
import joblib
import lightgbm as lgb
from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger(__name__)

MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
PENDING_DIR = os.path.join(MODELS_DIR, "pending")


def check_for_model_updates(app_state: dict):
    """Called by scheduler every 24h. Hot-swaps models if new files found in pending/."""
    os.makedirs(PENDING_DIR, exist_ok=True)

    lgb_pending = os.path.join(PENDING_DIR, "ember_model_2018")
    xgb_pending = os.path.join(PENDING_DIR, "xgboost_type_classifier.pkl")

    if os.path.exists(lgb_pending):
        try:
            new_model = lgb.Booster(model_file=lgb_pending)
            app_state["lgb_model"] = new_model
            dest = os.path.join(MODELS_DIR, "ember_model_2018")
            shutil.move(lgb_pending, dest)
            logger.info("LightGBM model hot-swapped successfully.")
        except Exception as e:
            logger.error(f"Failed to hot-swap LightGBM model: {e}")

    if os.path.exists(xgb_pending):
        try:
            new_model = joblib.load(xgb_pending)
            app_state["xgb_model"] = new_model
            dest = os.path.join(MODELS_DIR, "xgboost_type_classifier.pkl")
            shutil.move(xgb_pending, dest)
            logger.info("XGBoost model hot-swapped successfully.")
        except Exception as e:
            logger.error(f"Failed to hot-swap XGBoost model: {e}")


def start_scheduler(app_state: dict) -> BackgroundScheduler:
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        check_for_model_updates,
        trigger="interval",
        hours=24,
        args=[app_state],
        id="model_updater",
    )
    scheduler.start()
    logger.info("Model update scheduler started (interval: 24h).")
    return scheduler
