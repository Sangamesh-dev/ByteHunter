"""
Core analysis pipeline.
Orchestrates feature extraction → LightGBM threat scoring → XGBoost type classification → SHAP.
"""
import os
import time
import math
import tempfile
import logging
from datetime import datetime, timezone

import numpy as np

from features.ember_features import extract_ember_features
from features.fallback_features import analyze_fallback
from utils.hash_utils import compute_hashes
from utils.malware_labels import get_label_info, index_to_label, CLASS_ORDER

logger = logging.getLogger(__name__)

# ── SHAP feature name mapping (EMBER internal → human-readable) ───────────────
FEATURE_NAME_MAP = {
    "general_0": "Debug info present",
    "general_1": "Has relocations",
    "general_2": "Has resources",
    "general_3": "Digital signature",
    "general_4": "Has TLS",
    "general_5": "Symbol count",
    "general_6": "Import count",
    "general_7": "Export count",
    "header_0": "Machine type",
    "header_1": "Section count",
    "header_2": "Compile timestamp",
    "header_4": "Executable flag",
    "header_5": "DLL flag",
    "header_6": "PE magic",
    "header_9": "Code size",
    "header_12": "Entry point address",
    "header_14": "Image base",
    "section_0_4": ".text entropy",
    "section_1_4": ".data entropy",
    "section_2_4": ".rsrc entropy",
    "section_3_4": "Section 4 entropy",
    "section_4_4": "Section 5 entropy",
}

# ── Semantic Category Mapping ──────────────────────────────────────────────
CATEGORY_MAP = {
    "entropy": "Obfuscation",
    "import": "Execution Risk",
    "signature": "Trust Issues",
    "entry point": "Execution Risk",
    "debug": "Obfuscation",
    "header": "Suspicious Structure",
    "section": "Suspicious Structure",
    "frequency": "Obfuscation",
}

# ── Behavior Mapping (API -> Name, Severity) ────────────────────────────────
BEHAVIOR_MAP = {
    "CreateRemoteThread": {"name": "Code Injection", "severity": "HIGH"},
    "VirtualAllocEx": {"name": "Memory Manipulation", "severity": "HIGH"},
    "WriteProcessMemory": {"name": "Memory Manipulation", "severity": "HIGH"},
    "ShellExecuteA": {"name": "Execution", "severity": "MEDIUM"},
    "ShellExecuteW": {"name": "Execution", "severity": "MEDIUM"},
    "RegSetValueEx": {"name": "Persistence", "severity": "HIGH"},
    "WinExec": {"name": "Execution", "severity": "MEDIUM"},
    "URLDownloadToFile": {"name": "Network Download", "severity": "MEDIUM"},
    "InternetOpenUrl": {"name": "Network Communication", "severity": "MEDIUM"},
    "IsDebuggerPresent": {"name": "Anti-Debugging", "severity": "MEDIUM"},
}


def _feature_name(idx: int) -> str:
    """Map feature index to human-readable name."""
    if idx < 8:
        return FEATURE_NAME_MAP.get(f"general_{idx}", f"General feature {idx}")
    if idx < 70:
        return FEATURE_NAME_MAP.get(f"header_{idx - 8}", f"Header field {idx - 8}")
    if idx < 325:
        sec_idx = (idx - 70) // 51
        feat_idx = (idx - 70) % 51
        names = ["Name length", "Virtual size", "Raw size", "Offset", "Entropy",
                 "Readable", "Writable", "Executable", "Contains code", "Init data"]
        feat_name = names[feat_idx] if feat_idx < len(names) else f"Prop {feat_idx}"
        return f"Section {sec_idx + 1} {feat_name}"
    if idx < 1605:
        return "Import table hash"
    if idx < 1733:
        return "Export table hash"
    if idx < 1989:
        return f"Byte frequency [{idx - 1733}]"
    return f"Entropy histogram [{idx - 1989}]"


def _build_warning_signs(shap_vals: list[dict], metadata: dict, is_pe: bool) -> list[str]:
    """Generate human-readable IOC list from SHAP + metadata."""
    warnings = []

    # SHAP-driven warnings
    for item in shap_vals[:4]:
        val = item["value"]
        feat = item["feature"]
        if val > 0.1:
            if "entropy" in feat.lower():
                warnings.append(f"High section entropy detected ({feat})")
            elif "import" in feat.lower():
                warnings.append("Suspicious import table structure")
            elif "signature" in feat.lower():
                warnings.append("No valid digital signature")
            elif "entry point" in feat.lower():
                warnings.append("Unusual entry point address")
            elif "timestamp" in feat.lower():
                warnings.append("Suspicious compile timestamp")
            else:
                warnings.append(f"Anomalous feature: {feat}")

    # Metadata-driven warnings
    if is_pe and metadata:
        for sec in metadata.get("sections", []):
            if sec.get("entropy", 0) > 7.0:
                warnings.append(f"Very high entropy in {sec['name']} section ({sec['entropy']})")
            if sec.get("name", "").strip("\x00") not in (
                ".text", ".data", ".rdata", ".rsrc", ".reloc", ".bss", ".idata", ".edata", ""
            ):
                warnings.append(f"Unusual section name: {sec['name']}")

        imports = metadata.get("imports", [])
        suspicious_apis = [
            "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
            "ShellExecuteA", "ShellExecuteW", "RegSetValueEx",
            "WinExec", "URLDownloadToFile", "InternetOpenUrl",
        ]
        for api in suspicious_apis:
            if api in imports:
                warnings.append(f"{api} import detected")

        if not metadata.get("has_signature"):
            if "No valid digital signature" not in warnings:
                warnings.append("No valid digital signature")

    return warnings[:6]


def _build_flag_reason(shap_vals: list[dict], is_pe: bool, threat_score: float) -> str:
    if not is_pe:
        return (
            "Heuristic analysis detected suspicious patterns in this non-PE file. "
            "High entropy or embedded executable content may indicate obfuscation."
        )
    if not shap_vals:
        return "Static analysis identified anomalous characteristics consistent with malicious software."

    top = shap_vals[0]["feature"] if shap_vals else "unknown features"
    second = shap_vals[1]["feature"] if len(shap_vals) > 1 else None

    if threat_score > 80:
        base = f"Strong indicators of malicious behaviour: {top}"
    else:
        base = f"Suspicious characteristics detected: {top}"

    if second:
        base += f" and {second.lower()}"

    base += " suggest this file may be packed, obfuscated, or contain malicious code."
    return base


def _group_explanations(shap_vals: list[dict]) -> tuple[list[dict], str]:
    """Group SHAP features into semantic categories and build summary."""
    groups = {}
    for item in shap_vals[:6]:
        feat = item["feature"].lower()
        val = item["value"]
        if abs(val) < 0.01: continue
        
        category = "Suspicious Structure" # Default
        for key, cat in CATEGORY_MAP.items():
            if key in feat:
                category = cat
                break
        
        if category not in groups:
            groups[category] = []
        groups[category].append(item["feature"])

    explanations = []
    summary_parts = []
    for cat, feats in groups.items():
        reason = f"Indicators detected in: {', '.join(feats[:2])}"
        explanations.append({"category": cat, "reason": reason})
        summary_parts.append(f"{cat.lower()} patterns ({len(feats)} features)")
    
    summary = "Analysis identifies " + ", ".join(summary_parts) + ". "
    if any(c in ["Obfuscation", "Trust Issues"] for c in groups):
        summary += "These are strong indicators of evasion techniques."
    else:
        summary += "Results suggest anomalous but potentially non-malicious structural deviations."
        
    return explanations, summary


def _simulate_behaviors(metadata: dict) -> list[dict]:
    """Map observed imports to high-level behaviors."""
    behaviors = []
    seen = set()
    imports = metadata.get("imports", [])
    
    for api in imports:
        if api in BEHAVIOR_MAP:
            b = BEHAVIOR_MAP[api]
            if b["name"] not in seen:
                behaviors.append(b)
                seen.add(b["name"])
                
    return behaviors


# ── main pipeline ─────────────────────────────────────────────────────────────

def run_analysis(file_bytes: bytes, filename: str, app_state: dict) -> dict:
    start_time = time.time()

    # 1. Hashes
    hashes = compute_hashes(file_bytes)

    # 2. File metadata
    file_size = len(file_bytes)
    if file_size < 1024:
        size_str = f"{file_size} B"
    elif file_size < 1024 * 1024:
        size_str = f"{file_size / 1024:.1f} KB"
    else:
        size_str = f"{file_size / (1024 * 1024):.2f} MB"

    # 3. Feature extraction
    feature_vec, is_pe, pe_metadata = extract_ember_features(file_bytes)
    limited_analysis = not is_pe

    # 4. Threat scoring via LightGBM
    lgb_model = app_state.get("lgb_model")
    fallback_result = None

    if lgb_model is not None:
        try:
            score_raw = float(lgb_model.predict(feature_vec.reshape(1, -1))[0])
            threat_score = round(score_raw * 100, 1)
        except Exception as e:
            logger.warning(f"LightGBM inference failed: {e}")
            fallback_result = analyze_fallback(file_bytes, filename)
            threat_score = float(fallback_result["score"])
    else:
        fallback_result = analyze_fallback(file_bytes, filename)
        threat_score = float(fallback_result["score"])

    # 4.1 Multi-model Comparison (LGB, RF, LR)
    model_comparison = {"lightgbm": threat_score}
    rf_model = app_state.get("rf_model")
    lr_model = app_state.get("lr_model")
    
    scores = [threat_score]
    
    if rf_model:
        try:
            rf_score = float(rf_model.predict_proba(feature_vec.reshape(1, -1))[0][1]) * 100
            model_comparison["random_forest"] = round(rf_score, 1)
            scores.append(rf_score)
        except Exception: pass
        
    if lr_model:
        try:
            lr_score = float(lr_model.predict_proba(feature_vec.reshape(1, -1))[0][1]) * 100
            model_comparison["logistic_regression"] = round(lr_score, 1)
            scores.append(lr_score)
        except Exception: pass

    # 4.2 Agreement & Disagreement
    # Logic: Agreement is % of models that give same binary class (>=50 or <50)
    classes = [1 if s >= 50 else 0 for s in scores]
    agreement_count = max(classes.count(1), classes.count(0))
    model_agreement = round((agreement_count / len(classes)) * 100)
    
    # Significant disagreement: std dev of scores > 20
    model_disagreement_flag = np.std(scores) > 20
    warning_message = None
    if model_disagreement_flag:
        warning_message = "Model disagreement detected. Prediction confidence reduced."

    # 5. Verdict + risk level
    if threat_score < 30:
        verdict = "SAFE"
        risk_level = "LOW"
    elif threat_score <= 65:
        verdict = "SUSPICIOUS"
        risk_level = "MEDIUM"
    else:
        verdict = "MALICIOUS"
        risk_level = "HIGH"

    # 5.1 Confidence + Uncertainty
    confidence = abs(threat_score - 50) / 50
    uncertainty = float(np.std(scores))
    if confidence > 0.7:
        confidence_level = "HIGH"
    elif confidence >= 0.4:
        confidence_level = "MEDIUM"
    else:
        confidence_level = "LOW"

    # 6. Type classification (only if threat_score > 50)
    malware_type = None
    behavior_description = None
    xgb_model = app_state.get("xgb_model")

    if threat_score > 50 and xgb_model is not None:
        try:
            # Use byte n-gram-style features: byte histogram (256) + entropy features
            byte_counts = np.bincount(
                np.frombuffer(file_bytes[:min(len(file_bytes), 100_000)], dtype=np.uint8),
                minlength=256,
            ).astype(np.float32)
            total = max(byte_counts.sum(), 1)
            byte_hist = byte_counts / total

            from features.fallback_features import _entropy
            ent = _entropy(file_bytes)
            xgb_input = np.concatenate([byte_hist, [ent, math.log1p(file_size)]]).reshape(1, -1)

            pred_idx = int(xgb_model.predict(xgb_input)[0])
            class_name = index_to_label(pred_idx)
            label_info = get_label_info(class_name)
            malware_type = label_info["display"]
            behavior_description = label_info["description"]
        except Exception as e:
            logger.warning(f"XGBoost inference failed: {e}")

    # 7. SHAP explanation
    shap_features = []
    shap_explainer = app_state.get("shap_explainer")

    if shap_explainer is not None and lgb_model is not None:
        try:
            shap_vals = shap_explainer.shap_values(feature_vec.reshape(1, -1))[0]
            top_indices = np.argsort(np.abs(shap_vals))[::-1][:8]
            shap_features = [
                {
                    "feature": _feature_name(int(i)),
                    "value": round(float(shap_vals[i]), 4),
                }
                for i in top_indices
            ]
        except Exception as e:
            logger.warning(f"SHAP explanation failed: {e}")

    # Fallback SHAP-like features from entropy/size if SHAP unavailable
    if not shap_features:
        from features.fallback_features import _entropy as fe
        ent = fe(file_bytes)
        shap_features = [
            {"feature": "File entropy", "value": round((ent - 4.0) / 4.0, 4)},
            {"feature": "File size", "value": round(math.log1p(file_size) / 20, 4)},
        ]

    # 8. Warning signs
    if fallback_result:
        warning_signs = fallback_result.get("warning_signs", [])
    else:
        warning_signs = _build_warning_signs(shap_features, pe_metadata, is_pe)

    # 8.1 Advanced Explainability & Simulation
    explanations, explanation_summary = _group_explanations(shap_features)
    simulated_behaviors = _simulate_behaviors(pe_metadata)
    
    # 8.2 Threat Intelligence Simulation
    # If high score OR seen before (simulated by prevalence > 1)
    threat_intel = {
        "known_malicious": threat_score > 85,
        "source": "local-db"
    }

    # 9. Flag reason
    flag_reason = _build_flag_reason(shap_features, is_pe, threat_score)

    # 10. File type detection
    from features.fallback_features import detect_magic
    magic = detect_magic(file_bytes)
    if is_pe:
        file_type = "application/x-dosexec"
    else:
        type_map = {
            "PDF": "application/pdf",
            "ZIP/DOCX/XLSX/JAR": "application/zip",
            "ELF": "application/x-elf",
            "MS Office (OLE)": "application/msword",
            "GZIP": "application/gzip",
            "RAR": "application/x-rar",
            "7-Zip": "application/x-7z-compressed",
        }
        file_type = type_map.get(magic, "application/octet-stream")

    elapsed_ms = round((time.time() - start_time) * 1000)

    model_used = "LightGBM — EMBER 2018"
    if threat_score > 50 and xgb_model is not None:
        model_used += " + XGBoost — BIG-2015"

    res = {
        "filename": filename,
        "file_type": str(file_type or "application/octet-stream"),
        "file_size": len(file_bytes),
        "sha256": str(hashes["sha256"] or "N/A"),
        "md5": str(hashes["md5"] or "N/A"),
        "threat_score": threat_score,
        "verdict": verdict,
        "risk_level": risk_level,
        "malware_type": malware_type,
        "behavior_description": behavior_description,
        "flag_reason": flag_reason,
        "warning_signs": warning_signs,
        "explanations": explanations,
        "explanation_summary": explanation_summary,
        "simulated_behaviors": simulated_behaviors,
        "model_comparison": model_comparison,
        "model_agreement": model_agreement,
        "model_disagreement_flag": model_disagreement_flag,
        "warning_message": warning_message,
        "confidence": confidence,
        "confidence_level": confidence_level,
        "uncertainty": uncertainty,
        "threat_intel": threat_intel,
        "model_used": model_used,
        "analysis_time_ms": elapsed_ms,
        "isolated": True,
        "limited_analysis": limited_analysis,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cached": False,
    }

    # Final enforcement of structure and types for JSON safety
    return {
        "filename": res.get("filename") or "unknown",
        "threat_score": float(res.get("threat_score") or 0),
        "verdict": res.get("verdict") or "SAFE",
        "risk_level": res.get("risk_level") or "LOW",
        "explanations": res.get("explanations") or [],
        "explanation_summary": res.get("explanation_summary") or "",
        "simulated_behaviors": res.get("simulated_behaviors") or [],
        "confidence": float(res.get("confidence") or 0),
        "uncertainty": float(res.get("uncertainty") or 0),
        "timestamp": res.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "cached": bool(res.get("cached") or False),
        "md5": str(res.get("md5") or "N/A"),
        "sha256": str(res.get("sha256") or "N/A"),
        "file_type": str(res.get("file_type") or "application/octet-stream"),
        "file_size": int(res.get("file_size") or 0),
        "malware_type": res.get("malware_type"),
        "behavior_description": res.get("behavior_description"),
        "model_used": res.get("model_used"),
        "analysis_time_ms": res.get("analysis_time_ms"),
        "model_comparison": res.get("model_comparison"),
        "model_agreement": res.get("model_agreement"),
        "model_disagreement_flag": bool(res.get("model_disagreement_flag")),
        "warning_message": res.get("warning_message"),
        "confidence_level": res.get("confidence_level") or "LOW",
        "threat_intel": res.get("threat_intel") or {"known_malicious": False, "source": "local-db"}
    }
