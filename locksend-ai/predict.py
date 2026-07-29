"""
LockSend AI – Dự đoán risk score + quyết định bảo mật + giải thích SHAP

Input:  1 dòng đặc trưng flow (78 features CIC-IDS2017) hoặc batch CSV
Output: risk_score, risk_level, decision (ALLOW/MONITOR/REVOKE), explanation
"""

from __future__ import annotations

import os
import pickle
import sys
from typing import Any

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

import numpy as np
import pandas as pd

from model_store import ensure_model, model_path, models_dir

try:
    import shap
except ImportError:
    shap = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = models_dir()
MODEL_PATH = model_path()


def load_bundle() -> dict[str, Any]:
    path = ensure_model()
    # A08: Checksum đã được verify trong ensure_model() → log để audit trail
    with open(path, "rb") as f:
        bundle = pickle.load(f)  # nosec B301 — đã verify SHA-256 trước khi load
    model_type = bundle.get("model_type", "rf")
    model = bundle.get("model")
    # MLP bundle: model là MLPPredictor — đảm bảo net ở eval mode
    if model_type == "mlp" and hasattr(model, "net"):
        model.net.eval()
    return bundle


def risk_level(score: float, thresholds: dict) -> str:
    order = ["CRITICAL", "HIGH", "LOW", "NORMAL"]
    for level in order:
        lo, hi = thresholds[level]
        if level == "CRITICAL" and score >= lo:
            return level
        if lo <= score < hi:
            return level
    return "NORMAL"


def decision_for_level(level: str, decision_map: dict) -> str:
    return decision_map.get(level, "MONITOR")


def prepare_features(row: pd.DataFrame, feature_columns: list[str]) -> pd.DataFrame:
    row = row.copy()
    row.columns = row.columns.str.strip()
    X = pd.DataFrame(columns=feature_columns)
    for col in feature_columns:
        X[col] = row[col] if col in row.columns else 0
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    return X


def explain_shap(model, X: pd.DataFrame, top_k: int = 5) -> list[dict]:
    if shap is None:
        return [{"feature": "N/A", "impact": 0, "note": "Cai shap: pip install shap"}]

    explainer = shap.TreeExplainer(model)
    sv = explainer.shap_values(X)
    if isinstance(sv, list):
        sv = sv[1] if len(sv) > 1 else sv[0]
    sv = np.asarray(sv, dtype=float)
    if sv.ndim == 3:
        sv = sv[0, :, 1] if sv.shape[-1] > 1 else sv[0, :, 0]
    elif sv.ndim == 2:
        sv = sv[0]

    pairs = sorted(
        zip(X.columns, sv.flatten()[: len(X.columns)]),
        key=lambda x: abs(float(x[1])),
        reverse=True,
    )[:top_k]

    return [
        {
            "feature": name,
            "impact": float(val),
            "direction": "tang rui ro" if float(val) > 0 else "giam rui ro",
        }
        for name, val in pairs
    ]


def analyze_access(row: pd.DataFrame, bundle: dict | None = None) -> dict:
    bundle = bundle or load_bundle()
    model = bundle["model"]
    features = bundle["feature_columns"]
    thresholds = bundle["risk_thresholds"]
    decision_map = bundle["decision_map"]

    X = prepare_features(row, features)
    prob = float(model.predict_proba(X)[0, 1])
    level = risk_level(prob, thresholds)
    decision = decision_for_level(level, decision_map)
    reasons = explain_shap(model, X)

    reason_text = "; ".join(
        f"{r['feature']} ({r['direction']}, impact={r['impact']:.3f})"
        for r in reasons[:3]
    )

    return {
        "risk_score": round(prob, 4),
        "risk_level": level,
        "decision": decision,
        "is_attack": prob >= 0.5,
        "explanation": {
            "summary": (
                f"Risk {prob:.1%} → {level} → {decision}. "
                f"Top signals: {reason_text}"
            ),
            "top_features": reasons,
        },
    }


def analyze_batch_access(
    rows: pd.DataFrame,
    bundle: dict | None = None,
) -> list[dict[str, Any]]:
    """
    Batch inference tối ưu cho bulk analyze:
    - chuẩn hóa feature 1 lần cho cả batch
    - predict_proba 1 lần cho cả batch
    - bỏ SHAP per-row để tránh nhân CPU theo số token
    """
    bundle = bundle or load_bundle()
    model = bundle["model"]
    features = bundle["feature_columns"]
    thresholds = bundle["risk_thresholds"]
    decision_map = bundle["decision_map"]

    X = prepare_features(rows, features)
    probs = model.predict_proba(X)[:, 1]
    results: list[dict[str, Any]] = []
    for prob_raw in probs:
        prob = float(prob_raw)
        level = risk_level(prob, thresholds)
        decision = decision_for_level(level, decision_map)
        results.append(
            {
                "risk_score": round(prob, 4),
                "risk_level": level,
                "decision": decision,
                "is_attack": prob >= 0.5,
                "explanation": {
                    "summary": f"Risk {prob:.1%} → {level} → {decision}.",
                    "top_features": [],
                },
            }
        )
    return results


def demo_from_test_set(n_samples: int = 3) -> None:
    bundle = load_bundle()
    demos = [
        ("Tuesday", "Tuesday-WorkingHours.pcap_ISCX.csv", "BENIGN"),
        ("Wednesday DoS", "Wednesday-workingHours.pcap_ISCX.csv", "DoS Hulk"),
        ("Friday Bot", "Friday-WorkingHours-Morning.pcap_ISCX.csv", "Bot"),
        ("Friday DDoS", "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "DDoS"),
    ]

    for title, fname, attack_label in demos:
        path = os.path.join(DATA_DIR, fname)
        df = pd.read_csv(path, nrows=80_000, low_memory=False)
        df.columns = df.columns.str.strip()
        benign = df[df["Label"] == "BENIGN"].head(2)
        attacks = df[df["Label"] == attack_label].head(n_samples) if attack_label != "BENIGN" else pd.DataFrame()

        print(f"\n=== {title} ===")
        for _, row in benign.iterrows():
            r = analyze_access(pd.DataFrame([row]), bundle)
            print(f"  BENIGN → score={r['risk_score']} {r['risk_level']} → {r['decision']}")
        for _, row in attacks.iterrows():
            r = analyze_access(pd.DataFrame([row]), bundle)
            print(f"  {row['Label']!r} → score={r['risk_score']} {r['risk_level']} → {r['decision']}")


if __name__ == "__main__":
    demo_from_test_set()
