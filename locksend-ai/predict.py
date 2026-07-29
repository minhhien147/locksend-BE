"""
LockSend AI – Dự đoán risk score + quyết định bảo mật + giải thích SHAP

Input:  1 dòng đặc trưng flow (78 features CIC-IDS2017) hoặc batch CSV
Output: risk_score, risk_level, decision (ALLOW/MONITOR/REVOKE), explanation
"""

from __future__ import annotations

import logging
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

logger = logging.getLogger(__name__)

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


# TreeExplainer phải walk toàn bộ cây khi khởi tạo — với rừng lớn (model.pkl ~95MB)
# chi phí này lớn hơn cả lúc tính shap_values. Cache 1 slot cho model của process.
_explainer_cache: tuple[Any, Any] | None = None


def _get_explainer(model):
    global _explainer_cache
    if _explainer_cache is not None and _explainer_cache[0] is model:
        return _explainer_cache[1]
    explainer = shap.TreeExplainer(model)
    # Giữ strong ref tới model → so sánh `is` luôn hợp lệ, không bị trùng id sau GC.
    _explainer_cache = (model, explainer)
    return explainer


def _shap_matrix(model, X: pd.DataFrame) -> np.ndarray:
    """SHAP values của class 'attack' → ma trận (n_rows, n_features)."""
    explainer = _get_explainer(model)
    sv = explainer.shap_values(X)
    if isinstance(sv, list):
        sv = sv[1] if len(sv) > 1 else sv[0]
    sv = np.asarray(sv, dtype=float)
    if sv.ndim == 3:
        sv = sv[:, :, 1] if sv.shape[-1] > 1 else sv[:, :, 0]
    elif sv.ndim == 1:
        sv = sv.reshape(1, -1)
    return sv


def _top_features(columns: list[str], values: np.ndarray, top_k: int) -> list[dict]:
    pairs = sorted(
        zip(columns, np.asarray(values).flatten()[: len(columns)]),
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


def explain_shap(model, X: pd.DataFrame, top_k: int = 5) -> list[dict]:
    if shap is None:
        return [{"feature": "N/A", "impact": 0, "note": "Cai shap: pip install shap"}]

    return _top_features(list(X.columns), _shap_matrix(model, X)[0], top_k)


def explain_shap_batch(model, X: pd.DataFrame, top_k: int = 5) -> list[list[dict]]:
    """SHAP cho nhiều dòng trong MỘT lần gọi explainer (rẻ hơn gọi lẻ từng dòng)."""
    if shap is None:
        return [[] for _ in range(len(X))]

    sv = _shap_matrix(model, X)
    columns = list(X.columns)
    return [_top_features(columns, sv[i], top_k) for i in range(sv.shape[0])]


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
    explain_top_n: int = 10,
) -> list[dict[str, Any]]:
    """
    Batch inference tối ưu cho bulk analyze:
    - chuẩn hóa feature 1 lần cho cả batch
    - predict_proba 1 lần cho cả batch
    - SHAP chỉ tính cho `explain_top_n` token rủi ro cao nhất, trong một lần gọi
      explainer duy nhất. Đây là chỗ đắt nhất nên không tính cho toàn bộ batch;
      explain_top_n=0 để tắt hẳn.
    """
    bundle = bundle or load_bundle()
    model = bundle["model"]
    features = bundle["feature_columns"]
    thresholds = bundle["risk_thresholds"]
    decision_map = bundle["decision_map"]

    X = prepare_features(rows, features)
    probs = model.predict_proba(X)[:, 1]

    explanations: dict[int, list[dict]] = {}
    if explain_top_n > 0 and shap is not None and len(probs):
        top_k = min(int(explain_top_n), len(probs))
        top_idx = [int(i) for i in np.argsort(probs)[::-1][:top_k]]
        try:
            explanations = dict(
                zip(top_idx, explain_shap_batch(model, X.iloc[top_idx]))
            )
        except Exception as exc:
            # Model không phải tree (vd. MLP) → vẫn trả risk score, chỉ thiếu giải thích
            logger.warning("SHAP batch that bai, tra ket qua khong co giai thich: %s", exc)

    results: list[dict[str, Any]] = []
    for i, prob_raw in enumerate(probs):
        prob = float(prob_raw)
        level = risk_level(prob, thresholds)
        decision = decision_for_level(level, decision_map)
        top_features = explanations.get(i, [])
        summary = f"Risk {prob:.1%} → {level} → {decision}."
        if top_features:
            reason_text = "; ".join(
                f"{r['feature']} ({r['direction']}, impact={r['impact']:.3f})"
                for r in top_features[:3]
            )
            summary += f" Top signals: {reason_text}"
        results.append(
            {
                "risk_score": round(prob, 4),
                "risk_level": level,
                "decision": decision,
                "is_attack": prob >= 0.5,
                "explanation": {
                    "summary": summary,
                    "top_features": top_features,
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
