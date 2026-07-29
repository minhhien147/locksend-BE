"""
LockSend AI — Train IDSNet MLP với 258 chiều LockSend-specific features.

Model: IDSNet (PyTorch) — 3-class: Normal(0) / Suspicious(1) / Attack(2)
Input: 258 features từ data/locksend_258/train.csv.gz

Tham số sau khi train:
  n_features=258 → ~12,778,241 trainable parameters (~12.8M)

Chạy:
  # Bước 1 — sinh dataset (nếu chưa có)
  python generate_dataset_258.py --rows 200000

  # Bước 2 — train + ghi đè model.pkl chính
  python train_locksend_258.py
  python train_locksend_258.py --epochs 30 --batch-size 2048
  python train_locksend_258.py --set-main     # ghi đè model.pkl để backend dùng ngay

  # Bước 3 — kiểm tra
  python verify_model.py
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import pickle
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import (
        accuracy_score, classification_report,
        f1_score, precision_score, recall_score,
    )
    from sklearn.model_selection import train_test_split
except ImportError as e:
    print(f"Thiếu thư viện: {e}")
    print("Cài: pip install torch scikit-learn")
    sys.exit(1)

BASE_DIR   = Path(__file__).resolve().parent
DATA_PATH  = BASE_DIR / "data" / "locksend_258" / "train.csv.gz"
MODELS_DIR = BASE_DIR / "models"
MODEL_PATH = MODELS_DIR / "model_locksend_258.pkl"
METRICS_PATH = MODELS_DIR / "metrics_locksend_258.json"

LABEL_COL  = "risk_label"
N_CLASSES  = 3
LABEL_NAMES = ["Normal", "Suspicious", "Attack"]

RISK_THRESHOLDS_3CLASS = {
    "NORMAL":   0,
    "SUSPICIOUS": 1,
    "ATTACK":   2,
}

# ── Kiến trúc IDSNet 3-class ──────────────────────────────────────────────────

class IDSNet258(nn.Module):
    """
    IDSNet cho 258 chiều LockSend — 3-class output.

    Kiến trúc giống IDSNet gốc, chỉ đổi:
      - input: n_features=258 (thay vì 77)
      - output: Linear(128, 3) + CrossEntropyLoss (thay vì BCEWithLogitsLoss)

    Tham số: ~12,778,241 (~12.8M)
    """

    def __init__(self, n_features: int = 258, n_classes: int = 3):
        super().__init__()

        self.input_proj = nn.Sequential(
            nn.Linear(n_features, 2048),
            nn.BatchNorm1d(2048),
            nn.ReLU(),
            nn.Dropout(0.3),
        )

        # Block 1: 2048 → 2048 (residual)
        self.block1 = nn.Sequential(
            nn.Linear(2048, 2048),
            nn.BatchNorm1d(2048),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(2048, 2048),
            nn.BatchNorm1d(2048),
        )
        self.relu1 = nn.ReLU()

        # Block 2: 2048 → 1024
        self.block2 = nn.Sequential(
            nn.Linear(2048, 1024),
            nn.BatchNorm1d(1024),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(1024, 1024),
            nn.BatchNorm1d(1024),
            nn.ReLU(),
        )

        # Block 3: 1024 → 512
        self.block3 = nn.Sequential(
            nn.Linear(1024, 512),
            nn.BatchNorm1d(512),
            nn.ReLU(),
            nn.Dropout(0.2),
        )

        # Head → 3 classes
        self.head = nn.Sequential(
            nn.Linear(512, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Linear(128, n_classes),   # 3-class thay vì 1
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.input_proj(x)
        x = self.relu1(self.block1(x) + x)   # residual
        x = self.block2(x)
        x = self.block3(x)
        return self.head(x)   # logits shape: (batch, 3)

    @staticmethod
    def count_parameters(model: "IDSNet258") -> int:
        return sum(p.numel() for p in model.parameters() if p.requires_grad)


# ── Sklearn-compatible wrapper ─────────────────────────────────────────────────

class MLP258Predictor:
    """
    Bọc IDSNet258 thành interface tương thích predict.py.
    predict.py gọi model.predict_proba(X)[0, 1] — trả về prob của class 1+2.
    Để giữ tương thích: col-0 = P(Normal), col-1 = P(Suspicious+Attack).
    """

    def __init__(
        self,
        net: IDSNet258,
        scaler: StandardScaler,
        feature_columns: list[str],
        device: str = "cpu",
    ):
        self.net = net
        self.scaler = scaler
        self.feature_columns = feature_columns
        self.device = device
        self.n_features_in_ = len(feature_columns)
        self.n_classes = 3

    def _prepare(self, X: pd.DataFrame) -> torch.Tensor:
        X_aligned = pd.DataFrame(0.0, index=X.index, columns=self.feature_columns)
        for col in self.feature_columns:
            if col in X.columns:
                X_aligned[col] = X[col].values
        arr = self.scaler.transform(X_aligned.values.astype(np.float32))
        return torch.tensor(arr, dtype=torch.float32).to(self.device)

    def predict_proba_3class(self, X: pd.DataFrame) -> np.ndarray:
        """Trả về (N, 3): P(Normal), P(Suspicious), P(Attack)."""
        self.net.eval()
        with torch.no_grad():
            logits = self.net(self._prepare(X))
            probs = torch.softmax(logits, dim=-1).cpu().numpy()
        return probs  # shape (N, 3)

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """
        Tương thích predict.py: trả về (N, 2).
        col-0 = P(Normal), col-1 = P(Suspicious) + P(Attack).
        predict.py lấy [0, 1] → risk score = P(không phải normal).
        """
        p3 = self.predict_proba_3class(X)
        p_normal = p3[:, 0]
        p_threat = p3[:, 1] + p3[:, 2]   # sus + attack
        return np.column_stack([p_normal, p_threat])

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        return self.predict_proba_3class(X).argmax(axis=1)

    def risk_score(self, X: pd.DataFrame) -> tuple[float, int]:
        """Trả về (risk_score 0→1, predicted_class 0/1/2)."""
        p3 = self.predict_proba_3class(X)
        cls = int(p3.argmax(axis=1)[0])
        score = float(p3[0, 1] + p3[0, 2])  # P(sus) + P(attack)
        return score, cls


# ── Load dataset ──────────────────────────────────────────────────────────────

def load_data(path: Path, max_rows: int = 0) -> tuple[pd.DataFrame, pd.Series]:
    print(f"Đọc dataset: {path}")
    if not path.exists():
        print(f"\nKhông tìm thấy {path}")
        print("Chạy trước: python generate_dataset_258.py")
        sys.exit(1)

    with gzip.open(path, "rt", encoding="utf-8") as f:
        df = pd.read_csv(f, nrows=max_rows if max_rows > 0 else None)

    y = df[LABEL_COL].astype(int)
    X = df.drop(columns=[LABEL_COL])
    # Loại bỏ cột hint nếu còn sót
    X = X.drop(columns=["final_model_hint_score"], errors="ignore")

    print(f"  Rows: {len(X):,}  Features: {X.shape[1]}")
    for cls, name in enumerate(LABEL_NAMES):
        cnt = (y == cls).sum()
        print(f"  {name}({cls}): {cnt:,} ({cnt/len(y)*100:.1f}%)")

    return X, y


# ── Training ──────────────────────────────────────────────────────────────────

def train_epoch(net, loader, optimizer, criterion, device):
    net.train()
    total_loss = 0.0
    for X_b, y_b in loader:
        X_b, y_b = X_b.to(device), y_b.to(device)
        optimizer.zero_grad()
        loss = criterion(net(X_b), y_b)
        loss.backward()
        optimizer.step()
        total_loss += loss.item() * len(y_b)
    return total_loss / len(loader.dataset)


@torch.no_grad()
def eval_epoch(net, loader, criterion, device):
    net.eval()
    total_loss, all_preds, all_labels = 0.0, [], []
    for X_b, y_b in loader:
        X_b, y_b = X_b.to(device), y_b.to(device)
        logits = net(X_b)
        total_loss += criterion(logits, y_b).item() * len(y_b)
        all_preds.extend(logits.argmax(dim=1).cpu().tolist())
        all_labels.extend(y_b.cpu().tolist())
    acc = accuracy_score(all_labels, all_preds)
    return total_loss / len(loader.dataset), acc, all_preds, all_labels


def train_model(
    X: pd.DataFrame,
    y: pd.Series,
    *,
    epochs: int,
    batch_size: int,
    lr: float,
    device: str,
) -> tuple[MLP258Predictor, dict[str, Any]]:

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )

    scaler = StandardScaler()
    X_train_np = scaler.fit_transform(X_train.values.astype(np.float32))
    X_test_np  = scaler.transform(X_test.values.astype(np.float32))

    X_tr = torch.tensor(X_train_np, dtype=torch.float32)
    y_tr = torch.tensor(y_train.values, dtype=torch.long)
    X_te = torch.tensor(X_test_np,  dtype=torch.float32)
    y_te = torch.tensor(y_test.values,  dtype=torch.long)

    train_loader = DataLoader(TensorDataset(X_tr, y_tr), batch_size=batch_size, shuffle=True,  num_workers=0)
    test_loader  = DataLoader(TensorDataset(X_te, y_te), batch_size=batch_size, shuffle=False, num_workers=0)

    net = IDSNet258(n_features=X_train_np.shape[1], n_classes=N_CLASSES).to(device)
    n_params = IDSNet258.count_parameters(net)

    print(f"\n{'='*60}")
    print(f"  IDSNet258 — {n_params:,} tham số ({n_params/1e6:.2f}M)")
    print(f"  Kiến trúc: {X_train_np.shape[1]}→2048→[2048→2048]→[2048→1024→1024]→1024→512→256→128→{N_CLASSES}")
    print(f"  Device: {device}  Epochs: {epochs}  Batch: {batch_size}  LR: {lr}")
    print(f"  Train: {len(X_train):,}  Test: {len(X_test):,}")
    print(f"{'='*60}")

    # Class weights để xử lý imbalanced (Normal chiếm 75%)
    counts = np.bincount(y_train.values, minlength=N_CLASSES).astype(np.float32)
    class_weights = torch.tensor(counts.sum() / (N_CLASSES * counts), dtype=torch.float32).to(device)
    criterion = nn.CrossEntropyLoss(weight=class_weights)

    optimizer = torch.optim.AdamW(net.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.OneCycleLR(
        optimizer, max_lr=lr, steps_per_epoch=len(train_loader), epochs=epochs,
    )

    best_val_loss = float("inf")
    best_state    = None
    history: list[dict] = []

    for epoch in range(1, epochs + 1):
        t0 = time.time()
        train_loss = train_epoch(net, train_loader, optimizer, criterion, device)
        scheduler.step()
        val_loss, val_acc, _, _ = eval_epoch(net, test_loader, criterion, device)
        elapsed = time.time() - t0
        print(
            f"  Epoch {epoch:>3}/{epochs} | "
            f"train_loss={train_loss:.4f}  val_loss={val_loss:.4f}  "
            f"val_acc={val_acc:.4f}  ({elapsed:.1f}s)"
        )
        history.append({"epoch": epoch, "train_loss": train_loss, "val_loss": val_loss, "val_acc": val_acc})
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state = {k: v.cpu().clone() for k, v in net.state_dict().items()}

    if best_state:
        net.load_state_dict(best_state)

    # Final eval
    _, _, y_pred_list, y_true_list = eval_epoch(net, test_loader, criterion, device)
    y_pred = np.array(y_pred_list)
    y_true = np.array(y_true_list)

    metrics: dict[str, Any] = {
        "accuracy":    float(accuracy_score(y_true, y_pred)),
        "precision":   float(precision_score(y_true, y_pred, average="macro", zero_division=0)),
        "recall":      float(recall_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_macro":    float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "train_size":  int(len(X_train)),
        "test_size":   int(len(X_test)),
        "n_params":    n_params,
        "n_features":  int(X_train_np.shape[1]),
        "n_classes":   N_CLASSES,
        "epochs":      epochs,
        "batch_size":  batch_size,
        "history":     history,
    }

    print(f"\n{'='*60}")
    print("  === Final Metrics (3-class) ===")
    for k in ["accuracy", "precision", "recall", "f1_macro", "f1_weighted"]:
        print(f"    {k:<14}: {metrics[k]:.4f}")
    print(f"    n_params      : {n_params:,} ({n_params/1e6:.2f}M)")
    print(f"\n{classification_report(y_true, y_pred, target_names=LABEL_NAMES)}")
    print(f"{'='*60}")

    predictor = MLP258Predictor(net, scaler, list(X.columns), device=device)
    return predictor, metrics


# ── Save bundle ───────────────────────────────────────────────────────────────

def save_bundle(
    predictor: MLP258Predictor,
    metrics: dict[str, Any],
    overwrite_main: bool,
) -> None:
    import shutil
    from model_store import save_checksum

    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # Risk thresholds cho 3-class: risk_score = P(sus) + P(attack)
    risk_thresholds = {
        "NORMAL":   (0.0, 0.2),
        "LOW":      (0.2, 0.5),
        "HIGH":     (0.5, 0.8),
        "CRITICAL": (0.8, 1.0),
    }
    decision_map = {
        "NORMAL":   "ALLOW",
        "LOW":      "ALLOW",
        "HIGH":     "MONITOR",
        "CRITICAL": "REVOKE",
    }

    n_feat = metrics["n_feat"] if "n_feat" in metrics else len(predictor.feature_columns)

    bundle = {
        "model":              predictor,
        "model_type":         "mlp",
        "feature_columns":    predictor.feature_columns,
        "label_col":          LABEL_COL,
        "n_classes":          N_CLASSES,
        "label_names":        LABEL_NAMES,
        "dataset":            "locksend_258",
        "dataset_description": "LockSend-specific 258-dim behavioral features (synthetic v2)",
        "risk_thresholds":    risk_thresholds,
        "decision_map":       decision_map,
        "metrics":            metrics,
        "trained_at":         datetime.now(timezone.utc).isoformat(),
        "version":            "locksend-ai-mlp-258-2026",
        "architecture": {
            "type":       "IDSNet258",
            "n_features": metrics["n_features"],
            "n_classes":  N_CLASSES,
            "n_params":   metrics["n_params"],
            "layers":     f"{metrics['n_features']}→2048→[2048→2048 residual]→[2048→1024→1024]→1024→512→256→128→{N_CLASSES}",
            "activation": "ReLU + BatchNorm1d + Dropout",
            "residual":   True,
            "optimizer":  "AdamW + OneCycleLR",
            "loss":       "CrossEntropyLoss (weighted)",
        },
    }

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(bundle, f)
    digest = save_checksum(str(MODEL_PATH))

    metrics_out = {k: v for k, v in metrics.items() if k != "history"}
    metrics_out["architecture"] = bundle["architecture"]
    metrics_out["version"] = bundle["version"]
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics_out, f, indent=2, ensure_ascii=False)

    print(f"\nModel: {MODEL_PATH}")
    print(f"SHA-256: {digest[:16]}…")
    print(f"Metrics: {METRICS_PATH}")

    if overwrite_main:
        main_path = MODELS_DIR / "model.pkl"
        shutil.copy2(MODEL_PATH, main_path)
        shutil.copy2(METRICS_PATH, MODELS_DIR / "metrics.json")
        main_digest = save_checksum(str(main_path))
        print(f"\n→ Đã ghi đè model.pkl — backend dùng IDSNet258 từ bây giờ")
        print(f"   SHA-256 model.pkl: {main_digest[:16]}…")
    else:
        print("\n→ Chưa ghi đè model.pkl. Thêm --set-main để kích hoạt cho backend.")


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Train IDSNet258 — LockSend 258-dim MLP")
    parser.add_argument("--epochs",     type=int,   default=20)
    parser.add_argument("--batch-size", type=int,   default=1024)
    parser.add_argument("--lr",         type=float, default=3e-4)
    parser.add_argument("--max-rows",   type=int,   default=0, help="Giới hạn rows (0=tất cả)")
    parser.add_argument("--device",     type=str,   default="", help="cpu / cuda / mps (tự detect nếu bỏ trống)")
    parser.add_argument("--set-main",   action="store_true", help="Ghi đè model.pkl chính sau khi train")
    parser.add_argument("--data",       type=str,   default="", help="Path CSV.GZ thay thế")
    args = parser.parse_args()

    # Device
    if args.device:
        device = args.device
    elif torch.cuda.is_available():
        device = "cuda"
    elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        device = "mps"
    else:
        device = "cpu"

    data_path = Path(args.data) if args.data else DATA_PATH
    X, y = load_data(data_path, args.max_rows)

    predictor, metrics = train_model(
        X, y,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        device=device,
    )
    metrics["n_feat"] = len(predictor.feature_columns)

    save_bundle(predictor, metrics, overwrite_main=args.set_main)

    print("\nHướng dẫn tiếp:")
    if not args.set_main:
        print("  python train_locksend_258.py --set-main   # ghi đè model.pkl chính")
    print("  python verify_model.py                    # kiểm tra model")


if __name__ == "__main__":
    main()
