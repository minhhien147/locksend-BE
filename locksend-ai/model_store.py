"""Resolve model path — hỗ trợ Volume Railway và tải model từ URL."""

from __future__ import annotations

import hashlib
import os
import urllib.error
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MODELS_DIR = os.path.join(BASE_DIR, "models")


def models_dir() -> str:
    custom = os.getenv("LOCKSEND_AI_MODELS_DIR", "").strip()
    return custom if custom else DEFAULT_MODELS_DIR


def model_path() -> str:
    return os.path.join(models_dir(), "model.pkl")


def _checksum_path() -> str:
    return model_path() + ".sha256"


# A08: Tính checksum file ──────────────────────────────────────────────────────

def compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def save_checksum(model_file_path: str) -> str:
    """Tính và lưu SHA-256 của model.pkl vào model.pkl.sha256."""
    digest = compute_sha256(model_file_path)
    checksum_file = model_file_path + ".sha256"
    with open(checksum_file, "w", encoding="ascii") as f:
        f.write(digest)
    return digest


def _is_production() -> bool:
    return os.getenv("APP_ENV", "production").lower() not in ("development", "dev", "test")


def pinned_digest() -> str:
    """
    Digest tin cậy, set out-of-band qua env (secret store / biến deploy).

    Đây là neo tin cậy DUY NHẤT đáng giá: file .sha256 nằm cùng chỗ với model
    nên ai ghi được model.pkl thường cũng ghi được .sha256.
    """
    return os.getenv("LOCKSEND_AI_MODEL_SHA256", "").strip().lower()


def verify_checksum(model_file_path: str) -> None:
    """
    A08 – Software & Data Integrity:
    Kiểm tra SHA-256 của model.pkl trước khi pickle.load(). Raise nếu không khớp.

    Thứ tự tin cậy: env LOCKSEND_AI_MODEL_SHA256 → file .sha256 cạnh model.
    Trên production, KHÔNG có digest nào = từ chối load (trước đây lặng lẽ bỏ qua,
    nên chỉ cần xoá file .sha256 là vô hiệu hoá toàn bộ lớp bảo vệ này).
    """
    checksum_file = model_file_path + ".sha256"
    expected = pinned_digest()
    source = "env LOCKSEND_AI_MODEL_SHA256"

    if not expected and os.path.isfile(checksum_file):
        with open(checksum_file, "r", encoding="ascii") as f:
            expected = f.read().strip().lower()
        source = checksum_file

    if not expected:
        msg = (
            f"[A08] Không có SHA-256 tin cậy cho {model_file_path}. "
            "Set LOCKSEND_AI_MODEL_SHA256 hoặc commit file .sha256 trước khi load model."
        )
        if _is_production():
            raise ValueError(msg)
        print(f"[model_store] CẢNH BÁO (dev): {msg}")
        return

    actual = compute_sha256(model_file_path)
    if actual != expected:
        raise ValueError(
            f"[A08] Model checksum KHÔNG KHỚP (nguồn: {source})! "
            f"expected={expected[:16]}… actual={actual[:16]}… "
            f"File có thể bị tamper: {model_file_path}"
        )


def ensure_model() -> str:
    """Trả về path model.pkl; tải từ LOCKSEND_AI_MODEL_URL nếu chưa có file."""
    path = model_path()
    if os.path.isfile(path):
        # A08: Xác minh checksum mỗi khi load
        verify_checksum(path)
        return path

    url = os.getenv("LOCKSEND_AI_MODEL_URL", "").strip()
    if not url:
        raise FileNotFoundError(
            f"Chưa có model tại {path}. "
            "Train local: python train.py — hoặc set LOCKSEND_AI_MODEL_URL / Volume + LOCKSEND_AI_MODELS_DIR."
        )

    # A10: URL tải model chỉ đến từ env nhưng vẫn phải là HTTPS — HTTP cho phép
    # MITM thay model bằng payload pickle tuỳ ý.
    expected = pinned_digest()
    if _is_production():
        if not url.lower().startswith("https://"):
            raise ValueError(
                f"[A10] LOCKSEND_AI_MODEL_URL phải dùng HTTPS trên production: {url}"
            )
        # A08: không có digest cố định thì việc "tải rồi tự hash" chỉ xác nhận
        # đúng những byte attacker vừa gửi — không phải kiểm tra toàn vẹn.
        if not expected:
            raise ValueError(
                "[A08] Tải model từ URL trên production yêu cầu LOCKSEND_AI_MODEL_SHA256 "
                "(digest tin cậy đặt out-of-band) để đối chiếu sau khi tải."
            )

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    timeout = int(os.getenv("LOCKSEND_AI_MODEL_DOWNLOAD_TIMEOUT", "600"))
    try:
        with urllib.request.urlopen(url, timeout=timeout) as res, open(path, "wb") as out:
            while True:
                chunk = res.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
    except urllib.error.URLError as exc:
        raise FileNotFoundError(f"Không tải được model từ {url}: {exc}") from exc

    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        raise FileNotFoundError(f"Tải model thất bại — file rỗng: {path}")

    # A08: Đối chiếu với digest tin cậy TRƯỚC khi coi file là dùng được.
    actual = compute_sha256(path)
    if expected and actual != expected:
        os.remove(path)
        raise ValueError(
            f"[A08] Model tải từ {url} không khớp LOCKSEND_AI_MODEL_SHA256 "
            f"(expected={expected[:16]}… actual={actual[:16]}…) — đã xoá file."
        )

    save_checksum(path)
    print(f"[model_store] SHA-256 model: {actual[:16]}… (verified={bool(expected)})")

    return path
