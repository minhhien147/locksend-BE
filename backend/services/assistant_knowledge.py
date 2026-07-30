"""
Knowledge cho LockSend Assistant (Gemini).

Cách cập nhật tối ưu khi có tính năng mới:
  1. Sửa `backend/data/assistant/KNOWLEDGE.md` (kiến thức ổn định)
  2. Thêm bullet mới lên đầu `backend/data/assistant/CHANGELOG.md`
  3. Redeploy BE (production) — local: sửa file là đủ, loader hot-reload theo mtime

Không fine-tune Gemini; chỉ inject system prompt.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

LOCKSEND_ASSISTANT_RULES = """
Bạn là trợ lý LockSend. Chỉ trả lời về ứng dụng LockSend (mã hóa file, keypair, upload/download, SAS, vault, admin, bảo mật token).
Tuyệt đối KHÔNG yêu cầu passphrase, private key, hoặc nội dung file.
Không đưa lời khuyên phá vỡ zero-knowledge (ví dụ upload plaintext lên server).
Ưu tiên thông tin trong mục CHANGELOG (tính năng mới) nếu mâu thuẫn với phần kiến thức cũ.
""".strip()

_FALLBACK_KNOWLEDGE = """
# LockSend — kiến thức trợ lý (fallback)
- Mã hóa/giải mã phía trình duyệt; server chỉ lưu ciphertext.
- Keypair + passphrase tại trang Keys; đăng nhập ≠ mở khóa crypto.
- File lớn dùng chunked upload/download (Chrome/Edge).
- Admin: Users, Nhật ký activity, Token Security (rule + LockSend AI).
""".strip()

_cache_key: tuple[tuple[str, float], ...] | None = None
_cache_text: str = ""


def _assistant_dirs() -> list[Path]:
    """Thứ tự tìm thư mục knowledge (BE deploy + monorepo local)."""
    dirs: list[Path] = []
    env = (os.getenv("ASSISTANT_KNOWLEDGE_DIR") or "").strip()
    if env:
        dirs.append(Path(env))
    here = Path(__file__).resolve().parent
    # backend/data/assistant (canonical khi Railway Root Directory = backend)
    dirs.append(here.parent / "data" / "assistant")
    # monorepo docs/assistant (dev convenience)
    dirs.append(here.parent.parent / "docs" / "assistant")
    # unique preserve order
    seen: set[str] = set()
    out: list[Path] = []
    for d in dirs:
        key = str(d.resolve()) if d.exists() else str(d)
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out


def _read_file(path: Path) -> str | None:
    try:
        if path.is_file():
            return path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        logger.warning("Không đọc được %s: %s", path, exc)
    return None


def _load_from_disk() -> tuple[str, tuple[tuple[str, float], ...]]:
    knowledge = ""
    changelog = ""
    mtimes: list[tuple[str, float]] = []

    for d in _assistant_dirs():
        k_path = d / "KNOWLEDGE.md"
        c_path = d / "CHANGELOG.md"
        if not knowledge:
            text = _read_file(k_path)
            if text:
                knowledge = text
                try:
                    mtimes.append((str(k_path), k_path.stat().st_mtime))
                except OSError:
                    pass
        if not changelog:
            text = _read_file(c_path)
            if text:
                changelog = text
                try:
                    mtimes.append((str(c_path), c_path.stat().st_mtime))
                except OSError:
                    pass
        if knowledge and changelog:
            break

    if not knowledge:
        knowledge = _FALLBACK_KNOWLEDGE
        logger.warning(
            "Assistant knowledge MD không tìm thấy — dùng fallback. "
            "Đặt file tại backend/data/assistant/KNOWLEDGE.md"
        )

    parts = [knowledge]
    if changelog:
        parts.append(changelog)
    return "\n\n---\n\n".join(parts), tuple(mtimes)


def get_assistant_knowledge(*, force_reload: bool = False) -> str:
    """Knowledge + changelog, cache theo mtime file."""
    global _cache_key, _cache_text

    text, key = _load_from_disk()
    if force_reload or key != _cache_key:
        _cache_key = key
        _cache_text = text
        logger.debug("Assistant knowledge loaded (%d chars, %d files)", len(text), len(key))
    return _cache_text


def get_system_instruction() -> str:
    return f"{LOCKSEND_ASSISTANT_RULES}\n\n---\n\n{get_assistant_knowledge()}"


# Tương thích import cũ
LOCKSEND_ASSISTANT_KNOWLEDGE = _FALLBACK_KNOWLEDGE
