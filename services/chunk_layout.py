"""Offset/length helpers for azure_blocks chunked ciphertext layout."""

from __future__ import annotations


def _meta_int(meta: dict, *keys: str) -> int:
    for key in keys:
        val = meta.get(key)
        if val is not None:
            return int(val)
    raise KeyError(f"metadata thiếu một trong các trường: {', '.join(keys)}")


def encrypted_chunk_plaintext_length(meta: dict, chunk_index: int) -> int:
    chunk_count = _meta_int(meta, "chunkCount", "chunk_count")
    chunk_size = _meta_int(meta, "chunkSize", "chunk_size_bytes", "chunk_size")
    file_size = _meta_int(meta, "fileSize", "file_size_bytes", "file_size")
    if chunk_index < 0 or chunk_index >= chunk_count:
        raise IndexError(f"chunk_index {chunk_index} ngoài phạm vi 0–{chunk_count - 1}")
    if chunk_index < chunk_count - 1:
        return chunk_size
    return file_size - (chunk_count - 1) * chunk_size


def encrypted_chunk_byte_length(meta: dict, chunk_index: int) -> int:
    """AES-GCM ciphertext = plaintext + 16-byte auth tag."""
    return encrypted_chunk_plaintext_length(meta, chunk_index) + 16


def encrypted_chunk_offset(meta: dict, chunk_index: int) -> int:
    return sum(encrypted_chunk_byte_length(meta, i) for i in range(chunk_index))


def is_chunked_metadata(meta: dict | None) -> bool:
    if not meta:
        return False
    return bool(meta.get("isChunked") or meta.get("is_chunked"))
