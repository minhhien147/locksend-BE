"""Unit tests for chunked ciphertext blob layout."""

from services.chunk_layout import (
    encrypted_chunk_byte_length,
    encrypted_chunk_offset,
    is_chunked_metadata,
)


def _sample_meta() -> dict:
    return {
        "isChunked": True,
        "chunkCount": 3,
        "chunkSize": 64 * 1024 * 1024,
        "fileSize": 150 * 1024 * 1024,
    }


class TestChunkLayout:
    def test_encrypted_chunk_lengths(self):
        meta = _sample_meta()
        assert encrypted_chunk_byte_length(meta, 0) == 64 * 1024 * 1024 + 16
        assert encrypted_chunk_byte_length(meta, 1) == 64 * 1024 * 1024 + 16
        assert encrypted_chunk_byte_length(meta, 2) == 22 * 1024 * 1024 + 16

    def test_encrypted_chunk_offsets(self):
        meta = _sample_meta()
        assert encrypted_chunk_offset(meta, 0) == 0
        assert encrypted_chunk_offset(meta, 1) == encrypted_chunk_byte_length(meta, 0)
        assert encrypted_chunk_offset(meta, 2) == (
            encrypted_chunk_byte_length(meta, 0) + encrypted_chunk_byte_length(meta, 1)
        )

    def test_is_chunked_metadata(self):
        assert is_chunked_metadata({"isChunked": True}) is True
        assert is_chunked_metadata({"is_chunked": True}) is True
        assert is_chunked_metadata({}) is False
