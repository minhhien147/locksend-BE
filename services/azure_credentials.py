"""Lazy Azure credential — tránh DefaultAzureCredential() chặn lúc import (Railway healthcheck)."""

from __future__ import annotations

from functools import lru_cache

from azure.identity import DefaultAzureCredential


@lru_cache(maxsize=1)
def get_azure_credential() -> DefaultAzureCredential:
    return DefaultAzureCredential()
