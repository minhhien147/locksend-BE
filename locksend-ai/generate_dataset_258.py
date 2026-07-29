"""
LockSend AI — Sinh dataset synthetic 258 chiều (LockSend-specific features).

Output: locksend-ai/data/locksend_258/train.csv.gz  (default 200_000 dòng)

Labels:
  0 = Normal      (~75%)
  1 = Suspicious  (~15%)
  2 = Attack      (~10%)

Chạy:
    python generate_dataset_258.py                      # 200k dòng
    python generate_dataset_258.py --rows 500000        # 500k dòng
    python generate_dataset_258.py --rows 50000 --seed 99
"""

from __future__ import annotations

import argparse
import gzip
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

OUT_DIR = Path(__file__).resolve().parent / "data" / "locksend_258"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _rng(seed: int) -> np.random.Generator:
    return np.random.default_rng(seed)


def clip(arr: np.ndarray, lo: float = 0.0, hi: float = 1e9) -> np.ndarray:
    return np.clip(arr, lo, hi)


def flag(rng: np.random.Generator, n: int, p_sus: float, p_atk: float,
         labels: np.ndarray) -> np.ndarray:
    """Binary flag: bình thường = 0, suspicious/attack tăng prob."""
    out = np.zeros(n, dtype=np.float32)
    out[labels == 1] = (rng.random(np.sum(labels == 1)) < p_sus).astype(np.float32)
    out[labels == 2] = (rng.random(np.sum(labels == 2)) < p_atk).astype(np.float32)
    return out


def normal_feature(rng, n, labels,
                   mu_n, std_n,
                   mu_s, std_s,
                   mu_a, std_a,
                   lo=0.0, hi=1e9) -> np.ndarray:
    """Sinh giá trị liên tục theo label."""
    out = np.empty(n, dtype=np.float32)
    mask_n = labels == 0
    mask_s = labels == 1
    mask_a = labels == 2
    out[mask_n] = rng.normal(mu_n, std_n, mask_n.sum())
    out[mask_s] = rng.normal(mu_s, std_s, mask_s.sum())
    out[mask_a] = rng.normal(mu_a, std_a, mask_a.sum())
    return clip(out, lo, hi).astype(np.float32)


# ── Feature generators theo từng nhóm ────────────────────────────────────────

def gen_general_time(rng, n, labels) -> dict[str, np.ndarray]:
    hour = rng.uniform(0, 24, n)
    day  = rng.uniform(0, 7, n)
    # Attack thiên về ban đêm (22h–4h)
    atk = labels == 2
    hour[atk] = (rng.uniform(22, 28, atk.sum()) % 24)
    sus = labels == 1
    hour[sus] = (rng.uniform(19, 26, sus.sum()) % 24)

    out = {
        "event_hour_sin":              np.sin(2 * np.pi * hour / 24).astype(np.float32),
        "event_hour_cos":              np.cos(2 * np.pi * hour / 24).astype(np.float32),
        "event_day_sin":               np.sin(2 * np.pi * day / 7).astype(np.float32),
        "event_day_cos":               np.cos(2 * np.pi * day / 7).astype(np.float32),
        "is_weekend_flag":             flag(rng, n, 0.25, 0.55, labels),
        "is_night_flag":               ((hour < 6) | (hour >= 22)).astype(np.float32),
        "minutes_since_last_event":    normal_feature(rng, n, labels, 120, 60, 15, 10, 2, 2, lo=0, hi=1440),
        "session_age_minutes":         normal_feature(rng, n, labels, 30, 20, 5, 5, 1, 1, lo=0, hi=1440),
        "account_age_days":            normal_feature(rng, n, labels, 400, 200, 50, 40, 5, 5, lo=0, hi=3650),
        "account_trust_score":         normal_feature(rng, n, labels, 0.8, 0.15, 0.45, 0.2, 0.15, 0.1, lo=0, hi=1),
        "previous_warnings_30d":       normal_feature(rng, n, labels, 0.1, 0.3, 1.5, 1.0, 4.0, 2.0, lo=0, hi=50),
        "previous_blocks_30d":         normal_feature(rng, n, labels, 0.0, 0.1, 0.5, 0.5, 2.5, 1.5, lo=0, hi=30),
        "historical_risk_mean_30d":    normal_feature(rng, n, labels, 0.1, 0.05, 0.45, 0.15, 0.75, 0.15, lo=0, hi=1),
        "user_tenure_bucket":          normal_feature(rng, n, labels, 3, 1, 1.5, 0.8, 0.5, 0.5, lo=0, hi=5),
        "recent_password_change_flag": flag(rng, n, 0.15, 0.55, labels),
        "recent_key_rotation_flag":    flag(rng, n, 0.10, 0.40, labels),
    }
    return out


def gen_auth(rng, n, labels) -> dict[str, np.ndarray]:
    return {
        "failed_login_count_1m":         normal_feature(rng, n, labels, 0.0, 0.1, 1.0, 0.8, 8.0, 4.0, lo=0, hi=100),
        "failed_login_count_5m":         normal_feature(rng, n, labels, 0.0, 0.2, 3.0, 2.0, 25.0, 10.0, lo=0, hi=500),
        "failed_login_count_1h":         normal_feature(rng, n, labels, 0.1, 0.3, 5.0, 3.0, 60.0, 20.0, lo=0, hi=1000),
        "failed_login_count_24h":        normal_feature(rng, n, labels, 0.2, 0.5, 10.0, 5.0, 120.0, 40.0, lo=0, hi=2000),
        "success_login_count_1h":        normal_feature(rng, n, labels, 2.0, 1.0, 1.0, 0.8, 0.5, 0.5, lo=0, hi=50),
        "success_login_count_24h":       normal_feature(rng, n, labels, 5.0, 3.0, 3.0, 2.0, 1.0, 1.0, lo=0, hi=100),
        "otp_failed_count_1h":           normal_feature(rng, n, labels, 0.0, 0.1, 0.5, 0.5, 5.0, 3.0, lo=0, hi=50),
        "password_reset_count_24h":      normal_feature(rng, n, labels, 0.0, 0.1, 0.3, 0.3, 2.0, 1.5, lo=0, hi=20),
        "invalid_token_count_5m":        normal_feature(rng, n, labels, 0.0, 0.1, 1.0, 0.8, 10.0, 5.0, lo=0, hi=100),
        "invalid_token_count_1h":        normal_feature(rng, n, labels, 0.0, 0.2, 2.0, 1.5, 30.0, 15.0, lo=0, hi=300),
        "session_count_24h":             normal_feature(rng, n, labels, 3.0, 2.0, 8.0, 3.0, 20.0, 8.0, lo=1, hi=200),
        "concurrent_sessions":           normal_feature(rng, n, labels, 1.0, 0.5, 3.0, 1.5, 8.0, 4.0, lo=1, hi=50),
        "session_duration_minutes":      normal_feature(rng, n, labels, 25.0, 15.0, 5.0, 5.0, 1.0, 1.0, lo=0, hi=480),
        "refresh_token_count_1h":        normal_feature(rng, n, labels, 1.0, 0.5, 4.0, 2.0, 15.0, 7.0, lo=0, hi=100),
        "logout_missing_flag":           flag(rng, n, 0.20, 0.75, labels),
        "mfa_enabled_flag":              flag(rng, n, 0.70, 0.10, labels),
        "mfa_challenge_count_1h":        normal_feature(rng, n, labels, 0.5, 0.5, 2.0, 1.5, 6.0, 3.0, lo=0, hi=30),
        "new_device_login_flag":         flag(rng, n, 0.15, 0.70, labels),
        "new_location_login_flag":       flag(rng, n, 0.10, 0.60, labels),
        "impossible_travel_flag":        flag(rng, n, 0.02, 0.50, labels),
        "auth_endpoint_error_rate_1h":   normal_feature(rng, n, labels, 0.01, 0.02, 0.15, 0.10, 0.60, 0.20, lo=0, hi=1),
        "login_velocity_score":          normal_feature(rng, n, labels, 0.05, 0.05, 0.35, 0.20, 0.80, 0.15, lo=0, hi=1),
        "credential_stuffing_indicator": normal_feature(rng, n, labels, 0.02, 0.03, 0.30, 0.20, 0.85, 0.12, lo=0, hi=1),
        "brute_force_indicator":         normal_feature(rng, n, labels, 0.01, 0.02, 0.25, 0.20, 0.90, 0.10, lo=0, hi=1),
        "session_fixation_signal":       normal_feature(rng, n, labels, 0.01, 0.02, 0.10, 0.08, 0.55, 0.25, lo=0, hi=1),
    }


def gen_ip_network(rng, n, labels) -> dict[str, np.ndarray]:
    return {
        "ip_reputation_score":            normal_feature(rng, n, labels, 0.85, 0.10, 0.50, 0.20, 0.15, 0.10, lo=0, hi=1),
        "ip_age_days":                    normal_feature(rng, n, labels, 500, 300, 100, 80, 10, 10, lo=0, hi=3650),
        "ip_seen_before_flag":            flag(rng, n, 0.40, 0.05, labels),
        "ip_user_count_1h":               normal_feature(rng, n, labels, 1.0, 0.5, 5.0, 3.0, 20.0, 10.0, lo=1, hi=200),
        "ip_login_count_1h":              normal_feature(rng, n, labels, 1.0, 0.8, 8.0, 4.0, 40.0, 15.0, lo=0, hi=500),
        "ip_failed_ratio_1h":             normal_feature(rng, n, labels, 0.02, 0.03, 0.25, 0.15, 0.75, 0.15, lo=0, hi=1),
        "asn_reputation_score":           normal_feature(rng, n, labels, 0.80, 0.10, 0.45, 0.20, 0.15, 0.10, lo=0, hi=1),
        "country_risk_score":             normal_feature(rng, n, labels, 0.10, 0.08, 0.40, 0.20, 0.80, 0.15, lo=0, hi=1),
        "city_distance_km_from_last_login": normal_feature(rng, n, labels, 5, 10, 200, 150, 5000, 3000, lo=0, hi=20000),
        "geo_velocity_kmh":               normal_feature(rng, n, labels, 0, 5, 50, 40, 800, 400, lo=0, hi=2000),
        "vpn_flag":                       flag(rng, n, 0.20, 0.65, labels),
        "proxy_flag":                     flag(rng, n, 0.10, 0.50, labels),
        "tor_flag":                       flag(rng, n, 0.02, 0.45, labels),
        "datacenter_ip_flag":             flag(rng, n, 0.15, 0.60, labels),
        "public_wifi_risk_score":         normal_feature(rng, n, labels, 0.10, 0.10, 0.40, 0.20, 0.70, 0.20, lo=0, hi=1),
        "request_latency_ms_avg":         normal_feature(rng, n, labels, 80, 30, 40, 20, 15, 8, lo=1, hi=5000),
        "request_latency_ms_std":         normal_feature(rng, n, labels, 10, 5, 5, 3, 1, 0.5, lo=0, hi=500),
        "request_interval_ms_avg":        normal_feature(rng, n, labels, 3000, 2000, 500, 300, 50, 30, lo=10, hi=60000),
        "request_interval_ms_std":        normal_feature(rng, n, labels, 1000, 500, 100, 80, 5, 3, lo=0, hi=10000),
        "burst_request_count_1m":         normal_feature(rng, n, labels, 2, 2, 15, 8, 80, 30, lo=0, hi=1000),
        "unique_ip_count_24h":            normal_feature(rng, n, labels, 1, 0.5, 3, 2, 10, 5, lo=1, hi=50),
        "unique_country_count_24h":       normal_feature(rng, n, labels, 1, 0.3, 2, 1, 5, 3, lo=1, hi=30),
        "unique_asn_count_24h":           normal_feature(rng, n, labels, 1, 0.3, 2, 1, 6, 3, lo=1, hi=30),
        "tls_version_code":               normal_feature(rng, n, labels, 3, 0.2, 2, 0.5, 1, 0.5, lo=1, hi=4),
        "http_version_code":              normal_feature(rng, n, labels, 2, 0.2, 1.5, 0.5, 1, 0.3, lo=1, hi=3),
        "abnormal_origin_flag":           flag(rng, n, 0.08, 0.55, labels),
        "suspicious_referrer_flag":       flag(rng, n, 0.05, 0.45, labels),
        "ip_entropy_24h":                 normal_feature(rng, n, labels, 0.1, 0.05, 0.5, 0.2, 0.9, 0.08, lo=0, hi=1),
        "network_anomaly_score":          normal_feature(rng, n, labels, 0.05, 0.05, 0.40, 0.20, 0.85, 0.10, lo=0, hi=1),
        "geo_anomaly_score":              normal_feature(rng, n, labels, 0.05, 0.05, 0.35, 0.20, 0.80, 0.12, lo=0, hi=1),
    }


def gen_device_browser(rng, n, labels) -> dict[str, np.ndarray]:
    return {
        "browser_code":                  normal_feature(rng, n, labels, 2, 0.5, 2, 1, 5, 2, lo=1, hi=10),
        "browser_version_major":         normal_feature(rng, n, labels, 120, 10, 80, 30, 40, 20, lo=1, hi=200),
        "os_code":                       normal_feature(rng, n, labels, 2, 0.5, 2, 1, 4, 2, lo=1, hi=6),
        "os_version_major":              normal_feature(rng, n, labels, 10, 2, 8, 3, 5, 3, lo=1, hi=20),
        "device_type_code":              normal_feature(rng, n, labels, 1, 0.3, 1.5, 0.8, 3, 1.5, lo=1, hi=5),
        "user_agent_hash_bucket":        normal_feature(rng, n, labels, 50, 20, 30, 20, 5, 5, lo=0, hi=100),
        "device_fingerprint_bucket":     normal_feature(rng, n, labels, 50, 20, 30, 20, 5, 5, lo=0, hi=100),
        "fingerprint_seen_before_flag":  flag(rng, n, 0.30, 0.05, labels),
        "fingerprint_change_count_24h":  normal_feature(rng, n, labels, 0, 0.2, 1.5, 1.0, 8, 4, lo=0, hi=50),
        "screen_width":                  normal_feature(rng, n, labels, 1920, 300, 1366, 400, 1280, 200, lo=320, hi=3840),
        "screen_height":                 normal_feature(rng, n, labels, 1080, 200, 768, 200, 720, 150, lo=240, hi=2160),
        "timezone_offset_minutes":       normal_feature(rng, n, labels, 420, 100, 300, 200, 0, 200, lo=-720, hi=840),
        "browser_language_code":         normal_feature(rng, n, labels, 10, 5, 8, 5, 3, 5, lo=0, hi=50),
        "cookie_enabled_flag":           flag(rng, n, 0.85, 0.30, labels),
        "local_storage_enabled_flag":    flag(rng, n, 0.85, 0.25, labels),
        "webcrypto_supported_flag":      flag(rng, n, 0.90, 0.40, labels),
        "headless_browser_flag":         flag(rng, n, 0.05, 0.70, labels),
        "automation_driver_flag":        flag(rng, n, 0.02, 0.65, labels),
        "devtools_open_signal":          flag(rng, n, 0.08, 0.35, labels),
        "canvas_fingerprint_change_flag": flag(rng, n, 0.05, 0.55, labels),
        "device_anomaly_score":          normal_feature(rng, n, labels, 0.05, 0.05, 0.40, 0.20, 0.85, 0.10, lo=0, hi=1),
        "user_agent_missing_flag":       flag(rng, n, 0.01, 0.60, labels),
    }


def gen_upload(rng, n, labels) -> dict[str, np.ndarray]:
    return {
        "upload_count_1m":               normal_feature(rng, n, labels, 0.2, 0.3, 1.0, 0.8, 10.0, 5.0, lo=0, hi=200),
        "upload_count_5m":               normal_feature(rng, n, labels, 0.5, 0.5, 3.0, 2.0, 30.0, 15.0, lo=0, hi=500),
        "upload_count_1h":               normal_feature(rng, n, labels, 2.0, 2.0, 10.0, 6.0, 80.0, 30.0, lo=0, hi=2000),
        "upload_count_24h":              normal_feature(rng, n, labels, 5.0, 4.0, 20.0, 10.0, 200.0, 80.0, lo=0, hi=5000),
        "upload_size_mb_current":        normal_feature(rng, n, labels, 2.0, 3.0, 8.0, 6.0, 50.0, 30.0, lo=0, hi=1000),
        "upload_size_total_mb_1h":       normal_feature(rng, n, labels, 5.0, 5.0, 30.0, 20.0, 500.0, 200.0, lo=0, hi=10000),
        "upload_size_total_mb_24h":      normal_feature(rng, n, labels, 15.0, 10.0, 80.0, 50.0, 2000.0, 800.0, lo=0, hi=50000),
        "upload_file_size_avg_7d":       normal_feature(rng, n, labels, 3.0, 2.0, 5.0, 3.0, 20.0, 10.0, lo=0, hi=500),
        "upload_file_size_std_7d":       normal_feature(rng, n, labels, 1.0, 0.8, 3.0, 2.0, 15.0, 8.0, lo=0, hi=200),
        "upload_speed_mbps":             normal_feature(rng, n, labels, 5.0, 3.0, 10.0, 5.0, 50.0, 20.0, lo=0.01, hi=1000),
        "upload_fail_count_1h":          normal_feature(rng, n, labels, 0.1, 0.2, 1.0, 0.8, 8.0, 4.0, lo=0, hi=100),
        "upload_cancel_count_1h":        normal_feature(rng, n, labels, 0.1, 0.2, 0.8, 0.6, 5.0, 3.0, lo=0, hi=50),
        "upload_retry_count_1h":         normal_feature(rng, n, labels, 0.1, 0.2, 0.8, 0.6, 6.0, 3.0, lo=0, hi=50),
        "duplicate_file_hash_count_24h": normal_feature(rng, n, labels, 0.0, 0.1, 0.5, 0.5, 5.0, 3.0, lo=0, hi=100),
        "filename_length":               normal_feature(rng, n, labels, 15, 8, 20, 10, 60, 20, lo=1, hi=255),
        "file_extension_code":           normal_feature(rng, n, labels, 5, 3, 5, 3, 15, 5, lo=0, hi=50),
        "mime_type_code":                normal_feature(rng, n, labels, 5, 3, 5, 3, 12, 5, lo=0, hi=30),
        "file_entropy":                  normal_feature(rng, n, labels, 5.0, 0.8, 6.5, 0.8, 7.8, 0.2, lo=0, hi=8),
        "suspicious_extension_flag":     flag(rng, n, 0.05, 0.60, labels),
        "upload_endpoint_error_rate_1h": normal_feature(rng, n, labels, 0.01, 0.02, 0.10, 0.08, 0.50, 0.20, lo=0, hi=1),
        "chunk_count":                   normal_feature(rng, n, labels, 3, 2, 5, 3, 20, 10, lo=1, hi=500),
        "chunk_retry_ratio":             normal_feature(rng, n, labels, 0.01, 0.02, 0.10, 0.08, 0.40, 0.20, lo=0, hi=1),
        "upload_after_login_delay_sec":  normal_feature(rng, n, labels, 120, 100, 10, 10, 2, 2, lo=0, hi=3600),
        "mass_upload_score":             normal_feature(rng, n, labels, 0.05, 0.05, 0.40, 0.20, 0.85, 0.10, lo=0, hi=1),
        "upload_anomaly_score":          normal_feature(rng, n, labels, 0.05, 0.05, 0.40, 0.20, 0.85, 0.10, lo=0, hi=1),
    }


def gen_download(rng, n, labels) -> dict[str, np.ndarray]:
    return {
        "download_count_1m":                  normal_feature(rng, n, labels, 0.3, 0.4, 2.0, 1.0, 15.0, 8.0, lo=0, hi=300),
        "download_count_5m":                  normal_feature(rng, n, labels, 0.8, 0.6, 5.0, 3.0, 50.0, 20.0, lo=0, hi=1000),
        "download_count_1h":                  normal_feature(rng, n, labels, 3.0, 2.0, 15.0, 8.0, 100.0, 40.0, lo=0, hi=3000),
        "download_count_24h":                 normal_feature(rng, n, labels, 8.0, 5.0, 30.0, 15.0, 300.0, 100.0, lo=0, hi=5000),
        "download_size_mb_current":           normal_feature(rng, n, labels, 3.0, 3.0, 10.0, 8.0, 80.0, 40.0, lo=0, hi=2000),
        "download_size_total_mb_1h":          normal_feature(rng, n, labels, 8.0, 8.0, 50.0, 30.0, 800.0, 300.0, lo=0, hi=10000),
        "download_size_total_mb_24h":         normal_feature(rng, n, labels, 20.0, 15.0, 100.0, 60.0, 3000.0, 1000.0, lo=0, hi=50000),
        "download_speed_mbps":                normal_feature(rng, n, labels, 8.0, 5.0, 15.0, 8.0, 80.0, 30.0, lo=0.01, hi=1000),
        "download_fail_count_1h":             normal_feature(rng, n, labels, 0.1, 0.2, 1.0, 0.8, 8.0, 4.0, lo=0, hi=100),
        "download_retry_count_1h":            normal_feature(rng, n, labels, 0.1, 0.2, 0.8, 0.6, 5.0, 3.0, lo=0, hi=50),
        "download_from_new_country_flag":     flag(rng, n, 0.10, 0.60, labels),
        "download_from_new_device_flag":      flag(rng, n, 0.12, 0.65, labels),
        "download_after_share_delay_min":     normal_feature(rng, n, labels, 60, 50, 5, 5, 0.5, 0.5, lo=0, hi=10080),
        "expired_link_access_count_1h":       normal_feature(rng, n, labels, 0.0, 0.1, 0.5, 0.5, 5.0, 3.0, lo=0, hi=50),
        "invalid_share_link_count_1h":        normal_feature(rng, n, labels, 0.0, 0.1, 0.5, 0.5, 8.0, 4.0, lo=0, hi=100),
        "unique_file_download_count_1h":      normal_feature(rng, n, labels, 1.0, 1.0, 5.0, 3.0, 25.0, 10.0, lo=0, hi=200),
        "owner_to_recipient_distance_score":  normal_feature(rng, n, labels, 0.1, 0.1, 0.4, 0.2, 0.8, 0.15, lo=0, hi=1),
        "mass_download_score":                normal_feature(rng, n, labels, 0.05, 0.05, 0.40, 0.20, 0.85, 0.10, lo=0, hi=1),
        "download_without_preview_flag":      flag(rng, n, 0.15, 0.75, labels),
        "repeated_download_same_blob_count":  normal_feature(rng, n, labels, 0.5, 0.5, 2.0, 1.5, 15.0, 8.0, lo=0, hi=200),
        "blob_range_request_count":           normal_feature(rng, n, labels, 0.1, 0.2, 1.0, 0.8, 8.0, 4.0, lo=0, hi=100),
        "download_endpoint_error_rate_1h":    normal_feature(rng, n, labels, 0.01, 0.02, 0.10, 0.08, 0.50, 0.20, lo=0, hi=1),
        "download_anomaly_score":             normal_feature(rng, n, labels, 0.05, 0.05, 0.40, 0.20, 0.85, 0.10, lo=0, hi=1),
        "recipient_download_ratio_24h":       normal_feature(rng, n, labels, 0.3, 0.2, 0.7, 0.2, 0.98, 0.02, lo=0, hi=1),
        "download_after_expiry_attempt_flag": flag(rng, n, 0.03, 0.55, labels),
    }


def gen_share(rng, n, labels) -> dict[str, np.ndarray]:
    return {
        "share_count_1h":                       normal_feature(rng, n, labels, 0.5, 0.5, 3.0, 2.0, 20.0, 10.0, lo=0, hi=200),
        "share_count_24h":                      normal_feature(rng, n, labels, 1.5, 1.5, 8.0, 5.0, 60.0, 25.0, lo=0, hi=500),
        "recipient_count_current":              normal_feature(rng, n, labels, 1.5, 1.0, 5.0, 3.0, 20.0, 10.0, lo=0, hi=200),
        "unique_recipient_count_24h":           normal_feature(rng, n, labels, 2.0, 1.5, 8.0, 4.0, 30.0, 15.0, lo=0, hi=300),
        "external_recipient_ratio":             normal_feature(rng, n, labels, 0.15, 0.15, 0.50, 0.25, 0.90, 0.10, lo=0, hi=1),
        "share_link_created_count_24h":         normal_feature(rng, n, labels, 1.0, 1.0, 5.0, 3.0, 25.0, 10.0, lo=0, hi=200),
        "share_link_expiry_minutes_avg":        normal_feature(rng, n, labels, 1440, 500, 120, 80, 15, 10, lo=1, hi=43200),
        "share_link_access_count_1h":           normal_feature(rng, n, labels, 1.0, 1.0, 5.0, 3.0, 30.0, 15.0, lo=0, hi=300),
        "share_link_access_country_count_24h":  normal_feature(rng, n, labels, 1.0, 0.5, 2.0, 1.0, 8.0, 4.0, lo=1, hi=30),
        "revoke_share_count_24h":               normal_feature(rng, n, labels, 0.1, 0.2, 0.5, 0.5, 3.0, 2.0, lo=0, hi=30),
        "permission_change_count_24h":          normal_feature(rng, n, labels, 0.1, 0.2, 0.8, 0.6, 5.0, 3.0, lo=0, hi=50),
        "public_like_behavior_score":           normal_feature(rng, n, labels, 0.05, 0.05, 0.40, 0.20, 0.85, 0.10, lo=0, hi=1),
        "unusual_recipient_pattern_score":      normal_feature(rng, n, labels, 0.05, 0.05, 0.40, 0.20, 0.85, 0.10, lo=0, hi=1),
        "share_to_new_recipient_flag":          flag(rng, n, 0.20, 0.80, labels),
        "share_error_count_1h":                 normal_feature(rng, n, labels, 0.1, 0.2, 0.5, 0.5, 5.0, 3.0, lo=0, hi=50),
        "link_shortener_referral_flag":         flag(rng, n, 0.03, 0.40, labels),
        "share_access_velocity_score":          normal_feature(rng, n, labels, 0.05, 0.05, 0.40, 0.20, 0.85, 0.10, lo=0, hi=1),
        "access_before_recipient_login_flag":   flag(rng, n, 0.02, 0.45, labels),
        "broad_permission_flag":                flag(rng, n, 0.05, 0.55, labels),
        "share_anomaly_score":                  normal_feature(rng, n, labels, 0.05, 0.05, 0.40, 0.20, 0.85, 0.10, lo=0, hi=1),
    }


def gen_crypto(rng, n, labels) -> dict[str, np.ndarray]:
    return {
        "aes_key_size_bits":              normal_feature(rng, n, labels, 256, 0.5, 128, 50, 64, 30, lo=64, hi=512),
        "rsa_key_size_bits":              normal_feature(rng, n, labels, 4096, 100, 2048, 300, 512, 200, lo=512, hi=8192),
        "aes_encrypt_time_ms":            normal_feature(rng, n, labels, 20, 10, 15, 8, 5, 3, lo=0.1, hi=5000),
        "rsa_encrypt_time_ms":            normal_feature(rng, n, labels, 50, 20, 40, 20, 10, 8, lo=1, hi=10000),
        "key_generation_time_ms":         normal_feature(rng, n, labels, 100, 50, 80, 40, 20, 15, lo=1, hi=5000),
        "encryption_fail_count_1h":       normal_feature(rng, n, labels, 0.0, 0.1, 0.5, 0.5, 5.0, 3.0, lo=0, hi=50),
        "decryption_fail_count_1h":       normal_feature(rng, n, labels, 0.0, 0.1, 0.5, 0.5, 5.0, 3.0, lo=0, hi=50),
        "crypto_api_error_count_1h":      normal_feature(rng, n, labels, 0.0, 0.1, 0.3, 0.3, 3.0, 2.0, lo=0, hi=30),
        "client_encrypt_duration_ms":     normal_feature(rng, n, labels, 25, 12, 20, 10, 8, 5, lo=0.1, hi=5000),
        "client_decrypt_duration_ms":     normal_feature(rng, n, labels, 20, 10, 15, 8, 5, 3, lo=0.1, hi=5000),
        "encryption_time_per_mb_ms":      normal_feature(rng, n, labels, 10, 5, 8, 4, 2, 2, lo=0.01, hi=1000),
        "abnormal_encryption_time_flag":  flag(rng, n, 0.05, 0.55, labels),
        "private_key_access_count_1h":    normal_feature(rng, n, labels, 2, 2, 5, 3, 20, 10, lo=0, hi=200),
        "key_export_attempt_count_1h":    normal_feature(rng, n, labels, 0.0, 0.1, 0.3, 0.3, 5.0, 3.0, lo=0, hi=50),
        "local_key_missing_count_1h":     normal_feature(rng, n, labels, 0.0, 0.1, 0.3, 0.3, 3.0, 2.0, lo=0, hi=30),
        "aes_key_wrap_enabled_flag":      flag(rng, n, 0.90, 0.30, labels),
        "passphrase_used_flag":           flag(rng, n, 0.40, 0.15, labels),
        "key_rotation_count_30d":         normal_feature(rng, n, labels, 1.0, 0.5, 0.5, 0.5, 0.1, 0.1, lo=0, hi=30),
        "webcrypto_exception_rate":       normal_feature(rng, n, labels, 0.01, 0.01, 0.08, 0.05, 0.30, 0.15, lo=0, hi=1),
        "decrypt_wrong_key_count_1h":     normal_feature(rng, n, labels, 0.0, 0.1, 0.3, 0.3, 5.0, 3.0, lo=0, hi=50),
        "crypto_anomaly_score":           normal_feature(rng, n, labels, 0.05, 0.05, 0.40, 0.20, 0.85, 0.10, lo=0, hi=1),
        "entropy_after_encryption_estimate": normal_feature(rng, n, labels, 7.8, 0.1, 7.5, 0.3, 6.5, 1.0, lo=0, hi=8),
    }


def gen_api(rng, n, labels) -> dict[str, np.ndarray]:
    return {
        "api_request_count_1m":              normal_feature(rng, n, labels, 2, 2, 10, 5, 60, 25, lo=0, hi=1000),
        "api_request_count_5m":              normal_feature(rng, n, labels, 8, 6, 40, 20, 250, 100, lo=0, hi=5000),
        "api_request_count_1h":              normal_feature(rng, n, labels, 30, 20, 150, 80, 1000, 400, lo=0, hi=20000),
        "api_error_4xx_count_1h":            normal_feature(rng, n, labels, 0.5, 0.5, 5.0, 3.0, 40.0, 15.0, lo=0, hi=500),
        "api_error_5xx_count_1h":            normal_feature(rng, n, labels, 0.1, 0.2, 1.0, 0.8, 8.0, 4.0, lo=0, hi=100),
        "api_success_rate_1h":               normal_feature(rng, n, labels, 0.97, 0.02, 0.80, 0.10, 0.40, 0.20, lo=0, hi=1),
        "endpoint_upload_ratio":             normal_feature(rng, n, labels, 0.20, 0.10, 0.20, 0.10, 0.60, 0.20, lo=0, hi=1),
        "endpoint_download_ratio":           normal_feature(rng, n, labels, 0.25, 0.10, 0.25, 0.10, 0.70, 0.15, lo=0, hi=1),
        "endpoint_auth_ratio":               normal_feature(rng, n, labels, 0.15, 0.10, 0.30, 0.15, 0.60, 0.20, lo=0, hi=1),
        "endpoint_share_ratio":              normal_feature(rng, n, labels, 0.15, 0.10, 0.15, 0.10, 0.30, 0.15, lo=0, hi=1),
        "endpoint_admin_ratio":              normal_feature(rng, n, labels, 0.05, 0.05, 0.10, 0.08, 0.30, 0.15, lo=0, hi=1),
        "abnormal_endpoint_sequence_score":  normal_feature(rng, n, labels, 0.05, 0.05, 0.40, 0.20, 0.85, 0.10, lo=0, hi=1),
        "rate_limit_hit_count_1h":           normal_feature(rng, n, labels, 0.0, 0.1, 1.0, 0.8, 10.0, 5.0, lo=0, hi=100),
        "unauthorized_401_count_1h":         normal_feature(rng, n, labels, 0.1, 0.2, 2.0, 1.5, 20.0, 10.0, lo=0, hi=200),
        "forbidden_403_count_1h":            normal_feature(rng, n, labels, 0.1, 0.2, 1.5, 1.0, 15.0, 8.0, lo=0, hi=150),
        "not_found_404_count_1h":            normal_feature(rng, n, labels, 0.5, 0.5, 3.0, 2.0, 25.0, 10.0, lo=0, hi=300),
        "payload_size_kb_avg":               normal_feature(rng, n, labels, 50, 30, 40, 25, 15, 10, lo=0.1, hi=10000),
        "payload_size_kb_std":               normal_feature(rng, n, labels, 10, 8, 8, 6, 2, 1, lo=0, hi=1000),
        "repeated_same_request_count_1m":    normal_feature(rng, n, labels, 0.2, 0.3, 2.0, 1.5, 15.0, 8.0, lo=0, hi=200),
        "origin_mismatch_count_1h":          normal_feature(rng, n, labels, 0.0, 0.1, 0.3, 0.3, 3.0, 2.0, lo=0, hi=30),
        "cors_error_count_1h":               normal_feature(rng, n, labels, 0.0, 0.1, 0.3, 0.3, 3.0, 2.0, lo=0, hi=30),
        "csrf_invalid_count_1h":             normal_feature(rng, n, labels, 0.0, 0.1, 0.2, 0.2, 2.0, 1.5, lo=0, hi=20),
        "idor_pattern_score":                normal_feature(rng, n, labels, 0.02, 0.03, 0.30, 0.20, 0.80, 0.15, lo=0, hi=1),
        "replay_nonce_reuse_count_1h":       normal_feature(rng, n, labels, 0.0, 0.1, 0.2, 0.2, 2.0, 1.5, lo=0, hi=20),
        "api_latency_ms_avg":                normal_feature(rng, n, labels, 80, 30, 50, 25, 15, 8, lo=1, hi=5000),
        "api_latency_ms_std":                normal_feature(rng, n, labels, 10, 5, 8, 4, 2, 1, lo=0, hi=500),
        "api_anomaly_score":                 normal_feature(rng, n, labels, 0.05, 0.05, 0.40, 0.20, 0.85, 0.10, lo=0, hi=1),
        "bot_user_agent_score":              normal_feature(rng, n, labels, 0.02, 0.03, 0.25, 0.20, 0.85, 0.12, lo=0, hi=1),
    }


def gen_db_storage(rng, n, labels) -> dict[str, np.ndarray]:
    return {
        "db_query_count_1h":                   normal_feature(rng, n, labels, 20, 15, 60, 30, 300, 100, lo=0, hi=5000),
        "db_insert_count_1h":                  normal_feature(rng, n, labels, 2, 2, 8, 5, 50, 20, lo=0, hi=1000),
        "db_update_count_1h":                  normal_feature(rng, n, labels, 3, 3, 10, 6, 60, 25, lo=0, hi=1000),
        "db_delete_count_1h":                  normal_feature(rng, n, labels, 0.5, 0.5, 2.0, 1.5, 20.0, 10.0, lo=0, hi=200),
        "db_error_count_1h":                   normal_feature(rng, n, labels, 0.1, 0.2, 1.0, 0.8, 8.0, 4.0, lo=0, hi=100),
        "db_latency_ms_avg":                   normal_feature(rng, n, labels, 5, 3, 10, 5, 50, 20, lo=0.1, hi=1000),
        "suspicious_user_lookup_count_1h":     normal_feature(rng, n, labels, 0.0, 0.1, 0.5, 0.5, 5.0, 3.0, lo=0, hi=50),
        "repeated_token_lookup_count_1h":      normal_feature(rng, n, labels, 0.0, 0.1, 0.5, 0.5, 5.0, 3.0, lo=0, hi=50),
        "share_record_change_count_1h":        normal_feature(rng, n, labels, 0.5, 0.5, 2.0, 1.5, 10.0, 5.0, lo=0, hi=100),
        "permission_record_change_count_1h":   normal_feature(rng, n, labels, 0.3, 0.3, 1.5, 1.0, 8.0, 4.0, lo=0, hi=80),
        "metadata_access_count_1h":            normal_feature(rng, n, labels, 5, 4, 15, 8, 60, 25, lo=0, hi=500),
        "abnormal_db_pattern_score":           normal_feature(rng, n, labels, 0.05, 0.05, 0.40, 0.20, 0.85, 0.10, lo=0, hi=1),
        "blob_upload_count_1h":                normal_feature(rng, n, labels, 2, 2, 8, 5, 50, 20, lo=0, hi=500),
        "blob_download_count_1h":              normal_feature(rng, n, labels, 3, 2, 10, 6, 70, 30, lo=0, hi=1000),
        "blob_delete_count_1h":                normal_feature(rng, n, labels, 0.1, 0.2, 0.5, 0.5, 5.0, 3.0, lo=0, hi=50),
        "sas_url_created_count_1h":            normal_feature(rng, n, labels, 2, 1.5, 6, 3, 30, 12, lo=0, hi=300),
        "sas_url_access_count_1h":             normal_feature(rng, n, labels, 3, 2, 10, 5, 60, 25, lo=0, hi=600),
        "sas_url_expiry_minutes_avg":          normal_feature(rng, n, labels, 60, 30, 30, 20, 5, 5, lo=1, hi=10080),
        "sas_url_access_after_expiry_count":   normal_feature(rng, n, labels, 0.0, 0.1, 0.3, 0.3, 3.0, 2.0, lo=0, hi=30),
        "blob_access_country_count_24h":       normal_feature(rng, n, labels, 1, 0.5, 2, 1, 8, 4, lo=1, hi=30),
        "blob_access_ip_count_24h":            normal_feature(rng, n, labels, 1, 0.5, 3, 2, 15, 8, lo=1, hi=100),
        "storage_error_count_1h":              normal_feature(rng, n, labels, 0.1, 0.2, 0.5, 0.5, 5.0, 3.0, lo=0, hi=50),
        "public_blob_access_attempt_count":    normal_feature(rng, n, labels, 0.0, 0.1, 0.2, 0.2, 3.0, 2.0, lo=0, hi=30),
        "abnormal_blob_download_score":        normal_feature(rng, n, labels, 0.05, 0.05, 0.40, 0.20, 0.85, 0.10, lo=0, hi=1),
        "sas_abuse_score":                     normal_feature(rng, n, labels, 0.05, 0.05, 0.35, 0.20, 0.85, 0.10, lo=0, hi=1),
    }


def gen_derived(rng, n, labels) -> dict[str, np.ndarray]:
    """Derived risk scores — composite của các nhóm trên."""
    return {
        "behavior_change_score":           normal_feature(rng, n, labels, 0.05, 0.05, 0.45, 0.20, 0.88, 0.10, lo=0, hi=1),
        "deviation_from_normal_hour":      normal_feature(rng, n, labels, 0.05, 0.05, 0.40, 0.20, 0.85, 0.10, lo=0, hi=1),
        "normal_country_deviation_score":  normal_feature(rng, n, labels, 0.05, 0.05, 0.35, 0.20, 0.80, 0.12, lo=0, hi=1),
        "normal_device_deviation_score":   normal_feature(rng, n, labels, 0.05, 0.05, 0.35, 0.20, 0.80, 0.12, lo=0, hi=1),
        "baseline_upload_zscore":          normal_feature(rng, n, labels, 0.1, 0.3, 1.5, 1.0, 5.0, 2.0, lo=0, hi=20),
        "baseline_download_zscore":        normal_feature(rng, n, labels, 0.1, 0.3, 1.5, 1.0, 5.0, 2.0, lo=0, hi=20),
        "baseline_api_zscore":             normal_feature(rng, n, labels, 0.1, 0.3, 1.5, 1.0, 5.0, 2.0, lo=0, hi=20),
        "baseline_failed_login_zscore":    normal_feature(rng, n, labels, 0.1, 0.3, 1.5, 1.0, 5.0, 2.0, lo=0, hi=20),
        "ue_behavior_score":               normal_feature(rng, n, labels, 0.05, 0.05, 0.40, 0.20, 0.88, 0.10, lo=0, hi=1),
        "bot_behavior_score":              normal_feature(rng, n, labels, 0.02, 0.03, 0.35, 0.20, 0.90, 0.08, lo=0, hi=1),
        "scraping_score":                  normal_feature(rng, n, labels, 0.02, 0.03, 0.30, 0.20, 0.85, 0.10, lo=0, hi=1),
        "storage_breach_score":            normal_feature(rng, n, labels, 0.02, 0.03, 0.35, 0.20, 0.88, 0.10, lo=0, hi=1),
        "memory_key_theft_score":          normal_feature(rng, n, labels, 0.02, 0.03, 0.25, 0.20, 0.80, 0.12, lo=0, hi=1),
        "replay_attack_score":             normal_feature(rng, n, labels, 0.02, 0.03, 0.25, 0.20, 0.85, 0.10, lo=0, hi=1),
        "token_abuse_score":               normal_feature(rng, n, labels, 0.02, 0.03, 0.35, 0.20, 0.88, 0.10, lo=0, hi=1),
        "credential_stuffing_score":       normal_feature(rng, n, labels, 0.02, 0.03, 0.30, 0.20, 0.90, 0.08, lo=0, hi=1),
        "brute_force_score":               normal_feature(rng, n, labels, 0.02, 0.03, 0.30, 0.20, 0.90, 0.08, lo=0, hi=1),
        "anomaly_score":                   normal_feature(rng, n, labels, 0.05, 0.05, 0.45, 0.20, 0.90, 0.08, lo=0, hi=1),
        "rule_based_risk_score":           normal_feature(rng, n, labels, 0.05, 0.05, 0.45, 0.20, 0.88, 0.10, lo=0, hi=1),
        # final_model_hint_score bị loại — không train với cột này
    }


# ── Main generator ─────────────────────────────────────────────────────────────

def generate(n_rows: int = 200_000, seed: int = 42) -> pd.DataFrame:
    rng = _rng(seed)

    # Label distribution: 75% Normal, 15% Suspicious, 10% Attack
    labels = rng.choice([0, 1, 2], size=n_rows, p=[0.75, 0.15, 0.10])

    print(f"Generating {n_rows:,} rows  (seed={seed})")
    print(f"  Normal:     {(labels==0).sum():,}  ({(labels==0).mean()*100:.1f}%)")
    print(f"  Suspicious: {(labels==1).sum():,}  ({(labels==1).mean()*100:.1f}%)")
    print(f"  Attack:     {(labels==2).sum():,}  ({(labels==2).mean()*100:.1f}%)")

    cols: dict[str, np.ndarray] = {}
    cols.update(gen_general_time(rng, n_rows, labels))
    cols.update(gen_auth(rng, n_rows, labels))
    cols.update(gen_ip_network(rng, n_rows, labels))
    cols.update(gen_device_browser(rng, n_rows, labels))
    cols.update(gen_upload(rng, n_rows, labels))
    cols.update(gen_download(rng, n_rows, labels))
    cols.update(gen_share(rng, n_rows, labels))
    cols.update(gen_crypto(rng, n_rows, labels))
    cols.update(gen_api(rng, n_rows, labels))
    cols.update(gen_db_storage(rng, n_rows, labels))
    cols.update(gen_derived(rng, n_rows, labels))

    df = pd.DataFrame(cols)
    df["risk_label"] = labels.astype(np.int8)

    assert len(df.columns) - 1 == 258, f"Expected 258 features, got {len(df.columns)-1}"
    print(f"\nFeature columns: {len(df.columns)-1}  (target: risk_label)")
    return df


def main() -> None:
    parser = argparse.ArgumentParser(description="Sinh dataset 258 chiều cho LockSend AI")
    parser.add_argument("--rows", type=int, default=200_000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", type=str, default="", help="Path output CSV.GZ (mặc định: data/locksend_258/train.csv.gz)")
    args = parser.parse_args()

    df = generate(args.rows, args.seed)

    out_path = Path(args.out) if args.out else OUT_DIR / "train.csv.gz"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"\nGhi file: {out_path}")
    with gzip.open(out_path, "wt", encoding="utf-8") as f:
        df.to_csv(f, index=False)

    size_mb = out_path.stat().st_size / 1024 / 1024
    print(f"Xong! {size_mb:.1f} MB  ({args.rows:,} dòng x {len(df.columns)} cột)")
    print(f"\nBước tiếp: python train_locksend_258.py")


if __name__ == "__main__":
    main()
