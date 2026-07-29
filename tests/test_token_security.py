"""Unit tests cho rule-based token security scoring."""

from datetime import datetime, timedelta, timezone

from services.token_security import _risk_band, _score_user_risk, _session_status


def test_risk_band():
    assert _risk_band(0) == "low"
    assert _risk_band(30) == "medium"
    assert _risk_band(55) == "high"
    assert _risk_band(80) == "critical"


def test_score_many_ips():
    score, signals = _score_user_risk(
        active_count=4,
        unique_ips=3,
        unique_agents=1,
        recent_mass_revoke=False,
        reuse_indicators=0,
    )
    assert score >= 50
    assert "multiple_ip_addresses" in signals


def test_score_reuse_indicator():
    score, signals = _score_user_risk(1, 1, 1, False, reuse_indicators=1)
    assert score >= 50
    assert "refresh_token_reuse_pattern" in signals


class _FakeRt:
    def __init__(self, **kw):
        self.revoked_at = kw.get("revoked_at")
        self.replaced_by_jti = kw.get("replaced_by_jti")
        self.expires_at = kw.get("expires_at", datetime.now(timezone.utc) + timedelta(days=1))


def test_session_status_active():
    now = datetime.now(timezone.utc)
    rt = _FakeRt()
    assert _session_status(rt, now) == "active"
