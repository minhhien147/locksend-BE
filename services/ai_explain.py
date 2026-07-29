"""
LockSend AI — nhãn hành vi + giải thích tiếng Việt từ SHAP top features.
"""

from __future__ import annotations

from typing import Any

# (substring trong tên feature, id, nhãn VI, severity)
_BEHAVIOR_PATTERNS: tuple[tuple[tuple[str, ...], str, str, str], ...] = (
    (("down/up", "fwd packets", "flow packets", "packets/s"), "spam_request", "Spam request", "high"),
    (("dst port", "destination port"), "multi_source", "Nhiều nguồn truy cập", "medium"),
    (("flow duration", "active max", "idle max"), "long_session", "Session kéo dài", "medium"),
    (("bwd", "backward", "subflow bwd"), "bulk_activity", "Lưu lượng ngược bất thường", "medium"),
    (("flow bytes", "fwd bytes"), "high_bandwidth", "Băng thông cao", "medium"),
)

_DECISION_VI = {
    "ALLOW": "cho phép",
    "MONITOR": "theo dõi",
    "REVIEW": "chờ admin xem xét",
    "REVOKE": "thu hồi token",
}

_LEVEL_VI = {
    "low": "thấp",
    "medium": "trung bình",
    "high": "cao",
    "critical": "nghiêm trọng",
    "NORMAL": "bình thường",
    "LOW": "thấp",
    "HIGH": "cao",
    "CRITICAL": "nghiêm trọng",
}

_DECISION_ORDER = {
    "ALLOW": 0,
    "MONITOR": 1,
    "REVIEW": 2,
    "REVOKE": 3,
}


def _norm_feature(name: str) -> str:
    return name.strip().lower()


def behavior_badges(top_features: list[dict[str, Any]], limit: int = 4) -> list[dict[str, str]]:
    """Map SHAP features → badge hành vi (chỉ tín hiệu tăng rủi ro)."""
    seen: set[str] = set()
    badges: list[dict[str, str]] = []

    for feat in top_features:
        if float(feat.get("impact", 0)) <= 0:
            continue
        name = _norm_feature(str(feat.get("feature", "")))
        for keys, bid, label, severity in _BEHAVIOR_PATTERNS:
            if bid in seen:
                continue
            if any(k in name for k in keys):
                badges.append({"id": bid, "label": label, "severity": severity})
                seen.add(bid)
                break
        if len(badges) >= limit:
            break

    if not badges and top_features:
        top = top_features[0]
        if float(top.get("impact", 0)) > 0:
            badges.append({
                "id": "anomaly",
                "label": "Hành vi lệch chuẩn",
                "severity": "medium",
            })

    return badges


def rule_ai_agreement(rule_level: str | None, ai_level: str | None) -> dict[str, Any]:
    """So sánh mức rủi ro rule engine vs AI."""
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    r = order.get((rule_level or "low").lower(), 1)
    a = order.get((ai_level or "medium").lower(), 1)
    delta = abs(a - r)

    if delta == 0:
        status, label = "agree", "Đồng thuận"
    elif delta == 1:
        status, label = "partial", "Gần khớp"
    else:
        status, label = "disagree", "Không đồng thuận"

    return {
        "status": status,
        "label": label,
        "rule_level": rule_level,
        "ai_level": ai_level,
        "delta": delta,
    }


def compose_final_decision(
    ai_decision: str | None,
    rule_recommendation: str | None,
) -> dict[str, Any]:
    """
    Quyết định cuối cho UI/admin.
    - AI chỉ đưa ra khuyến nghị.
    - Nếu AI hoặc rule engine muốn REVOKE, quyết định cuối phải là REVIEW
      để admin là người chốt thu hồi thủ công.
    """
    ai = str(ai_decision or "MONITOR").upper()
    rule = str(rule_recommendation or "ALLOW").upper()
    ai_severity = _DECISION_ORDER.get(ai, 1)
    rule_severity = _DECISION_ORDER.get(rule, 0)
    highest = max(ai_severity, rule_severity)
    if highest >= _DECISION_ORDER["REVOKE"]:
        final = "REVIEW"
    elif highest >= _DECISION_ORDER["MONITOR"]:
        final = "MONITOR"
    else:
        final = "ALLOW"
    return {
        "ai_decision": ai,
        "rule_recommendation": rule,
        "decision": final,
        "requires_admin_action": final == "REVIEW",
        "overridden_by_rule": final != ai,
    }


def summary_vi(
    risk_score_pct: int,
    risk_level: str,
    ai_level_raw: str,
    decision: str,
    top_features: list[dict[str, Any]],
    badges: list[dict[str, str]],
) -> str:
    """Tóm tắt giải thích AI bằng tiếng Việt."""
    level_txt = _LEVEL_VI.get(ai_level_raw, _LEVEL_VI.get(risk_level, risk_level))
    decision_txt = _DECISION_VI.get(decision, decision.lower())

    if badges:
        signal_txt = ", ".join(b["label"] for b in badges[:3])
    else:
        increasing = [
            f["feature"]
            for f in top_features[:2]
            if float(f.get("impact", 0)) > 0
        ]
        signal_txt = ", ".join(increasing) if increasing else "không rõ"

    return (
        f"Nguy cơ AI {risk_score_pct}% (mức {level_txt}) — đề xuất {decision_txt}. "
        f"Tín hiệu: {signal_txt}."
    )


def enrich_ai_result(result: dict[str, Any], metric: dict[str, Any]) -> dict[str, Any]:
    """Bổ sung badge, summary_vi, rule comparison vào kết quả analyze."""
    explanation = result.get("explanation") or {}
    top_features: list[dict[str, Any]] = list(explanation.get("top_features") or [])
    badges = behavior_badges(top_features)

    rule_level = metric.get("risk_level")
    ai_level = result.get("risk_level")
    final_decision = compose_final_decision(
        str(result.get("decision", "MONITOR")),
        str(metric.get("recommendation", "ALLOW")),
    )

    enriched = dict(result)
    enriched["ai_decision"] = final_decision["ai_decision"]
    enriched["decision"] = final_decision["decision"]
    enriched["requires_admin_action"] = final_decision["requires_admin_action"]
    enriched["overridden_by_rule"] = final_decision["overridden_by_rule"]
    enriched["behavior_badges"] = badges
    enriched["summary_vi"] = summary_vi(
        int(result.get("risk_score_pct", 0)),
        str(ai_level or ""),
        str(result.get("ai_level_raw", "")),
        str(final_decision["decision"]),
        top_features,
        badges,
    )
    enriched["rule_score"] = metric.get("risk_score")
    enriched["rule_level"] = rule_level
    enriched["rule_recommendation"] = final_decision["rule_recommendation"]
    enriched["agreement"] = rule_ai_agreement(
        str(rule_level) if rule_level else None,
        str(ai_level) if ai_level else None,
    )
    if explanation:
        enriched["explanation"] = {**explanation, "summary_vi": enriched["summary_vi"]}
    return enriched
