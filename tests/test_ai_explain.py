"""Tests cho ai_explain — badge hành vi và so sánh rule/AI."""

from services.ai_explain import behavior_badges, enrich_ai_result, rule_ai_agreement, summary_vi


def test_behavior_badges_spam_and_port():
    top = [
        {"feature": "Down/Up Ratio", "impact": 0.04, "direction": "tang rui ro"},
        {"feature": "Dst Port", "impact": 0.03, "direction": "tang rui ro"},
        {"feature": "Bwd Byts/b Avg", "impact": -0.03, "direction": "giam rui ro"},
    ]
    badges = behavior_badges(top)
    labels = {b["label"] for b in badges}
    assert "Spam request" in labels
    assert "Nhiều nguồn truy cập" in labels


def test_rule_ai_agreement_disagree():
    out = rule_ai_agreement("low", "high")
    assert out["status"] == "disagree"
    assert out["delta"] == 2


def test_enrich_ai_result_adds_vietnamese_fields():
    result = {
        "risk_score_pct": 73,
        "risk_level": "high",
        "ai_level_raw": "HIGH",
        "decision": "MONITOR",
        "explanation": {
            "summary": "Risk 73% → HIGH → MONITOR.",
            "top_features": [{"feature": "Down/Up Ratio", "impact": 0.04, "direction": "tang rui ro"}],
        },
    }
    metric = {"risk_score": 45, "risk_level": "medium", "recommendation": "MONITOR"}
    enriched = enrich_ai_result(result, metric)
    assert enriched["rule_score"] == 45
    assert enriched["summary_vi"]
    assert enriched["behavior_badges"]
    assert enriched["agreement"]["status"] in ("agree", "partial", "disagree")
