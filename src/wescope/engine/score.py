"""위험 점수 0~100 (RULES.md §5): risk = round(100 × (1 − Π(1 − w_sev × w_conf)))"""
from collections import defaultdict

W_SEV = {"CRITICAL": 0.50, "HIGH": 0.30, "MEDIUM": 0.12, "LOW": 0.04, "INFO": 0.0}
W_CONF = {"Likely": 1.0, "Potential": 0.6}


def risk_score(findings) -> int:
    """findings: 열린 발견만. 같은 rule_id는 상위 3건, 체인이 있으면 구성 발견 대신 체인만."""
    in_chain = {fp for f in findings if f.chain for fp in f.related}
    per_rule = defaultdict(list)
    for f in findings:
        if f.fingerprint not in in_chain:
            per_rule[f.rule_id].append(W_SEV[f.severity] * W_CONF[f.confidence])
    safe = 1.0
    for weights in per_rule.values():
        for w in sorted(weights, reverse=True)[:3]:
            safe *= 1 - w
    return round(100 * (1 - safe))
