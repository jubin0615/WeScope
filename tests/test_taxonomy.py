from wescope.models.finding import SEVERITIES
from wescope.paths import RULES_DIR
from wescope.taxonomy import catalog, owasp

# RULES.md §2의 M1 규칙과 문서에 적힌 OWASP 2025 코드 (CWE에서 자동 계산된 값이 문서와 같아야 한다)
M1_RULES = {
    "secret-env-file": "A01:2025", "secret-credential-file": "A01:2025", "secret-hardcoded": "A07:2025",
    "secret-frontend-env": "A01:2025", "secret-client-bundle": "A07:2025", "secret-infra-config": "A07:2025",
    "secret-dev-tool": "A07:2025", "secret-data-file": "A01:2025", "secret-doc": "A07:2025", "git-hygiene": None,
    "authz-admin-route": "A01:2025", "authz-idor": "A01:2025", "authz-no-auth-write": "A07:2025",
    "authz-jwt-no-verify": "A04:2025", "authz-csrf-exempt": "A01:2025",
    "inject-sql": "A05:2025", "inject-code": "A05:2025", "inject-command": "A05:2025", "inject-xss": "A05:2025",
    "inject-xss-template": "A05:2025", "inject-path": "A01:2025", "inject-ssrf": "A01:2025",
    "inject-deserialize": "A08:2025", "inject-upload": "A06:2025", "inject-open-redirect": "A01:2025",
    "config-debug": "A02:2025", "config-allowed-hosts": None, "config-cors-wildcard": "A02:2025",
    "config-cors-credentials": "A02:2025", "config-cookie-flags": "A02:2025", "config-weak-secret": "A04:2025",
    "config-weak-hash": "A04:2025", "config-tls-verify-off": "A07:2025", "config-default-credential": "A07:2025",
    "config-error-exposure": "A10:2025", "config-fail-open": "A10:2025", "config-swallowed-exception": "A10:2025",
    "config-security-todo": None,
}


# ChatGPT 보완 탐지 유형 (RULES.md §3) → OWASP. CWE가 없는 유형·목록 밖 CWE는 None
AI_RULES = {
    "ai-idor": "A01:2025", "ai-missing-authz": "A01:2025", "ai-client-trusted-identity": "A06:2025",
    "ai-mass-assignment": "A08:2025", "ai-price-tampering": "A06:2025", "ai-state-skip": "A06:2025",
    "ai-race-double-spend": "A06:2025", "ai-weak-reset-token": "A07:2025", "ai-account-enumeration": None,
    "ai-session-fixation": "A07:2025", "ai-insecure-file-access": "A01:2025", "ai-cross-file-injection-sql": "A05:2025",
    "ai-cross-file-injection-command": "A05:2025", "ai-cross-file-xss": "A05:2025", "ai-cross-file-path": "A01:2025",
    "ai-llm-excessive-agency": None, "ai-unsupported-lang-injection": "A05:2025", "ai-unsupported-lang-authz": "A01:2025",
}


def test_catalog_has_exactly_the_m1_and_ai_rules():
    assert set(catalog.rules()) == set(M1_RULES) | set(AI_RULES)
    assert catalog.rule("ai-llm-excessive-agency")["owasp_ai"] == ["LLM06"]


def test_owasp_is_derived_from_cwe_as_documented():
    for rule_id, expected in {**M1_RULES, **AI_RULES}.items():
        assert owasp.classify(catalog.rule(rule_id)["cwe"]) == expected, rule_id
    assert owasp.classify("CWE-1004") == "A02:2025" and owasp.classify("CWE-1275") == "A01:2025"   # 쿠키 세부 CWE


def test_owasp_catalog_one_cwe_one_category():
    items = catalog.owasp_top10()
    assert [i["code"] for i in items] == [f"A{n:02d}:2025" for n in range(1, 11)]
    assert len(owasp._index()) == sum(len(i["cwes"]) for i in items) == 249


def test_every_rule_has_complete_korean_metadata():
    areas = {a["code"] for a in catalog.ws_areas()}
    for rule in catalog.rules().values():
        assert rule["category"] in areas
        assert rule["severity"] in SEVERITIES and rule["confidence"] in ("Likely", "Potential")
        for field in ("title_ko", "tech_name_ko", "why_ko", "fix_ko", "avoid_ko", "fix_example", "limitations_ko"):
            assert rule[field] and rule[field].strip(), f"{rule['id']}.{field}"


def test_semgrep_rule_ids_belong_to_catalog():
    import yaml
    for path in (RULES_DIR / "semgrep").glob("*.yml"):
        for rule in yaml.safe_load(path.read_text(encoding="utf-8"))["rules"]:
            assert rule["id"].split("--")[0] in catalog.rules(), rule["id"]
