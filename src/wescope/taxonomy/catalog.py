"""규칙 메타 로더. rules/catalog/*.yml(목록 형식) + rules/semgrep/*.yml의 metadata.

Semgrep 규칙 id가 `inject-xss--dom`처럼 `--`로 나뉘면 앞부분이 rule_id다 (한 규칙을 여러 패턴으로 나눌 때).
한국어 설명(title_ko)이 있는 쪽이 그 rule_id의 메타 원본이다.
"""
from functools import cache

import yaml

from wescope.paths import RULES_DIR

RULE_FIELDS = ("category", "cwe", "severity", "confidence", "title_ko", "tech_name_ko",
               "why_ko", "fix_ko", "avoid_ko", "fix_example", "limitations_ko")


def _load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@cache
def rules() -> dict[str, dict]:
    found: dict[str, dict] = {}

    def add(rule_id, meta, origin):
        if rule_id in found:
            raise ValueError(f"규칙 메타가 두 곳에 있어요: {rule_id} ({origin})")
        found[rule_id] = {"id": rule_id, "owasp_ai": list(meta.get("owasp_ai") or []), **{k: meta.get(k) for k in RULE_FIELDS}}

    for path in sorted((RULES_DIR / "catalog").glob("*.yml")):
        data = _load(path)
        if isinstance(data, list):
            for rule in data:
                add(rule["id"], rule, path.name)
    for path in sorted((RULES_DIR / "semgrep").glob("*.yml")):
        for rule in _load(path)["rules"]:
            meta = rule.get("metadata", {})
            if "title_ko" in meta:
                add(rule["id"].split("--")[0], meta, path.name)
    return found


def rule(rule_id: str) -> dict:
    return rules()[rule_id]


@cache
def ws_areas() -> list[dict]:
    return _load(RULES_DIR / "catalog" / "ws-top10.yml")["items"]


@cache
def owasp_top10() -> list[dict]:
    return _load(RULES_DIR / "catalog" / "owasp-top10-2025.yml")["items"]
