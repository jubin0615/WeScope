"""결과 JSON 형식 동결 (B6). tests/fixtures/results/*.json은 대시보드가 엔진 없이 화면을 만드는 기준이다.

형식을 바꿔야 하면: 문서(ARCHITECTURE §4) → schema_version → 샘플 재생성 순서로 바꾼다. 이 테스트가 깨지면 프론트도 깨진다.
"""
import json
import re
from pathlib import Path

import pytest

from wescope.analyzers.secrets.patterns import PROVIDERS
from wescope.models.scan_result import SCHEMA_VERSION, ScanResult

SAMPLES = sorted((Path(__file__).parent / "fixtures" / "results").glob("*.json"))
TOP_LEVEL = ["scan_id", "scanned_at", "trigger", "source", "commit", "baseline_scan", "profile", "analyzers", "coverage",
             "owasp_coverage", "findings", "summary", "repo", "ai", "ai_coverage", "schema_version"]
FINDING = ["rule_id", "category", "cwe", "owasp", "severity", "confidence", "title_ko", "tech_name_ko", "why_ko", "fix_ko",
           "avoid_ko", "fix_example", "limitations_ko", "location", "evidence", "fingerprint", "id", "owasp_ai", "source",
           "confidence_source", "scope", "extra", "change", "introduced_in", "status", "triage", "fix", "chain", "related"]


def test_samples_exist():
    assert {p.stem for p in SAMPLES} == {"first-scan", "rescan-new-fixed-dismissed", "secrets-git", "clean",
                                         "semgrep-skipped", "with-fix"}


@pytest.mark.parametrize("path", SAMPLES, ids=lambda p: p.stem)
def test_sample_matches_current_schema(path):
    text = path.read_text(encoding="utf-8")
    data = json.loads(text)
    assert data["schema_version"] == SCHEMA_VERSION
    assert list(data) == TOP_LEVEL
    for finding in data["findings"]:
        assert list(finding) == FINDING
    assert json.loads(ScanResult.from_json(text).to_json()) == data      # 읽고 다시 써도 같다
    for _, pattern, _ in PROVIDERS:
        assert not pattern.search(text), "샘플에 원문 형식의 비밀값이 있어요"
    assert not re.search(r"[A-Za-z]:\\\\Users|/tmp/|AppData", text), "샘플에 실제 PC 경로가 남았어요"


def test_rescan_sample_covers_change_states():
    data = json.loads((Path(__file__).parent / "fixtures/results/rescan-new-fixed-dismissed.json").read_text("utf-8"))
    assert {f["change"] for f in data["findings"]} == {"new", "existing", "fixed"}
    assert {f["status"] for f in data["findings"]} == {"open", "dismissed"}
    assert data["baseline_scan"]


FIX = ["summary_ko", "diff", "files", "behavior_change_ko", "follow_ups", "new_dependencies", "test_hint_ko", "confidence",
       "verification", "checks", "attempts", "cache_key", "instruction_suspect"]
AI = ["level", "model", "requests", "cache_hits", "fixes", "budget_exceeded", "remaining_groups", "error"]


def test_fix_sample_matches_fixer_output_shape():
    """B8: 수정안(fix)·AI 요약(ai) 형식. llm/fixer.py가 만드는 키와 같아야 한다 (AI.md §3-3·§3-4)."""
    from wescope.llm import fixer
    data = json.loads((Path(__file__).parent / "fixtures/results/with-fix.json").read_text("utf-8"))
    fixes = [f["fix"] for f in data["findings"] if f["fix"]]
    assert {f["verification"] for f in fixes} == {"verified", "failed"}
    for fix in fixes:
        assert list(fix) == FIX and list(fix["checks"]) == ["apply", "syntax", "rescan", "reasons"]
    assert list(data["ai"]) == AI and list(data["ai"]["fixes"]) == ["verified", "partial", "failed"]
    assert FIX[:8] == list(fixer._FIELDS)
