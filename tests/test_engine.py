import shutil
from types import SimpleNamespace

import pytest

from conftest import materialize
from wescope.analyzers.base import Analyzer, AnalyzerResult, ToolMissing
from wescope.collector.inventory import AppProfile
from wescope.collector.snapshot import Target
from wescope.engine.aggregate import aggregate
from wescope.engine.runner import run_all
from wescope.engine.score import risk_score
from wescope.models.finding import Finding, Location, RawHit
from wescope.scan import run_scan

needs_semgrep = pytest.mark.skipif(not shutil.which("semgrep"), reason="semgrep 미설치")


class Fake(Analyzer):
    categories = ("WS-01",)
    languages = frozenset({"*"})

    def __init__(self, id, behavior, applies=True):
        self.id, self.behavior, self._applies = id, behavior, applies

    def applies(self, ctx):
        return self._applies

    def run(self, ctx):
        if isinstance(self.behavior, Exception):
            raise self.behavior
        return AnalyzerResult([RawHit("secret-hardcoded", "a.py", 1)])


def test_runner_isolates_failures():
    analyzers = [Fake("boom", ValueError("x")), Fake("tool", ToolMissing("없음")), Fake("na", None, applies=False),
                 Fake("ok", None)]
    hits, statuses = run_all(SimpleNamespace(), analyzers)
    assert [(s.id, s.status) for s in statuses] == [("boom", "failed"), ("tool", "skipped"), ("na", "not_applicable"),
                                                    ("ok", "ok")]
    assert statuses[0].note == "ValueError" and statuses[1].note == "없음"
    assert len(hits) == 1
    with pytest.raises(ValueError):
        run_all(SimpleNamespace(), analyzers, strict=True)


def finding(rule, severity, confidence, fp=None):
    return Finding(rule_id=rule, category="WS-05", cwe=None, owasp=None, severity=severity, confidence=confidence,
                   title_ko="", tech_name_ko="", why_ko="", fix_ko="", avoid_ko="", fix_example="", limitations_ko="",
                   location=Location("a.py", 1), evidence="", fingerprint=fp or f"{rule}{severity}{confidence}")


def test_risk_score_examples_from_rules_md():
    assert risk_score([finding("r1", "CRITICAL", "Likely")]) == 50
    assert risk_score([finding("r1", "HIGH", "Likely", "a"), finding("r2", "HIGH", "Likely", "b")]) == 51
    assert risk_score([finding(f"r{i}", "HIGH", "Potential") for i in range(5)]) == 63
    assert risk_score([finding("same", "HIGH", "Likely", str(i)) for i in range(5)]) == 66   # 같은 규칙은 상위 3건만
    assert risk_score([finding("todo", "INFO", "Potential")]) == 0


def test_dismissed_and_fixed_are_kept_but_not_counted():
    ctx = SimpleNamespace(source={}, profile=AppProfile(), skipped={})
    kept = finding("inject-sql", "HIGH", "Likely", "keep")
    ignored = finding("inject-xss", "HIGH", "Likely", "ignored")
    fixed = finding("inject-code", "HIGH", "Likely", "fixed")
    fixed.change = "fixed"
    result = aggregate([kept, ignored, fixed], [], ctx, ignored={"ignored"})
    assert {f.fingerprint: f.status for f in result.findings}["ignored"] == "dismissed"
    assert result.summary["severity"]["HIGH"] == 1 and result.summary["fixed"] == 1
    assert result.summary["risk_score"] == 30
    assert [f.id for f in result.findings] == ["F-001", "F-002", "F-003"] and result.findings[-1].change == "fixed"


@needs_semgrep
def test_fingerprints_survive_line_shifts(tmp_path):
    root, _ = materialize("vuln_flask", tmp_path)
    first = run_scan(Target("folder", str(root)))
    app = root / "app.py"
    app.write_text("\n\n\n" + app.read_text(encoding="utf-8"), encoding="utf-8")
    second = run_scan(Target("folder", str(root)), previous=first)
    assert {f.change for f in second.findings} == {"existing"}
    assert {f.fingerprint for f in second.findings} == {f.fingerprint for f in first.findings}


def test_new_fixed_unknown(tmp_path):
    root, _ = materialize("vuln_flask", tmp_path)
    app = root / "app.py"
    source = app.read_text(encoding="utf-8")
    first = run_scan(Target("folder", str(root)))

    app.write_text(source.replace("app.run(debug=True)", "app.run()"), encoding="utf-8")
    second = run_scan(Target("folder", str(root)), previous=first)
    changes = {(f.rule_id, f.change) for f in second.findings}
    assert ("config-debug", "fixed") in changes and second.summary["fixed"] == 1 and second.summary["new"] == 0

    third = run_scan(Target("folder", str(root)), previous=second)      # FIXED는 한 번만 보인다
    assert third.summary["fixed"] == 0

    app.write_text(source + "\ndef broken(:\n", encoding="utf-8")       # 파싱 실패 → 해결로 보지 않음
    fourth = run_scan(Target("folder", str(root)), previous=third)
    assert {f.change for f in fourth.findings if f.rule_id == "authz-idor"} == {"unknown"}
    assert not [f for f in fourth.findings if f.change == "fixed" and f.location.file == "app.py"]
