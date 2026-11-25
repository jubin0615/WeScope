import shutil

import pytest

from conftest import make_git_repo, materialize
from test_fixtures import ZOO_COMMITTED
from wescope.collector.snapshot import Target
from wescope.report.markdown import render
from wescope.scan import run_scan

needs_semgrep = pytest.mark.skipif(not shutil.which("semgrep"), reason="semgrep 미설치")


@needs_semgrep
@pytest.mark.parametrize("name", ["vuln_flask", "secrets_zoo"])
def test_report_has_every_finding_and_no_secret(name, tmp_path):
    root, planted = materialize(name, tmp_path)
    if name == "secrets_zoo":
        make_git_repo(root, ZOO_COMMITTED)
    result = run_scan(Target("folder", str(root)))
    report = render(result)
    assert not [p for p in planted if p in report]
    for f in result.findings:
        assert f.tech_name_ko in report and f.location.file in report
    assert "OWASP Top 10:2025 분류 기준 점검 범위" in report
    assert "안전을 보증하지 않아요" in report
    for claim in ("OWASP 준수", "OWASP 통과", "안전합니다"):     # PRD §5: 준수·통과·안전 판정을 쓰지 않는다
        assert claim not in report


def test_clean_report_says_no_open_findings(tmp_path, monkeypatch):
    monkeypatch.setattr("wescope.analyzers.semgrep.find_semgrep", lambda: None)
    root, _ = materialize("clean_app", tmp_path)
    report = render(run_scan(Target("folder", str(root))))
    assert "열린 발견이 없어요" in report and "첫 검사예요" in report
    assert "| semgrep | WS-05, WS-02, WS-06 | 건너뜀 | semgrep이 설치되어 있지 않아요 |" in report
