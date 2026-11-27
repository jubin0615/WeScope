"""테스트용 앱 전체 스캔: 기대 발견 재현 · 안전 표본 오탐 0 · 비밀값 원문 0 · 결정성 · 실패 격리 · JSON 왕복."""
import shutil

import pytest

from conftest import expected_hits, make_git_repo, materialize
from wescope.collector.snapshot import Target
from wescope.models.scan_result import ScanResult
from wescope.scan import run_scan

needs_semgrep = pytest.mark.skipif(not shutil.which("semgrep"), reason="semgrep 미설치")

ZOO_COMMITTED = [".env", "serviceAccountKey.json", "app.db", ".gitignore", "README.md", "components", "config",
                 "docker-compose.yml", ".github", ".npmrc", "tests", ".env.example"]
ZOO_FILE_LEVEL = ["secret-env-file .env", "secret-env-file .env.local", "secret-credential-file serviceAccountKey.json",
                  "secret-data-file app.db", "git-hygiene .gitignore"]


def scan(name, tmp_path, **kw):
    root, planted = materialize(name, tmp_path)
    if name == "secrets_zoo":
        make_git_repo(root, ZOO_COMMITTED)
    return root, planted, run_scan(Target("folder", str(root)), strict=True, **kw)


def found(result):
    return {(f.rule_id, f.location.file, f.location.line) for f in result.findings}


@needs_semgrep
@pytest.mark.parametrize("name", ["vuln_flask", "vuln_express", "vuln_django"])
def test_vulnerable_apps_match_expectations(name, tmp_path):
    root, _, result = scan(name, tmp_path)
    assert found(result) == expected_hits(root)
    assert all(a.status in ("ok", "not_applicable") for a in result.analyzers)


@needs_semgrep
def test_secrets_zoo_uses_git_state(tmp_path):
    root, _, result = scan("secrets_zoo", tmp_path)
    assert found(result) == expected_hits(root, ZOO_FILE_LEVEL)
    severity = {(f.rule_id, f.location.file): f.severity for f in result.findings}
    assert severity[("secret-env-file", ".env")] == "CRITICAL"          # 커밋됨
    assert severity[("secret-env-file", ".env.local")] == "HIGH"        # 커밋 안 됨 + ignore 안 됨
    assert severity[("git-hygiene", ".gitignore")] == "HIGH"            # .env* 미등록
    assert severity[("secret-hardcoded", "config/aws.py")] == "CRITICAL"
    assert severity[("secret-client-bundle", "components/AdminPanel.tsx")] == "CRITICAL"


@needs_semgrep
def test_clean_app_has_no_findings(tmp_path):
    _, _, result = scan("clean_app", tmp_path)
    assert found(result) == set()
    assert result.summary["risk_score"] == 0


@needs_semgrep
@pytest.mark.parametrize("name", ["vuln_flask", "vuln_express", "vuln_django", "secrets_zoo"])
def test_no_secret_leaves_in_result(name, tmp_path):
    """불변식: 심은 비밀값(.env 안의 값 포함)이 결과 JSON 어디에도 원문으로 남지 않는다."""
    _, planted, result = scan(name, tmp_path)
    text = result.to_json()
    assert planted and not [p for p in planted if p in text]


@needs_semgrep
@pytest.mark.parametrize("name", ["vuln_flask", "vuln_django"])
def test_same_code_same_result(name, tmp_path):
    """불변식: 같은 코드를 두 번 검사하면 발견·검사 범위·요약이 같다."""
    root, _ = materialize(name, tmp_path)
    first, second = (run_scan(Target("folder", str(root))) for _ in range(2))
    assert first.findings == second.findings
    assert first.coverage == second.coverage and first.summary == second.summary


def test_missing_semgrep_only_skips_its_area(tmp_path, monkeypatch):
    """불변식: Semgrep이 없어도 스캔은 끝나고, WS-05만 '건너뜀'이 된다."""
    monkeypatch.setattr("wescope.analyzers.semgrep.find_semgrep", lambda: None)
    root, _, result = scan("vuln_flask", tmp_path)
    status = {a.id: a.status for a in result.analyzers}
    assert status["semgrep"] == "skipped" and status["secrets"] == "ok"
    coverage = {row.code: row.state for row in result.coverage}
    assert coverage["WS-05"] == "skipped"
    assert {f.rule_id for f in result.findings} >= {"secret-hardcoded", "authz-idor", "config-debug"}


@needs_semgrep
def test_result_json_round_trip(tmp_path):
    _, _, result = scan("vuln_flask", tmp_path)
    assert ScanResult.from_json(result.to_json()) == result


def test_finds_semgrep_next_to_python_before_path(tmp_path, monkeypatch):
    """pipx·가상환경 설치는 semgrep이 PATH에 없고 We-Scope의 Python 옆 스크립트 폴더에만 있다."""
    import os
    import sysconfig
    from wescope.analyzers.semgrep import find_semgrep
    scripts = tmp_path / "Scripts"
    scripts.mkdir()
    exe = scripts / ("semgrep.exe" if os.name == "nt" else "semgrep")
    exe.write_text("")
    exe.chmod(0o755)
    monkeypatch.setattr(sysconfig, "get_path", lambda name, scheme=None: str(scripts))
    monkeypatch.setenv("PATH", "")
    assert os.path.samefile(find_semgrep(), exe)
    monkeypatch.setattr(sysconfig, "get_path", lambda name, scheme=None: str(tmp_path / "none"))
    assert find_semgrep() is None
